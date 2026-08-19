//! The anchor: a copy of the chain head kept outside the store.
//!
//! [`crate::chain`] names the limitation this module answers. A hash chain detects
//! *partial* tampering — an entry edited, removed, reordered — because every record
//! binds the one before it. It does not detect a **forward rewrite**: whoever can
//! write the store can recompute every hash from the point they changed, and the
//! result verifies from genesis. Nothing kept inside the store can close that, because
//! the edit and the evidence would live in the same place.
//!
//! An anchor is that evidence kept elsewhere: the sequence number and the hash of the
//! head at a point in time, appended to a file that is not the store — best of all on
//! a host or in a backup the store's writer cannot reach. A later verification that
//! finds a different hash at the anchored sequence has proof of a rewrite, where
//! before it had a chain that merely looked consistent.
//!
//! Three properties of the format, each deliberate:
//!
//! - **One JSON object per line, appended.** The newest anchor is the last line, and
//!   the older ones stay. The file can of course be rewritten too — but only by
//!   reaching a second place, which is the entire point.
//! - **No secret material and no signature.** The record is a hash, a sequence number,
//!   and a timestamp. A signature would need a key, and a key kept next to the store
//!   protects nothing the store's writer cannot also reach. What an anchor buys is
//!   separation, not cryptography.
//! - **A mismatch does not say which cause it has.** A rewritten chain and an anchor
//!   file belonging to a different store produce the same contradiction, and this code
//!   reports both possibilities rather than guessing. Either one is worth stopping
//!   for.
//!
//! Retention is where this becomes load-bearing rather than merely prudent: cutting
//! the queryable device removes the records that a verification from genesis would
//! start at, so what remains has to be verified forward from a known point. That point
//! is an anchor.
//!
//! # Example
//!
//! ```
//! use ciphr_audit::anchor::{Anchor, verify_with_anchor};
//! use ciphr_audit::{Action, AuditSink, Chain, Entry, StoredRecord, verify_from_genesis};
//!
//! # let directory = tempfile::tempdir()?;
//! # let path = directory.path().join("audit.jsonl");
//! let device = ciphr_audit::FileDevice::open(&path, None)?;
//! let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new())?;
//! sink.record(&Entry::allowed(Action::Read), 1_767_225_599_999)?;
//!
//! let text = std::fs::read_to_string(&path)?;
//! let records: Vec<StoredRecord<'_>> = text
//!     .lines()
//!     .enumerate()
//!     .map(|(index, line)| StoredRecord { seq: index as u64 + 1, payload: line, hash: None })
//!     .collect();
//!
//! // Take an anchor over a verified chain, write the line somewhere else, and later
//! // check the chain against it.
//! let verified = verify_from_genesis(records.iter().copied())?;
//! let anchor = Anchor::over(&verified, 1_767_225_600_000);
//! let line = anchor.encode();
//!
//! let read_back = Anchor::parse(&line)?;
//! assert_eq!(read_back, anchor);
//! assert!(verify_with_anchor(&read_back, &records).is_ok());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};

use crate::chain::{HASH_LEN, hash_payload};
use crate::error::{BreakKind, ChainBreak};
use crate::time::rfc3339_millis;
use crate::verify::{StoredRecord, Verified, verify, verify_from_genesis};

/// The format version written into every anchor record.
///
/// A reader that meets a version it does not know refuses rather than guesses: an
/// anchor is evidence, and evidence read under the wrong assumption is worse than
/// evidence that could not be read at all.
pub const FORMAT_VERSION: u32 = 1;

/// A chain head, recorded outside the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// When the anchor was taken, RFC 3339 in UTC.
    ///
    /// Descriptive only — nothing verifies against it. It exists so that a person
    /// reading the file during an incident can tell how much of the trail an anchor
    /// covers without reconstructing it from sequence numbers.
    pub taken_at: String,
    /// The sequence number of the head at that moment.
    pub seq: u64,
    /// The hash of the record at that sequence number.
    pub hash: [u8; HASH_LEN],
}

/// The wire form. Field order is the file format; `serde_json` writes declaration
/// order and the tests below pin the result.
#[derive(Serialize, Deserialize)]
struct Wire {
    anchor: u32,
    taken_at: String,
    seq: u64,
    hash: String,
}

/// What can be wrong with an anchor record on its way in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// The line is not the JSON object an anchor is.
    Malformed {
        /// What the parser objected to. Never the line itself: an anchor file may sit
        /// next to material that is not one, and an error message is a place values
        /// leak from.
        detail: String,
    },
    /// The record was written by a format this build does not know.
    UnknownVersion {
        /// The version the record claims.
        found: u32,
    },
    /// The hash field is not a chain hash.
    NotAHash {
        /// What was wrong with it.
        detail: String,
    },
    /// The record anchors sequence zero, which no record has.
    ///
    /// Sequence numbers start at one, so a zero here is either an empty chain that
    /// should not have been anchored or a hand-edited file.
    ZeroSequence,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed { detail } => write!(f, "not an anchor record: {detail}"),
            Self::UnknownVersion { found } => write!(
                f,
                "anchor format version {found} is not one this build can read (expected \
                 {FORMAT_VERSION})"
            ),
            Self::NotAHash { detail } => write!(f, "the anchored hash is unusable: {detail}"),
            Self::ZeroSequence => {
                f.write_str("the record anchors sequence 0, and no record has that sequence number")
            }
        }
    }
}

impl core::error::Error for AnchorError {}

impl Anchor {
    /// Take an anchor over a verified chain.
    ///
    /// Deliberately takes [`Verified`] rather than a sequence number and a hash: an
    /// anchor over an unverified chain would notarize whatever it found, including a
    /// break. Requiring the proof as the argument makes that mistake unavailable
    /// rather than merely discouraged.
    ///
    /// `now_millis` is passed in for the same reason the rest of this crate does not
    /// read the clock: a record has to be reproducible in a test.
    pub fn over(verified: &Verified, now_millis: i64) -> Self {
        Self {
            taken_at: rfc3339_millis(now_millis),
            seq: verified.head_seq,
            hash: verified.head_hash,
        }
    }

    /// The single line this anchor is stored as, without a trailing newline.
    pub fn encode(&self) -> String {
        let wire = Wire {
            anchor: FORMAT_VERSION,
            taken_at: self.taken_at.clone(),
            seq: self.seq,
            hash: ciphr_core::hex::encode(&self.hash),
        };
        // The struct has no field that can fail to serialize, so this cannot error;
        // producing an obviously wrong line would still be better than a panic in a
        // command an operator runs on a schedule.
        serde_json::to_string(&wire).unwrap_or_default()
    }

    /// Read one anchor from one line.
    ///
    /// # Errors
    ///
    /// [`AnchorError`] if the line is not an anchor record this build can read.
    pub fn parse(line: &str) -> Result<Self, AnchorError> {
        let wire: Wire = serde_json::from_str(line).map_err(|error| AnchorError::Malformed {
            detail: error.to_string(),
        })?;

        if wire.anchor != FORMAT_VERSION {
            return Err(AnchorError::UnknownVersion { found: wire.anchor });
        }
        if wire.seq == 0 {
            return Err(AnchorError::ZeroSequence);
        }

        let mut hash = [0_u8; HASH_LEN];
        ciphr_core::hex::decode_into(&wire.hash, &mut hash).map_err(|error| {
            AnchorError::NotAHash {
                detail: error.to_string(),
            }
        })?;

        Ok(Self {
            taken_at: wire.taken_at,
            seq: wire.seq,
            hash,
        })
    }

    /// The most recent anchor in the contents of an anchor file.
    ///
    /// The last non-empty line, because the file is appended to. `Ok(None)` for a file
    /// that is empty or holds only blank lines — a first anchor has nothing to check
    /// itself against, and that is not an error.
    ///
    /// # Errors
    ///
    /// [`AnchorError`] if the last non-empty line is not a readable anchor. An
    /// unreadable newest line is not skipped in favour of an older one: the newest
    /// anchor is the one a check has to be made against, and quietly using an earlier
    /// one would check less than the caller asked for.
    pub fn latest(contents: &str) -> Result<Option<Self>, AnchorError> {
        match contents.lines().rfind(|line| !line.trim().is_empty()) {
            None => Ok(None),
            Some(line) => Self::parse(line).map(Some),
        }
    }
}

/// Verify a chain against an anchor taken over it earlier.
///
/// Two shapes of input are checkable, and they are the two that occur:
///
/// - **The whole chain**, beginning at sequence 1. It is verified from genesis, and
///   the record at the anchored sequence must hash to the anchored hash.
/// - **What is left after a cut**, beginning immediately after the anchored sequence.
///   The anchored hash is then the predecessor the first surviving record must chain
///   to.
///
/// Anything else — a run that starts in the middle, or one that ends before the
/// anchored sequence — yields [`BreakKind::AnchorUnreachable`]. That is a refusal to
/// check rather than a verdict: an anchor that cannot be attached to the records in
/// hand proves nothing about them, and reporting success would be the worse answer.
///
/// # Errors
///
/// The first [`ChainBreak`] found. The chain itself is checked before the anchor is,
/// because a break inside the records is the more specific finding: a rewrite detected
/// by the anchor is *consistent* records that disagree with the outside world, and
/// reporting that at a record which is itself broken would point at the wrong problem.
pub fn verify_with_anchor(
    anchor: &Anchor,
    records: &[StoredRecord<'_>],
) -> Result<Verified, ChainBreak> {
    let unreachable = |head_seq: u64| ChainBreak {
        seq: anchor.seq,
        kind: BreakKind::AnchorUnreachable { head_seq },
    };

    let Some(first) = records.first() else {
        return Err(unreachable(0));
    };
    let head_seq = records.last().map_or(0, |record| record.seq);

    // What is left after a cut: the anchored record is gone, and the anchor stands in
    // for it as the expected predecessor. `verify` does the rest, including reporting a
    // first record that does not chain to it.
    if first.seq == anchor.seq.saturating_add(1) {
        return verify(records.iter().copied(), anchor.hash);
    }

    if first.seq != 1 || head_seq < anchor.seq {
        return Err(unreachable(head_seq));
    }

    let verified = verify_from_genesis(records.iter().copied())?;

    let Some(anchored) = records.iter().find(|record| record.seq == anchor.seq) else {
        // The run starts at 1 and reaches past the anchored sequence, so the record is
        // missing from the middle rather than absent by design. `verify_from_genesis`
        // above would have reported the resulting gap; this is here so that a future
        // change to that ordering cannot turn the case into a silent pass.
        return Err(unreachable(verified.head_seq));
    };

    let computed = hash_payload(anchored.payload.as_bytes());
    if computed != anchor.hash {
        return Err(ChainBreak {
            seq: anchor.seq,
            kind: BreakKind::AnchorMismatch {
                anchored: ciphr_core::hex::encode(&anchor.hash),
                stored: ciphr_core::hex::encode(&computed),
            },
        });
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::{Anchor, AnchorError, FORMAT_VERSION, verify_with_anchor};
    use crate::chain::{Chain, hash_payload};
    use crate::entry::{Action, Entry};
    use crate::error::BreakKind;
    use crate::verify::{StoredRecord, verify_from_genesis};

    /// A chain of `count` records, as the bytes a device would have stored.
    ///
    /// `alter` picks a sequence number to record as denied rather than allowed, which
    /// is how the rewrite test produces a chain of the same shape and different
    /// content.
    fn chain_of(count: u64, alter: Option<u64>) -> Vec<String> {
        let mut chain = Chain::new();
        let mut payloads = Vec::new();
        for index in 1..=count {
            let entry = if alter == Some(index) {
                Entry::denied(Action::Read, "no rule matched")
            } else {
                Entry::allowed(Action::Read)
            };
            let record = chain
                .encode(
                    &entry,
                    1_767_225_599_000 + i64::try_from(index).expect("small"),
                )
                .expect("encode");
            chain.commit(&record);
            payloads.push(record.payload);
        }
        payloads
    }

    fn records(payloads: &[String], first_seq: u64) -> Vec<StoredRecord<'_>> {
        payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| StoredRecord {
                seq: first_seq + u64::try_from(index).expect("small"),
                payload,
                hash: None,
            })
            .collect()
    }

    fn anchor_over(payloads: &[String], through: usize, at_millis: i64) -> Anchor {
        let rows = records(payloads, 1);
        let verified =
            verify_from_genesis(rows[..through].iter().copied()).expect("the chain must verify");
        Anchor::over(&verified, at_millis)
    }

    #[test]
    fn a_record_round_trips_through_its_line() {
        let payloads = chain_of(3, None);
        let anchor = anchor_over(&payloads, 3, 1_767_225_600_000);

        let line = anchor.encode();
        assert_eq!(
            line,
            format!(
                "{{\"anchor\":{FORMAT_VERSION},\"taken_at\":\"2026-01-01T00:00:00.000Z\",\
                 \"seq\":3,\"hash\":\"{}\"}}",
                ciphr_core::hex::encode(&anchor.hash)
            ),
            "the line is the file format, so it is pinned rather than assumed"
        );
        assert_eq!(Anchor::parse(&line).expect("parse"), anchor);
    }

    #[test]
    fn an_anchor_is_taken_over_the_head_it_verified() {
        let payloads = chain_of(5, None);
        let anchor = anchor_over(&payloads, 5, 0);

        assert_eq!(anchor.seq, 5);
        assert_eq!(anchor.hash, hash_payload(payloads[4].as_bytes()));
        assert_eq!(anchor.taken_at, "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn the_newest_line_is_the_one_that_counts() {
        let payloads = chain_of(2, None);
        let first = anchor_over(&payloads, 1, 0);
        let second = anchor_over(&payloads, 2, 86_400_000);

        let file = format!("{}\n{}\n\n", first.encode(), second.encode());
        assert_eq!(Anchor::latest(&file).expect("parse"), Some(second));
        assert_eq!(Anchor::latest("").expect("empty"), None);
        assert_eq!(Anchor::latest("\n  \n").expect("blank"), None);
    }

    #[test]
    fn an_unreadable_newest_line_is_not_skipped_for_an_older_one() {
        let payloads = chain_of(1, None);
        let file = format!("{}\nnot an anchor\n", anchor_over(&payloads, 1, 0).encode());

        assert!(matches!(
            Anchor::latest(&file),
            Err(AnchorError::Malformed { .. })
        ));
    }

    #[test]
    fn a_record_from_an_unknown_format_is_refused() {
        let line =
            "{\"anchor\":2,\"taken_at\":\"2026-01-01T00:00:00.000Z\",\"seq\":1,\"hash\":\"00\"}";
        assert_eq!(
            Anchor::parse(line),
            Err(AnchorError::UnknownVersion { found: 2 })
        );
    }

    #[test]
    fn a_hash_of_the_wrong_length_is_refused() {
        let line = format!(
            "{{\"anchor\":{FORMAT_VERSION},\"taken_at\":\"2026-01-01T00:00:00.000Z\",\"seq\":1,\
             \"hash\":\"abcd\"}}"
        );
        assert!(matches!(
            Anchor::parse(&line),
            Err(AnchorError::NotAHash { .. })
        ));
    }

    #[test]
    fn sequence_zero_is_refused() {
        let line = format!(
            "{{\"anchor\":{FORMAT_VERSION},\"taken_at\":\"2026-01-01T00:00:00.000Z\",\"seq\":0,\
             \"hash\":\"{}\"}}",
            "00".repeat(32)
        );
        assert_eq!(Anchor::parse(&line), Err(AnchorError::ZeroSequence));
    }

    #[test]
    fn a_chain_that_grew_past_its_anchor_still_verifies() {
        let payloads = chain_of(6, None);
        let anchor = anchor_over(&payloads, 4, 0);

        let verified =
            verify_with_anchor(&anchor, &records(&payloads, 1)).expect("the anchor must hold");
        assert_eq!(verified.head_seq, 6, "growth is not a contradiction");
        assert_eq!(verified.records, 6);
    }

    /// The reason this module exists.
    ///
    /// A rewrite recomputes every hash forward, so the chain verifies from genesis —
    /// [`crate::chain`] says so and there is a test for it there. Against an anchor
    /// taken before the rewrite, the same chain is caught.
    #[test]
    fn a_forward_rewrite_verifies_from_genesis_and_fails_against_an_anchor() {
        let original = chain_of(3, None);
        let anchor = anchor_over(&original, 3, 0);

        // Same length, one entry changed, every hash recomputed from that point.
        let rewritten = chain_of(3, Some(2));
        let rewritten_rows = records(&rewritten, 1);

        verify_from_genesis(rewritten_rows.iter().copied())
            .expect("a forward rewrite verifies -- that is the gap being covered");

        let found =
            verify_with_anchor(&anchor, &rewritten_rows).expect_err("the anchor must catch it");
        assert_eq!(found.seq, 3);
        match found.kind {
            BreakKind::AnchorMismatch { anchored, stored } => {
                assert_eq!(anchored, ciphr_core::hex::encode(&anchor.hash));
                assert_ne!(stored, anchored, "the rewrite changed the head");
            }
            other => panic!("expected an anchor mismatch, got {other:?}"),
        }
    }

    #[test]
    fn what_survives_a_cut_is_verified_forward_from_the_anchor() {
        let payloads = chain_of(6, None);
        let anchor = anchor_over(&payloads, 3, 0);

        // The cut: records 1 to 3 are gone from this device, 4 to 6 remain.
        let survivors = records(&payloads[3..], 4);
        let verified = verify_with_anchor(&anchor, &survivors).expect("verify forward");
        assert_eq!(verified.records, 3);
        assert_eq!(verified.head_seq, 6);
    }

    #[test]
    fn a_survivor_that_does_not_chain_to_the_anchor_is_a_break() {
        let payloads = chain_of(6, None);
        // Sequence 3 claimed, but the hash is record 2's: what an anchor from the wrong
        // store, or a cut recorded one record early, looks like.
        let anchor = Anchor {
            seq: 3,
            ..anchor_over(&payloads, 2, 0)
        };

        let found =
            verify_with_anchor(&anchor, &records(&payloads[3..], 4)).expect_err("must not verify");
        assert_eq!(found.kind, BreakKind::PrevHashMismatch);
    }

    #[test]
    fn an_anchor_that_cannot_be_attached_is_refused_rather_than_passed() {
        let payloads = chain_of(5, None);

        // Beyond the head: the chain is shorter than the anchor says it was.
        let ahead = Anchor {
            seq: 9,
            ..anchor_over(&payloads, 5, 0)
        };
        assert_eq!(
            verify_with_anchor(&ahead, &records(&payloads, 1))
                .expect_err("cannot be checked")
                .kind,
            BreakKind::AnchorUnreachable { head_seq: 5 }
        );

        // A run that starts in the middle, neither containing the anchored record nor
        // following it: records 3 to 5 against an anchor at sequence 1.
        let behind = anchor_over(&payloads, 1, 0);
        assert_eq!(
            verify_with_anchor(&behind, &records(&payloads[2..], 3))
                .expect_err("cannot be checked")
                .kind,
            BreakKind::AnchorUnreachable { head_seq: 5 }
        );

        // Nothing at all.
        assert_eq!(
            verify_with_anchor(&behind, &[])
                .expect_err("cannot be checked")
                .kind,
            BreakKind::AnchorUnreachable { head_seq: 0 }
        );
    }
}
