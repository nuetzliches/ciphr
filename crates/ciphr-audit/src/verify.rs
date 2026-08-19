//! Chain verification, and what to do when it fails.
//!
//! Verification recomputes the hash of every stored record and checks that each one
//! chains to its predecessor. It re-serializes nothing: the hash is over the stored
//! bytes, so this works on records written by an older build, and a change in how
//! JSON is produced can never invalidate a chain that was already written.
//!
//! # Recovery from a broken chain
//!
//! Documented here because a procedure invented during an incident is a procedure
//! nobody trusts.
//!
//! A break is a fact about the *stored* data, and there is no cryptographic way to
//! repair it — that is the point of the design. What can be done:
//!
//! 1. **Do not re-chain the entries.** Rewriting hashes to make the chain verify
//!    destroys the only evidence of what happened and produces a trail that lies. If
//!    that is ever done deliberately, it belongs in a new record, written by hand,
//!    saying so.
//! 2. **Find where it breaks.** [`verify`] reports the first sequence number that
//!    fails and how. `HashMismatch` at one record with everything after it intact
//!    means that record was edited in place. `PrevHashMismatch` means a record was
//!    removed, inserted, or reordered at that point.
//! 3. **Compare the devices.** Two devices hold the same chain; the file device is
//!    the useful second copy precisely because it is not the database. A break in one
//!    and not the other localizes the damage.
//! 4. **Treat the gap as unknown, not as empty.** Every access between the break and
//!    the next verified record has to be assumed unlogged, and whatever those
//!    credentials could reach has to be treated as potentially read.
//! 5. **Start a new chain deliberately.** After the incident is understood, resume
//!    from the last verified head, or start a fresh chain with the old one archived
//!    read-only. Both are defensible; silently continuing is not.
//!
//! A hash chain in a store an attacker can write to detects *partial* tampering. It
//! does not detect a complete forward rewrite — see the module documentation on
//! [`crate::chain`]. Copying the head hash somewhere outside the store is what closes
//! that gap: [`crate::anchor`] is that copy, and
//! [`crate::anchor::verify_with_anchor`] is this verification done against one. Where
//! the copy is kept remains an operational decision, and it is the decision that
//! decides whether the anchor is worth anything.

use serde::Deserialize;

use crate::chain::{GENESIS, HASH_LEN, hash_payload};
use crate::error::{BreakKind, ChainBreak};

/// One record as it was stored, for verification.
#[derive(Debug, Clone, Copy)]
pub struct StoredRecord<'a> {
    /// The sequence number the record is stored under.
    ///
    /// For the file device this is the line's position in the chain; for a database
    /// it is the column. Either way it is checked against what the payload says.
    pub seq: u64,
    /// The exact stored bytes.
    pub payload: &'a str,
    /// The stored hash, when the storage keeps one alongside the payload.
    ///
    /// The file device does not — the hash of the line *is* the hash — so `None`
    /// there. When present it is checked, because a stored hash that disagrees with
    /// the payload is itself evidence.
    pub hash: Option<[u8; HASH_LEN]>,
}

/// The result of verifying a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// How many records were checked.
    pub records: u64,
    /// The sequence number of the last record, or zero for an empty chain.
    pub head_seq: u64,
    /// The hash of the last record, or the genesis value for an empty chain.
    pub head_hash: [u8; HASH_LEN],
}

/// Only the fields verification needs. Unknown fields are ignored on purpose: a
/// record written by a newer build must still be checkable by an older one.
#[derive(Debug, Deserialize)]
struct Header {
    seq: u64,
    prev_hash: String,
}

/// Verify a chain of records, in order.
///
/// Pass every record from the first one for a full check, or a suffix together with
/// the hash it should chain to via `expected_prev`.
///
/// # Errors
///
/// Returns the first [`ChainBreak`] found. Verification stops there: everything after
/// a break is untrustworthy anyway, and reporting a hundred consequential errors would
/// bury the one that matters.
pub fn verify<'a, I>(records: I, expected_prev: [u8; HASH_LEN]) -> Result<Verified, ChainBreak>
where
    I: IntoIterator<Item = StoredRecord<'a>>,
{
    let mut previous = expected_prev;
    let mut expected_seq: Option<u64> = None;
    let mut count = 0_u64;
    let mut head_seq = 0_u64;

    for record in records {
        if let Some(expected) = expected_seq
            && record.seq != expected
        {
            return Err(ChainBreak {
                seq: record.seq,
                kind: BreakKind::SequenceGap { expected },
            });
        }

        let header: Header = serde_json::from_str(record.payload).map_err(|error| ChainBreak {
            seq: record.seq,
            kind: BreakKind::Malformed {
                // The error carries a position and a type, never the content.
                detail: error.to_string(),
            },
        })?;

        if header.seq != record.seq {
            return Err(ChainBreak {
                seq: record.seq,
                kind: BreakKind::SequenceMismatch {
                    payload_seq: header.seq,
                },
            });
        }

        let mut claimed_prev = [0_u8; HASH_LEN];
        ciphr_core::hex::decode_into(&header.prev_hash, &mut claimed_prev).map_err(|error| {
            ChainBreak {
                seq: record.seq,
                kind: BreakKind::Malformed {
                    detail: format!("prev_hash is not a chain hash: {error}"),
                },
            }
        })?;

        if claimed_prev != previous {
            return Err(ChainBreak {
                seq: record.seq,
                kind: BreakKind::PrevHashMismatch,
            });
        }

        let computed = hash_payload(record.payload.as_bytes());
        if let Some(stored) = record.hash
            && stored != computed
        {
            return Err(ChainBreak {
                seq: record.seq,
                kind: BreakKind::HashMismatch,
            });
        }

        previous = computed;
        expected_seq = Some(record.seq + 1);
        head_seq = record.seq;
        count += 1;
    }

    Ok(Verified {
        records: count,
        head_seq,
        head_hash: previous,
    })
}

/// Verify a chain from the beginning.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_from_genesis<'a, I>(records: I) -> Result<Verified, ChainBreak>
where
    I: IntoIterator<Item = StoredRecord<'a>>,
{
    verify(records, GENESIS)
}

#[cfg(test)]
mod tests {
    use super::{StoredRecord, verify_from_genesis};
    use crate::chain::{Chain, GENESIS, hash_payload};
    use crate::entry::{Action, Entry};
    use crate::error::BreakKind;

    /// A chain of `count` records, as they would be stored.
    fn chain_of(count: u64) -> Vec<(u64, String)> {
        let mut chain = Chain::new();
        let mut stored = Vec::new();
        for tick in 1..=count {
            let record = chain
                .encode(&Entry::allowed(Action::Read), i64::try_from(tick).unwrap())
                .expect("encode");
            chain.commit(&record);
            stored.push((record.seq, record.payload));
        }
        stored
    }

    fn as_records(stored: &[(u64, String)]) -> Vec<StoredRecord<'_>> {
        stored
            .iter()
            .map(|(seq, payload)| StoredRecord {
                seq: *seq,
                payload,
                hash: None,
            })
            .collect()
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let stored = chain_of(5);
        let verified = verify_from_genesis(as_records(&stored)).expect("must verify");

        assert_eq!(verified.records, 5);
        assert_eq!(verified.head_seq, 5);
        assert_eq!(verified.head_hash, hash_payload(stored[4].1.as_bytes()));
    }

    #[test]
    fn an_empty_chain_verifies_to_genesis() {
        let verified = verify_from_genesis(Vec::new()).expect("must verify");
        assert_eq!(verified.records, 0);
        assert_eq!(verified.head_seq, 0);
        assert_eq!(verified.head_hash, GENESIS);
    }

    #[test]
    fn an_edited_record_is_detected() {
        let mut stored = chain_of(4);
        // Change one character of an entry: the sort of edit someone would make to
        // hide which path they read.
        stored[1].1 = stored[1].1.replace("\"read\"", "\"list\"");

        let break_at = verify_from_genesis(as_records(&stored)).expect_err("must not verify");
        // The edited record still chains correctly to its predecessor; the break shows
        // up at the *next* record, whose prev_hash no longer matches.
        assert_eq!(break_at.seq, 3);
        assert_eq!(break_at.kind, BreakKind::PrevHashMismatch);
    }

    #[test]
    fn an_edited_record_with_a_stored_hash_is_detected_at_the_record_itself() {
        let mut chain = Chain::new();
        let first = chain
            .encode(&Entry::allowed(Action::Read), 1)
            .expect("encode");
        chain.commit(&first);

        let tampered = first.payload.replace("\"read\"", "\"list\"");
        let records = vec![StoredRecord {
            seq: 1,
            payload: &tampered,
            // The database keeps a hash column; the attacker did not update it.
            hash: Some(first.hash),
        }];

        let break_at = verify_from_genesis(records).expect_err("must not verify");
        assert_eq!(break_at.seq, 1);
        assert_eq!(break_at.kind, BreakKind::HashMismatch);
    }

    #[test]
    fn a_removed_record_is_detected() {
        let stored = chain_of(5);
        let mut records = as_records(&stored);
        records.remove(2);

        let break_at = verify_from_genesis(records).expect_err("must not verify");
        // The sequence jumps, which is caught before any hash is even computed.
        assert_eq!(break_at.seq, 4);
        assert_eq!(break_at.kind, BreakKind::SequenceGap { expected: 3 });
    }

    #[test]
    fn reordered_records_are_detected() {
        let stored = chain_of(4);
        let mut records = as_records(&stored);
        records.swap(1, 2);

        let break_at = verify_from_genesis(records).expect_err("must not verify");
        assert_eq!(break_at.seq, 3);
        assert_eq!(break_at.kind, BreakKind::SequenceGap { expected: 2 });
    }

    #[test]
    fn a_record_whose_payload_disagrees_with_its_row_is_detected() {
        // What a copied row looks like: the payload says one sequence number, the
        // column says another.
        let stored = chain_of(2);
        let records = vec![StoredRecord {
            seq: 1,
            payload: &stored[1].1,
            hash: None,
        }];

        let break_at = verify_from_genesis(records).expect_err("must not verify");
        assert_eq!(
            break_at.kind,
            BreakKind::SequenceMismatch { payload_seq: 2 }
        );
    }

    #[test]
    fn an_unreadable_record_is_reported_without_its_content() {
        let payload = "{not json";
        let records = vec![StoredRecord {
            seq: 1,
            payload,
            hash: None,
        }];

        let break_at = verify_from_genesis(records).expect_err("must not verify");
        assert!(matches!(break_at.kind, BreakKind::Malformed { .. }));
        assert!(
            !break_at.to_string().contains("not json"),
            "the message must not echo stored content"
        );
    }

    #[test]
    fn a_forward_rewrite_verifies_which_is_the_known_limitation() {
        // Someone who can write to the store can recompute every hash from the point
        // they changed. This test exists so that the limitation is stated in code as
        // well as in prose, and so that nobody later mistakes the chain for
        // protection against a writer.
        let mut chain = Chain::new();
        let mut rewritten = Vec::new();
        for tick in 1..=3_i64 {
            let record = chain
                .encode(&Entry::denied(Action::Read, "not-granted"), tick)
                .expect("encode");
            chain.commit(&record);
            rewritten.push((record.seq, record.payload));
        }

        assert!(verify_from_genesis(as_records(&rewritten)).is_ok());
    }
}
