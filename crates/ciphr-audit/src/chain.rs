//! The hash chain.
//!
//! Every record carries the hash of the one before it, so removing or altering a
//! single entry is **detectable** rather than merely unlikely. That is the property
//! the audit trail is worth having: an access log that can be quietly trimmed
//! answers nothing.
//!
//! # What is hashed
//!
//! The hash is the SHA-256 of **exactly the bytes that are stored** — the JSON
//! encoding of `{seq, ts, prev_hash, entry}`. Two consequences, both deliberate:
//!
//! - Verification never re-serializes anything. It hashes the stored text and
//!   compares, so a future change in how JSON is produced cannot invalidate a chain
//!   written today.
//! - `prev_hash` is inside the hashed bytes, which is what chains the records
//!   together. There is no separate `SHA-256(prev || payload)` step, because that
//!   would mean the same value appearing in two places, and two places can disagree.
//!
//! # What a hash chain does not do
//!
//! It detects *partial* tampering: an entry removed, an entry edited, entries
//! reordered. It does **not** detect a complete rewrite by someone who can write to
//! the store, because they can recompute every hash forward from the point they
//! changed. Detecting that needs an anchor outside the store — a copy of the head
//! hash somewhere else, or the file device on a different host. This limitation is
//! inherent, and stating it is part of the design rather than a caveat to be found
//! later.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::entry::Entry;
use crate::error::AuditError;
use crate::time::rfc3339_millis;

/// Length of a chain hash, in bytes.
pub const HASH_LEN: usize = 32;

/// The `prev_hash` of the first record: thirty-two zero bytes.
pub const GENESIS: [u8; HASH_LEN] = [0_u8; HASH_LEN];

/// A record, as it is serialized and hashed.
///
/// The field order here **is** the wire format: `serde_json` writes fields in
/// declaration order, and the known-answer test pins the result.
#[derive(Debug, Serialize)]
struct Record<'a> {
    seq: u64,
    ts: String,
    prev_hash: String,
    entry: &'a Entry,
}

/// A record that has been serialized and hashed, ready for a device to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRecord {
    /// Sequence number, starting at one.
    pub seq: u64,
    /// Milliseconds since the Unix epoch, as passed in.
    pub ts_millis: i64,
    /// The hash of the previous record.
    pub prev_hash: [u8; HASH_LEN],
    /// The hash of [`Self::payload`].
    pub hash: [u8; HASH_LEN],
    /// The exact bytes to store: the JSON encoding of the record.
    pub payload: String,
}

impl EncodedRecord {
    /// The hash as lower-case hexadecimal.
    pub fn hash_hex(&self) -> String {
        ciphr_core::hex::encode(&self.hash)
    }

    /// The previous hash as lower-case hexadecimal.
    pub fn prev_hash_hex(&self) -> String {
        ciphr_core::hex::encode(&self.prev_hash)
    }
}

/// The chain state: what the next record's sequence number and `prev_hash` are.
///
/// Held by the sink rather than by a device, because every device must record the
/// same chain. Two devices with independent chains would produce two histories that
/// cannot be compared, which defeats having a second device at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    next_seq: u64,
    prev_hash: [u8; HASH_LEN],
}

impl Chain {
    /// Start a new chain.
    pub const fn new() -> Self {
        Self {
            next_seq: 1,
            prev_hash: GENESIS,
        }
    }

    /// Resume an existing chain from its head.
    ///
    /// The head comes from the store at startup. Resuming from the wrong place
    /// produces a chain break at the next verification, which is the intended
    /// outcome: a gap that is visible beats a gap that is not.
    pub const fn resume(last_seq: u64, last_hash: [u8; HASH_LEN]) -> Self {
        Self {
            next_seq: last_seq + 1,
            prev_hash: last_hash,
        }
    }

    /// The sequence number the next record will get.
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The hash the next record will chain to.
    pub const fn head_hash(&self) -> [u8; HASH_LEN] {
        self.prev_hash
    }

    /// Encode an entry as the next record, **without** advancing the chain.
    ///
    /// Advancing is a separate step ([`Chain::commit`]) so that a record which no
    /// device managed to store does not consume a sequence number. A gap in the
    /// sequence is indistinguishable from a deleted entry, and an audit trail that
    /// reports tampering after a disk error would train its readers to ignore it.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Encode`] if the entry cannot be serialized. In
    /// practice this means a `String` field containing invalid UTF-8, which the
    /// type system already prevents.
    pub fn encode(&self, entry: &Entry, now_millis: i64) -> Result<EncodedRecord, AuditError> {
        let record = Record {
            seq: self.next_seq,
            ts: rfc3339_millis(now_millis),
            prev_hash: ciphr_core::hex::encode(&self.prev_hash),
            entry,
        };

        let payload = serde_json::to_string(&record).map_err(AuditError::Encode)?;
        let hash = hash_payload(payload.as_bytes());

        Ok(EncodedRecord {
            seq: self.next_seq,
            ts_millis: now_millis,
            prev_hash: self.prev_hash,
            hash,
            payload,
        })
    }

    /// Advance the chain past a record that was stored.
    ///
    /// # Panics
    ///
    /// Panics if the record is not the one this chain expected. That would mean the
    /// caller stored a record built against different state, and continuing would
    /// write a chain that is broken by construction — a panic is the lesser
    /// failure, and it is unreachable through the public API of this crate.
    pub fn commit(&mut self, record: &EncodedRecord) {
        assert_eq!(
            record.seq, self.next_seq,
            "a record was committed out of order"
        );
        self.next_seq += 1;
        self.prev_hash = record.hash;
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash stored record bytes.
pub fn hash_payload(payload: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(payload);
    let mut hash = [0_u8; HASH_LEN];
    hash.copy_from_slice(&digest);
    hash
}

#[cfg(test)]
mod tests {
    use super::{Chain, GENESIS, hash_payload};
    use crate::entry::{Action, Entry, Principal, RequestContext};
    use ciphr_core::{SecretPath, SecretVersion};

    fn sample_entry() -> Entry {
        let path = SecretPath::parse("infra/service-a/DB_PASSWORD").expect("valid");
        Entry::allowed(Action::Read)
            .with_principal(Principal {
                name: "deploy-runner".to_owned(),
                kind: Some("machine".to_owned()),
                token_id: Some("a1b2c3d4".to_owned()),
            })
            .with_path(&path)
            .with_version(SecretVersion::FIRST)
            .with_rule("infra-read", "infra/**")
            .with_request(RequestContext {
                request_id: Some("r-1".to_owned()),
                client_ip: Some("10.0.0.7".to_owned()),
                user_agent: Some("curl/8.5.0".to_owned()),
                http_status: Some(200),
                channel: None,
            })
    }

    #[test]
    fn kat_record_encoding() {
        // Pins the stored form. A change here means every existing chain fails to
        // verify, so it must be a decision and never a side effect.
        let chain = Chain::new();
        let record = chain.encode(&sample_entry(), 1_767_225_599_999).unwrap();

        assert_eq!(
            record.payload,
            r#"{"seq":1,"ts":"2025-12-31T23:59:59.999Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry":{"principal":{"name":"deploy-runner","kind":"machine","token_id":"a1b2c3d4"},"action":"read","path":"infra/service-a/DB_PASSWORD","version":1,"allowed":true,"deny_reason":null,"rule":{"policy":"infra-read","pattern":"infra/**"},"request":{"request_id":"r-1","client_ip":"10.0.0.7","user_agent":"curl/8.5.0","http_status":200,"channel":null}}}"#
        );
        assert_eq!(record.hash_hex(), KAT_HASH);
        assert_eq!(record.prev_hash, GENESIS);
    }

    const KAT_HASH: &str = "e7510c2f0500827d9a706398fafbc26911915722c245b4c60f73c5f634e75b62";

    #[test]
    fn absent_fields_are_written_as_null_rather_than_omitted() {
        // So that "not applicable" and "an older version did not record this" stay
        // distinguishable in a file read years later.
        let chain = Chain::new();
        let record = chain.encode(&Entry::allowed(Action::Init), 0).unwrap();
        assert!(record.payload.contains(r#""path":null"#));
        assert!(record.payload.contains(r#""principal":null"#));
        assert!(record.payload.contains(r#""http_status":null"#));
    }

    #[test]
    fn the_hash_is_the_hash_of_the_stored_bytes() {
        // The property that makes verification independent of the serializer.
        let chain = Chain::new();
        let record = chain.encode(&sample_entry(), 42).unwrap();
        assert_eq!(record.hash, hash_payload(record.payload.as_bytes()));
    }

    #[test]
    fn each_record_chains_to_the_previous_one() {
        let mut chain = Chain::new();

        let first = chain.encode(&sample_entry(), 1).unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(first.prev_hash, GENESIS);
        chain.commit(&first);

        let second = chain.encode(&sample_entry(), 2).unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_hash, first.hash);
        assert_ne!(second.hash, first.hash);
        chain.commit(&second);

        assert_eq!(chain.next_seq(), 3);
        assert_eq!(chain.head_hash(), second.hash);
    }

    #[test]
    fn encoding_without_committing_does_not_consume_a_sequence_number() {
        // What happens when every device fails: the record is discarded and the next
        // attempt reuses the number, so no gap appears in the sequence.
        let mut chain = Chain::new();
        let discarded = chain.encode(&sample_entry(), 1).unwrap();
        assert_eq!(discarded.seq, 1);

        let retried = chain.encode(&sample_entry(), 2).unwrap();
        assert_eq!(retried.seq, 1);
        chain.commit(&retried);
        assert_eq!(chain.next_seq(), 2);
    }

    #[test]
    fn a_resumed_chain_continues_where_it_left_off() {
        let mut original = Chain::new();
        let first = original.encode(&sample_entry(), 1).unwrap();
        original.commit(&first);

        let resumed = Chain::resume(first.seq, first.hash);
        let second = resumed.encode(&sample_entry(), 2).unwrap();

        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_hash, first.hash);
    }
}
