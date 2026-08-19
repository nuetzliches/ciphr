#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! The audit trail — the reason this project exists.
//!
//! Two properties are non-negotiable, and both are tested rather than assumed:
//!
//! - **Fail-closed.** If no configured device accepts the record, the request is
//!   refused and no secret is served. The record is written before the response is
//!   produced, never after. See [`device::AuditSink`].
//! - **Hash-chained.** Every entry binds the previous one, so later modification or
//!   deletion of individual entries is detectable rather than merely unlikely. See
//!   [`chain`] for what is hashed, and [`verify`] for what a break means and how to
//!   respond to one.
//!
//! An entry carries identities, paths, decisions, and the matching rule. It never
//! carries a secret value, key material, or a token — only a token's non-secret
//! identifier ([`entry::Entry`]).
//!
//! # What this crate deliberately does not decide
//!
//! It does not know what an HTTP request is, does not read the clock, and does not
//! open a database. Timestamps are passed in, so that a record can be reproduced in a
//! test; the SQLite device lives in `ciphr-store`, which is the crate that owns the
//! connection and the migrations. This crate is a sink for facts.
//!
//! # Example
//!
//! ```
//! use ciphr_audit::{Action, AuditSink, Chain, Entry, Principal, StoredRecord, verify_from_genesis};
//! use ciphr_core::SecretPath;
//!
//! # let directory = tempfile::tempdir()?;
//! # let audit_path = directory.path().join("audit.jsonl");
//! let device = ciphr_audit::FileDevice::open(&audit_path, None)?;
//! let mut sink = AuditSink::new(vec![Box::new(device)], Chain::new())?;
//!
//! let path = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
//! let entry = Entry::allowed(Action::Read)
//!     .with_principal(Principal::named("deploy-runner"))
//!     .with_path(&path)
//!     .with_rule("infra-read", "infra/**");
//!
//! let written = sink.record(&entry, 1_767_225_599_999)?;
//! assert_eq!(written.seq, 1);
//! assert!(written.failures.is_empty());
//!
//! // The chain can be verified from the file alone: each line is exactly the bytes
//! // that were hashed.
//! let text = std::fs::read_to_string(&audit_path)?;
//! let records: Vec<StoredRecord<'_>> = text
//!     .lines()
//!     .enumerate()
//!     .map(|(index, line)| StoredRecord { seq: index as u64 + 1, payload: line, hash: None })
//!     .collect();
//! assert_eq!(verify_from_genesis(records)?.head_hash, written.hash);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

pub mod anchor;
pub mod chain;
pub mod device;
pub mod entry;
pub mod error;
pub mod file;
pub mod time;
pub mod verify;

pub use anchor::{Anchor, AnchorError, verify_with_anchor};
pub use chain::{Chain, EncodedRecord, GENESIS, HASH_LEN, hash_payload};
pub use device::{AuditDevice, AuditSink, Written};
pub use entry::{Action, DecidingRule, Entry, Principal, RequestContext};
pub use error::{AuditError, BreakKind, ChainBreak, DeviceFailure};
pub use file::FileDevice;
pub use verify::{Start, StoredRecord, Verified, verify, verify_from, verify_from_genesis};
