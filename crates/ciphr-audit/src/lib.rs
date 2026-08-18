#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! The audit trail — the reason this project exists.
//!
//! Two properties are non-negotiable and are tested rather than assumed:
//!
//! - **Fail-closed.** If no configured audit device accepts the record, the
//!   request is refused and no secret is served. The record is written before
//!   the response is sent, never after.
//! - **Hash-chained.** Every entry binds the previous one, so later
//!   modification or deletion of individual entries is detectable rather than
//!   merely unlikely.
//!
//! An entry carries identities, paths, decisions, and the matching rule. It
//! never carries a secret value, key material, or a token — only a token's
//! non-secret identifier.
