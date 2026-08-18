#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Envelope encryption and the seal abstraction.
//!
//! Master key wraps root key, root key wraps one data encryption key per
//! secret *version*, and that key encrypts exactly one payload — so nonce
//! reuse cannot occur by construction. Path and version are bound as
//! additional authenticated data, so a ciphertext cannot be moved from one
//! path to another.
//!
//! Together with `ciphr-policy` this crate *is*
//! the project; everything else is packaging. It therefore carries a hard
//! dependency budget, stays small enough for one person to review in full, and
//! must pass external review before the first production use.
//!
//! No custom constructions: established AEAD primitives, composed in the
//! documented standard pattern, with known-answer tests so a later refactor
//! cannot silently break compatibility.
