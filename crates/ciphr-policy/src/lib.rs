#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Path-based authorization: TOML policies, typed rules, and the evaluator.
//!
//! Deny by default. A capability is granted only by a matching rule; the most
//! specific match wins, and on a tie denial wins. An empty capability set is
//! an explicit denial that beats any less specific permission.
//!
//! Glob matching is deliberately minimal — `*` covers exactly one path
//! segment, `**` covers one or more, and there are no regular expressions and
//! no character classes. Policies come from configuration under version
//! control; there is no policy-write API (ADR-3).
//!
//! This crate shares the review and dependency budget of
//! `ciphr-crypto`: it is small on purpose,
//! because an authorization bug here fails silently.
