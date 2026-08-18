#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! The HTTP API: routing, authentication, authorization, and handlers.
//!
//! This is the one process in the system that holds plaintext secrets and key
//! material. The admin UI and the MCP server are interchangeable attachments
//! that talk to this API from the outside (ADR-11, ADR-13), which is what
//! keeps that statement true.
//!
//! Consequences that shape the code in this crate:
//!
//! - Every route except `/v1/health` requires an authenticated identity.
//! - Administrative reads are authorized through the same evaluator as secret
//!   reads, as the virtual paths `sys/audit`, `sys/identities`, and
//!   `sys/policies`. There is no second authorization mechanism and no `admin`
//!   capability.
//! - The router calls the path normalization from
//!   `ciphr-core` — never its own.
//! - Bulk endpoints write one audit entry per secret served, never one per
//!   call.
