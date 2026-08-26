#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! The HTTP API: routing, authentication, authorization, and handlers.
//!
//! This is the one process in the system that holds plaintext secrets and key
//! material. The admin UI and the MCP server are interchangeable attachments that
//! talk to this API from the outside (ADR-11, ADR-13), which is what keeps that
//! statement true.
//!
//! Consequences that shape the code here:
//!
//! - Every route requires an authenticated identity, with two exceptions and both are
//!   named: `/v1/health`, and — where a deployment turned the `oidc_login` entry on —
//!   `POST /v1/auth/oidc/login`, which is the request a caller makes *because* it holds
//!   no credential of this system yet (ADR-26). What stands in for authentication there
//!   is a signature from a provider the configuration names, and until that verifies
//!   the request is treated exactly like an anonymous one — including writing nothing
//!   to the trail.
//! - Administrative reads are authorized through the same evaluator as secret reads,
//!   as the virtual paths `sys/audit`, `sys/identities`, and `sys/policies`. There is
//!   no second authorization mechanism and no `admin` capability.
//! - The router calls the path normalization from `ciphr-core` — never its own.
//! - Bulk endpoints write one audit entry per secret served, never one per call.
//! - No response leaves the process, and no change is made, before the audit entry is
//!   stored. See [`state`] for how reads and writes differ in ordering, and why.
//!
//! # Startup
//!
//! [`Server::start`] refuses to run rather than starting in a state that cannot keep
//! its promises. It fails if the configuration has no audit device, if the policy file
//! does not load, if the store is not initialized, if the master key is absent or
//! wrong, if an audit device cannot be opened, or if the TLS material is unusable. All
//! of those are better as a process that does not start than as one that serves
//! requests it cannot audit.
//!
//! It also refuses on an optional surface entry that is on and cannot say since when
//! and why, and on one the configuration names that this binary does not contain
//! (ADR-20, [`surface`]). Both are the same kind of failure as the audit device: a
//! configuration that cannot answer the question is a configuration error rather than
//! an operating mode.

pub mod api;
pub mod config;
pub mod error;
pub mod oidc;
pub mod server;
pub mod state;
pub mod surface;
pub mod tls;

pub use config::{AuditConfig, AuthConfig, Config, SealConfig, StorageBackend, StorageConfig};
pub use error::{ApiError, ConfigError, StartupError};
pub use server::{Check, Server, StoreReady, Unreachable};
pub use state::DeviceHealth;
pub use state::{AppState, Caller, Composition};
pub use surface::{Active as ActiveSurface, ENTRIES as SURFACE_ENTRIES};
