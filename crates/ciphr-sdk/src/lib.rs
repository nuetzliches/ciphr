#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Rust client for the ciphr HTTP API.
//!
//! The reason this crate ships is the third secret-consumption route: an
//! application that fetches its own secrets at startup leaves no plaintext on
//! disk and none in the container configuration. A useful side effect is that
//! the audit entry then carries the identity of the *service* rather than that
//! of the deploy runner.
//!
//! The client speaks only documented v1 endpoints. It holds no key material
//! and performs no cryptography beyond TLS.
