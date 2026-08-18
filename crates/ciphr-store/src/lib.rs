#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Persistence: the `Store` trait, its SQLite backend, and the migrations.
//!
//! The database holds ciphertext only and is not a trust anchor. The trait
//! exists so a different backend stays possible without touching the layers
//! above it; SQLite is the v1 choice because it adds no network dependency
//! that could take the secret store down with it (ADR-7).
//!
//! Migrations are numbered, additive SQL files applied in numeric order.
