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
//!
//! # The shortest useful program
//!
//! ```no_run
//! use ciphr_sdk::{Client, SecretPath};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // All three are required, and the certificate authority is required by design:
//! // there is no way to build a client that trusts the public CA set (ADR-17).
//! let client = Client::builder(
//!     "https://ciphr.internal:4400",
//!     &std::fs::read_to_string("/run/secrets/ciphr-token")?,
//!     &std::fs::read("/etc/ciphr/ca.crt")?,
//! )
//! .build()?;
//!
//! let environment = client.environment(&SecretPath::parse("infra/service-a")?)?;
//!
//! // Names are safe to log; values are not, and the type system enforces the
//! // difference rather than a review catching it. A `Display` on a value does not
//! // exist, so the line below cannot be written the other way round by accident.
//! let received: Vec<&str> = environment.names().map(|name| name.as_str()).collect();
//! assert!(received.contains(&"DB_PASSWORD"));
//!
//! // The value is borrowed, never formatted. Reading from here rather than putting it
//! // in the environment keeps it out of /proc/<pid>/environ entirely.
//! let password = environment.get("DB_PASSWORD").expect("under the prefix");
//! assert!(!password.is_empty());
//! # Ok(())
//! # }
//! ```
//!
//! # At startup, where the service may be waiting on the store
//!
//! There is no retry loop in this crate ([`SdkError::is_retryable`] says which failures could
//! change on their own, and nothing here decides how long to wait). This is what one looks
//! like in the caller, and it is the shape a container start wants: a bounded wait for the
//! two states that can resolve themselves, and an immediate failure for everything else.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use ciphr_sdk::{Client, Environment, SdkError, SecretPath};
//!
//! fn fetch(client: &Client, prefix: &SecretPath) -> Result<Environment, SdkError> {
//!     let step = Duration::from_secs(2);
//!     let budget = Duration::from_secs(30);
//!     let mut waited = Duration::ZERO;
//!
//!     loop {
//!         match client.environment(prefix) {
//!             Ok(environment) => return Ok(environment),
//!             // A refused token and a missing capability are not waited on: they cannot
//!             // become true by themselves, and a service that retries them looks like a
//!             // slow start rather than the misconfiguration it is.
//!             Err(error) if !error.is_retryable() => return Err(error),
//!             Err(error) if waited >= budget => return Err(error),
//!             Err(_) => {
//!                 std::thread::sleep(step);
//!                 waited += step;
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Handing the values to a child process
//!
//! Reading from the [`Environment`] directly is the better option — the value then never
//! enters `/proc/<pid>/environ` at all. Where the consumer is a program that only reads
//! environment variables, this is the way to give it them without setting any of *this*
//! process's:
//!
//! ```no_run
//! use std::process::Command;
//!
//! use ciphr_sdk::{Client, SecretPath};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let client: Client = todo!();
//! let environment = client.environment(&SecretPath::parse("infra/service-a")?)?;
//!
//! let mut command = Command::new("/usr/local/bin/migrate");
//! for (name, value) in environment.into_entries() {
//!     // Values are UTF-8 text on the wire (`openapi.yaml`); a binary secret is encoded
//!     // by whoever stored it.
//!     command.env(name.as_str(), std::str::from_utf8(value.expose())?);
//! }
//!
//! let status = command.status()?;
//! assert!(status.success());
//! # Ok(())
//! # }
//! ```
//!
//! The names are the ones `ciphr export`, `ciphr-ci` and `ciphr-run` produce for the same
//! paths (ADR-18), so a program moved from one route to another meets the same environment.
//!
//! # Three properties this crate has by construction
//!
//! - **It cannot trust the public CA set.** The transport is compiled without
//!   `webpki-roots` and the trust anchor is a required constructor argument (ADR-19).
//!   Pointing this client at a `WebPKI` certificate is not a mistake it is possible to
//!   make.
//! - **It cannot log a secret.** Values live in [`Plaintext`], which
//!   implements neither `Debug`, `Display` nor `Serialize`, and no type here that holds
//!   one derives `Debug` either (ADR-1).
//! - **It cannot set an environment variable.** Doing so is `unsafe` in this edition, and
//!   this crate forbids `unsafe_code`. [`Environment`] hands back a mapping; reading from
//!   it directly keeps the value out of `/proc/<pid>/environ` entirely, and
//!   `Command::env` covers the child-process case.
//!
//! # One route, two shapes
//!
//! `POST /v1/export` is a surface entry and is off unless a deployment names it (ADR-20).
//! [`Client::read_all`] therefore reads through it where it exists and one
//! `GET /v1/secrets/{path}` per path where it does not, and [`Client::environment`] and
//! [`Client::environment_of`] are built on that — so a service fetching its own secrets
//! works against a deployment that made no decision about optional routes at all. The
//! audit trail is the same either way (one entry per secret served, never one per call);
//! a refusal is not, and [`Client::read_all`] says how.
//!
//! # What is not here yet
//!
//! - **The administrative reads** — `/v1/audit`, `/v1/identities`, `/v1/policies`. They
//!   exist in the API and are unimplemented here. The consumer that needs them is the MCP
//!   server (ADR-13, post-v1); the CLI reads them from the store directly, without a
//!   network hop.
//! - **No configuration convention.** There is no `Client::from_env()` reading a
//!   `CIPHR_URL` or `CIPHR_TOKEN`. Inventing one here would make it the convention by
//!   accident, and where a consumer's credential comes from is a deployment decision
//!   (plan section 12).
//! - **No retry loop.** [`SdkError::is_retryable`] says which failures could change on
//!   their own; how long a service waits for its secrets before giving up is the service's
//!   policy, not this crate's.

pub mod client;
pub mod environment;
pub mod error;
pub mod types;

pub use client::{Client, ClientBuilder};
pub use environment::Environment;
pub use error::SdkError;
pub use types::{Classification, DeviceHealth, Health, History, Secret, VersionSummary, Written};

/// The `ciphr-core` types that appear in this crate's own signatures.
///
/// **A consumer of this crate must not have to name `ciphr-core` in its manifest.** Every
/// type below is unavoidable in ordinary use — [`SecretPath`] is an argument to every
/// call, [`Plaintext`] is what a value *is*, [`EnvVarName`] is what [`Environment`] hands
/// back, and [`PathError`] and [`EnvNameError`] sit inside [`SdkError`] variants. Without
/// these re-exports the shortest useful program needs a second dependency, and that
/// dependency then has to be kept at the same version as this one by hand, which is a
/// versioning trap rather than an inconvenience.
///
/// They are re-exported rather than wrapped: a newtype around [`SecretPath`] would be a
/// second definition of path normalization's public face, and ADR-9's rule that there is
/// exactly one normalization is worth more than a tidier dependency graph.
///
/// `ci/check-sdk-reexports.sh` fails if a core type enters this crate's API without
/// landing here.
pub use ciphr_core::{
    EnvNameError, EnvVarName, PathError, Plaintext, Rotation, SecretPath, SecretVersion,
};
