#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Domain types shared by every other crate in the workspace.
//!
//! This crate owns the vocabulary of the system — secret paths, versions,
//! rotation classes — and the wrapper types that keep plaintext out of logs and
//! error messages.
//!
//! Two rules apply here more strictly than anywhere else:
//!
//! - **Path normalization lives here and nowhere else.** The HTTP router and the
//!   policy evaluator must call the same function, because any divergence
//!   between the two is an authorization bypass (ADR-9).
//! - **Secret-bearing types implement neither `Debug`, `Display` nor
//!   `Serialize`.** Logging a secret is a compile error, not a code-review
//!   question (ADR-1).

pub mod base64url;
pub mod capability;
pub mod env_name;
pub mod file_mode;
pub mod hex;
pub mod path;
pub mod pattern;
pub mod rotation;
pub mod secret;
pub mod version;

pub use capability::{Capability, CapabilityError};
pub use env_name::{EnvNameError, EnvVarName, NameFault};
pub use file_mode::{BIND_MOUNT_HINT, BIND_MOUNT_MODE};
pub use path::{PathError, SecretPath};
pub use pattern::{PathPattern, PatternError};
pub use rotation::{Rotation, RotationError};
pub use secret::Plaintext;
pub use version::SecretVersion;
