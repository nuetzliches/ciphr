#![forbid(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

//! Path-based authorization: TOML policies, typed rules, and the evaluator.
//!
//! Deny by default. A capability is granted only by a matching rule; the most
//! specific match wins, and on a tie denial wins. An empty capability set is an
//! explicit denial that beats any less specific permission. The full semantics are
//! documented on [`evaluate`], and they are binding — ambiguity there is an
//! authorization bug, not a documentation gap.
//!
//! Glob matching is deliberately minimal and lives in `ciphr-core` next to path
//! parsing, so that a pattern and a path are normalized by **the same function**
//! (ADR-9). Policies come from configuration under version control; there is no
//! policy-write API (ADR-3).
//!
//! This crate shares the review and dependency budget of `ciphr-crypto`: it is
//! small on purpose, because an authorization bug here fails silently. Its two
//! dependencies beyond `ciphr-core` are a TOML parser and `serde`, which is what
//! ADR-2 chose when it rejected a custom DSL — the alternative is a hand-written
//! parser in the authorization path.
//!
//! # Example
//!
//! ```
//! use ciphr_core::{Capability, SecretPath};
//! use ciphr_policy::PolicySet;
//!
//! let policies = PolicySet::from_toml(r#"
//!     [[identity]]
//!     name     = "deploy-runner"
//!     kind     = "machine"
//!     policies = ["infra-read"]
//!
//!     [[policy]]
//!     name = "infra-read"
//!
//!       [[policy.rule]]
//!       path         = "infra/**"
//!       capabilities = ["read", "list"]
//!
//!       [[policy.rule]]
//!       path         = "infra/ciphr/**"
//!       capabilities = []
//! "#)?;
//!
//! let secret = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
//! assert!(policies.evaluate("deploy-runner", &secret, Capability::Read).is_allowed());
//! assert!(!policies.evaluate("deploy-runner", &secret, Capability::Write).is_allowed());
//!
//! // A more specific denial beats the broader grant.
//! let own = SecretPath::parse("infra/ciphr/MASTER_KEY_BACKUP")?;
//! assert!(!policies.evaluate("deploy-runner", &own, Capability::Read).is_allowed());
//!
//! // Deny by default: nothing matches, so nothing is granted.
//! let elsewhere = SecretPath::parse("ci/widget/TOKEN")?;
//! assert!(!policies.evaluate("deploy-runner", &elsewhere, Capability::Read).is_allowed());
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

pub mod error;
pub mod evaluate;
pub mod model;

pub use error::PolicyError;
pub use evaluate::{Decision, DenyReason, Effect, MatchedRule};
pub use model::{Identity, IdentityKind, Policy, PolicySet, Rule};
