//! Why a policy file was rejected.
//!
//! Everything here is a *load-time* error. A policy file that is wrong must fail
//! to load rather than load partially: half a policy set is a set of permissions
//! nobody wrote, and it would fail in the direction of granting access that was
//! meant to be denied by a rule that did not survive parsing.

use core::fmt;

use ciphr_core::{Capability, CapabilityError, PatternError};

/// A policy file could not be turned into a usable policy set.
#[derive(Debug)]
pub enum PolicyError {
    /// The file is not valid TOML, or does not match the expected shape.
    ///
    /// Includes an unknown key: a misspelled field is an error rather than a
    /// silently ignored line, which is the main reason the schema is derived
    /// rather than read by hand (ADR-2).
    Syntax(toml::de::Error),
    /// A rule's path pattern is invalid.
    Pattern {
        /// The policy the rule belongs to.
        policy: String,
        /// The pattern as written.
        pattern: String,
        /// What is wrong with it.
        reason: PatternError,
    },
    /// A capability name is not one of the seven.
    Capability {
        /// The policy the rule belongs to.
        policy: String,
        /// The pattern the rule applies to.
        pattern: String,
        /// What is wrong with it.
        reason: CapabilityError,
    },
    /// The same capability appears twice in one rule.
    ///
    /// Harmless in effect, and rejected anyway: it is the signature of a
    /// copy-and-paste edit, and a policy file is exactly where an unnoticed
    /// copy-and-paste edit is worth stopping.
    DuplicateCapability {
        /// The policy the rule belongs to.
        policy: String,
        /// The pattern the rule applies to.
        pattern: String,
        /// The capability that appears twice.
        capability: String,
    },
    /// A rule that names the reserved prefix grants a capability about secrets.
    ///
    /// Refused rather than accepted and denied at request time (ADR-23). `read` on
    /// `sys/audit` used to authorize the audit trail and now authorizes nothing, so a
    /// file carrying it means something other than what it says — and the reader who
    /// finds out is a monitoring identity that silently stopped seeing anything. One
    /// edit per file, and the message names the capability that is meant instead.
    SecretCapabilityOnControlPlane {
        /// The policy the rule belongs to.
        policy: String,
        /// The pattern the rule applies to.
        pattern: String,
        /// The capability that no longer means anything there.
        capability: Capability,
    },
    /// Two rules in one policy use the same pattern.
    ///
    /// Ambiguous: they have equal specificity, so if they disagree the tie rule
    /// denies, and the author almost certainly meant one of them to win.
    DuplicatePattern {
        /// The policy holding both rules.
        policy: String,
        /// The pattern that appears twice.
        pattern: String,
    },
    /// Two policies share a name.
    DuplicatePolicy {
        /// The name used twice.
        name: String,
    },
    /// Two identities share a name.
    DuplicateIdentity {
        /// The name used twice.
        name: String,
    },
    /// An identity refers to a policy that does not exist.
    ///
    /// Refused rather than ignored. Ignoring it would mean an identity silently
    /// has fewer permissions than its author believes — which usually surfaces as
    /// a broken deploy — or, if the missing policy contained the *denials*, more.
    UnknownPolicy {
        /// The identity that refers to it.
        identity: String,
        /// The policy name that does not exist.
        policy: String,
    },
    /// An identity lists the same policy twice.
    DuplicatePolicyReference {
        /// The identity.
        identity: String,
        /// The policy named twice.
        policy: String,
    },
    /// An identity has a kind that is not `machine` or `human`.
    UnknownIdentityKind {
        /// The identity.
        identity: String,
        /// What was written.
        found: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "invalid policy file: {error}"),
            Self::Pattern {
                policy,
                pattern,
                reason,
            } => write!(
                f,
                "policy '{policy}': rule path '{pattern}' is invalid: {reason}"
            ),
            Self::Capability {
                policy,
                pattern,
                reason,
            } => write!(f, "policy '{policy}', rule '{pattern}': {reason}"),
            Self::DuplicateCapability {
                policy,
                pattern,
                capability,
            } => write!(
                f,
                "policy '{policy}', rule '{pattern}': capability '{capability}' appears twice"
            ),
            Self::SecretCapabilityOnControlPlane {
                policy,
                pattern,
                capability,
            } => write!(
                f,
                "policy '{policy}', rule '{pattern}': '{capability}' is a capability about a \
                 secret, and '{pattern}' names the control plane. Since ADR-23 reading a \
                 control-plane path is 'inspect' and revoking a token is 'revoke'; a rule under \
                 '{prefix}/' may grant only those. Replace '{capability}' rather than removing the \
                 rule, or the identity loses the access it was written for",
                prefix = ciphr_core::path::RESERVED_PREFIX
            ),
            Self::DuplicatePattern { policy, pattern } => write!(
                f,
                "policy '{policy}' has two rules for '{pattern}'; one of them would never apply"
            ),
            Self::DuplicatePolicy { name } => write!(f, "two policies are named '{name}'"),
            Self::DuplicateIdentity { name } => write!(f, "two identities are named '{name}'"),
            Self::UnknownPolicy { identity, policy } => write!(
                f,
                "identity '{identity}' refers to policy '{policy}', which is not defined"
            ),
            Self::DuplicatePolicyReference { identity, policy } => {
                write!(f, "identity '{identity}' lists policy '{policy}' twice")
            }
            Self::UnknownIdentityKind { identity, found } => write!(
                f,
                "identity '{identity}' has kind '{found}', expected 'machine' or 'human'"
            ),
        }
    }
}

impl core::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Pattern { reason, .. } => Some(reason),
            Self::Capability { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(error: toml::de::Error) -> Self {
        Self::Syntax(error)
    }
}
