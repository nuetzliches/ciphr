//! What an identity may do — with a secret, and with the control plane.
//!
//! Seven capabilities, and deliberately **no `admin`**. Administration happens
//! through configuration and the CLI on the host (ADR-3), so there is no
//! privileged capability that could be obtained by finding a gap in a policy
//! file, and no rule anyone can write that grants everything.
//!
//! **Five of them are about a secret and two are about the control plane, and that
//! split is ADR-23.** Before it, `read` meant both — a secret's value and
//! `sys/audit`, `sys/identities`, `sys/policies`, `sys/surface`, `sys/honeypots` —
//! with only the path separating them. So `path = "**"` with `read`, the shape
//! somebody writes for a break-glass identity meaning *all the secrets*, granted
//! the audit trail and the map of the authorization model along with them. Nobody
//! wrote down that they wanted that, which is the same argument
//! [`crate::Rotation`]'s default settled: the path of least resistance must not be
//! the permissive one.
//!
//! Adding a capability is adding a variant here. It must never be a special case
//! in the evaluator: one code path decides every access, or the reasoning about
//! that path stops being worth anything. **The reserved prefix is likewise not the
//! evaluator's business** — [`Self::is_control_plane`] exists so that a *loader*
//! can refuse a file that grants a secret capability under `sys/`, which is a
//! different job from deciding an access.

use core::fmt;

/// An action on a secret path, or on the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Read a value.
    Read,
    /// Write a new version.
    Write,
    /// Soft-delete a version.
    Delete,
    /// List paths under a prefix, or list the versions of a secret.
    List,
    /// Restore a soft-deleted version.
    Undelete,
    /// Read a control-plane path: the audit trail, the identity inventory, the
    /// policy structure, the active surface, the honeypot inventory, the token
    /// inventory.
    ///
    /// Its own capability because those are not secrets and reading them is not the
    /// same authority (ADR-23). `sys/policies` is the map of the authorization
    /// model, and `sys/audit` says which paths legitimate consumers actually fetch —
    /// which is the same information as which paths they never fetch, and ADR-15's
    /// placement rule is that bait belongs exactly there.
    Inspect,
    /// Revoke a token.
    ///
    /// The one control-plane *mutation* this project has (ADR-24), and a verb of its
    /// own rather than part of a general `admin`: a later mutation has to be named to
    /// be granted, instead of riding along on a grant somebody wrote last year.
    Revoke,
}

impl Capability {
    /// Every capability, for configuration help and exhaustive tests.
    pub const ALL: [Self; 7] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::List,
        Self::Undelete,
        Self::Inspect,
        Self::Revoke,
    ];

    /// The form used in policy files and in the audit trail.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Undelete => "undelete",
            Self::Inspect => "inspect",
            Self::Revoke => "revoke",
        }
    }

    /// Whether this capability is about the control plane rather than about a secret.
    ///
    /// **For a loader, not for the evaluator.** ADR-23 keeps the decision path free of
    /// any knowledge of the reserved prefix: a rule is evaluated the same way whatever
    /// it points at, and the separation is carried by which capability it grants. What
    /// this predicate is for is the refusal *before* any access is decided — a policy
    /// file that grants `read` on `sys/audit` no longer means what it says, and is
    /// refused with the replacement named rather than accepted and quietly denied.
    #[must_use]
    pub const fn is_control_plane(self) -> bool {
        matches!(self, Self::Inspect | Self::Revoke)
    }

    /// Parse the configured form.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError`] for anything unknown. A misspelled capability
    /// is rejected rather than ignored: silently dropping it would turn a typo
    /// into a permission that quietly does not exist, or — worse, in a denial
    /// rule — into a permission that quietly does.
    pub fn parse(input: &str) -> Result<Self, CapabilityError> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == input)
            .ok_or_else(|| CapabilityError::Unknown {
                found: input.to_owned(),
            })
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unknown capability name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// The input matched none of the known capabilities.
    Unknown {
        /// What was supplied.
        found: String,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { found } => {
                write!(f, "unknown capability '{found}', expected one of: ")?;
                for (index, capability) in Capability::ALL.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(capability.as_str())?;
                }
                Ok(())
            }
        }
    }
}

impl core::error::Error for CapabilityError {}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilityError};

    #[test]
    fn round_trips_every_capability() {
        for capability in Capability::ALL {
            assert_eq!(Capability::parse(capability.as_str()).unwrap(), capability);
        }
    }

    #[test]
    fn there_is_no_admin_capability() {
        // Not a formality. If this ever parses, ADR-3 has been undone and a policy
        // file can grant everything.
        assert!(Capability::parse("admin").is_err());
        assert!(Capability::parse("root").is_err());
        assert!(Capability::parse("*").is_err());
    }

    /// The split ADR-23 decided, as a property rather than as two lists to keep in
    /// sync: every capability is about a secret or about the control plane, and the
    /// two new ones are the control-plane half.
    #[test]
    fn exactly_the_two_new_verbs_are_about_the_control_plane() {
        let control: Vec<&str> = Capability::ALL
            .into_iter()
            .filter(|capability| capability.is_control_plane())
            .map(Capability::as_str)
            .collect();
        assert_eq!(control, ["inspect", "revoke"]);

        // And the five that existed before still mean a secret. A future capability
        // that is neither is what this pins against: it would have to choose a side
        // here, which is the point where somebody thinks about it.
        for capability in [
            Capability::Read,
            Capability::Write,
            Capability::Delete,
            Capability::List,
            Capability::Undelete,
        ] {
            assert!(
                !capability.is_control_plane(),
                "{capability} is not a secret"
            );
        }
    }

    #[test]
    fn rejects_a_misspelling_instead_of_ignoring_it() {
        assert_eq!(
            Capability::parse("raed"),
            Err(CapabilityError::Unknown {
                found: "raed".to_owned()
            })
        );
    }
}
