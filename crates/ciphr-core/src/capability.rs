//! What an identity may do with a secret.
//!
//! Five capabilities, and deliberately **no `admin`**. Administration happens
//! through configuration and the CLI on the host (ADR-3), so there is no
//! privileged capability that could be obtained by finding a gap in a policy
//! file, and no rule anyone can write that grants everything.
//!
//! Adding a capability is adding a variant here. It must never be a special case
//! in the evaluator: one code path decides every access, or the reasoning about
//! that path stops being worth anything.

use core::fmt;

/// An action on a secret path.
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
}

impl Capability {
    /// Every capability, for configuration help and exhaustive tests.
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::List,
        Self::Undelete,
    ];

    /// The form used in policy files and in the audit trail.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Undelete => "undelete",
        }
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
