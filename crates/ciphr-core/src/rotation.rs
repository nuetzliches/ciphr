//! How safe a secret is to rotate.
//!
//! The operational promise of a secret store is rotation, and versioning makes
//! rotating a value *easier* rather than harder: write a new version, the next
//! deploy picks it up, and data encrypted under the old value is gone. Not every
//! secret survives that. The classification therefore lives in the data model
//! from the start — classifying an existing corpus afterwards is far more tedious
//! than carrying the field along.
//!
//! This is **metadata only**. It never influences an authorization decision; it
//! drives warnings in the CLI and the UI. Keeping it out of the authorization
//! path means a mistake here cannot become an access-control bug.

use core::fmt;

/// How a secret behaves when its value changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rotation {
    /// Nobody has said. The default, and deliberately not a safe-sounding one.
    ///
    /// The column default used to be [`Rotation::Rotatable`], which meant every
    /// secret written without an explicit class asserted "safe to rotate" —
    /// a claim no human had made. Two consequences followed: the path of least
    /// resistance was the destructive one, and "is the corpus classified?" was
    /// unanswerable, because a deliberate `rotatable` and an untouched default
    /// were the same byte in the same column.
    ///
    /// This is the same argument [`Rotation::parse`] already made about typos.
    /// It simply had not been applied to the absence of an answer.
    #[default]
    Unclassified,
    /// The normal case: a new value takes effect and nothing is lost.
    Rotatable,
    /// Only read when something is first initialized — a database seed password,
    /// an initial admin credential. Later changes have no effect on the running
    /// system, which makes a rotation look successful while changing nothing.
    SeedOnly,
    /// Encrypts data at rest. A new value makes existing data unreadable.
    BreaksData,
    /// Must match the value a persistent volume was initialized with.
    VolumeBound,
    /// Rotation works, but discards all sessions and derived tokens.
    InvalidatesSessions,
}

impl Rotation {
    /// Every class, for CLI help and for exhaustiveness in tests.
    pub const ALL: [Self; 6] = [
        Self::Unclassified,
        Self::Rotatable,
        Self::SeedOnly,
        Self::BreaksData,
        Self::VolumeBound,
        Self::InvalidatesSessions,
    ];

    /// The wire and storage form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Rotatable => "rotatable",
            Self::SeedOnly => "seed-only",
            Self::BreaksData => "breaks-data",
            Self::VolumeBound => "volume-bound",
            Self::InvalidatesSessions => "invalidates-sessions",
        }
    }

    /// Parse the wire form.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError`] for an unknown class. Unknown values are
    /// rejected rather than defaulted, because defaulting to `rotatable` would
    /// turn a typo into "safe to rotate".
    pub fn parse(input: &str) -> Result<Self, RotationError> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == input)
            .ok_or_else(|| RotationError::Unknown {
                found: input.to_owned(),
            })
    }

    /// Whether changing this value can destroy data or silently do nothing.
    ///
    /// The two failure shapes are deliberately grouped: a rotation that shreds
    /// data and a rotation that quietly has no effect are both cases where the
    /// operator needs to stop and think, and both are worse than an outage.
    pub const fn needs_care(self) -> bool {
        match self {
            Self::Rotatable => false,
            // Unknown counts as dangerous. The point of the class is that nobody
            // has established this value is safe to rotate, and treating that as
            // "probably fine" would restore exactly the behaviour it replaced.
            Self::Unclassified
            | Self::SeedOnly
            | Self::BreaksData
            | Self::VolumeBound
            | Self::InvalidatesSessions => true,
        }
    }

    /// What to do instead of rotating blindly.
    ///
    /// Kept next to the classification rather than in a manual, so that the
    /// advice reaches the operator at the moment of the decision — and so that it
    /// cannot drift out of date relative to the classes it describes.
    pub const fn advice(self) -> &'static str {
        match self {
            Self::Unclassified => {
                "Nobody has classified this secret, so nothing here says a rotation is \
                 safe. Find out what reads it and what happens when the value changes, \
                 then record the answer with `ciphr rotation <path> <class>`. Treat it as \
                 dangerous until then: the classes that destroy data look exactly like \
                 this one from here."
            }
            Self::Rotatable => "Safe to rotate: write a new version and redeploy the consumers.",
            Self::SeedOnly => {
                "Only read during first initialization. Rotating changes the stored value \
                 without changing the running system, so the two drift apart silently. \
                 Change it in the initialized system first, then record the new value here."
            }
            Self::BreaksData => {
                "This value encrypts data at rest. A new value makes existing data \
                 unreadable. Re-encrypt with the application's own key-change procedure, \
                 or accept the data loss knowingly; a restore from backup will need the \
                 old value, so keep the previous version."
            }
            Self::VolumeBound => {
                "Must match what the persistent volume was initialized with. Rotating \
                 requires changing it inside the volume as well, or recreating the volume. \
                 A restart with a mismatched value usually fails to start rather than \
                 corrupting anything, which is the good case."
            }
            Self::InvalidatesSessions => {
                "Rotation works, but every session and derived token becomes invalid. \
                 Expect users to be signed out and integrations to need new tokens; \
                 schedule it rather than doing it mid-day."
            }
        }
    }
}

impl fmt::Display for Rotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unknown rotation class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationError {
    /// The input matched none of the known classes.
    Unknown {
        /// What was supplied.
        found: String,
    },
}

impl fmt::Display for RotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { found } => {
                write!(f, "unknown rotation class '{found}', expected one of: ")?;
                for (index, class) in Rotation::ALL.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(class.as_str())?;
                }
                Ok(())
            }
        }
    }
}

impl core::error::Error for RotationError {}

#[cfg(test)]
mod tests {
    use super::{Rotation, RotationError};

    #[test]
    fn round_trips_every_class() {
        for class in Rotation::ALL {
            assert_eq!(Rotation::parse(class.as_str()).unwrap(), class);
        }
    }

    #[test]
    fn the_default_is_the_one_nobody_chose_and_it_is_not_treated_as_safe() {
        // This is the whole change. A value written without an explicit class must
        // not claim to be safe to rotate, and must not be indistinguishable from a
        // value somebody looked at and decided was safe.
        assert_eq!(Rotation::default(), Rotation::Unclassified);
        assert!(Rotation::Unclassified.needs_care());
        assert_ne!(Rotation::Unclassified, Rotation::Rotatable);
    }

    #[test]
    fn rotatable_is_the_only_class_that_needs_no_care() {
        // Stated as a property rather than left implicit: every other class,
        // including the absence of an answer, stops the operator.
        for class in Rotation::ALL {
            assert_eq!(
                !class.needs_care(),
                class == Rotation::Rotatable,
                "{class} disagrees about whether it needs care"
            );
        }
    }

    #[test]
    fn rejects_unknown_instead_of_defaulting() {
        // A typo must not become "safe to rotate".
        assert_eq!(
            Rotation::parse("rotateable"),
            Err(RotationError::Unknown {
                found: "rotateable".to_owned()
            })
        );
    }

    #[test]
    fn every_class_that_needs_care_says_what_to_do_instead() {
        for class in Rotation::ALL {
            let advice = class.advice();
            assert!(!advice.is_empty());
            if class.needs_care() {
                assert!(
                    advice.len() > 80,
                    "{class} needs more than a one-liner of advice"
                );
            }
        }
    }
}
