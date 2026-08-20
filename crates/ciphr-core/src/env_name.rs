//! The environment variable name for a secret, and the one rule that derives it.
//!
//! A secret arrives in a process as an environment variable, and something has to
//! decide what that variable is called. The convention is the **last path segment**:
//! `infra/service-a/DB_PASSWORD` becomes `DB_PASSWORD`, because the last segment is
//! the name the consuming process already uses, so the common case needs no mapping
//! table.
//!
//! The convention itself is not new; it has been in the CLI's export since phase 3.
//! What lives here is the part that was missing, and the reason this module exists at
//! all rather than a method on the export format:
//!
//! - **A name is refused if it is not a usable variable name.** A path segment may
//!   contain `-`, `.`, and letters from any script ([`SecretPath`]), none of which a
//!   shell accepts in a name. Producing `db-password=…` yields a line that cannot be
//!   sourced and that this project's own `import --from-dotenv` rejects.
//! - **A set of paths is refused if two of them produce the same name.** Under one
//!   prefix, `db/PASSWORD` and `cache/PASSWORD` both want to be `PASSWORD`. Rendered
//!   into a `.env` file or appended to a runner's environment file, the second wins
//!   silently — a service receives a valid secret that is the wrong one, which is the
//!   worst available failure mode: nothing errors, and the audit trail records both
//!   reads as successful.
//!
//! Both are refusals rather than repairs. A derived name (`PASSWORD_2`, or one
//! qualified with its parent segment) would be a name no consumer asked for, and the
//! operator would have to discover the mapping from the output instead of stating it.
//!
//! # Why this is in `ciphr-core` and not in the CLI
//!
//! Three things produce this name: `ciphr export`, the SDK when a consumer asks for its
//! secrets as an environment (section 13, route C), and `ciphr run` if ADR-14 is
//! accepted (route B). ADR-14 states the requirement directly — the routes "must answer
//! it the same way or the same secret will arrive under two names depending on which
//! route a service takes". A second copy of this rule is how that happens, so there is
//! one copy and everything calls it. The same argument as ADR-9 makes for path
//! normalization, with a smaller blast radius.
//!
//! # What this rule does not govern
//!
//! `ciphr export --format json` is keyed by the full path and never produces a variable
//! name, so it is unaffected by either refusal: a path whose last segment is
//! `db-password` exports as JSON and cannot be exported as `dotenv`. That is the
//! intended asymmetry — JSON promises a path, and `dotenv` promises something a shell
//! can read.

use core::fmt;

use crate::path::SecretPath;

/// A validated environment variable name.
///
/// Obtainable only through [`EnvVarName::parse`] or [`EnvVarName::for_path`], so a
/// value of this type is a name some shell will accept.
///
/// `Debug` and `Display` are implemented deliberately: a variable name is not a
/// secret, and an error that cannot name the variable it is about is not much of an
/// error. The *value* never comes near this type.
///
/// ```
/// use ciphr_core::{EnvVarName, SecretPath};
///
/// let path = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
/// assert_eq!(EnvVarName::for_path(&path)?.as_str(), "DB_PASSWORD");
///
/// // A perfectly valid secret path whose last segment is not a variable name:
/// let dashed = SecretPath::parse("infra/service-a/db-password")?;
/// assert!(EnvVarName::for_path(&dashed).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvVarName(String);

impl EnvVarName {
    /// Validate a name.
    ///
    /// The accepted set is the portable one: an ASCII letter or `_` first, then ASCII
    /// letters, digits and `_`. Deliberately narrower than what some container runtimes
    /// tolerate — a name only that runtime accepts is a name the shell in the same image
    /// cannot read, and finding that out at deploy time is worse than finding it out
    /// here.
    ///
    /// # Errors
    ///
    /// [`EnvNameError::NotAName`] with the reason, which names the offending text. A
    /// variable name is not a secret, so quoting it is safe.
    pub fn parse(input: &str) -> Result<Self, EnvNameError> {
        let fault = if input.is_empty() {
            Some(NameFault::Empty)
        } else if input.starts_with(|c: char| c.is_ascii_digit()) {
            // POSIX: a name shall not begin with a digit. `1FOO=x` is a line no shell
            // can source, however willingly a container runtime passes it along.
            Some(NameFault::LeadingDigit)
        } else {
            input
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
                .map(|character| NameFault::Character { character })
        };

        if let Some(reason) = fault {
            return Err(EnvNameError::NotAName {
                found: input.to_owned(),
                reason,
            });
        }

        Ok(Self(input.to_owned()))
    }

    /// The name for a secret: its last path segment.
    ///
    /// # Errors
    ///
    /// [`EnvNameError::NotAName`] if that segment is not a usable variable name. The
    /// error carries the segment, not the path, because the segment is the part the
    /// operator has to change.
    pub fn for_path(path: &SecretPath) -> Result<Self, EnvNameError> {
        let segment = path.segments().next_back().unwrap_or_else(|| path.as_str());
        Self::parse(segment)
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Names for a whole set of paths, refusing a set that would produce a collision.
    ///
    /// Returns the names in the order of the input, so a caller can zip them back onto
    /// the values it holds without a second lookup.
    ///
    /// # Errors
    ///
    /// [`EnvNameError::NotAName`] for the first path whose last segment is unusable, or
    /// [`EnvNameError::Collision`] naming **both** paths that want the same name. Naming
    /// only one would leave the operator to find the other, and the pair is the whole
    /// content of the problem.
    ///
    /// ```
    /// use ciphr_core::{EnvVarName, SecretPath};
    ///
    /// let paths = [
    ///     SecretPath::parse("infra/a/db/PASSWORD")?,
    ///     SecretPath::parse("infra/a/cache/PASSWORD")?,
    /// ];
    /// // Rendered into a `.env` file the second would silently win, so the whole
    /// // export is refused instead.
    /// assert!(EnvVarName::assign(&paths).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn assign<'a, I>(paths: I) -> Result<Vec<Self>, EnvNameError>
    where
        I: IntoIterator<Item = &'a SecretPath>,
    {
        // Paired with the path each name came from, because the collision error has to
        // name both sides and the first one is otherwise already forgotten.
        let mut assigned: Vec<(Self, &SecretPath)> = Vec::new();

        for path in paths {
            let name = Self::for_path(path)?;

            if let Some((_, first)) = assigned.iter().find(|(existing, _)| *existing == name) {
                return Err(EnvNameError::Collision {
                    name: name.0,
                    first: first.as_str().to_owned(),
                    second: path.as_str().to_owned(),
                });
            }

            assigned.push((name, path));
        }

        Ok(assigned.into_iter().map(|(name, _)| name).collect())
    }
}

impl fmt::Display for EnvVarName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Why a name could not be derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvNameError {
    /// The text is not a usable environment variable name.
    NotAName {
        /// The offending text — a path segment, or a key read from a `.env` file.
        found: String,
        /// Which rule it breaks.
        reason: NameFault,
    },
    /// Two paths in one set produce the same name.
    Collision {
        /// The name both of them want.
        name: String,
        /// The path that claimed it first.
        first: String,
        /// The path that would have overwritten it.
        second: String,
    },
}

impl fmt::Display for EnvNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAName { found, reason } => {
                write!(
                    formatter,
                    "{found:?} cannot be an environment variable name: {reason}"
                )
            }
            Self::Collision {
                name,
                first,
                second,
            } => write!(
                formatter,
                "{first} and {second} would both be {name}; one of them has to be renamed \
                 or exported separately"
            ),
        }
    }
}

impl core::error::Error for EnvNameError {}

/// The specific rule a name breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameFault {
    /// Nothing at all.
    Empty,
    /// Starts with a digit, which POSIX forbids for a name.
    LeadingDigit,
    /// Contains something outside `[A-Za-z0-9_]`.
    Character {
        /// The first offending character.
        character: char,
    },
}

impl fmt::Display for NameFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("it is empty"),
            Self::LeadingDigit => formatter.write_str("a name may not start with a digit"),
            Self::Character { character } => write!(
                formatter,
                "{character:?} is not allowed; use letters, digits and underscore"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EnvNameError, EnvVarName, NameFault};
    use crate::path::SecretPath;

    fn path(input: &str) -> SecretPath {
        SecretPath::parse(input).expect("valid path")
    }

    #[test]
    fn the_name_is_the_last_path_segment() {
        assert_eq!(
            EnvVarName::for_path(&path("infra/service-a/DB_PASSWORD"))
                .expect("a usable name")
                .as_str(),
            "DB_PASSWORD"
        );
        assert_eq!(
            EnvVarName::for_path(&path("SINGLE"))
                .expect("a usable name")
                .as_str(),
            "SINGLE"
        );
    }

    #[test]
    fn a_valid_path_segment_is_not_automatically_a_valid_name() {
        // These three are all legal secret paths. None of them is a name a shell reads,
        // and before this rule existed all three were exported as `KEY=value` lines.
        for input in [
            "infra/a/db-password",
            "infra/a/db.password",
            "infra/a/Grüße",
        ] {
            let error = EnvVarName::for_path(&path(input)).expect_err("must be refused");
            assert!(
                matches!(error, EnvNameError::NotAName { .. }),
                "{input}: {error}"
            );
        }
    }

    #[test]
    fn a_leading_digit_is_refused() {
        // Accepted by container runtimes, unusable in a shell. `2FA_SECRET` is the
        // realistic way someone hits this.
        let error = EnvVarName::for_path(&path("infra/a/2FA_SECRET")).expect_err("refused");
        assert_eq!(
            error,
            EnvNameError::NotAName {
                found: "2FA_SECRET".to_owned(),
                reason: NameFault::LeadingDigit,
            }
        );
        // A digit elsewhere is fine, which is the common case this must not break.
        assert!(EnvVarName::parse("OAUTH2_SECRET").is_ok());
    }

    #[test]
    fn an_underscore_may_lead_and_an_empty_name_may_not_exist() {
        assert!(EnvVarName::parse("_PRIVATE").is_ok());
        assert_eq!(
            EnvVarName::parse(""),
            Err(EnvNameError::NotAName {
                found: String::new(),
                reason: NameFault::Empty,
            })
        );
    }

    #[test]
    fn two_paths_under_one_prefix_may_not_claim_the_same_name() {
        // The failure this exists to prevent: rendered to a `.env` file, the second
        // assignment wins and the service gets a valid secret that is the wrong one.
        let paths = [path("infra/a/db/PASSWORD"), path("infra/a/cache/PASSWORD")];
        let error = EnvVarName::assign(&paths).expect_err("must be refused");

        let EnvNameError::Collision {
            name,
            first,
            second,
        } = error
        else {
            panic!("expected a collision, got {error}");
        };
        assert_eq!(name, "PASSWORD");
        // Both paths are named: one of them alone leaves the operator hunting.
        assert_eq!(first, "infra/a/db/PASSWORD");
        assert_eq!(second, "infra/a/cache/PASSWORD");
    }

    #[test]
    fn names_come_back_in_the_order_they_went_in() {
        // Callers zip these onto the values they already hold, so order is part of the
        // contract rather than an implementation detail.
        let paths = [
            path("infra/a/ONE"),
            path("infra/b/TWO"),
            path("infra/c/THREE"),
        ];
        let names = EnvVarName::assign(&paths).expect("no collision");
        let rendered: Vec<&str> = names.iter().map(EnvVarName::as_str).collect();
        assert_eq!(rendered, ["ONE", "TWO", "THREE"]);
    }

    #[test]
    fn an_empty_set_is_not_an_error() {
        // Whether "nothing to export" is a problem is the caller's question — the CLI
        // says yes, a consumer fetching an optional prefix may say no.
        assert!(EnvVarName::assign(&[]).expect("no collision").is_empty());
    }

    #[test]
    fn the_message_says_what_to_do_about_it() {
        let paths = [path("a/db/PASSWORD"), path("a/cache/PASSWORD")];
        let message = EnvVarName::assign(&paths).expect_err("refused").to_string();
        assert!(message.contains("a/db/PASSWORD"), "{message}");
        assert!(message.contains("a/cache/PASSWORD"), "{message}");
        assert!(message.contains("renamed"), "{message}");

        let message = EnvVarName::parse("db-password")
            .expect_err("refused")
            .to_string();
        assert!(message.contains("db-password"), "{message}");
        assert!(message.contains("underscore"), "{message}");
    }

    #[test]
    fn every_name_this_accepts_is_a_usable_path_segment() {
        // The round trip that has to hold: a name that survives `export --format dotenv`
        // must be importable again, or a corpus can leave through one door and not come
        // back through the other.
        for input in ["DB_PASSWORD", "_PRIVATE", "OAUTH2_SECRET", "A"] {
            let name = EnvVarName::parse(input).expect("a usable name");
            let round_tripped = path(&format!("infra/a/{}", name.as_str()));
            assert_eq!(
                EnvVarName::for_path(&round_tripped).expect("still a name"),
                name
            );
        }
    }
}
