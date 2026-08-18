//! Secret paths and the one path normalization in the system.
//!
//! Everything that identifies a secret goes through [`SecretPath::parse`]: the
//! HTTP router, the CLI, the policy evaluator, and the additional authenticated
//! data that binds a ciphertext to its location. That is not a style preference
//! but the substance of ADR-9 — two normalizations that disagree by one edge
//! case are an authorization bypass, and this is the class of bug that is
//! invisible until someone reads a secret they should not have.
//!
//! # Rules
//!
//! A path is a non-empty sequence of segments joined by `/`:
//!
//! - Normalized to Unicode NFC, so two encodings of the same name are the same
//!   secret rather than two secrets.
//! - Case sensitive. `Infra/db` and `infra/db` are different paths.
//! - No empty segments, which rules out a leading slash, a trailing slash, and
//!   `//` anywhere.
//! - No `.` or `..` segments. They are rejected rather than resolved: a
//!   normalizer that *computes* with paths has to be trusted to compute the same
//!   way everywhere, and rejecting is a property, not a computation.
//! - No control characters and no whitespace. A path is an identifier, not
//!   prose, and an invisible difference between two paths is a trap.
//! - No `*`. The policy language uses `*` and `**` as glob wildcards
//!   ([`ciphr-policy`]), so a literal `*` in a secret path would make "does this
//!   rule match this path" ambiguous. Patterns are a separate type; secret paths
//!   never contain wildcards.
//! - Length limits, so that a path cannot become a way to bloat the database or
//!   an audit entry.
//!
//! [`ciphr-policy`]: https://github.com/nuetzliches/ciphr

use core::fmt;
use core::str::FromStr;

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

/// Maximum length of a whole path, in bytes of its NFC form.
pub const MAX_PATH_LEN: usize = 1024;

/// Maximum length of a single segment, in bytes of its NFC form.
pub const MAX_SEGMENT_LEN: usize = 128;

/// A normalized secret path.
///
/// The only way to obtain one is [`SecretPath::parse`], so a value of this type
/// is normalized by construction. Nothing in the codebase should accept a path
/// as a plain string.
///
/// ```
/// use ciphr_core::SecretPath;
///
/// let path = SecretPath::parse("infra/service-a/DB_PASSWORD")?;
/// assert_eq!(path.as_str(), "infra/service-a/DB_PASSWORD");
/// assert_eq!(path.segments().count(), 3);
///
/// // Rejected rather than repaired:
/// assert!(SecretPath::parse("infra//a").is_err());
/// assert!(SecretPath::parse("infra/../a").is_err());
/// assert!(SecretPath::parse("infra/a/").is_err());
/// # Ok::<(), ciphr_core::PathError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretPath(String);

impl SecretPath {
    /// Normalize and validate a path.
    ///
    /// Normalization is applied first and validation second, so the rules are
    /// checked against the form that will actually be stored.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] describing the first rule the input breaks. The
    /// error names the offending segment, which is safe: a path is not a secret.
    pub fn parse(input: &str) -> Result<Self, PathError> {
        let normalized = normalize(input);

        if normalized.is_empty() {
            return Err(PathError::Empty);
        }
        if normalized.len() > MAX_PATH_LEN {
            return Err(PathError::TooLong {
                limit: MAX_PATH_LEN,
                found: normalized.len(),
            });
        }

        for segment in normalized.split('/') {
            validate_segment(segment)?;
        }

        Ok(Self(normalized))
    }

    /// The normalized path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The segments, without the separators. Never empty.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Number of segments, which is what the policy evaluator measures
    /// specificity in.
    pub fn segment_count(&self) -> usize {
        self.segments().count()
    }

    /// Whether this path lies under `prefix`, on a segment boundary.
    ///
    /// Segment-aware on purpose: `infra/ab` must not be treated as living under
    /// `infra/a`, which is what a plain string prefix check would conclude.
    ///
    /// ```
    /// use ciphr_core::SecretPath;
    ///
    /// let prefix = SecretPath::parse("infra/a")?;
    /// assert!(SecretPath::parse("infra/a/db")?.starts_with(&prefix));
    /// assert!(SecretPath::parse("infra/a")?.starts_with(&prefix));
    /// assert!(!SecretPath::parse("infra/ab")?.starts_with(&prefix));
    /// # Ok::<(), ciphr_core::PathError>(())
    /// ```
    pub fn starts_with(&self, prefix: &Self) -> bool {
        if self.0 == prefix.0 {
            return true;
        }
        self.0.len() > prefix.0.len()
            && self.0.as_bytes()[prefix.0.len()] == b'/'
            && self.0.starts_with(prefix.as_str())
    }

    /// Consume the path, returning the normalized string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretPath {
    type Err = PathError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Apply the normalization half of the rules: NFC, and nothing else.
///
/// Kept separate from validation so that a test can assert the property that
/// matters — normalizing an already normalized path changes nothing.
fn normalize(input: &str) -> String {
    match is_nfc_quick(input.chars()) {
        IsNormalized::Yes => input.to_owned(),
        _ => input.nfc().collect(),
    }
}

fn validate_segment(segment: &str) -> Result<(), PathError> {
    if segment.is_empty() {
        return Err(PathError::EmptySegment);
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(PathError::SegmentTooLong {
            limit: MAX_SEGMENT_LEN,
            found: segment.len(),
        });
    }
    if segment == "." || segment == ".." {
        return Err(PathError::RelativeSegment {
            segment: segment.to_owned(),
        });
    }
    for ch in segment.chars() {
        if ch.is_control() {
            return Err(PathError::ControlCharacter);
        }
        if ch.is_whitespace() {
            return Err(PathError::Whitespace);
        }
        if ch == '*' {
            return Err(PathError::Wildcard);
        }
    }
    Ok(())
}

/// Why a path was rejected.
///
/// Carries the offending segment where that helps, and no more: paths and
/// identities may appear in errors, values and key material may not (ADR-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The path was empty.
    Empty,
    /// The path exceeded [`MAX_PATH_LEN`].
    TooLong {
        /// The limit.
        limit: usize,
        /// The length supplied.
        found: usize,
    },
    /// A segment exceeded [`MAX_SEGMENT_LEN`].
    SegmentTooLong {
        /// The limit.
        limit: usize,
        /// The length supplied.
        found: usize,
    },
    /// An empty segment: a leading or trailing `/`, or `//`.
    EmptySegment,
    /// A `.` or `..` segment.
    RelativeSegment {
        /// The offending segment.
        segment: String,
    },
    /// A control character.
    ControlCharacter,
    /// A whitespace character.
    Whitespace,
    /// A `*`, which is reserved for policy patterns.
    Wildcard,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("path is empty"),
            Self::TooLong { limit, found } => {
                write!(f, "path is {found} bytes, limit is {limit}")
            }
            Self::SegmentTooLong { limit, found } => {
                write!(f, "path segment is {found} bytes, limit is {limit}")
            }
            Self::EmptySegment => {
                f.write_str("path contains an empty segment: no leading, trailing or doubled '/'")
            }
            Self::RelativeSegment { segment } => {
                write!(f, "path contains the relative segment '{segment}'")
            }
            Self::ControlCharacter => f.write_str("path contains a control character"),
            Self::Whitespace => f.write_str("path contains whitespace"),
            Self::Wildcard => {
                f.write_str("path contains '*', which is reserved for policy patterns")
            }
        }
    }
}

impl core::error::Error for PathError {}

#[cfg(test)]
mod tests {
    use super::{MAX_PATH_LEN, MAX_SEGMENT_LEN, PathError, SecretPath, normalize};

    #[test]
    fn accepts_ordinary_paths() {
        for input in [
            "a",
            "infra/service-a/DB_PASSWORD",
            "ci/widget/registry_token",
            "sys/audit",
            "a/b/c/d/e/f/g",
            "with.dots/and-dashes/and_underscores",
            "percent%and_underscore_are_literal",
        ] {
            assert!(SecretPath::parse(input).is_ok(), "should accept {input}");
        }
    }

    #[test]
    fn rejects_what_the_rules_say_it_rejects() {
        let cases: &[(&str, PathError)] = &[
            ("", PathError::Empty),
            ("/infra", PathError::EmptySegment),
            ("infra/", PathError::EmptySegment),
            ("infra//a", PathError::EmptySegment),
            (
                "infra/../a",
                PathError::RelativeSegment {
                    segment: "..".to_owned(),
                },
            ),
            (
                "./infra",
                PathError::RelativeSegment {
                    segment: ".".to_owned(),
                },
            ),
            ("infra/a b", PathError::Whitespace),
            ("infra/a\tb", PathError::ControlCharacter),
            ("infra/a\nb", PathError::ControlCharacter),
            ("infra/*", PathError::Wildcard),
            ("infra/**", PathError::Wildcard),
        ];
        for (input, expected) in cases {
            assert_eq!(
                SecretPath::parse(input).unwrap_err(),
                *expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn enforces_length_limits() {
        let long_segment = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert!(matches!(
            SecretPath::parse(&long_segment),
            Err(PathError::SegmentTooLong { .. })
        ));

        let segment = "a".repeat(MAX_SEGMENT_LEN);
        let many = [segment.as_str(); MAX_PATH_LEN / MAX_SEGMENT_LEN + 1].join("/");
        assert!(matches!(
            SecretPath::parse(&many),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn normalizes_to_nfc_so_two_encodings_are_one_secret() {
        // "ä" as one code point, and as "a" plus a combining diaeresis.
        let composed = SecretPath::parse("infra/f\u{00e4}hig").unwrap();
        let decomposed = SecretPath::parse("infra/fa\u{0308}hig").unwrap();
        assert_eq!(composed, decomposed);
        assert_eq!(composed.as_str(), "infra/f\u{00e4}hig");
    }

    #[test]
    fn is_case_sensitive() {
        assert_ne!(
            SecretPath::parse("infra/db").unwrap(),
            SecretPath::parse("Infra/db").unwrap()
        );
    }

    #[test]
    fn normalization_is_idempotent() {
        for input in ["infra/fa\u{0308}hig", "a/b", "\u{1e9b}\u{0323}"] {
            let once = normalize(input);
            assert_eq!(normalize(&once), once, "input {input:?}");
        }
    }

    #[test]
    fn starts_with_respects_segment_boundaries() {
        let prefix = SecretPath::parse("infra/a").unwrap();
        assert!(SecretPath::parse("infra/a").unwrap().starts_with(&prefix));
        assert!(SecretPath::parse("infra/a/b").unwrap().starts_with(&prefix));
        assert!(!SecretPath::parse("infra/ab").unwrap().starts_with(&prefix));
        assert!(!SecretPath::parse("infra").unwrap().starts_with(&prefix));
    }
}
