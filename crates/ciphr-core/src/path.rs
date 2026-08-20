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
//! - **Segments are drawn from an allowed set**: letters and digits in any script,
//!   plus `-`, `_` and `.`. Everything else is refused, which is what keeps invisible
//!   characters out — a zero-width space, a soft hyphen or a bidirectional override is
//!   none of those, and any of them would produce a second path that renders exactly
//!   like the first. A list of what to reject would have to be extended with every
//!   Unicode revision; a list of what to accept does not.
//! - Control characters and whitespace get their own errors rather than the generic
//!   one, because those are the two a person actually types by accident.
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

/// The first segment of the virtual administrative paths.
///
/// `sys/audit`, `sys/identities`, and `sys/policies` are what the administrative
/// endpoints authorize against, through the ordinary evaluator — which is why no
/// `admin` capability exists. They are not secrets and no secret may be created
/// under them; see [`SecretPath::is_reserved`].
///
/// Defined here, in the crate that owns the path type, because two places deciding
/// what "reserved" means is how they come to disagree — the same reason
/// normalization has exactly one home (ADR-9).
pub const RESERVED_PREFIX: &str = "sys";

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
    ///
    /// Double-ended, because the last segment is the conventional environment variable
    /// name for a secret and callers should not have to collect to get at it.
    pub fn segments(&self) -> impl DoubleEndedIterator<Item = &str> {
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

    /// Whether this path lies under the reserved prefix [`RESERVED_PREFIX`].
    ///
    /// A real secret here would shadow one of the virtual administrative paths, and
    /// then a single rule granting `read` on `sys/audit` would authorize two
    /// different things: the audit trail, and whatever value someone stored under
    /// that name. Storage refuses it, so the refusal holds for every caller rather
    /// than for those that arrive over HTTP.
    ///
    /// Segment-aware, like [`SecretPath::starts_with`]: `system/config` is not
    /// reserved.
    ///
    /// ```
    /// use ciphr_core::SecretPath;
    ///
    /// assert!(SecretPath::parse("sys/audit")?.is_reserved());
    /// assert!(SecretPath::parse("sys/anything/deeper")?.is_reserved());
    /// assert!(!SecretPath::parse("system/config")?.is_reserved());
    /// # Ok::<(), ciphr_core::PathError>(())
    /// ```
    pub fn is_reserved(&self) -> bool {
        self.segments().next() == Some(RESERVED_PREFIX)
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
/// `pub(crate)` because [`crate::pattern::PathPattern`] must normalize the same
/// way. That is ADR-9 as a fact of the code rather than a promise: there is one
/// function, and a pattern and a path cannot disagree about what they are.
///
/// Kept separate from validation so that a test can assert the property that
/// matters — normalizing an already normalized path changes nothing.
pub(crate) fn normalize(input: &str) -> String {
    match is_nfc_quick(input.chars()) {
        IsNormalized::Yes => input.to_owned(),
        _ => input.nfc().collect(),
    }
}

/// What is wrong with a segment, in terms both paths and patterns share.
///
/// Wildcards are deliberately absent: they are the one rule where paths and
/// patterns differ, so each type decides that for itself and everything else is
/// decided in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentProblem {
    /// The segment was empty.
    Empty,
    /// The segment was longer than [`MAX_SEGMENT_LEN`].
    TooLong {
        /// Length supplied.
        found: usize,
    },
    /// The segment was `.` or `..`.
    Relative,
    /// The segment contained a control character.
    Control,
    /// The segment contained whitespace.
    Whitespace,
    /// The segment contained a character outside the allowed set.
    Disallowed {
        /// The offending character.
        character: char,
    },
}

/// Check everything about a segment except wildcards.
pub(crate) fn inspect_segment(segment: &str) -> Result<(), SegmentProblem> {
    if segment.is_empty() {
        return Err(SegmentProblem::Empty);
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(SegmentProblem::TooLong {
            found: segment.len(),
        });
    }
    if segment == "." || segment == ".." {
        return Err(SegmentProblem::Relative);
    }
    for ch in segment.chars() {
        // These two come first only for the error message: both are already excluded by
        // the allowed set below, but "contains whitespace" says more than "contains a
        // character that is not allowed here".
        if ch.is_control() {
            return Err(SegmentProblem::Control);
        }
        if ch.is_whitespace() {
            return Err(SegmentProblem::Whitespace);
        }
        if !is_allowed(ch) {
            return Err(SegmentProblem::Disallowed { character: ch });
        }
    }
    Ok(())
}

/// Whether a character may appear in a segment.
///
/// An allowlist, deliberately. The rule this replaced rejected control characters and
/// whitespace, which let every format character through: U+200B, U+00AD, U+FEFF, U+2060
/// and U+202E were all accepted, and each produces a path that renders identically to
/// another one — or, for the bidirectional override, as a different one entirely. A
/// denylist would have to grow with every Unicode revision, and a gap in it is invisible
/// until someone exploits it.
///
/// `*` is allowed **here** and refused by both callers afterwards, each with its own
/// error: a path may not contain one at all, and a pattern may not contain one inside a
/// larger segment. Rejecting it in this function would replace both messages with a
/// worse one.
///
/// Letters and digits of any script are allowed, so this is not an ASCII rule.
/// Confusables across scripts remain possible and remain out of scope — a documented
/// boundary rather than an oversight.
fn is_allowed(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.' | '*')
}

fn validate_segment(segment: &str) -> Result<(), PathError> {
    inspect_segment(segment).map_err(|problem| match problem {
        SegmentProblem::Empty => PathError::EmptySegment,
        SegmentProblem::TooLong { found } => PathError::SegmentTooLong {
            limit: MAX_SEGMENT_LEN,
            found,
        },
        SegmentProblem::Relative => PathError::RelativeSegment {
            segment: segment.to_owned(),
        },
        SegmentProblem::Control => PathError::ControlCharacter,
        SegmentProblem::Whitespace => PathError::Whitespace,
        SegmentProblem::Disallowed { character } => PathError::DisallowedCharacter { character },
    })?;

    // The one rule a pattern does not share: in a path, `*` is never special and
    // never allowed, so a literal can never be mistaken for a wildcard.
    if segment.contains('*') {
        return Err(PathError::Wildcard);
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
    /// A character outside the allowed set.
    DisallowedCharacter {
        /// The offending character.
        character: char,
    },
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
            Self::DisallowedCharacter { character } => write!(
                f,
                "path contains U+{:04X}; segments allow letters, digits, '-', '_' and '.'",
                u32::from(*character)
            ),
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
            "underscore_is_a_like_wildcard_and_stays_literal",
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
    #[test]
    fn invisible_characters_are_refused() {
        // The reason the segment rules are an allowlist. Every one of these was accepted
        // by the previous rule -- it rejected control characters and whitespace, and none
        // of these is either -- and every one produces a path that renders identically to
        // another, or, for the bidirectional override, as a different one entirely.
        for (name, input) in [
            ("zero width space", "infra/db\u{200b}"),
            ("soft hyphen", "infra/db\u{00ad}"),
            ("zero width no-break space", "infra/db\u{feff}"),
            ("word joiner", "infra/db\u{2060}"),
            ("right-to-left override", "infra/\u{202e}db"),
            ("mongolian vowel separator", "infra/db\u{180e}"),
        ] {
            assert!(
                matches!(
                    SecretPath::parse(input),
                    Err(PathError::DisallowedCharacter { .. })
                ),
                "{name} must be refused"
            );
        }

        // No-break space is whitespace, and keeps the more specific error.
        assert_eq!(
            SecretPath::parse("infra/db\u{00a0}"),
            Err(PathError::Whitespace)
        );
    }

    #[test]
    fn confusables_remain_possible_and_that_is_the_documented_boundary() {
        // Not a gap that was missed. Both of these are letters, so any rule that admits
        // non-ASCII names at all admits them. Refusing them means either an ASCII-only
        // path space or a script-mixing policy, and neither is in v1.
        assert!(SecretPath::parse("infr\u{0430}/db").is_ok(), "cyrillic a");
        assert!(SecretPath::parse("\u{fb01}le/x").is_ok(), "fi ligature");

        // They are still distinct paths, which is what keeps authorization sound: a
        // pattern for one does not match the other.
        assert_ne!(
            SecretPath::parse("infr\u{0430}/db"),
            SecretPath::parse("infra/db")
        );
    }

    #[test]
    fn the_allowed_set_covers_what_paths_actually_contain() {
        for input in [
            "infra/host-a/service-b/DB_PASSWORD",
            "infra/_group/service/API_TOKEN",
            "with.dots/and-dashes/and_underscores",
            // Letters of any script, not an ASCII rule.
            "\u{65e5}\u{672c}/x",
        ] {
            assert!(SecretPath::parse(input).is_ok(), "should accept {input}");
        }
    }
}
