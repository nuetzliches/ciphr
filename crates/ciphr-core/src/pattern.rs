//! Path patterns: the glob language policies are written in.
//!
//! A pattern is a path with wildcards, and it goes through **the same
//! normalization** as [`SecretPath`] — literally the same function (ADR-9). Two
//! normalizations that disagree by one edge case are an authorization bypass, and
//! the cheapest way to guarantee they cannot disagree is for there to be one.
//!
//! # The language, in full
//!
//! - `*` matches **exactly one** path segment.
//! - `**` matches **one or more** segments, and may appear only as the **last**
//!   segment.
//! - Everything else is a literal segment, compared byte for byte after NFC
//!   normalization. Case sensitive.
//!
//! That is all of it. No regular expressions, no character classes, no partial
//! wildcards inside a segment, no negation, no alternation. The language is small
//! enough that "does this rule match this path" can be answered by reading, which
//! is the property that matters for a language whose job is to deny access.
//!
//! # Two deliberate restrictions
//!
//! **`**` only at the end.** A `**` in the middle (`infra/**/db`) turns matching
//! into a backtracking search, and backtracking glob matchers are where subtle
//! bugs live. Restricted to the tail, matching is a single linear scan with no
//! branching — which can be verified by reading it. Nothing in the design needs a
//! middle `**`; if something ever does, that is a decision to take deliberately,
//! with tests written for the backtracking case.
//!
//! **No partial wildcards.** `infra/ab*` is rejected rather than treated as a
//! prefix match. Partial matching invites `db*` to mean "db-primary and also
//! db-secondary and also anything else starting with db", which is how a policy
//! ends up granting more than its author read into it.
//!
//! # `**` does not match zero segments
//!
//! `infra/**` matches `infra/a` and `infra/a/b`, but **not** `infra` itself. A
//! rule about the contents of a subtree should not silently also be a rule about
//! the thing containing it; if both are wanted, that is two rules, and writing
//! them out makes the intent visible in the policy file.

use core::fmt;
use core::str::FromStr;

use crate::path::{
    MAX_PATH_LEN, MAX_SEGMENT_LEN, SecretPath, SegmentProblem, inspect_segment, normalize,
};

/// One segment of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Segment {
    /// A literal segment, compared byte for byte.
    Literal(String),
    /// `*` — exactly one segment, any content.
    One,
    /// `**` — one or more segments. Only ever the last segment.
    Rest,
}

/// A normalized path pattern.
///
/// ```
/// use ciphr_core::{PathPattern, SecretPath};
///
/// let pattern = PathPattern::parse("infra/*/DB_PASSWORD")?;
/// assert!(pattern.matches(&SecretPath::parse("infra/service-a/DB_PASSWORD")?));
/// assert!(!pattern.matches(&SecretPath::parse("infra/a/b/DB_PASSWORD")?));
///
/// let subtree = PathPattern::parse("infra/**")?;
/// assert!(subtree.matches(&SecretPath::parse("infra/a")?));
/// assert!(subtree.matches(&SecretPath::parse("infra/a/b/c")?));
/// // `**` covers one or more segments, never zero:
/// assert!(!subtree.matches(&SecretPath::parse("infra")?));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern {
    segments: Vec<Segment>,
    text: String,
}

impl PathPattern {
    /// Normalize and validate a pattern.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError`] describing the first rule the input breaks.
    /// Patterns come from a configuration file in version control, so the error
    /// names the offending segment — there is nothing secret in a pattern.
    pub fn parse(input: &str) -> Result<Self, PatternError> {
        let text = normalize(input);

        if text.is_empty() {
            return Err(PatternError::Empty);
        }
        if text.len() > MAX_PATH_LEN {
            return Err(PatternError::TooLong {
                limit: MAX_PATH_LEN,
                found: text.len(),
            });
        }

        let raw: Vec<&str> = text.split('/').collect();
        let last = raw.len() - 1;
        let mut segments = Vec::with_capacity(raw.len());

        for (index, segment) in raw.into_iter().enumerate() {
            match segment {
                "*" => segments.push(Segment::One),
                "**" => {
                    if index != last {
                        return Err(PatternError::TrailingMultiWildcardOnly);
                    }
                    segments.push(Segment::Rest);
                }
                literal => {
                    inspect_segment(literal).map_err(|problem| match problem {
                        SegmentProblem::Empty => PatternError::EmptySegment,
                        SegmentProblem::TooLong { found } => PatternError::SegmentTooLong {
                            limit: MAX_SEGMENT_LEN,
                            found,
                        },
                        SegmentProblem::Relative => PatternError::RelativeSegment {
                            segment: literal.to_owned(),
                        },
                        SegmentProblem::Control => PatternError::ControlCharacter,
                        SegmentProblem::Whitespace => PatternError::Whitespace,
                    })?;

                    if literal.contains('*') {
                        return Err(PatternError::PartialWildcard {
                            segment: literal.to_owned(),
                        });
                    }
                    segments.push(Segment::Literal(literal.to_owned()));
                }
            }
        }

        Ok(Self { segments, text })
    }

    /// Build a pattern that matches exactly one path.
    ///
    /// Useful where a caller has a path and needs it as a rule: the result
    /// contains no wildcards, so it can never match anything else.
    pub fn exact(path: &SecretPath) -> Self {
        Self {
            segments: path
                .segments()
                .map(|s| Segment::Literal(s.to_owned()))
                .collect(),
            text: path.as_str().to_owned(),
        }
    }

    /// The normalized pattern text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether this pattern matches a path.
    ///
    /// A single linear scan, no backtracking — which is only possible because
    /// `**` is restricted to the last segment.
    pub fn matches(&self, path: &SecretPath) -> bool {
        let mut pattern = self.segments.iter();
        let mut actual = path.segments();

        loop {
            match (pattern.next(), actual.next()) {
                // `**` absorbs this segment and every one after it — it has already
                // consumed at least this one, which is why it cannot match zero —
                // or both sides ran out together on a literal match.
                (Some(Segment::Rest), Some(_)) | (None, None) => return true,
                // One side has segments the other does not account for: the pattern
                // wanted more than the path has, or the path went deeper than the
                // pattern allows.
                (Some(_), None) | (None, Some(_)) => return false,
                (Some(Segment::One), Some(_)) => {}
                (Some(Segment::Literal(expected)), Some(found)) => {
                    if expected != found {
                        return false;
                    }
                }
            }
        }
    }

    /// How specific this pattern is: the number of literal segments.
    ///
    /// This is the ordering the policy evaluator uses to decide which of several
    /// matching rules applies. Counting literals means `infra/ciphr/**` (two) beats
    /// `infra/**` (one), which is what makes a narrow exception to a broad grant
    /// expressible at all.
    pub fn specificity(&self) -> usize {
        self.segments
            .iter()
            .filter(|segment| matches!(segment, Segment::Literal(_)))
            .count()
    }

    /// Whether the pattern contains a wildcard.
    pub fn has_wildcard(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| !matches!(segment, Segment::Literal(_)))
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for PathPattern {
    type Err = PatternError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Why a pattern was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// The pattern was empty.
    Empty,
    /// The pattern exceeded [`MAX_PATH_LEN`].
    TooLong {
        /// The limit.
        limit: usize,
        /// The length supplied.
        found: usize,
    },
    /// A literal segment exceeded [`MAX_SEGMENT_LEN`].
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
    /// A `*` inside a larger segment, such as `ab*`.
    PartialWildcard {
        /// The offending segment.
        segment: String,
    },
    /// A `**` that was not the last segment.
    TrailingMultiWildcardOnly,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("pattern is empty"),
            Self::TooLong { limit, found } => {
                write!(f, "pattern is {found} bytes, limit is {limit}")
            }
            Self::SegmentTooLong { limit, found } => {
                write!(f, "pattern segment is {found} bytes, limit is {limit}")
            }
            Self::EmptySegment => f.write_str(
                "pattern contains an empty segment: no leading, trailing or doubled '/'",
            ),
            Self::RelativeSegment { segment } => {
                write!(f, "pattern contains the relative segment '{segment}'")
            }
            Self::ControlCharacter => f.write_str("pattern contains a control character"),
            Self::Whitespace => f.write_str("pattern contains whitespace"),
            Self::PartialWildcard { segment } => write!(
                f,
                "segment '{segment}' mixes a wildcard with literal characters; \
                 '*' and '**' must be whole segments"
            ),
            Self::TrailingMultiWildcardOnly => {
                f.write_str("'**' is only allowed as the last segment of a pattern")
            }
        }
    }
}

impl core::error::Error for PatternError {}

#[cfg(test)]
mod tests {
    use super::{PathPattern, PatternError};
    use crate::SecretPath;

    fn path(text: &str) -> SecretPath {
        SecretPath::parse(text).expect("test paths are valid")
    }

    fn pattern(text: &str) -> PathPattern {
        PathPattern::parse(text).expect("test patterns are valid")
    }

    #[test]
    fn literal_patterns_match_exactly_one_path() {
        let p = pattern("infra/a/DB");
        assert!(p.matches(&path("infra/a/DB")));
        assert!(!p.matches(&path("infra/a/DBX")));
        assert!(!p.matches(&path("infra/a")));
        assert!(!p.matches(&path("infra/a/DB/x")));
        assert_eq!(p.specificity(), 3);
        assert!(!p.has_wildcard());
    }

    #[test]
    fn single_wildcard_covers_exactly_one_segment() {
        let p = pattern("infra/*/DB");
        assert!(p.matches(&path("infra/a/DB")));
        assert!(p.matches(&path("infra/anything-here/DB")));
        assert!(!p.matches(&path("infra/a/b/DB")));
        assert!(!p.matches(&path("infra/DB")));
        assert_eq!(p.specificity(), 2);
        assert!(p.has_wildcard());
    }

    #[test]
    fn multi_wildcard_covers_one_or_more_segments_never_zero() {
        let p = pattern("infra/**");
        assert!(p.matches(&path("infra/a")));
        assert!(p.matches(&path("infra/a/b")));
        assert!(p.matches(&path("infra/a/b/c/d/e")));
        assert!(!p.matches(&path("infra")));
        assert!(!p.matches(&path("other/a")));
        assert_eq!(p.specificity(), 1);
    }

    #[test]
    fn a_bare_multi_wildcard_matches_every_path() {
        let p = pattern("**");
        for text in ["a", "a/b", "infra/service/DB_PASSWORD"] {
            assert!(p.matches(&path(text)), "should match {text}");
        }
        assert_eq!(p.specificity(), 0);
    }

    #[test]
    fn matching_is_case_sensitive_and_segment_aware() {
        assert!(!pattern("infra/**").matches(&path("Infra/a")));
        // `infra/ab` is not inside `infra/a`, and no pattern for the latter should
        // suggest otherwise.
        assert!(!pattern("infra/a/**").matches(&path("infra/ab/c")));
    }

    #[test]
    fn patterns_normalize_the_same_way_paths_do() {
        // "ä" composed, versus "a" plus a combining diaeresis. If the pattern and
        // the path normalized differently, this would be an authorization bypass
        // rather than a curiosity.
        let composed = pattern("infra/f\u{00e4}hig/**");
        assert!(composed.matches(&path("infra/fa\u{0308}hig/x")));

        let decomposed = pattern("infra/fa\u{0308}hig/**");
        assert_eq!(composed, decomposed);
        assert!(decomposed.matches(&path("infra/f\u{00e4}hig/x")));
    }

    #[test]
    fn rejects_partial_wildcards() {
        assert_eq!(
            PathPattern::parse("infra/ab*"),
            Err(PatternError::PartialWildcard {
                segment: "ab*".to_owned()
            })
        );
        assert_eq!(
            PathPattern::parse("infra/*x/db"),
            Err(PatternError::PartialWildcard {
                segment: "*x".to_owned()
            })
        );
        assert_eq!(
            PathPattern::parse("infra/**x"),
            Err(PatternError::PartialWildcard {
                segment: "**x".to_owned()
            })
        );
    }

    #[test]
    fn rejects_a_multi_wildcard_that_is_not_last() {
        assert_eq!(
            PathPattern::parse("infra/**/db"),
            Err(PatternError::TrailingMultiWildcardOnly)
        );
        assert_eq!(
            PathPattern::parse("**/db"),
            Err(PatternError::TrailingMultiWildcardOnly)
        );
    }

    #[test]
    fn rejects_the_same_malformed_input_paths_reject() {
        for (input, expected) in [
            ("", PatternError::Empty),
            ("/infra", PatternError::EmptySegment),
            ("infra/", PatternError::EmptySegment),
            ("infra//a", PatternError::EmptySegment),
            ("infra/a b", PatternError::Whitespace),
            ("infra/a\tb", PatternError::ControlCharacter),
        ] {
            assert_eq!(PathPattern::parse(input), Err(expected), "input {input:?}");
        }
        assert!(matches!(
            PathPattern::parse("infra/../a"),
            Err(PatternError::RelativeSegment { .. })
        ));
    }

    #[test]
    fn specificity_orders_a_narrow_exception_above_a_broad_grant() {
        // This ordering is what makes "everything under infra, except our own
        // secrets" expressible.
        assert!(pattern("infra/ciphr/**").specificity() > pattern("infra/**").specificity());
        assert!(pattern("infra/a/DB").specificity() > pattern("infra/*/DB").specificity());
    }

    #[test]
    fn exact_patterns_match_only_their_own_path() {
        let target = path("infra/a/DB");
        let p = PathPattern::exact(&target);
        assert!(!p.has_wildcard());
        assert!(p.matches(&target));
        assert!(!p.matches(&path("infra/a/DBX")));
        assert_eq!(p.as_str(), "infra/a/DB");
    }
}
