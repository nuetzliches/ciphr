//! Property tests for path normalization.
//!
//! The unit tests in `src/path.rs` cover the cases someone thought of. These
//! cover the ones nobody did, which is the point: normalization is the function
//! ADR-9 makes shared between the router and the policy evaluator, so a case
//! where it behaves unexpectedly is a case where authorization can disagree with
//! routing.

use ciphr_core::SecretPath;
use ciphr_core::path::{MAX_PATH_LEN, MAX_SEGMENT_LEN};
use proptest::prelude::*;

/// Paths that should be accepted: the allowed set from `path.rs`, one to five
/// segments.
///
/// Kept in step with `is_allowed` by hand. `=` and `+` were in this generator until the
/// segment rules were narrowed to an allowlist; they are no longer legal, and leaving
/// them here would have made the property tests fail rather than the paths.
fn valid_path() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_.-]{1,20}(/[a-zA-Z0-9_.-]{1,20}){0,4}")
        .expect("the regex is a literal and compiles")
        .prop_filter("segments must not be relative", |candidate| {
            candidate
                .split('/')
                .all(|segment| segment != "." && segment != "..")
        })
}

proptest! {
    /// Parsing an already parsed path changes nothing. If this ever fails, two
    /// components can hold different opinions about the same path.
    #[test]
    fn parsing_is_idempotent(input in ".{0,64}") {
        if let Ok(once) = SecretPath::parse(&input) {
            let twice = SecretPath::parse(once.as_str())
                .expect("a normalized path must parse");
            prop_assert_eq!(once, twice);
        }
    }

    /// Whatever comes out satisfies the rules that go in. Stated as a property so
    /// that adding a rule to the parser without applying it everywhere is caught.
    #[test]
    fn accepted_paths_obey_every_rule(input in ".{0,64}") {
        if let Ok(path) = SecretPath::parse(&input) {
            let text = path.as_str();
            prop_assert!(!text.is_empty());
            prop_assert!(text.len() <= MAX_PATH_LEN);
            prop_assert!(!text.starts_with('/'));
            prop_assert!(!text.ends_with('/'));
            prop_assert!(!text.contains("//"));
            prop_assert!(!text.contains('*'));

            for segment in path.segments() {
                prop_assert!(!segment.is_empty());
                prop_assert!(segment.len() <= MAX_SEGMENT_LEN);
                prop_assert_ne!(segment, ".");
                prop_assert_ne!(segment, "..");
                prop_assert!(!segment.chars().any(|c| c.is_control() || c.is_whitespace()));
            }
        }
    }

    /// The segments are a lossless decomposition: joining them reproduces the
    /// path. A normalizer that dropped or merged a segment would be a normalizer
    /// that can be talked into pointing somewhere else.
    #[test]
    fn segments_rejoin_to_the_same_path(input in valid_path()) {
        let path = SecretPath::parse(&input).expect("generated paths are valid");
        let rejoined = path.segments().collect::<Vec<_>>().join("/");
        prop_assert_eq!(rejoined, path.as_str().to_owned());
    }

    /// A path is under its own prefixes and under nothing else.
    #[test]
    fn prefix_matching_follows_segment_boundaries(input in valid_path()) {
        let path = SecretPath::parse(&input).expect("generated paths are valid");
        let segments: Vec<&str> = path.segments().collect();

        for count in 1..=segments.len() {
            let prefix = SecretPath::parse(&segments[..count].join("/"))
                .expect("a prefix of a valid path is valid");
            prop_assert!(path.starts_with(&prefix));
        }

        // Extending the last segment must break the relationship: `infra/ab` is
        // not under `infra/a`.
        let mut extended = segments.clone();
        let last = extended.len() - 1;
        let longer = format!("{}x", extended[last]);
        extended[last] = &longer;
        let sibling = SecretPath::parse(&extended.join("/"))
            .expect("appending an identifier character stays valid");
        prop_assert!(!path.starts_with(&sibling));
    }
}
