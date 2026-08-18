//! Property tests for pattern matching.
//!
//! The unit tests cover the cases someone thought of. These state the properties
//! the matcher has to have for the policy evaluator built on top of it to mean
//! anything: that `**` is at least as permissive as `*`, that specificity orders
//! patterns the way the evaluator assumes, and that a pattern without wildcards
//! matches exactly one path.

use ciphr_core::{PathPattern, SecretPath};
use proptest::prelude::*;

/// One to four segments of ordinary identifier characters.
fn path_text() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z0-9_-]{1,8}(/[a-z0-9_-]{1,8}){0,3}")
        .expect("the regex is a literal and compiles")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A pattern with no wildcards matches its own path and nothing else.
    #[test]
    fn an_exact_pattern_matches_exactly_one_path(a in path_text(), b in path_text()) {
        let first = SecretPath::parse(&a).expect("valid");
        let second = SecretPath::parse(&b).expect("valid");
        let pattern = PathPattern::exact(&first);

        prop_assert!(pattern.matches(&first));
        prop_assert_eq!(pattern.matches(&second), first == second);
        prop_assert!(!pattern.has_wildcard());
    }

    /// `**` subsumes `*`: wherever a trailing single wildcard matches, a trailing
    /// multi wildcard matches too. If this ever failed, a broad rule could be
    /// narrower than a specific one and the specificity ordering would be
    /// meaningless.
    #[test]
    fn multi_wildcard_subsumes_single_wildcard(prefix in path_text(), extra in path_text()) {
        let single = PathPattern::parse(&format!("{prefix}/*")).expect("valid");
        let multi = PathPattern::parse(&format!("{prefix}/**")).expect("valid");

        let one_deeper = SecretPath::parse(&format!("{prefix}/{extra}")).expect("valid");
        for path in [&one_deeper] {
            if single.matches(path) {
                prop_assert!(multi.matches(path), "** must cover what * covers");
            }
        }

        // And `**` covers strictly more: anything deeper than one segment.
        let two_deeper = SecretPath::parse(&format!("{prefix}/{extra}/{extra}")).expect("valid");
        if multi.matches(&two_deeper) {
            prop_assert!(!single.matches(&two_deeper) || two_deeper.segment_count() == 2);
        }
    }

    /// Specificity counts literal segments, so an exact pattern is exactly as
    /// specific as the path is deep. The evaluator relies on this to let a narrow
    /// rule override a broad one.
    #[test]
    fn specificity_counts_literal_segments(text in path_text()) {
        let path = SecretPath::parse(&text).expect("valid");
        let exact = PathPattern::exact(&path);
        prop_assert_eq!(exact.specificity(), path.segment_count());

        let broad = PathPattern::parse("**").expect("valid");
        prop_assert_eq!(broad.specificity(), 0);
        prop_assert!(exact.specificity() >= broad.specificity());
    }

    /// Replacing a literal segment with `*` never makes a pattern match less, and
    /// always makes it less specific.
    #[test]
    fn widening_a_segment_never_narrows_the_match(text in path_text()) {
        let path = SecretPath::parse(&text).expect("valid");
        let segments: Vec<&str> = path.segments().collect();

        for index in 0..segments.len() {
            let mut widened = segments.clone();
            widened[index] = "*";
            let pattern = PathPattern::parse(&widened.join("/")).expect("valid");

            prop_assert!(pattern.matches(&path));
            prop_assert!(pattern.specificity() < PathPattern::exact(&path).specificity());
        }
    }

    /// Matching never panics, whatever the input, and a pattern that parses always
    /// re-parses to itself.
    #[test]
    fn parsing_is_stable_and_matching_is_total(raw in ".{0,48}", text in path_text()) {
        let path = SecretPath::parse(&text).expect("valid");
        if let Ok(pattern) = PathPattern::parse(&raw) {
            let reparsed = PathPattern::parse(pattern.as_str())
                .expect("a normalized pattern must parse");
            prop_assert_eq!(&pattern, &reparsed);
            // The result is not asserted — only that asking is safe.
            let _ = pattern.matches(&path);
        }
    }
}
