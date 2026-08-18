//! Fuzz pattern parsing and matching.
//!
//! The matcher decides whether a policy rule applies to a path. Two things are
//! checked here that the unit tests cannot cover exhaustively: that a parsed pattern
//! never claims a shape it does not have, and that a pattern without wildcards
//! matches exactly one path — the property the specificity ordering rests on.
//!
//! The input is split into a pattern and a path so that one fuzzing run exercises
//! both sides of the comparison.

#![no_main]

use ciphr_core::{PathPattern, SecretPath};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    // A newline splits the two halves. Inputs without one exercise parsing only,
    // which is also worth doing.
    let (raw_pattern, raw_path) = input.split_once('\n').unwrap_or((input, ""));

    let Ok(pattern) = PathPattern::parse(raw_pattern) else {
        return;
    };

    let text = pattern.as_str();

    // Parsing is stable: a pattern that parsed must re-parse to itself.
    let again = PathPattern::parse(text).expect("a normalized pattern must parse");
    assert_eq!(pattern, again, "pattern parsing is not idempotent: {text:?}");

    // `**` is only ever the last segment, which is what keeps matching a linear scan.
    let segments: Vec<&str> = text.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        if *segment == "**" {
            assert_eq!(
                index,
                segments.len() - 1,
                "accepted '**' before the end: {text:?}"
            );
        } else {
            assert!(
                *segment == "*" || !segment.contains('*'),
                "accepted a partial wildcard: {text:?}"
            );
        }
    }

    // Specificity counts literal segments, so it can never exceed the segment count.
    assert!(
        pattern.specificity() <= segments.len(),
        "specificity exceeds the number of segments: {text:?}"
    );
    assert_eq!(
        pattern.has_wildcard(),
        pattern.specificity() != segments.len(),
        "has_wildcard disagrees with specificity: {text:?}"
    );

    // A pattern with no wildcards is an exact match and nothing else.
    if !pattern.has_wildcard() {
        let own = SecretPath::parse(text).expect("a wildcard-free pattern is a valid path");
        assert!(pattern.matches(&own), "an exact pattern must match its path");
        assert_eq!(pattern.specificity(), own.segment_count());
    }

    let Ok(path) = SecretPath::parse(raw_path) else {
        return;
    };

    // Matching must not panic, and a match must respect the segment count when the
    // pattern has no `**` to absorb the remainder.
    let matched = pattern.matches(&path);
    if matched && !text.split('/').any(|segment| segment == "**") {
        assert_eq!(
            path.segment_count(),
            segments.len(),
            "matched a path of a different depth without '**': {text:?} vs {path}"
        );
    }

    // An exact pattern matches one path only.
    if !pattern.has_wildcard() {
        assert_eq!(
            matched,
            path.as_str() == text,
            "an exact pattern matched something else: {text:?} vs {path}"
        );
    }
});
