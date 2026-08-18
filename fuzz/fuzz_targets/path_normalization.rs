//! Fuzz path normalization.
//!
//! This is the function ADR-9 makes shared between the HTTP router and the policy
//! evaluator, so an input that makes it behave unexpectedly is an input that can
//! make routing and authorization disagree. The property tests generate paths from a
//! regular expression — that is, from what someone thought to write down. This
//! generates whatever libFuzzer can think of, which is the point.
//!
//! The target asserts the invariants rather than just checking for panics. A
//! normalizer that returns a path containing `..` without crashing is the failure
//! that matters here.

#![no_main]

use ciphr_core::SecretPath;
use ciphr_core::path::{MAX_PATH_LEN, MAX_SEGMENT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    let Ok(path) = SecretPath::parse(input) else {
        // Rejection is always an acceptable outcome; the rules are deliberately
        // strict. What must never happen is accepting something that breaks them.
        return;
    };

    let text = path.as_str();

    // Every rule the type promises, checked on the accepted output.
    assert!(!text.is_empty(), "accepted an empty path");
    assert!(text.len() <= MAX_PATH_LEN, "accepted an over-long path");
    assert!(!text.starts_with('/'), "accepted a leading slash: {text:?}");
    assert!(!text.ends_with('/'), "accepted a trailing slash: {text:?}");
    assert!(!text.contains("//"), "accepted a doubled slash: {text:?}");
    assert!(
        !text.contains('*'),
        "accepted a wildcard in a path: {text:?}"
    );

    for segment in path.segments() {
        assert!(!segment.is_empty(), "accepted an empty segment: {text:?}");
        assert!(
            segment.len() <= MAX_SEGMENT_LEN,
            "accepted an over-long segment: {text:?}"
        );
        assert_ne!(segment, ".", "accepted a '.' segment: {text:?}");
        assert_ne!(segment, "..", "accepted a '..' segment: {text:?}");
        assert!(
            !segment.chars().any(|c| c.is_control() || c.is_whitespace()),
            "accepted whitespace or a control character: {text:?}"
        );
    }

    // Idempotence. If this ever fails, two components can hold different opinions
    // about the same path, which is the bug class ADR-9 exists to prevent.
    let again = SecretPath::parse(text).expect("a normalized path must parse");
    assert_eq!(path, again, "normalization is not idempotent: {text:?}");

    // The segments are a lossless decomposition of the path.
    let rejoined = path.segments().collect::<Vec<_>>().join("/");
    assert_eq!(rejoined, text, "segments do not rejoin to the path");
});
