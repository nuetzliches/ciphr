//! RFC 3339 timestamps, in UTC, without a dependency.
//!
//! An audit trail that stores epoch milliseconds is unambiguous and unreadable. A
//! file someone opens during an incident should say `2026-08-18T16:41:23.412Z`, so
//! the formatting happens here rather than being pushed onto every reader.
//!
//! Twenty lines of civil-date arithmetic instead of a date library, for the same
//! reason the hexadecimal encoder is hand-written: the dependency budget in the
//! crates that hold security-relevant logic is spent where it buys something. The
//! algorithm is Howard Hinnant's `civil_from_days`, which is the standard,
//! well-reviewed approach; the tests below check it against values computed
//! independently, including leap days and a century boundary.
//!
//! UTC only. A local time zone in an audit trail is a way to make two entries
//! from different hosts incomparable.

/// Format milliseconds since the Unix epoch as an RFC 3339 timestamp in UTC.
///
/// Negative values — times before 1970 — are formatted correctly rather than
/// clamped. A clock that far wrong is a problem to see, not to hide.
///
/// ```
/// assert_eq!(ciphr_audit::time::rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
/// assert_eq!(ciphr_audit::time::rfc3339_millis(1_709_164_800_123), "2024-02-29T00:00:00.123Z");
/// ```
pub fn rfc3339_millis(millis: i64) -> String {
    // Floor division, so that a negative millisecond count borrows from the second
    // rather than truncating towards zero.
    let seconds = millis.div_euclid(1000);
    let sub_milli = millis.rem_euclid(1000);

    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3600;
    let minute = (second_of_day % 3600) / 60;
    let second = second_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_milli:03}Z")
}

/// Convert days since 1970-01-01 into a civil date.
///
/// Hinnant's algorithm: shift the epoch to 0000-03-01 so that the leap day lands
/// at the end of the cycle, then unwind the 400-year, 100-year, and 4-year cycles.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    })
    .unwrap_or(1);

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::rfc3339_millis;

    #[test]
    fn matches_independently_computed_values() {
        // Ground truth from a separate implementation, not from this code.
        let cases = [
            (0_i64, "1970-01-01T00:00:00.000Z"),
            (1_000, "1970-01-01T00:00:01.000Z"),
            (-1, "1969-12-31T23:59:59.999Z"),
            (946_684_800_000, "2000-01-01T00:00:00.000Z"),
            // Leap day in a year divisible by 4.
            (1_709_164_800_123, "2024-02-29T00:00:00.123Z"),
            // Leap day in a year divisible by 400 — the case a naive rule gets wrong.
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            // 2100 is not a leap year, so this is the day after 2020-02-29 logic
            // must not be applied to a century.
            (1_583_020_800_000, "2020-03-01T00:00:00.000Z"),
            (4_102_444_800_000, "2100-01-01T00:00:00.000Z"),
            (1_767_225_599_999, "2025-12-31T23:59:59.999Z"),
        ];

        for (millis, expected) in cases {
            assert_eq!(rfc3339_millis(millis), expected, "for {millis}");
        }
    }

    #[test]
    fn is_lexicographically_ordered_like_time() {
        // The property that makes these timestamps useful in a text file: sorting
        // the lines sorts the events.
        let mut previous = rfc3339_millis(-86_400_000);
        for millis in [
            0_i64,
            1,
            999,
            1_000,
            946_684_800_000,
            1_709_164_800_123,
            4_102_444_800_000,
        ] {
            let current = rfc3339_millis(millis);
            assert!(
                previous < current,
                "{previous} should sort before {current}"
            );
            previous = current;
        }
    }

    #[test]
    fn every_output_has_the_same_shape() {
        for millis in [-62_135_596_800_000_i64, -1, 0, 1, 253_402_300_799_999] {
            let formatted = rfc3339_millis(millis);
            assert_eq!(formatted.len(), 24, "{formatted}");
            assert!(formatted.ends_with('Z'));
        }
    }
}
