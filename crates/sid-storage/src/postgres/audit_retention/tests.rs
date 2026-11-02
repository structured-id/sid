// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// Only monthly partition names parse; the default partition and anything
/// malformed are left alone.
#[test]
fn partition_names_parse_strictly() {
    assert_eq!(partition_month("audit_records_2026_03"), Some((2026, 3)));
    assert_eq!(partition_month("audit_records_default"), None);
    assert_eq!(partition_month("audit_records_2026_13"), None);
    assert_eq!(partition_month("audit_records_2026_3"), None);
    assert_eq!(partition_month("other_2026_03"), None);
}

/// December rolls over to January of the next year.
#[test]
fn month_after_december_is_january() {
    assert_eq!(
        next_month(2026, 12).unwrap(),
        NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
    );
    assert_eq!(
        next_month(2026, 3).unwrap(),
        NaiveDate::from_ymd_opt(2026, 4, 1).unwrap()
    );
}

/// A cut in the middle of March starts at the 1st of March: March itself is
/// still running on it and is kept whole.
#[test]
fn month_start_truncates_to_the_first() {
    let at = "2026-03-15T10:00:00Z".parse::<DateTime<Utc>>().unwrap();
    assert_eq!(
        month_start(at).unwrap(),
        "2026-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
    );
}
