// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use super::drain_interval;

/// Unset: the default fits inside the usual 30 s pod termination grace.
#[test]
fn test_drain_interval_default() {
    assert_eq!(drain_interval(None).unwrap(), Duration::from_secs(25));
}

#[test]
fn test_drain_interval_from_setting() {
    assert_eq!(drain_interval(Some("2")).unwrap(), Duration::from_secs(2));
    assert_eq!(
        drain_interval(Some("3600")).unwrap(),
        Duration::from_secs(3600)
    );
}

/// A drain of zero would cut every call at once and an unbounded one would
/// never end; neither, nor an unreadable value, starts the server.
#[test]
fn test_drain_interval_refuses_out_of_range_or_unreadable() {
    for value in ["0", "3601", "-1", "25s", ""] {
        let error = drain_interval(Some(value)).expect_err(value);
        assert!(
            error.to_string().contains("SID_SHUTDOWN_DRAIN_SECONDS"),
            "{error}"
        );
    }
}
