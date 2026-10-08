// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::LOGOUT_DELIVERY_ATTEMPTS;

/// Retries back off exponentially from one second: 1 s, 2 s, 4 s, 8 s, 16 s.
#[test]
fn test_retry_schedule_is_exponential_from_one_second() {
    let delays: Vec<u64> = (1..=5).map(|a| LOGOUT_RETRY.after(a).as_secs()).collect();
    assert_eq!(delays, [1, 2, 4, 8, 16]);
}

/// The schedule has one delay per retry: the initial attempt plus five
/// retries is the attempt budget the owed work is stored with, so the last
/// attempt ends the work instead of waiting on a delay that never runs.
#[test]
fn test_attempt_budget_is_initial_plus_five_retries() {
    assert_eq!(LOGOUT_DELIVERY_ATTEMPTS, 6);
    assert_eq!(
        LOGOUT_RETRY.after(LOGOUT_DELIVERY_ATTEMPTS - 1).as_secs(),
        16,
        "the fifth retry is the last scheduled one"
    );
}
