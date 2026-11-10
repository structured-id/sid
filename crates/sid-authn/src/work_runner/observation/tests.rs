// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// A wait is measured from the store's due time; a store clock ahead of this
/// process gives zero, not a negative or panicking duration.
#[test]
fn elapsed_is_zero_when_the_store_clock_is_ahead() {
    let now = Utc::now();
    assert_eq!(
        elapsed(now + chrono::Duration::seconds(5), now),
        Duration::ZERO
    );
    assert_eq!(
        elapsed(now - chrono::Duration::milliseconds(1500), now),
        Duration::from_millis(1500)
    );
}

/// Each outcome has its own label at its own index, so a recorded outcome
/// never lands under another's label.
#[test]
fn every_outcome_has_its_own_label() {
    let labels: Vec<&str> = Settled::ALL.iter().map(|s| s.as_str()).collect();
    let mut distinct = labels.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), labels.len(), "{labels:?}");
    for (i, settled) in Settled::ALL.iter().enumerate() {
        assert_eq!(settled.index(), i, "{settled:?}");
    }
}
