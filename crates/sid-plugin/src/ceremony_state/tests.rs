//! The in-process store owes every scenario the shared stores do.

use super::InProcessCeremonyState;
use crate::conformance::ceremony_state as scenario;

macro_rules! in_process {
    ($($name:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $name() {
            scenario::$name(&InProcessCeremonyState::new()).await;
        }
    )*};
}

in_process!(
    state_is_taken_once,
    concurrent_takers_get_it_once,
    expired_state_is_refused_at_use,
    put_replaces,
    replace_applies_only_to_what_was_read,
    concurrent_replacements_apply_once,
    key_is_admitted_once,
    concurrent_admissions_succeed_once,
    events_count_within_their_window,
    concurrent_events_are_counted_once,
    counts_are_read_and_cleared,
    admission_is_confirmed_only_to_its_holder,
    concurrent_holders_admit_once,
    records_move_with_their_deadlines,
);

/// Records are kept only while their deadline is after the cutoff: one that
/// ends at it or before is dropped from both collections.
#[test]
fn records_are_kept_while_live_at_the_cutoff() {
    use super::{CeremonyCount, CeremonyEntry, CeremonyRecords};
    let at = chrono::Utc::now();
    let state = |name: &str, offset: i64| CeremonyEntry {
        namespace: "ns".into(),
        key: name.into(),
        value: Vec::new(),
        expires_at: at + chrono::Duration::seconds(offset),
    };
    let count = |name: &str, offset: i64| CeremonyCount {
        namespace: "ns".into(),
        key: name.into(),
        count: 1,
        window_ends: at + chrono::Duration::seconds(offset),
    };
    let mut records = CeremonyRecords {
        states: vec![state("live", 1), state("ending", 0), state("ended", -1)],
        counts: vec![count("live", 1), count("ending", 0), count("ended", -1)],
    };
    records.retain_live_at(at);
    assert_eq!(records.states, vec![state("live", 1)]);
    assert_eq!(records.counts, vec![count("live", 1)]);
}
