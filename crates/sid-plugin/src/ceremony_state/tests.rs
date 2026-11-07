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
