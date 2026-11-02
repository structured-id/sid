// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn kind_accepts_dotted_lowercase_names() {
    assert_eq!(
        WorkKind::new("logout.backchannel").unwrap().as_str(),
        "logout.backchannel"
    );
    assert!(WorkKind::new("notify.email_v2").is_ok());
}

#[test]
fn kind_refuses_other_names() {
    for bad in ["", "Notify", "a b", "x/y", &"a".repeat(65)] {
        assert!(WorkKind::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn state_round_trips_through_its_name() {
    for state in [
        WorkState::Pending,
        WorkState::Claimed,
        WorkState::Completed,
        WorkState::Failed,
        WorkState::Expired,
        WorkState::Cancelled,
    ] {
        assert_eq!(WorkState::parse(state.as_str()).unwrap(), state);
    }
    assert!(WorkState::parse("done").is_err());
}

fn snapshot(state: WorkState, attempts: u32) -> WorkSnapshot {
    let now = Utc::now();
    WorkSnapshot {
        record: WorkRecord {
            id: WorkId::new(),
            kind: WorkKind::new("logout.backchannel").unwrap(),
            state,
            attempts,
            max_attempts: 3,
            generation: 2,
            last_error: None,
            ambiguous: false,
            result: None,
            not_before: now,
            expires_at: None,
            created_at: now,
            updated_at: now,
        },
        payload: b"p".to_vec(),
    }
}

/// A claim does not travel to another store: claimed work with attempts
/// left is due again there, and one on its last attempt is failed, as an
/// abandoned last claim ends. Other states arrive as they were.
#[test]
fn claim_does_not_travel_between_stores() {
    assert_eq!(
        snapshot(WorkState::Claimed, 1).at_rest().state,
        WorkState::Pending
    );
    let last = snapshot(WorkState::Claimed, 3).at_rest();
    assert_eq!(last.state, WorkState::Failed);
    assert!(last.last_error.is_some());
    for state in [
        WorkState::Pending,
        WorkState::Completed,
        WorkState::Failed,
        WorkState::Expired,
        WorkState::Cancelled,
    ] {
        let rest = snapshot(state, 3).at_rest();
        assert_eq!(rest.state, state);
        assert!(rest.last_error.is_none());
    }
}
