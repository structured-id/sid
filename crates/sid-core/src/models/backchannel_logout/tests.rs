// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::models::{ProfileId, Session};
use chrono::Utc;

fn session(client_id: Option<&str>) -> Session {
    let mut session = Session::new(
        ProfileId::generate(),
        "127.0.0.1".into(),
        Utc::now() + chrono::Duration::hours(1),
    );
    session.client_id = client_id.map(str::to_string);
    session
}

/// A session issued to a client owes that client a logout naming the
/// session; a first-party session owes none.
#[test]
fn test_only_client_sessions_owe_a_logout() {
    let ended = session(Some("rp"));
    let owed = LogoutDelivery::for_ended_session(&ended).unwrap();
    assert_eq!(owed.client_id, "rp");
    assert_eq!(owed.profile_id, ended.profile_id.to_string());
    assert_eq!(owed.session_id, ended.id.to_string());
    assert!(LogoutDelivery::for_ended_session(&session(None)).is_none());
}

/// Ending the same session again owes the same work (same id), so a retried
/// revocation stores nothing new; another session or client owes other work.
#[test]
fn test_work_id_follows_session_and_client() {
    let ended = session(Some("rp"));
    let owed = LogoutDelivery::for_ended_session(&ended).unwrap();
    assert_eq!(owed.work().id, owed.work().id);

    let mut other_client = owed.clone();
    other_client.client_id = "rp-2".into();
    assert_ne!(owed.work().id, other_client.work().id);
    let other_session = LogoutDelivery::for_ended_session(&session(Some("rp"))).unwrap();
    assert_ne!(owed.work().id, other_session.work().id);
}

/// The work carries the delivery and its attempt budget.
#[test]
fn test_work_carries_delivery_and_attempts() {
    let owed = LogoutDelivery::for_ended_session(&session(Some("rp"))).unwrap();
    let work = owed.work();
    assert_eq!(work.kind.as_str(), LOGOUT_DELIVERY_KIND);
    assert_eq!(work.max_attempts, LOGOUT_DELIVERY_ATTEMPTS);
    let back: LogoutDelivery = serde_json::from_slice(&work.payload).unwrap();
    assert_eq!(back, owed);
}
