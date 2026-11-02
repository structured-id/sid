// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::models::{EVENT_RELAY_KIND, LOGOUT_DELIVERY_KIND, SESSION_REVOCATION_KIND};

fn end() -> SessionEnd {
    SessionEnd::new(RevocationReason::Admin, "admin-profile")
}

/// A session issued to a client owes the client's logout, the revoked event
/// and the revocation of its access tokens; a first-party session owes the
/// event and the revocation.
#[test]
fn test_client_session_owes_logout_and_event() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());

    let owed = end().owed(sid, pid, Some("rp"));
    let kinds: Vec<&str> = owed.iter().map(|w| w.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            LOGOUT_DELIVERY_KIND,
            EVENT_RELAY_KIND,
            SESSION_REVOCATION_KIND
        ]
    );
    let logout: LogoutDelivery = serde_json::from_slice(&owed[0].payload).unwrap();
    assert_eq!(logout.client_id, "rp");
    assert_eq!(logout.session_id, sid.to_string());

    let first_party = end().owed(sid, pid, None);
    let kinds: Vec<&str> = first_party.iter().map(|w| w.kind.as_str()).collect();
    assert_eq!(kinds, [EVENT_RELAY_KIND, SESSION_REVOCATION_KIND]);
}

/// Every ended session owes the revocation of its access tokens in every
/// process, committed with its end: a crash before the revocation is
/// published no longer leaves its tokens live until they expire. Ending it
/// again owes the same work (same id).
#[test]
fn test_ended_session_owes_its_token_revocation() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());

    let owed = end().owed(sid, pid, None);
    let revocation = owed
        .iter()
        .find(|w| w.kind.as_str() == SESSION_REVOCATION_KIND)
        .expect("the token revocation is owed");
    let payload: SessionRevocation = serde_json::from_slice(&revocation.payload).unwrap();
    assert_eq!(payload.session_id, sid.to_string());

    let again = SessionEnd::new(RevocationReason::UserRequested, "system").owed(sid, pid, None);
    assert!(again.iter().any(|w| w.id == revocation.id));
    let other = end().owed(SessionId::generate(), pid, None);
    assert!(other.iter().all(|w| w.id != revocation.id));
}

/// A session ends once: ending it again owes the same event work (same id),
/// whatever the reason, while another session owes other work.
#[test]
fn test_revoked_event_id_follows_session() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());
    let again = SessionEnd::new(RevocationReason::UserRequested, "system");

    let first = end().owed(sid, pid, None).remove(0);
    assert_eq!(first.id, again.owed(sid, pid, None).remove(0).id);
    let other = end().owed(SessionId::generate(), pid, None).remove(0);
    assert_ne!(first.id, other.id);
}

/// A session whose owner is not a local Profile owes its lifecycle fact and
/// the revocation of its tokens, the same work items a Profile's session
/// owes for them.
#[test]
fn test_lifecycle_owed_work_includes_the_revocation() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());
    let owed = end().owed_by_lifecycle(sid);
    let kinds: Vec<&str> = owed.iter().map(|w| w.kind.as_str()).collect();
    assert_eq!(kinds, [EVENT_RELAY_KIND, SESSION_REVOCATION_KIND]);
    let profile = end().owed(sid, pid, None);
    assert_eq!(owed[0].id, profile[0].id);
    assert_eq!(owed[1].id, profile[1].id);
}

/// The lifecycle fact of a session whose owner is not a local Profile names
/// the session, the reason and the actor category, and carries no owner: the
/// same event id as the Profile-enriched form, without its `profile_id`.
#[test]
fn test_lifecycle_event_names_no_owner() {
    let sid = SessionId::generate();
    let end = SessionEnd::new(RevocationReason::UserRequested, "self");

    let work = end.lifecycle_event(sid).relay();
    let event: Event = serde_json::from_slice(&work.payload).unwrap();

    assert_eq!(event.event_type, event_types::SESSION_REVOKED);
    assert_eq!(event.data["session_id"], sid.to_string());
    assert_eq!(event.data["reason"], "user_requested");
    assert_eq!(event.data["by"], "self");
    assert!(event.data.get("profile_id").is_none());
    assert_eq!(work.id, end.owed(sid, ProfileId::generate(), None)[0].id);
}

/// The relayed event is `sid.session.revoked.v1` naming the session, its
/// profile, the reason and the actor, as the event catalog defines it.
#[test]
fn test_revoked_event_carries_reason_and_actor() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());

    let owed = end().owed(sid, pid, None);
    let event: Event = serde_json::from_slice(&owed[0].payload).unwrap();
    assert_eq!(event.event_type, event_types::SESSION_REVOKED);
    assert_eq!(event.subject.as_deref(), Some(&*format!("session/{sid}")));
    assert_eq!(event.data["session_id"], sid.to_string());
    assert_eq!(event.data["profile_id"], pid.to_string());
    assert_eq!(event.data["reason"], "admin");
    assert_eq!(event.data["by"], "admin-profile");
}
