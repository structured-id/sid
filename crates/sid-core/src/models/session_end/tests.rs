// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::models::{EVENT_RELAY_KIND, LOGOUT_DELIVERY_KIND};

fn end() -> SessionEnd {
    SessionEnd::new(RevocationReason::Admin, "admin-profile")
}

/// A session issued to a client owes the client's logout and the revoked
/// event; a first-party session owes only the event.
#[test]
fn test_client_session_owes_logout_and_event() {
    let (sid, pid) = (SessionId::generate(), ProfileId::generate());

    let owed = end().owed(sid, pid, Some("rp"));
    let kinds: Vec<&str> = owed.iter().map(|w| w.kind.as_str()).collect();
    assert_eq!(kinds, [LOGOUT_DELIVERY_KIND, EVENT_RELAY_KIND]);
    let logout: LogoutDelivery = serde_json::from_slice(&owed[0].payload).unwrap();
    assert_eq!(logout.client_id, "rp");
    assert_eq!(logout.session_id, sid.to_string());

    let first_party = end().owed(sid, pid, None);
    let kinds: Vec<&str> = first_party.iter().map(|w| w.kind.as_str()).collect();
    assert_eq!(kinds, [EVENT_RELAY_KIND]);
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
