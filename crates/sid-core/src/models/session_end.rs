// SPDX-License-Identifier: AGPL-3.0-only
//! What an ended session owes, committed with the deletion that ends it.

use super::backchannel_logout::LogoutDelivery;
use super::durable_work::NewWork;
use super::event::{Event, event_types};
use super::profile::ProfileId;
use super::revocation::RevocationReason;
use super::session::{Session, SessionId};
use uuid::Uuid;

/// Why sessions end and who ended them. Every session a storage deletion
/// ends owes its client a back-channel logout (when it was issued to one) and
/// a `sid.session.revoked.v1` event carrying this reason and actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub reason: RevocationReason,
    /// The actor that ended the sessions: a ProfileId or `system`.
    pub by: String,
}

impl SessionEnd {
    pub fn new(reason: RevocationReason, by: impl Into<String>) -> Self {
        Self {
            reason,
            by: by.into(),
        }
    }

    /// The work `ended` owes.
    pub fn owed_by(&self, ended: &Session) -> Vec<NewWork> {
        self.owed(ended.id, ended.profile_id, ended.client_id.as_deref())
    }

    /// The work one ended session owes.
    pub fn owed(
        &self,
        session_id: SessionId,
        profile_id: ProfileId,
        client_id: Option<&str>,
    ) -> Vec<NewWork> {
        let mut owed = Vec::with_capacity(2);
        if let Some(client_id) = client_id {
            owed.push(
                LogoutDelivery {
                    client_id: client_id.to_owned(),
                    profile_id: profile_id.to_string(),
                    session_id: session_id.to_string(),
                }
                .work(),
            );
        }
        owed.push(self.revoked_event(session_id, profile_id).relay());
        owed
    }

    /// The `sid.session.revoked.v1` event of one ended session. A session
    /// ends once, so its id follows from the session: ending it again owes
    /// the same event, stored and published once.
    pub fn revoked_event(&self, session_id: SessionId, profile_id: ProfileId) -> Event {
        let mut event = Event::new("sid-session", event_types::SESSION_REVOKED)
            .with_subject(format!("session/{session_id}"))
            .with_data(serde_json::json!({
                "session_id": session_id.to_string(),
                "profile_id": profile_id.to_string(),
                "reason": self.reason.as_str(),
                "by": self.by,
            }));
        event.id = Uuid::new_v5(
            &SESSION_REVOKED_NAMESPACE,
            session_id.to_string().as_bytes(),
        )
        .to_string();
        event
    }
}

/// Namespace of session-revoked event ids.
const SESSION_REVOKED_NAMESPACE: Uuid = Uuid::from_u128(0x3f9a_61d2_7b04_4c85_9e1f_a2d7_08b3_c5e9);

#[cfg(test)]
mod tests;
