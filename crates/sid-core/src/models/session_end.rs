// SPDX-License-Identifier: AGPL-3.0-only
//! What an ended session owes, committed with the deletion that ends it.

use super::backchannel_logout::LogoutDelivery;
use super::durable_work::{NewWork, WorkId, WorkKind};
use super::event::{Event, event_types};
use super::profile::ProfileId;
use super::revocation::RevocationReason;
use super::session::{Session, SessionId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Work kind revoking one ended session's access tokens in every process.
pub const SESSION_REVOCATION_KIND: &str = "session.revocation";

/// How long an ended session's access tokens can still be valid: the longest
/// access token lifetime a deployment may configure (sixty minutes). Its
/// revocation is retried that long, then is moot and expires.
pub const SESSION_REVOCATION_WINDOW: chrono::Duration = chrono::Duration::minutes(60);

/// Attempts of one revocation: enough that its handler's schedule, repeating
/// its last delay, keeps retrying through [`SESSION_REVOCATION_WINDOW`].
pub const SESSION_REVOCATION_ATTEMPTS: u32 = 130;

/// Namespace of session revocation work ids.
const SESSION_REVOCATION_NAMESPACE: Uuid =
    Uuid::from_u128(0x5b2d_8e17_c643_4a09_b1f8_6e3a_d2c4_7f15);

/// The revocation of one ended session's access tokens owed to every
/// process, committed with the deletion that ends the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRevocation {
    pub session_id: String,
}

impl SessionRevocation {
    /// The durable work that publishes it, retried while a token of the
    /// session can live. Its id follows from the session, so ending the same
    /// session again owes nothing new.
    pub fn work(&self) -> NewWork {
        let kind = WorkKind::new(SESSION_REVOCATION_KIND).expect("the revocation kind is valid");
        let payload = serde_json::to_vec(self).expect("a session revocation serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = WorkId(Uuid::new_v5(
            &SESSION_REVOCATION_NAMESPACE,
            self.session_id.as_bytes(),
        ));
        work.max_attempts = SESSION_REVOCATION_ATTEMPTS;
        work.expires_at = Some(chrono::Utc::now() + SESSION_REVOCATION_WINDOW);
        work
    }
}

/// Why sessions end and who ended them. Every session a storage deletion
/// ends owes its client a back-channel logout (when it was issued to one), a
/// `sid.session.revoked.v1` event carrying this reason and actor, and the
/// revocation of its access tokens in every process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub reason: RevocationReason,
    /// The actor that ended the sessions as the event names it: a local
    /// ProfileId, `system`, or the actor's category where its identity stays
    /// in the owning audit.
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
        let mut owed = Vec::with_capacity(3);
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
        owed.push(
            SessionRevocation {
                session_id: session_id.to_string(),
            }
            .work(),
        );
        owed
    }

    /// The `sid.session.revoked.v1` event of one ended session: the lifecycle
    /// fact, which names no owner. A session ends once, so its id follows
    /// from the session: ending it again owes the same event, stored and
    /// published once.
    pub fn lifecycle_event(&self, session_id: SessionId) -> Event {
        let mut event = Event::new("sid-session", event_types::SESSION_REVOKED)
            .with_subject(format!("session/{session_id}"))
            .with_data(serde_json::json!({
                "session_id": session_id.to_string(),
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

    /// The lifecycle event of a local Profile's ended session, enriched with
    /// that Profile.
    pub fn revoked_event(&self, session_id: SessionId, profile_id: ProfileId) -> Event {
        let mut event = self.lifecycle_event(session_id);
        event.data["profile_id"] = serde_json::Value::String(profile_id.to_string());
        event
    }
}

/// Namespace of session-revoked event ids.
const SESSION_REVOKED_NAMESPACE: Uuid = Uuid::from_u128(0x3f9a_61d2_7b04_4c85_9e1f_a2d7_08b3_c5e9);

#[cfg(test)]
mod tests;
