// SPDX-License-Identifier: AGPL-3.0-only
//! Back-channel logout owed to a relying party for an ended session.
//!
//! It is durable work: delivered by a worker, retried, and kept as a failed
//! record (the dead letter) when every attempt fails.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::durable_work::{NewWork, WorkId, WorkKind};

/// Work kind delivering one back-channel logout.
pub const LOGOUT_DELIVERY_KIND: &str = "logout.backchannel";

/// Attempts per logout delivery: the first and five retries.
pub const LOGOUT_DELIVERY_ATTEMPTS: u32 = 6;

/// Namespace of logout delivery ids.
const LOGOUT_NAMESPACE: Uuid = Uuid::from_u128(0x7c1e_52a9_03d4_4f6b_8a2e_91c0_5d37_e684);

/// A back-channel logout owed to one relying party for one ended session,
/// committed with the revocation that ends the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutDelivery {
    pub client_id: String,
    pub profile_id: String,
    pub session_id: String,
}

impl LogoutDelivery {
    /// The logout an ended session owes, if it was issued to a client.
    pub fn for_ended_session(session: &super::session::Session) -> Option<Self> {
        session.client_id.as_ref().map(|client_id| Self {
            client_id: client_id.clone(),
            profile_id: session.profile_id.to_string(),
            session_id: session.id.to_string(),
        })
    }

    /// The durable work that delivers it. Its id follows from the session and
    /// client, so ending the same session again owes nothing new.
    pub fn work(&self) -> NewWork {
        let kind = WorkKind::new(LOGOUT_DELIVERY_KIND).expect("the logout kind is valid");
        let payload = serde_json::to_vec(self).expect("a logout delivery serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = WorkId(Uuid::new_v5(
            &LOGOUT_NAMESPACE,
            format!("{}:{}", self.session_id, self.client_id).as_bytes(),
        ));
        work.max_attempts = LOGOUT_DELIVERY_ATTEMPTS;
        work
    }
}

#[cfg(test)]
mod tests;
