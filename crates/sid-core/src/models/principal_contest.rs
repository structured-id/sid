// SPDX-License-Identifier: AGPL-3.0-only
//! Contestation check owed by a new login-handle binding.
//!
//! When a profile binds an identifier other profiles already hold, every
//! other holder is told the identifier is now contested
//! (`sid.principal.contested.v1`). The binding owes the check as durable work
//! in its own transaction; the check reads the committed bindings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::durable_work::{NewWork, WorkId, WorkKind};
use super::event::{Event, event_types};
use super::principal::PrincipalType;
use super::profile::ProfileId;

/// Work kind of the contestation check.
pub const PRINCIPAL_CONTEST_CHECK_KIND: &str = "principal.contest_check";

/// Attempts per check: storage being unavailable is the only failure.
pub const PRINCIPAL_CONTEST_CHECK_ATTEMPTS: u32 = 10;

/// Namespace of contestation check and event ids.
const CONTEST_NAMESPACE: Uuid = Uuid::from_u128(0x61c8_0f3a_d2b7_4e95_8c14_b3a9_e7d2_0f68);

/// The check owed after `new_holder` bound `value` of `principal_type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContestCheck {
    pub principal_type: PrincipalType,
    pub value: String,
    pub new_holder: ProfileId,
}

impl ContestCheck {
    pub fn new(
        principal_type: PrincipalType,
        value: impl Into<String>,
        new_holder: ProfileId,
    ) -> Self {
        Self {
            principal_type,
            value: value.into(),
            new_holder,
        }
    }

    fn identity(&self) -> String {
        format!(
            "{}:{}:{}",
            self.principal_type.as_str(),
            self.value,
            self.new_holder
        )
    }

    /// The durable work that runs the check. Its id follows from the binding,
    /// so binding the same identifier again owes nothing new.
    pub fn work(&self) -> NewWork {
        let kind = WorkKind::new(PRINCIPAL_CONTEST_CHECK_KIND).expect("the contest kind is valid");
        let payload = serde_json::to_vec(self).expect("a contest check serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = WorkId(Uuid::new_v5(&CONTEST_NAMESPACE, self.identity().as_bytes()));
        work.max_attempts = PRINCIPAL_CONTEST_CHECK_ATTEMPTS;
        work
    }

    /// The event telling `holder` that the identifier is contested. Its id
    /// follows from the binding and the holder, so a repeated check tells
    /// each holder once.
    pub fn contested_event(&self, holder: ProfileId) -> Event {
        let mut event = Event::new("sid-identity", event_types::PRINCIPAL_CONTESTED)
            .with_subject(format!("profile/{holder}"))
            .with_data(serde_json::json!({
                "profile_id": holder.to_string(),
                "principal_type": self.principal_type.as_str(),
                "principal_value": self.value,
                "new_claimer_profile_id": self.new_holder.to_string(),
            }));
        event.id = Uuid::new_v5(
            &CONTEST_NAMESPACE,
            format!("{}:{holder}", self.identity()).as_bytes(),
        )
        .to_string();
        event
    }
}

#[cfg(test)]
mod tests;
