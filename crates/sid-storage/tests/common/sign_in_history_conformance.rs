// SPDX-License-Identifier: AGPL-3.0-only
//! The sign-in history conformance harness of this crate's backends: owners
//! are Profiles, sign-ins their stored sessions.

use async_trait::async_trait;
use sid_core::models::ProfileId;
use sid_plugin::conformance::sign_in_history::SignInHistoryHarness;
use sid_plugin::{SignInHistoryStore, StorageBackend};
use uuid::Uuid;

use super::{create_test_profile, create_test_session, test_audit};

pub struct ProfileSignIns<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl SignInHistoryHarness for ProfileSignIns<'_> {
    type Owner = ProfileId;

    fn store(&self) -> &dyn SignInHistoryStore<Owner = ProfileId> {
        self.0
    }

    async fn owner(&self) -> ProfileId {
        let profile = create_test_profile("sign_in");
        self.0
            .create_profile(&profile, test_audit())
            .await
            .expect("a test profile");
        profile.id
    }

    async fn sign_in(&self, owner: &ProfileId, ip: &str, device: Option<Uuid>) {
        let mut session = create_test_session(*owner);
        session.ip_address = ip.to_string();
        session.device_id = device;
        self.0
            .create_session_atomic(&session, 0, None, test_audit())
            .await
            .expect("a stored session");
    }

    async fn begin_sign_in(&self, owner: &ProfileId, ip: &str, device: Option<Uuid>) {
        let mut pending = sid_core::models::Session::new_awaiting_second_factor(
            *owner,
            ip.to_string(),
            sid_core::models::AuthLevel::Basic,
            vec!["pwd".into()],
        );
        pending.device_id = device;
        self.0
            .create_session_atomic(&pending, 0, None, test_audit())
            .await
            .expect("a stored pending context");
    }
}
