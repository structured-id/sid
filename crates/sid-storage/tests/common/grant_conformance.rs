// SPDX-License-Identifier: AGPL-3.0-only
//! The grant store conformance harness of this crate's backends: owners are
//! Profiles, grants are bound to a registered resource.

use async_trait::async_trait;
use sid_core::models::{ProfileId, ResourceId};
use sid_plugin::conformance::grant_store::{GrantHarness, OwnerStatusHarness};
use sid_plugin::{CredentialStore, GrantStore, StorageBackend};

use super::{create_test_profile, test_audit};

pub struct ProfileGrants<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl GrantHarness for ProfileGrants<'_> {
    type Owner = ProfileId;

    fn store(&self) -> &dyn GrantStore<Owner = ProfileId> {
        self.0
    }

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.0
    }

    async fn owner(&self) -> ProfileId {
        let profile = create_test_profile("grant");
        self.0
            .create_profile(&profile, test_audit())
            .await
            .expect("a test profile");
        profile.id
    }

    async fn resource(&self) -> ResourceId {
        super::application::grant_resource(self.0).await
    }
}

#[async_trait]
impl OwnerStatusHarness for ProfileGrants<'_> {
    async fn suspend(&self, owner: &ProfileId) {
        let mut profile = self
            .0
            .get_profile(*owner)
            .await
            .unwrap()
            .expect("the owner's profile");
        profile.status = sid_core::models::ProfileStatus::Suspended;
        assert!(
            self.0.update_profile(&profile, test_audit()).await.unwrap(),
            "the suspension applies"
        );
    }
}
