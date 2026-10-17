// SPDX-License-Identifier: AGPL-3.0-only
//! The credential store conformance harness of this crate's backends: owners
//! are Profiles.

use async_trait::async_trait;
use sid_core::models::ProfileId;
use sid_plugin::conformance::credential_store::CredentialHarness;
use sid_plugin::{CredentialStore, StorageBackend};

use super::{create_test_profile, test_audit};

pub struct ProfileCredentials<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl CredentialHarness for ProfileCredentials<'_> {
    type Owner = ProfileId;

    fn store(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.0
    }

    async fn owner(&self) -> ProfileId {
        let profile = create_test_profile("credential");
        self.0
            .create_profile(&profile, test_audit())
            .await
            .expect("a test profile");
        profile.id
    }

    fn missing_owner(&self) -> ProfileId {
        ProfileId::generate()
    }
}
