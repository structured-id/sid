// SPDX-License-Identifier: AGPL-3.0-only
//! The principal store conformance harness of this crate's backends: owners
//! are Profiles, principals their email claims.

use async_trait::async_trait;
use sid_core::models::{Principal, PrincipalType, ProfileId};
use sid_plugin::conformance::principal_store::{PrincipalHarness, SignInPrincipal};
use sid_plugin::{PrincipalStore, StorageBackend};
use uuid::Uuid;

use super::{create_test_profile, test_audit};

pub struct ProfilePrincipals<'a>(pub &'a dyn StorageBackend);

#[async_trait]
impl PrincipalHarness for ProfilePrincipals<'_> {
    type Owner = ProfileId;

    fn store(&self) -> &dyn PrincipalStore<Owner = ProfileId> {
        self.0
    }

    async fn owner(&self) -> ProfileId {
        let profile = create_test_profile("principal");
        self.0
            .create_profile(&profile, test_audit())
            .await
            .expect("a test profile");
        profile.id
    }

    async fn hold(&self, owner: &ProfileId) -> SignInPrincipal {
        let value = format!("signin{}@sid.example.com", Uuid::now_v7().simple());
        self.0
            .save_principal(&Principal::new_email(*owner, &value), test_audit())
            .await
            .expect("a held principal");
        let entity = self
            .0
            .get_principal_by_value(PrincipalType::Email, &value)
            .await
            .unwrap()
            .expect("the principal is stored");
        SignInPrincipal {
            principal_type: PrincipalType::Email,
            value,
            key_revision: entity.email_policy_revision,
        }
    }

    async fn release(&self, owner: &ProfileId, principal: &SignInPrincipal) {
        let entity = self
            .0
            .get_principal_by_value(principal.principal_type, &principal.value)
            .await
            .unwrap()
            .expect("the principal is stored");
        assert!(
            self.0
                .unbind_principal(entity.id, *owner, test_audit())
                .await
                .unwrap()
        );
    }
}
