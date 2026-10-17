// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in principal resolution of local Profiles (`PrincipalStore`).

use async_trait::async_trait;
use sid_core::Result as SidResult;
use sid_core::models::{PrincipalType, ProfileId};
use sid_plugin::PrincipalStore;
use sid_plugin::principal_store::resolve_profile_principal;

use super::PostgresBackend;

#[async_trait]
impl PrincipalStore for PostgresBackend {
    type Owner = ProfileId;

    async fn resolve_sign_in_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
        key_revision: Option<i64>,
    ) -> SidResult<Option<ProfileId>> {
        resolve_profile_principal(self, principal_type, value, key_revision).await
    }
}
