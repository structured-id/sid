// SPDX-License-Identifier: AGPL-3.0-only
//! The grant store conformance harness of this crate's backends: owners are
//! Profiles, grants are bound to a registered resource.

use async_trait::async_trait;
use sid_core::models::{ProfileId, ResourceId};
use sid_plugin::conformance::grant_store::GrantHarness;
use sid_plugin::{CredentialStore, GrantStore, StorageBackend};

use super::{create_test_profile, test_audit};

/// The database a host's policy write advances the login-policy epoch in.
/// Each integration binary constructs only its own backend's variant.
pub enum PolicyDatabase<'a> {
    #[allow(dead_code)]
    Postgres(&'a sqlx::PgPool),
    #[cfg(feature = "storage-sqlite")]
    #[allow(dead_code)]
    Sqlite(&'a sqlx::SqlitePool),
}

pub struct ProfileGrants<'a> {
    pub store: &'a dyn StorageBackend,
    pub policy: PolicyDatabase<'a>,
}

impl<'a> ProfileGrants<'a> {
    #[allow(dead_code)]
    pub fn postgres(backend: &'a sid_storage::PostgresBackend) -> Self {
        Self {
            store: backend,
            policy: PolicyDatabase::Postgres(backend.pool()),
        }
    }

    #[cfg(feature = "storage-sqlite")]
    #[allow(dead_code)]
    pub fn sqlite(backend: &'a sid_storage::sqlite::SqliteBackend) -> Self {
        Self {
            store: backend,
            policy: PolicyDatabase::Sqlite(backend.pool()),
        }
    }
}

#[async_trait]
impl GrantHarness for ProfileGrants<'_> {
    type Owner = ProfileId;

    fn store(&self) -> &dyn GrantStore<Owner = ProfileId> {
        self.store
    }

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.store
    }

    async fn owner(&self) -> ProfileId {
        let profile = create_test_profile("grant");
        self.store
            .create_profile(&profile, test_audit())
            .await
            .expect("a test profile");
        profile.id
    }

    async fn resource(&self) -> ResourceId {
        super::application::grant_resource(self.store).await
    }

    async fn advance_login_policy(&self) -> i64 {
        match &self.policy {
            PolicyDatabase::Postgres(pool) => {
                let mut tx = pool.begin().await.expect("a policy write");
                let epoch = sid_storage::PostgresBackend::advance_login_policy_epoch(&mut tx)
                    .await
                    .expect("the epoch advances");
                tx.commit().await.expect("the policy write commits");
                epoch
            }
            #[cfg(feature = "storage-sqlite")]
            PolicyDatabase::Sqlite(pool) => {
                let mut tx = sid_storage::sqlite::SqliteBackend::begin_write_on(pool)
                    .await
                    .expect("a policy write");
                let epoch = sid_storage::sqlite::SqliteBackend::advance_login_policy_epoch(&mut tx)
                    .await
                    .expect("the epoch advances");
                tx.commit().await.expect("the policy write commits");
                epoch
            }
        }
    }
}
