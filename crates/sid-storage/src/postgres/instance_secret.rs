// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's sealed shared secrets (`InstanceSecretStore`).

use async_trait::async_trait;
use sid_core::models::{InstanceSecret, MutationContext};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::InstanceSecretStore;

use super::PostgresBackend;

#[async_trait]
impl InstanceSecretStore for PostgresBackend {
    async fn get_instance_secret(&self, secret: InstanceSecret) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar("SELECT sealed FROM instance_secrets WHERE name = $1")
            .bind(secret.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("get instance secret: {e}")))
    }

    async fn insert_instance_secret(
        &self,
        secret: InstanceSecret,
        sealed: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let inserted = sqlx::query(
            "INSERT INTO instance_secrets (name, sealed) VALUES ($1, $2)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(secret.as_str())
        .bind(sealed)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("insert instance secret: {e}")))?
        .rows_affected()
            == 1;
        if inserted {
            Self::audit_in_tx(&mut tx, &format!("instance_secret:{secret}"), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(inserted)
    }
}
