// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's sealed shared secrets in CoordiNode: one node per
//! secret under a unique name, so of replicas storing one at once the first
//! commit wins and the others read its value.

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use sid_core::Result as SidResult;
use sid_core::models::{InstanceSecret, MutationContext};
use sid_plugin::InstanceSecretStore;

use super::{CoordinodeBackend, Decision, Params, finalize, get_bytes};

#[async_trait]
impl InstanceSecretStore for CoordinodeBackend {
    async fn get_instance_secret(&self, secret: InstanceSecret) -> SidResult<Option<Vec<u8>>> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (s:SidInstanceSecret) WHERE s.name = $name RETURN s.sealed AS sealed",
                Params::default().with("name", Value::String(secret.as_str().to_owned())),
            )?;
            Ok(Decision::Abandon(
                rows.first()
                    .map(|row| get_bytes(row, "sealed"))
                    .transpose()?,
            ))
        })
        .await
    }

    async fn insert_instance_secret(
        &self,
        secret: InstanceSecret,
        sealed: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let sealed = sealed.to_vec();
        self.transaction(move |tx| {
            let name = Value::String(secret.as_str().to_owned());
            let stored = tx.run(
                "MATCH (s:SidInstanceSecret) WHERE s.name = $name RETURN s.name AS name",
                Params::default().with("name", name.clone()),
            )?;
            // The first value is kept for ever: a later insert stores nothing.
            if !stored.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            super::enrollment::check_claim_allowed(tx, secret)?;
            // Concurrent first inserts create one unique name: all but one
            // commit conflict and run again, finding the stored value.
            tx.run(
                "CREATE (s:SidInstanceSecret {name: $name, sealed: $sealed})",
                Params::default()
                    .with("name", name)
                    .with("sealed", Value::Binary(sealed.clone())),
            )?;
            finalize(tx, &format!("instance_secret:{secret}"), audit.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}
