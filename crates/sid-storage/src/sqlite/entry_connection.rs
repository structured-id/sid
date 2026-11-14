// SPDX-License-Identifier: AGPL-3.0-only
//! The registered entry connections in SQLite. Every write runs in the
//! single writer's transaction, so a change reads the stored connection and
//! writes over it as one step.

use async_trait::async_trait;
use sid_core::models::{
    ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, IssuerId, MutationContext,
    OrgId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::EncryptedField;
use sid_plugin::entry_connection::EntryConnectionStore;

use super::{SqliteBackend, col, dt_col, fmt_dt, insert_error};

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn chain(handle: EntryHandle) -> String {
    format!("entry_connection:{handle}")
}

fn connection_of(row: &sqlx::sqlite::SqliteRow) -> SidResult<EntryConnection> {
    let handle: Vec<u8> = col(row, "handle")?;
    let handle = handle
        .try_into()
        .map(EntryHandle::from_bytes)
        .map_err(|_| SidError::Storage("a stored entry connection handle".into()))?;
    let owner: String = col(row, "owner")?;
    let method: String = col(row, "credential_method")?;
    let credential: Vec<u8> = col(row, "credential")?;
    let credential = match method.as_str() {
        "client_secret_basic" => ClientCredential::SecretBasic(
            EncryptedField::from_bytes(&credential)
                .map_err(|e| SidError::Storage(format!("entry connection credential: {e}")))?,
        ),
        other => {
            return Err(SidError::Storage(format!(
                "stored entry connection credential method {other:?}"
            )));
        }
    };
    let revision: i64 = col(row, "revision")?;
    Ok(EntryConnection {
        handle,
        owner: owner
            .parse::<ConnectionOwner>()
            .map_err(SidError::Storage)?,
        name: col(row, "name")?,
        issuer: col(row, "issuer")?,
        source: col::<Option<OrgId>>(row, "source")?,
        recipient_issuer: col::<IssuerId>(row, "recipient_issuer")?,
        callback: col(row, "callback")?,
        client_id: col(row, "client_id")?,
        credential,
        enabled: col(row, "enabled")?,
        revision: u64::try_from(revision)
            .map_err(|_| SidError::Storage("a negative entry connection revision".into()))?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn credential_bytes(credential: &ClientCredential) -> Vec<u8> {
    match credential {
        ClientCredential::SecretBasic(sealed) => sealed.to_bytes(),
    }
}

fn stored_revision(revision: u64) -> SidResult<i64> {
    i64::try_from(revision)
        .map_err(|e| SidError::Validation(format!("entry connection revision: {e}")))
}

#[async_trait]
impl EntryConnectionStore for SqliteBackend {
    async fn entry_connection(&self, handle: EntryHandle) -> SidResult<Option<EntryConnection>> {
        sqlx::query("SELECT * FROM entry_connections WHERE handle = ?")
            .bind(handle.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read an entry connection"))?
            .as_ref()
            .map(connection_of)
            .transpose()
    }

    async fn entry_connection_of_issuer(&self, issuer: &str) -> SidResult<Option<EntryConnection>> {
        sqlx::query("SELECT * FROM entry_connections WHERE issuer = ?")
            .bind(issuer)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read an issuer's entry connection"))?
            .as_ref()
            .map(connection_of)
            .transpose()
    }

    async fn list_entry_connections(&self) -> SidResult<Vec<EntryConnection>> {
        sqlx::query("SELECT * FROM entry_connections ORDER BY created_at, handle")
            .fetch_all(&self.pool)
            .await
            .map_err(storage("list entry connections"))?
            .iter()
            .map(connection_of)
            .collect()
    }

    async fn create_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO entry_connections (handle, owner, name, issuer, source,
                 recipient_issuer, callback, client_id, credential_method, credential, enabled,
                 revision, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(connection.handle.as_bytes().as_slice())
        .bind(connection.owner.as_str())
        .bind(&connection.name)
        .bind(&connection.issuer)
        .bind(connection.source)
        .bind(connection.recipient_issuer)
        .bind(&connection.callback)
        .bind(&connection.client_id)
        .bind(connection.credential.method())
        .bind(credential_bytes(&connection.credential))
        .bind(connection.enabled)
        .bind(stored_revision(connection.revision)?)
        .bind(fmt_dt(&connection.created_at))
        .bind(fmt_dt(&connection.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("entry connection", e))?;
        Self::commit_mutation(tx, &chain(connection.handle), ctx).await
    }

    async fn update_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let stored = sqlx::query("SELECT * FROM entry_connections WHERE handle = ?")
            .bind(connection.handle.as_bytes().as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read an entry connection"))?
            .as_ref()
            .map(connection_of)
            .transpose()?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        if !stored.same_registration(connection) {
            return Err(SidError::Validation(
                "a change may not alter what identifies an entry connection".into(),
            ));
        }
        if stored.revision != connection.revision {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE entry_connections SET name = ?, client_id = ?, credential_method = ?,
                 credential = ?, enabled = ?, updated_at = ?, revision = revision + 1
             WHERE handle = ? AND revision = ?",
        )
        .bind(&connection.name)
        .bind(&connection.client_id)
        .bind(connection.credential.method())
        .bind(credential_bytes(&connection.credential))
        .bind(connection.enabled)
        .bind(fmt_dt(&connection.updated_at))
        .bind(connection.handle.as_bytes().as_slice())
        .bind(stored_revision(connection.revision)?)
        .execute(&mut *tx)
        .await
        .map_err(storage("change an entry connection"))?;
        // A sign-in decided through the connection before this change does
        // not commit after it (see `StorageBackend::update_entry_connection`).
        Self::advance_login_policy_epoch(&mut tx).await?;
        Self::commit_mutation(tx, &chain(connection.handle), ctx).await?;
        Ok(true)
    }

    async fn remove_entry_connection(
        &self,
        handle: EntryHandle,
        revision: u64,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let removed =
            sqlx::query("DELETE FROM entry_connections WHERE handle = ? AND revision = ?")
                .bind(handle.as_bytes().as_slice())
                .bind(stored_revision(revision)?)
                .execute(&mut *tx)
                .await
                .map_err(storage("remove an entry connection"))?
                .rows_affected()
                == 1;
        if removed {
            Self::advance_login_policy_epoch(&mut tx).await?;
            Self::commit_mutation(tx, &chain(handle), ctx).await?;
        }
        Ok(removed)
    }
}
