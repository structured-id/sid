// SPDX-License-Identifier: AGPL-3.0-only
//! The registered entry connections in PostgreSQL. A change locks the
//! connection's row, so it reads the stored connection and writes over it
//! as one step; the issuer's uniqueness decides between two registrations
//! of one issuer.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::{
    ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, IssuerId, MutationContext,
    OrgId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::EncryptedField;
use sid_plugin::entry_connection::EntryConnectionStore;
use sqlx::Row;
use uuid::Uuid;

use super::{PostgresBackend, insert_error};

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn chain(handle: EntryHandle) -> String {
    format!("entry_connection:{handle}")
}

fn key(handle: EntryHandle) -> Uuid {
    Uuid::from_bytes(*handle.as_bytes())
}

fn connection_of(row: &sqlx::postgres::PgRow) -> SidResult<EntryConnection> {
    let column =
        |name: &'static str| move |e: sqlx::Error| SidError::Storage(format!("column {name}: {e}"));
    let handle: Uuid = row.try_get("handle").map_err(column("handle"))?;
    let owner: String = row.try_get("owner").map_err(column("owner"))?;
    let method: String = row
        .try_get("credential_method")
        .map_err(column("credential_method"))?;
    let credential: Vec<u8> = row.try_get("credential").map_err(column("credential"))?;
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
    let revision: i64 = row.try_get("revision").map_err(column("revision"))?;
    Ok(EntryConnection {
        handle: EntryHandle::from_bytes(*handle.as_bytes()),
        owner: owner
            .parse::<ConnectionOwner>()
            .map_err(SidError::Storage)?,
        name: row.try_get("name").map_err(column("name"))?,
        issuer: row.try_get("issuer").map_err(column("issuer"))?,
        source: row
            .try_get::<Option<OrgId>, _>("source")
            .map_err(column("source"))?,
        recipient_issuer: row
            .try_get::<IssuerId, _>("recipient_issuer")
            .map_err(column("recipient_issuer"))?,
        callback: row.try_get("callback").map_err(column("callback"))?,
        use_return: row.try_get("use_return").map_err(column("use_return"))?,
        client_id: row.try_get("client_id").map_err(column("client_id"))?,
        credential,
        enabled: row.try_get("enabled").map_err(column("enabled"))?,
        revision: u64::try_from(revision)
            .map_err(|_| SidError::Storage("a negative entry connection revision".into()))?,
        created_at: row
            .try_get::<DateTime<Utc>, _>("created_at")
            .map_err(column("created_at"))?,
        updated_at: row
            .try_get::<DateTime<Utc>, _>("updated_at")
            .map_err(column("updated_at"))?,
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
impl EntryConnectionStore for PostgresBackend {
    async fn entry_connection(&self, handle: EntryHandle) -> SidResult<Option<EntryConnection>> {
        sqlx::query("SELECT * FROM entry_connections WHERE handle = $1")
            .bind(key(handle))
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read an entry connection"))?
            .as_ref()
            .map(connection_of)
            .transpose()
    }

    async fn entry_connection_of_issuer(&self, issuer: &str) -> SidResult<Option<EntryConnection>> {
        sqlx::query("SELECT * FROM entry_connections WHERE issuer = $1")
            .bind(issuer)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read an issuer's entry connection"))?
            .as_ref()
            .map(connection_of)
            .transpose()
    }

    async fn list_entry_connections(&self) -> SidResult<Vec<EntryConnection>> {
        // By the handle's bytes, as every store orders them.
        sqlx::query("SELECT * FROM entry_connections ORDER BY created_at, uuid_send(handle)")
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
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        sqlx::query(
            "INSERT INTO entry_connections (handle, owner, name, issuer, source,
                 recipient_issuer, callback, use_return, client_id, credential_method,
                 credential, enabled, revision, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(key(connection.handle))
        .bind(connection.owner.as_str())
        .bind(&connection.name)
        .bind(&connection.issuer)
        .bind(connection.source)
        .bind(connection.recipient_issuer)
        .bind(&connection.callback)
        .bind(&connection.use_return)
        .bind(&connection.client_id)
        .bind(connection.credential.method())
        .bind(credential_bytes(&connection.credential))
        .bind(connection.enabled)
        .bind(stored_revision(connection.revision)?)
        .bind(connection.created_at)
        .bind(connection.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("entry connection", e))?;
        Self::audit_in_tx(&mut tx, &chain(connection.handle), ctx).await?;
        tx.commit().await.map_err(storage("commit"))
    }

    async fn update_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The row is held to the commit: a concurrent change waits and then
        // meets the moved revision.
        let stored = sqlx::query("SELECT * FROM entry_connections WHERE handle = $1 FOR UPDATE")
            .bind(key(connection.handle))
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
            "UPDATE entry_connections SET name = $2, client_id = $3, credential_method = $4,
                 credential = $5, enabled = $6, updated_at = $7, revision = revision + 1
             WHERE handle = $1 AND revision = $8",
        )
        .bind(key(connection.handle))
        .bind(&connection.name)
        .bind(&connection.client_id)
        .bind(connection.credential.method())
        .bind(credential_bytes(&connection.credential))
        .bind(connection.enabled)
        .bind(connection.updated_at)
        .bind(stored_revision(connection.revision)?)
        .execute(&mut *tx)
        .await
        .map_err(storage("change an entry connection"))?;
        // A sign-in decided through the connection before this change does
        // not commit after it (see `StorageBackend::update_entry_connection`).
        Self::advance_login_policy_epoch(&mut tx).await?;
        Self::audit_in_tx(&mut tx, &chain(connection.handle), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }

    async fn remove_entry_connection(
        &self,
        handle: EntryHandle,
        revision: u64,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let removed =
            sqlx::query("DELETE FROM entry_connections WHERE handle = $1 AND revision = $2")
                .bind(key(handle))
                .bind(stored_revision(revision)?)
                .execute(&mut *tx)
                .await
                .map_err(storage("remove an entry connection"))?
                .rows_affected()
                == 1;
        if removed {
            Self::advance_login_policy_epoch(&mut tx).await?;
            Self::audit_in_tx(&mut tx, &chain(handle), ctx).await?;
            tx.commit().await.map_err(storage("commit"))?;
        }
        Ok(removed)
    }
}
