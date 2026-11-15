// SPDX-License-Identifier: AGPL-3.0-only
//! The registered entry connections in CoordiNode: one node per connection,
//! unique by its handle and by its issuer. A change holds the node it read,
//! so a concurrent change runs again on what the first one committed.

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, IssuerId, MutationContext,
    OrgId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::EncryptedField;
use sid_plugin::entry_connection::EntryConnectionStore;
use uuid::Uuid;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_bytes, get_id,
    get_int, get_opt_id, get_opt_text, get_parsed, get_text, get_time, hold_first, opt_text,
    opt_uuid, stored_time, time, uuid,
};

const FIELDS: &str = "c.handle AS handle, c.owner AS owner, c.name AS name, c.issuer AS issuer,
    c.source AS source, c.recipient_issuer AS recipient_issuer, c.callback AS callback,
    c.use_return AS use_return, c.client_id AS client_id, c.credential_method AS credential_method,
    c.credential AS credential, c.enabled AS enabled, c.revision AS revision,
    c.created_at AS created_at, c.updated_at AS updated_at";

fn chain(handle: EntryHandle) -> String {
    format!("entry_connection:{handle}")
}

fn handle_value(handle: EntryHandle) -> Value {
    Value::Binary(handle.as_bytes().to_vec())
}

fn connection_of(row: &Row) -> SidResult<EntryConnection> {
    let handle = get_bytes(row, "handle")?
        .try_into()
        .map(EntryHandle::from_bytes)
        .map_err(|_| SidError::Storage("a stored entry connection handle".into()))?;
    let method = get_text(row, "credential_method")?;
    let credential = match method.as_str() {
        "client_secret_basic" => ClientCredential::SecretBasic(
            EncryptedField::from_bytes(&get_bytes(row, "credential")?)
                .map_err(|e| SidError::Storage(format!("entry connection credential: {e}")))?,
        ),
        other => {
            return Err(SidError::Storage(format!(
                "stored entry connection credential method {other:?}"
            )));
        }
    };
    Ok(EntryConnection {
        handle,
        owner: get_parsed::<ConnectionOwner>(row, "owner")?,
        name: get_text(row, "name")?,
        issuer: get_text(row, "issuer")?,
        source: get_opt_id::<OrgId>(row, "source")?,
        recipient_issuer: get_id::<IssuerId>(row, "recipient_issuer")?,
        callback: get_text(row, "callback")?,
        use_return: get_opt_text(row, "use_return")?,
        client_id: get_text(row, "client_id")?,
        credential,
        enabled: get_bool(row, "enabled")?,
        revision: u64::try_from(get_int(row, "revision")?)
            .map_err(|_| SidError::Storage("a negative entry connection revision".into()))?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// What a change writes: the fields that may change.
fn changed(connection: &EntryConnection) -> Params {
    let ClientCredential::SecretBasic(sealed) = &connection.credential;
    Params::default()
        .with("handle", handle_value(connection.handle))
        .with("name", Value::String(connection.name.clone()))
        .with("client_id", Value::String(connection.client_id.clone()))
        .with(
            "credential_method",
            Value::String(connection.credential.method().to_owned()),
        )
        .with("credential", Value::Binary(sealed.to_bytes()))
        .with("enabled", Value::Bool(connection.enabled))
        .with("updated_at", time(connection.updated_at))
}

fn found(
    tx: &Statements<'_>,
    handle: EntryHandle,
) -> SidResult<Option<(Vec<Row>, EntryConnection)>> {
    let rows = tx.run(
        &format!(
            "MATCH (c:SidEntryConnection) WHERE c.handle = $handle
             RETURN id(c) AS node, {FIELDS}"
        ),
        Params::default().with("handle", handle_value(handle)),
    )?;
    match rows.first() {
        Some(row) => {
            let connection = connection_of(row)?;
            Ok(Some((rows, connection)))
        }
        None => Ok(None),
    }
}

#[async_trait]
impl EntryConnectionStore for CoordinodeBackend {
    async fn entry_connection(&self, handle: EntryHandle) -> SidResult<Option<EntryConnection>> {
        self.read(move |tx| Ok(found(tx, handle)?.map(|(_, connection)| connection)))
            .await
    }

    async fn entry_connection_of_issuer(&self, issuer: &str) -> SidResult<Option<EntryConnection>> {
        let issuer = issuer.to_owned();
        self.read(move |tx| {
            tx.run(
                &format!("MATCH (c:SidEntryConnection) WHERE c.issuer = $issuer RETURN {FIELDS}"),
                Params::default().with("issuer", Value::String(issuer.clone())),
            )?
            .first()
            .map(connection_of)
            .transpose()
        })
        .await
    }

    async fn list_entry_connections(&self) -> SidResult<Vec<EntryConnection>> {
        let mut connections = self
            .read(|tx| {
                tx.run(
                    &format!("MATCH (c:SidEntryConnection) RETURN {FIELDS}"),
                    Params::default(),
                )?
                .iter()
                .map(connection_of)
                .collect::<SidResult<Vec<_>>>()
            })
            .await?;
        connections.sort_by_key(|c| (c.created_at, c.handle));
        Ok(connections)
    }

    async fn create_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let connection = connection.clone();
        self.mutate(chain(connection.handle), ctx, move |tx| {
            // Looked for first, so a held handle or issuer is a conflict and
            // not a retry; one created meanwhile collides on its unique key,
            // runs again and is then found here.
            let taken = tx.run(
                "MATCH (c:SidEntryConnection)
                 WHERE c.handle = $handle OR c.issuer = $issuer RETURN c.handle AS handle",
                Params::default()
                    .with("handle", handle_value(connection.handle))
                    .with("issuer", Value::String(connection.issuer.clone())),
            )?;
            if !taken.is_empty() {
                return Err(SidError::Conflict("entry connection already exists".into()));
            }
            let source: Option<Uuid> = connection.source.map(Into::into);
            tx.create_absent(
                "CREATE (c:SidEntryConnection {handle: $handle, owner: $owner, name: $name,
                     issuer: $issuer, source: $source, recipient_issuer: $recipient_issuer,
                     callback: $callback, use_return: $use_return, client_id: $client_id,
                     credential_method: $credential_method, credential: $credential,
                     enabled: $enabled, revision: $revision, created_at: $created_at,
                     updated_at: $updated_at})",
                changed(&connection)
                    .with("owner", Value::String(connection.owner.as_str().to_owned()))
                    .with("issuer", Value::String(connection.issuer.clone()))
                    .with("source", opt_uuid(source.as_ref()))
                    .with(
                        "recipient_issuer",
                        uuid(&Uuid::from(connection.recipient_issuer)),
                    )
                    .with("callback", Value::String(connection.callback.clone()))
                    .with("use_return", opt_text(connection.use_return.as_deref()))
                    .with(
                        "revision",
                        Value::Int(i64::try_from(connection.revision).map_err(|e| {
                            SidError::Validation(format!("entry connection revision: {e}"))
                        })?),
                    )
                    .with("created_at", time(connection.created_at)),
            )?;
            Ok(())
        })
        .await
    }

    async fn update_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let connection = connection.clone();
        self.transaction(move |tx| {
            let Some((rows, stored)) = found(tx, connection.handle)? else {
                return Ok(Decision::Abandon(false));
            };
            // Times are compared as the store keeps them.
            let mut asked = connection.clone();
            asked.created_at = stored_time(asked.created_at);
            if !stored.same_registration(&asked) {
                return Err(SidError::Validation(
                    "a change may not alter what identifies an entry connection".into(),
                ));
            }
            if stored.revision != connection.revision {
                return Ok(Decision::Abandon(false));
            }
            // Held for the commit: a change committed meanwhile makes this
            // one run again and meet the moved revision.
            if !hold_first(tx, &rows)? {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (c:SidEntryConnection) WHERE c.handle = $handle
                 SET c.name = $name, c.client_id = $client_id,
                     c.credential_method = $credential_method, c.credential = $credential,
                     c.enabled = $enabled, c.updated_at = $updated_at,
                     c.revision = c.revision + 1",
                changed(&connection),
            )?;
            // A sign-in decided through the connection before this change
            // does not commit after it.
            super::login_policy::advance_epoch(tx)?;
            finalize(tx, &chain(connection.handle), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    async fn remove_entry_connection(
        &self,
        handle: EntryHandle,
        revision: u64,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let Some((rows, stored)) = found(tx, handle)? else {
                return Ok(Decision::Abandon(false));
            };
            if stored.revision != revision || !hold_first(tx, &rows)? {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (c:SidEntryConnection) WHERE c.handle = $handle DELETE c",
                Params::default().with("handle", handle_value(handle)),
            )?;
            super::login_policy::advance_epoch(tx)?;
            finalize(tx, &chain(handle), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}
