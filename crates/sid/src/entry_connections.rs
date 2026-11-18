// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's entry connections: its registrations as a client at
//! the installations whose identities sign in here.
//!
//! In plain words: an administrator writes down "we are registered at that
//! issuer as this client, with this secret", and from then on the sign-in
//! page can send a browser there. Nothing here decides who is let in: that
//! is the login settings' and then the ordinary permissions' decision.
//!
//! Two writers share these records and neither has the other's authority.
//! An administrator manages the connections to outside issuers. The
//! installation's provisioning sets the one authority its own Profiles sign
//! in through; an administrator's command reads it and never creates,
//! changes or removes it, and provisioning never takes over a connection an
//! administrator registered.

use std::sync::Arc;

use prost::Message;
use secrecy::SecretString;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::federated_entry::TrustedIssuer;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::operation::{KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::entry_connection::{
    CALLBACK, MAX_NAME, credential_context, is_issuer_identifier, is_use_return,
};
use sid_core::models::{
    AuditEntry, ClientCredential, ConnectionOwner, EntryConnection, EntryHandle, MutationContext,
    OidcIssuer, OperationCompletion, OperationContext, OperationKey, OrgId,
};
use sid_keys::KeyManager;
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::federation::entry_connection_service as keyed;
use sid_proto::sid::v1::{
    self, CreateEntryConnectionRequest, ListEntryConnectionsResponse,
    ListSignInConnectionsResponse, RemoveEntryConnectionRequest, SignInConnection,
    UpdateEntryConnectionRequest,
};
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

/// The namespace of the record that the provisioned authority of an issuer
/// was set.
const PROVISIONED: &str = "entry-connection";

/// The command a provisioning writes its connection with, as its record
/// names it.
const PROVISION: &str = "entry_connection.provision";

/// Why an entry connection operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EntryConnectionError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a credential that cannot be sealed or
    /// opened); its cause is in the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("no entry connection {0}")]
    NotFound(EntryHandle),
    /// The handle names no issuer of this installation.
    #[error("no issuer {0} in this installation")]
    UnknownIssuer(String),
    /// The issuer has a connection already: one issuer has one connection.
    #[error("the issuer has an entry connection already")]
    IssuerTaken,
    /// The connection is the installation's provisioning's: an
    /// administrator's command does not write it.
    #[error("the entry connection is set by the installation's provisioning")]
    Provisioned,
    /// The connection changed since the revision the command names.
    #[error("changed concurrently")]
    ChangedConcurrently,
    /// The installation issuer already has a provisioned authority, and it
    /// is another issuer: an established one is never replaced.
    #[error("another issuer is the provisioned authority already")]
    Established,
}

impl From<FieldError> for EntryConnectionError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> EntryConnectionError {
    tracing::error!(operation, error = %cause, "internal failure");
    EntryConnectionError::Internal
}

fn invalid(field: &'static str, reason: impl Into<String>) -> EntryConnectionError {
    EntryConnectionError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// `name` when it is a display name: not empty, at most [`MAX_NAME`]
/// characters.
fn display_name(name: &str) -> Result<(), EntryConnectionError> {
    if name.is_empty() {
        return Err(EntryConnectionError::MissingField("name"));
    }
    if name.chars().count() > MAX_NAME {
        return Err(invalid("name", format!("at most {MAX_NAME} characters")));
    }
    Ok(())
}

fn handle_of(text: &str) -> Result<EntryHandle, EntryConnectionError> {
    EntryHandle::parse(text).map_err(|e| invalid("handle", e.to_string()))
}

/// The exact redirect URI every connection of `issuer` registers.
fn callback(issuer: &OidcIssuer) -> String {
    format!("{}{CALLBACK}", issuer.canonical_url)
}

/// What the installation's provisioning names of the authority its own
/// Profiles sign in through.
#[derive(Debug, Clone)]
pub struct Provisioned {
    /// How the sign-in page names it.
    pub name: String,
    /// The exact issuer identifier.
    pub issuer: String,
    /// The organization whose installation issues there, when it is one's.
    pub source: Option<OrgId>,
    /// This installation's client id at the issuer.
    pub client_id: String,
    /// The client secret registered for it.
    pub client_secret: SecretString,
    /// Where a holder returns to the authority's side after authenticating
    /// here for a use that side coordinates, as the authority computed it;
    /// none when it coordinates no such use.
    pub use_return: Option<String>,
}

/// The entry connections of one installation.
pub struct EntryConnections {
    storage: Arc<dyn StorageBackend>,
    /// Seals and opens the connections' client credentials.
    keys: Arc<dyn KeyManager>,
    /// The installation's issuers, by handle and by route.
    issuers: Arc<IssuerRegistry>,
}

impl EntryConnections {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        keys: Arc<dyn KeyManager>,
        issuers: Arc<IssuerRegistry>,
    ) -> Self {
        Self {
            storage,
            keys,
            issuers,
        }
    }

    async fn stored(&self, handle: EntryHandle) -> Result<EntryConnection, EntryConnectionError> {
        self.storage
            .entry_connection(handle)
            .await?
            .ok_or(EntryConnectionError::NotFound(handle))
    }

    /// The installation issuer `handle` names (the empty handle naming the
    /// root-addressed base issuer).
    async fn issuer(&self, handle: &str) -> Result<OidcIssuer, EntryConnectionError> {
        self.issuers
            .by_handle(handle)
            .await?
            .ok_or_else(|| EntryConnectionError::UnknownIssuer(handle.to_owned()))
    }

    async fn seal(
        &self,
        handle: EntryHandle,
        secret: &str,
    ) -> Result<ClientCredential, EntryConnectionError> {
        self.keys
            .encrypt(secret.as_bytes(), &credential_context(handle))
            .await
            .map(ClientCredential::SecretBasic)
            .map_err(|e| internal("seal an entry connection credential", e))
    }

    /// The connections as an administrator reads them, oldest first.
    pub async fn list(
        &self,
        caller: &Caller,
    ) -> Result<ListEntryConnectionsResponse, EntryConnectionError> {
        caller.require_admin()?;
        let issuers = self.storage.list_oidc_issuers().await?;
        let connections = self.storage.list_entry_connections().await?;
        Ok(ListEntryConnectionsResponse {
            connections: connections.iter().map(|c| view(c, &issuers)).collect(),
        })
    }

    /// Register a connection to an outside issuer, its secret sealed for it.
    /// A retry of a completed registration answers with the connection it
    /// made and makes no second one. The command's fingerprint, an unsalted
    /// digest stored with its result, leaves the secret out: a reader of the
    /// database without the key manager's keys could otherwise test guesses
    /// of the secret.
    pub async fn create(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateEntryConnectionRequest,
    ) -> Result<v1::EntryConnection, EntryConnectionError> {
        caller.require_admin()?;
        display_name(&req.name)?;
        if req.issuer.is_empty() {
            return Err(EntryConnectionError::MissingField("issuer"));
        }
        // OpenID Connect Core 1.0 §1.2: an Issuer Identifier.
        if !is_issuer_identifier(&req.issuer) {
            return Err(invalid("issuer", "an https URL without query or fragment"));
        }
        if req.client_id.is_empty() {
            return Err(EntryConnectionError::MissingField("client_id"));
        }
        if req.client_secret.is_empty() {
            return Err(EntryConnectionError::MissingField("client_secret"));
        }
        let source = req
            .source_organization
            .as_ref()
            .map(|id| wire_id(Some(id), "source_organization"))
            .transpose()?;
        let fingerprinted = CreateEntryConnectionRequest {
            client_secret: String::new(),
            ..req.clone()
        };
        let command = KeyedCommand::by_profile::<keyed::CreateEntryConnection>(
            caller.profile_id,
            operation,
            &fingerprinted,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the issuer
        // its connection took) is that attempt's answer.
        let answer: Result<v1::EntryConnection, EntryConnectionError> = async {
            let issuer = self.issuer(&req.issuer_handle).await?;
            let handle = EntryHandle::generate();
            let now = stored_now();
            let connection = EntryConnection {
                handle,
                owner: ConnectionOwner::Administration,
                name: req.name.clone(),
                issuer: req.issuer.clone(),
                source,
                recipient_issuer: issuer.id,
                callback: callback(&issuer),
                // An administrator's connection coordinates no holder use.
                use_return: None,
                client_id: req.client_id.clone(),
                credential: self.seal(handle, &req.client_secret).await?,
                enabled: req.enabled,
                revision: 0,
                created_at: now,
                updated_at: now,
            };
            let response = view(&connection, std::slice::from_ref(&issuer));
            let ctx = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "entry_connection.create",
                handle.to_string(),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            match self.storage.create_entry_connection(&connection, ctx).await {
                Ok(()) => {}
                Err(SidError::OperationCompleted(_)) => {
                    return Err(EntryConnectionError::ChangedConcurrently);
                }
                Err(SidError::Conflict(_)) => return Err(EntryConnectionError::IssuerTaken),
                Err(e) => return Err(e.into()),
            }
            info!(connection = %handle, "entry connection registered");
            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    /// Change what `req` names of an administrator's connection, over the
    /// revision it names; a new secret is sealed for the connection. A retry
    /// of a completed change answers with the connection as that change left
    /// it and never writes it over a later one; the fingerprint leaves a new
    /// secret out, as for a registration.
    pub async fn update(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateEntryConnectionRequest,
    ) -> Result<v1::EntryConnection, EntryConnectionError> {
        caller.require_admin()?;
        let handle = handle_of(&req.handle)?;
        if let Some(name) = &req.name {
            display_name(name)?;
        }
        if req.client_id.as_ref().is_some_and(String::is_empty) {
            return Err(EntryConnectionError::MissingField("client_id"));
        }
        if req.client_secret.as_ref().is_some_and(String::is_empty) {
            return Err(EntryConnectionError::MissingField("client_secret"));
        }
        let fingerprinted = UpdateEntryConnectionRequest {
            client_secret: req.client_secret.as_ref().map(|_| String::new()),
            ..req.clone()
        };
        let command = KeyedCommand::by_profile::<keyed::UpdateEntryConnection>(
            caller.profile_id,
            operation,
            &fingerprinted,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the
        // revision its change moved on) is that attempt's answer.
        let answer: Result<v1::EntryConnection, EntryConnectionError> = async {
            let mut connection = self.stored(handle).await?;
            if connection.owner != ConnectionOwner::Administration {
                return Err(EntryConnectionError::Provisioned);
            }
            if connection.revision != req.revision {
                return Err(EntryConnectionError::ChangedConcurrently);
            }
            if let Some(name) = &req.name {
                connection.name.clone_from(name);
            }
            if let Some(client_id) = &req.client_id {
                connection.client_id.clone_from(client_id);
            }
            if let Some(secret) = &req.client_secret {
                connection.credential = self.seal(handle, secret).await?;
            }
            if let Some(enabled) = req.enabled {
                connection.enabled = enabled;
            }
            connection.updated_at = stored_now();
            // The answer is the connection as the change leaves it: at the
            // next revision.
            let mut left = connection.clone();
            left.revision += 1;
            let issuers = self.storage.list_oidc_issuers().await?;
            let response = view(&left, &issuers);
            let ctx = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "entry_connection.update",
                handle.to_string(),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            match self.storage.update_entry_connection(&connection, ctx).await {
                Ok(true) => {}
                // Removed or changed since it was read: never recreated or
                // overwritten.
                Ok(false) | Err(SidError::OperationCompleted(_)) => {
                    return Err(EntryConnectionError::ChangedConcurrently);
                }
                Err(e) => return Err(e.into()),
            }
            info!(connection = %handle, enabled = left.enabled, "entry connection changed");
            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    /// Remove an administrator's connection at the revision `req` names. A
    /// handle is never reused, so a connection already removed stays removed
    /// and the repeat answers as the first.
    pub async fn remove(
        &self,
        caller: &Caller,
        req: RemoveEntryConnectionRequest,
    ) -> Result<(), EntryConnectionError> {
        caller.require_admin()?;
        let handle = handle_of(&req.handle)?;
        let Some(connection) = self.storage.entry_connection(handle).await? else {
            return Ok(());
        };
        if connection.owner != ConnectionOwner::Administration {
            return Err(EntryConnectionError::Provisioned);
        }
        let ctx = AuditEntry::admin(
            caller.profile_id.to_string(),
            "entry_connection.remove",
            handle.to_string(),
        )
        .into();
        if self
            .storage
            .remove_entry_connection(handle, req.revision, ctx)
            .await?
        {
            info!(connection = %handle, "entry connection removed");
            return Ok(());
        }
        // Not removed at that revision: gone meanwhile, or changed.
        match self.storage.entry_connection(handle).await? {
            None => Ok(()),
            Some(_) => Err(EntryConnectionError::ChangedConcurrently),
        }
    }

    /// The enabled connections of the installation issuer whose route
    /// `issuer_handle` names ([`IssuerRegistry::routed`]), as its sign-in
    /// page offers them: public, the user is not signed in yet. An unknown
    /// issuer offers none.
    pub async fn sign_in_connections(
        &self,
        issuer_handle: &str,
    ) -> Result<ListSignInConnectionsResponse, EntryConnectionError> {
        let Some(issuer) = self.issuers.routed(issuer_handle).await? else {
            return Ok(ListSignInConnectionsResponse::default());
        };
        let connections = self.storage.list_entry_connections().await?;
        Ok(ListSignInConnectionsResponse {
            connections: connections
                .iter()
                .filter(|c| c.enabled && c.recipient_issuer == issuer.id)
                .map(|c| SignInConnection {
                    handle: c.handle.to_string(),
                    name: c.name.clone(),
                })
                .collect(),
        })
    }

    /// The enabled connection `handle` of installation issuer `issuer`, with
    /// the client it authenticates as there, for one entry step; `None` when
    /// the handle names no connection, another issuer's, or a disabled one:
    /// nothing is started or completed through it.
    pub async fn for_entry(
        &self,
        issuer: &OidcIssuer,
        handle: EntryHandle,
    ) -> Result<Option<(EntryConnection, TrustedIssuer)>, EntryConnectionError> {
        let Some(connection) = self.storage.entry_connection(handle).await? else {
            return Ok(None);
        };
        if !connection.enabled || connection.recipient_issuer != issuer.id {
            return Ok(None);
        }
        let ClientCredential::SecretBasic(sealed) = &connection.credential;
        let secret = self
            .keys
            .decrypt(sealed, &credential_context(handle))
            .await
            .map_err(|e| internal("open an entry connection credential", e))?;
        let secret = String::from_utf8(secret)
            .map_err(|e| internal("decode an entry connection credential", e))?;
        let trusted = TrustedIssuer {
            issuer: connection.issuer.clone(),
            client_id: connection.client_id.clone(),
            client_secret: SecretString::from(secret),
        };
        Ok(Some((connection, trusted)))
    }

    /// The provisioned authority of installation issuer `issuer`, once set.
    pub async fn provisioned(
        &self,
        issuer: &OidcIssuer,
    ) -> Result<Option<EntryConnection>, EntryConnectionError> {
        let Some(record) = self
            .storage
            .get_operation_result(PROVISIONED, &provisioned_key(issuer))
            .await?
        else {
            return Ok(None);
        };
        let handle = <[u8; 16]>::try_from(record.completion.result.as_slice())
            .map(EntryHandle::from_bytes)
            .map_err(|_| internal("read the provisioned authority", "a malformed handle"))?;
        Ok(Some(self.stored(handle).await?))
    }

    /// Set `authority` as the one the own Profiles of installation issuer
    /// `issuer` sign in through, for the authenticated provisioning caller
    /// `actor`. The same issuer again changes nothing and answers with the
    /// connection as it is now: a later authorized state is never
    /// overwritten by a repeated provisioning. Another issuer, once one is
    /// set, is refused; so is an issuer an administrator registered.
    pub async fn provision(
        &self,
        actor: &str,
        issuer: &OidcIssuer,
        authority: Provisioned,
    ) -> Result<EntryConnection, EntryConnectionError> {
        use secrecy::ExposeSecret;
        display_name(&authority.name)?;
        if !is_issuer_identifier(&authority.issuer) {
            return Err(invalid("issuer", "an https URL without query or fragment"));
        }
        if authority.client_id.is_empty() {
            return Err(EntryConnectionError::MissingField("client_id"));
        }
        if let Some(url) = &authority.use_return
            && !is_use_return(url)
        {
            return Err(invalid(
                "use_return",
                "an https URL without query or fragment",
            ));
        }
        let established = |set: EntryConnection| {
            if set.issuer == authority.issuer {
                Ok(set)
            } else {
                Err(EntryConnectionError::Established)
            }
        };
        if let Some(set) = self.provisioned(issuer).await? {
            return established(set);
        }
        let handle = EntryHandle::generate();
        let now = stored_now();
        let connection = EntryConnection {
            handle,
            owner: ConnectionOwner::Provisioning,
            name: authority.name.clone(),
            issuer: authority.issuer.clone(),
            source: authority.source,
            recipient_issuer: issuer.id,
            callback: callback(issuer),
            use_return: authority.use_return.clone(),
            client_id: authority.client_id.clone(),
            credential: self
                .seal(handle, authority.client_secret.expose_secret())
                .await?,
            enabled: true,
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        // Committed with the connection: of two provisionings racing for one
        // installation issuer, one sets the authority and the other reads it.
        let ctx = MutationContext::from(AuditEntry::machine(actor, PROVISION, handle.to_string()))
            .with_operation(OperationCompletion::new(
                PROVISIONED,
                provisioned_key(issuer),
                PROVISION,
                authority.issuer.as_bytes(),
                handle.as_bytes().to_vec(),
            ));
        match self.storage.create_entry_connection(&connection, ctx).await {
            Ok(()) => {
                info!(connection = %handle, "provisioned authority set");
                Ok(connection)
            }
            Err(SidError::OperationCompleted(_)) => match self.provisioned(issuer).await? {
                Some(set) => established(set),
                None => Err(internal("set the provisioned authority", "no record")),
            },
            // The issuer is a connection an administrator registered.
            Err(SidError::Conflict(_)) => Err(EntryConnectionError::IssuerTaken),
            Err(e) => Err(e.into()),
        }
    }
}

/// Now, at the microsecond precision every backend stores a time in: the
/// connection a command answers with is the one a later read returns.
fn stored_now() -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound as _;
    chrono::Utc::now().trunc_subsecs(6)
}

/// The key of the record that installation issuer `issuer` has its
/// provisioned authority.
fn provisioned_key(issuer: &OidcIssuer) -> OperationKey {
    OperationKey::parse(&format!("provisioned:{}", issuer.id))
        .expect("an issuer id is an operation key")
}

/// A connection as an administrator reads it; its credential is write-only.
/// `issuers` are the installation's issuers, to name the one it serves.
fn view(connection: &EntryConnection, issuers: &[OidcIssuer]) -> v1::EntryConnection {
    v1::EntryConnection {
        handle: connection.handle.to_string(),
        owner: match connection.owner {
            ConnectionOwner::Provisioning => v1::EntryConnectionOwner::Provisioning,
            ConnectionOwner::Administration => v1::EntryConnectionOwner::Administration,
        } as i32,
        name: connection.name.clone(),
        issuer: connection.issuer.clone(),
        source_organization: connection.source.map(Into::into),
        issuer_handle: issuers
            .iter()
            .find(|i| i.id == connection.recipient_issuer)
            .map(|i| i.handle.to_string())
            .unwrap_or_default(),
        callback: connection.callback.clone(),
        client_id: connection.client_id.clone(),
        enabled: connection.enabled,
        revision: connection.revision,
        created_at: Some(to_timestamp(connection.created_at)),
        updated_at: Some(to_timestamp(connection.updated_at)),
    }
}

#[cfg(test)]
mod tests;
