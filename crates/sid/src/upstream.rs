// SPDX-License-Identifier: AGPL-3.0-only
//! The upstream identity providers an installation trusts (Google, GitHub,
//! Microsoft and others, where SID is the relying party): their
//! administration, the public list the sign-in page shows, and a provider
//! with its client secret opened for an upstream sign-in. The secret is
//! stored only encrypted under the key manager and never returned.

use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::upstream_provider::ProviderTrustCategory;
use sid_core::models::{
    AuditEntry, MutationContext, OperationContext, UpstreamProtocol as DomainUpstreamProtocol,
    UpstreamProvider as DomainUpstreamProvider, UpstreamProviderId, client_secret_context,
};
use sid_keys::KeyManager;
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::federation::upstream_service as keyed;
use sid_proto::sid::v1::{
    self, CreateUpstreamProviderRequest, DeleteUpstreamProviderRequest, EnabledProviderInfo,
    GetUpstreamProviderRequest, ListEnabledProvidersResponse, ListUpstreamProvidersResponse,
    UpdateUpstreamProviderRequest, UpstreamProviderResponse,
};
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

/// Why an upstream provider operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
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
    /// A failure of this installation (a secret that cannot be sealed or
    /// opened); its cause is in the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("upstream provider {0} not found")]
    NotFound(UpstreamProviderId),
    /// Another provider has this name.
    #[error("an upstream provider named {0:?} already exists")]
    NameTaken(String),
    /// A disabled provider signs nobody in.
    #[error("upstream provider {0} is disabled")]
    Disabled(UpstreamProviderId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<FieldError> for UpstreamError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> UpstreamError {
    tracing::error!(operation, error = %cause, "internal failure");
    UpstreamError::Internal
}

/// The upstream providers of one installation.
pub struct Upstream {
    storage: Arc<dyn StorageBackend>,
    /// Seals and opens the providers' client secrets.
    keys: Arc<dyn KeyManager>,
}

impl Upstream {
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn KeyManager>) -> Self {
        Self { storage, keys }
    }

    async fn stored(
        &self,
        id: UpstreamProviderId,
    ) -> Result<DomainUpstreamProvider, UpstreamError> {
        self.storage
            .get_upstream_provider(id)
            .await?
            .ok_or(UpstreamError::NotFound(id))
    }

    /// Provider `id` with its client secret opened, for an upstream sign-in;
    /// a disabled provider signs nobody in.
    pub async fn sign_in_provider(
        &self,
        id: UpstreamProviderId,
    ) -> Result<(DomainUpstreamProvider, String), UpstreamError> {
        let provider = self.stored(id).await?;
        if !provider.enabled {
            return Err(UpstreamError::Disabled(id));
        }
        let secret = self
            .keys
            .decrypt(&provider.client_secret, &client_secret_context(id))
            .await
            .map_err(|e| internal("decrypt upstream client secret", e))?;
        let secret =
            String::from_utf8(secret).map_err(|e| internal("decode upstream client secret", e))?;
        Ok((provider, secret))
    }

    /// Register a provider, its secret sealed for it. A retry of a completed
    /// creation answers with the provider it created and creates no second
    /// one. The command's fingerprint, an unsalted digest stored with its
    /// result, leaves the secret out: a reader of the database without the
    /// key manager's keys could otherwise test guesses of the secret.
    pub async fn create(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateUpstreamProviderRequest,
    ) -> Result<UpstreamProviderResponse, UpstreamError> {
        caller.require_admin()?;
        if req.name.is_empty() {
            return Err(UpstreamError::MissingField("name"));
        }
        if req.client_id.is_empty() {
            return Err(UpstreamError::MissingField("client_id"));
        }
        if req.client_secret.is_empty() {
            return Err(UpstreamError::MissingField("client_secret"));
        }
        let fingerprinted = CreateUpstreamProviderRequest {
            client_secret: String::new(),
            ..req.clone()
        };
        let command = KeyedCommand::by_profile::<keyed::CreateUpstreamProvider>(
            caller.profile_id,
            operation,
            &fingerprinted,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the name its
        // provider took) is that attempt's answer.
        let answer: Result<UpstreamProviderResponse, UpstreamError> = async {
            let protocol = protocol_from_proto(req.protocol)?;
            let provider_id = UpstreamProviderId::generate();
            let encrypted = self
                .keys
                .encrypt(
                    req.client_secret.as_bytes(),
                    &client_secret_context(provider_id),
                )
                .await
                .map_err(|e| internal("encrypt upstream client secret", e))?;
            let mut provider =
                DomainUpstreamProvider::new(&req.name, protocol, &req.client_id, encrypted);
            provider.id = provider_id;
            provider.trust_category = trust_from_proto(req.trust_category);
            provider.discovery_url = optional(&req.discovery_url);
            provider.authorization_endpoint = optional(&req.authorization_endpoint);
            provider.token_endpoint = optional(&req.token_endpoint);
            provider.userinfo_endpoint = optional(&req.userinfo_endpoint);
            if !req.scopes.is_empty() {
                provider.scopes = req.scopes.clone();
            }
            provider.show_on_login = req.show_on_login;
            provider.display_order = req.display_order;
            provider.logo_url = optional(&req.logo_url);
            let response = UpstreamProviderResponse {
                provider: Some(provider_to_proto(&provider)),
            };
            let ctx = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "upstream_provider.create",
                provider.id.to_string(),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            match self.storage.create_upstream_provider(&provider, ctx).await {
                Ok(_) => {}
                Err(SidError::OperationCompleted(_)) => {
                    return Err(UpstreamError::ChangedConcurrently);
                }
                Err(SidError::Conflict(_)) => {
                    return Err(UpstreamError::NameTaken(provider.name.clone()));
                }
                Err(e) => return Err(e.into()),
            }
            info!(
                "Created upstream provider {} ({})",
                provider.name, provider.id
            );
            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    pub async fn get(
        &self,
        caller: &Caller,
        req: GetUpstreamProviderRequest,
    ) -> Result<UpstreamProviderResponse, UpstreamError> {
        caller.require_admin()?;
        let id = wire_id(req.provider_id.as_ref(), "provider_id")?;
        Ok(UpstreamProviderResponse {
            provider: Some(provider_to_proto(&self.stored(id).await?)),
        })
    }

    /// Change the fields given; a new secret is sealed for the provider. A
    /// retry of a completed edit answers with the provider as that edit left
    /// it and never writes it over a later edit; the fingerprint leaves a
    /// new secret out, as for a creation.
    pub async fn update(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateUpstreamProviderRequest,
    ) -> Result<UpstreamProviderResponse, UpstreamError> {
        caller.require_admin()?;
        let provider_id = wire_id(req.provider_id.as_ref(), "provider_id")?;
        let fingerprinted = UpdateUpstreamProviderRequest {
            client_secret: req.client_secret.as_ref().map(|_| String::new()),
            ..req.clone()
        };
        let command = KeyedCommand::by_profile::<keyed::UpdateUpstreamProvider>(
            caller.profile_id,
            operation,
            &fingerprinted,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the
        // revision its edit moved on) is that attempt's answer.
        let answer: Result<UpstreamProviderResponse, UpstreamError> = async {
            let mut provider = self.stored(provider_id).await?;
            if let Some(name) = req.name.clone() {
                provider.name = name;
            }
            if let Some(proto) = req.protocol {
                provider.protocol = protocol_from_proto(proto)?;
            }
            if let Some(tc) = req.trust_category {
                provider.trust_category = trust_from_proto(tc);
            }
            if let Some(enabled) = req.enabled {
                provider.enabled = enabled;
            }
            if let Some(client_id) = req.client_id.clone() {
                provider.client_id = client_id;
            }
            if let Some(ref secret) = req.client_secret {
                provider.client_secret = self
                    .keys
                    .encrypt(secret.as_bytes(), &client_secret_context(provider_id))
                    .await
                    .map_err(|e| internal("encrypt upstream client secret", e))?;
            }
            if let Some(url) = &req.discovery_url {
                provider.discovery_url = optional(url);
            }
            if let Some(ep) = &req.authorization_endpoint {
                provider.authorization_endpoint = optional(ep);
            }
            if let Some(ep) = &req.token_endpoint {
                provider.token_endpoint = optional(ep);
            }
            if let Some(ep) = &req.userinfo_endpoint {
                provider.userinfo_endpoint = optional(ep);
            }
            if !req.scopes.is_empty() {
                provider.scopes = req.scopes.clone();
            }
            if let Some(sol) = req.show_on_login {
                provider.show_on_login = sol;
            }
            if let Some(order) = req.display_order {
                provider.display_order = order;
            }
            if let Some(logo) = &req.logo_url {
                provider.logo_url = optional(logo);
            }
            provider.updated_at = chrono::Utc::now();
            let response = UpstreamProviderResponse {
                provider: Some(provider_to_proto(&provider)),
            };
            let ctx = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "upstream_provider.update",
                provider.id.to_string(),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            match self.storage.update_upstream_provider(&provider, ctx).await {
                Ok(true) => {}
                // Deleted or changed since it was read: never recreated or
                // overwritten.
                Ok(false) | Err(SidError::OperationCompleted(_)) => {
                    return Err(UpstreamError::ChangedConcurrently);
                }
                Err(e) => return Err(e.into()),
            }
            info!(
                "Updated upstream provider {} ({})",
                provider.name, provider.id
            );
            Ok(response)
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    pub async fn delete(
        &self,
        caller: &Caller,
        req: DeleteUpstreamProviderRequest,
    ) -> Result<(), UpstreamError> {
        caller.require_admin()?;
        let id = wire_id(req.provider_id.as_ref(), "provider_id")?;
        self.storage
            .delete_upstream_provider(
                id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "upstream_provider.delete",
                    id.to_string(),
                )
                .into(),
            )
            .await?;
        info!("Deleted upstream provider {}", id);
        Ok(())
    }

    /// Every provider, enabled or not: a disabled one is found to enable
    /// again.
    pub async fn list(
        &self,
        caller: &Caller,
    ) -> Result<ListUpstreamProvidersResponse, UpstreamError> {
        caller.require_admin()?;
        let providers = self.storage.list_upstream_providers().await?;
        Ok(ListUpstreamProvidersResponse {
            providers: providers.iter().map(provider_to_proto).collect(),
        })
    }

    /// The enabled providers as the sign-in page shows them: public, the
    /// user is not signed in yet.
    pub async fn enabled(&self) -> Result<ListEnabledProvidersResponse, UpstreamError> {
        let providers = self.storage.list_enabled_upstream_providers().await?;
        Ok(ListEnabledProvidersResponse {
            providers: providers.iter().map(provider_to_enabled_info).collect(),
        })
    }
}

/// An empty proto string is no value.
fn optional(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn protocol_from_proto(proto: i32) -> Result<DomainUpstreamProtocol, UpstreamError> {
    match v1::UpstreamProtocol::try_from(proto) {
        Ok(v1::UpstreamProtocol::Oidc) => Ok(DomainUpstreamProtocol::Oidc),
        Ok(v1::UpstreamProtocol::Oauth2) => Ok(DomainUpstreamProtocol::OAuth2),
        _ => Err(UpstreamError::InvalidField {
            field: "protocol",
            reason: "must be OIDC or OAuth2".into(),
        }),
    }
}

fn protocol_to_proto(protocol: DomainUpstreamProtocol) -> i32 {
    match protocol {
        DomainUpstreamProtocol::Oidc => v1::UpstreamProtocol::Oidc as i32,
        DomainUpstreamProtocol::OAuth2 => v1::UpstreamProtocol::Oauth2 as i32,
    }
}

/// A request's trust category; unspecified is social.
fn trust_from_proto(proto: i32) -> ProviderTrustCategory {
    match v1::TrustCategory::try_from(proto) {
        Ok(v1::TrustCategory::Corporate) => ProviderTrustCategory::Corporate,
        Ok(v1::TrustCategory::Government) => ProviderTrustCategory::Government,
        Ok(v1::TrustCategory::Financial) => ProviderTrustCategory::Financial,
        _ => ProviderTrustCategory::Social,
    }
}

fn trust_to_proto(category: ProviderTrustCategory) -> i32 {
    match category {
        ProviderTrustCategory::Social => v1::TrustCategory::Social as i32,
        ProviderTrustCategory::Corporate => v1::TrustCategory::Corporate as i32,
        ProviderTrustCategory::Government => v1::TrustCategory::Government as i32,
        ProviderTrustCategory::Financial => v1::TrustCategory::Financial as i32,
    }
}

/// A provider as the API returns it; its client secret is write-only.
fn provider_to_proto(p: &DomainUpstreamProvider) -> v1::UpstreamProvider {
    v1::UpstreamProvider {
        id: Some(p.id.into()),
        name: p.name.clone(),
        protocol: protocol_to_proto(p.protocol),
        trust_category: trust_to_proto(p.trust_category),
        enabled: p.enabled,
        client_id: p.client_id.clone(),
        discovery_url: p.discovery_url.clone().unwrap_or_default(),
        authorization_endpoint: p.authorization_endpoint.clone().unwrap_or_default(),
        token_endpoint: p.token_endpoint.clone().unwrap_or_default(),
        userinfo_endpoint: p.userinfo_endpoint.clone().unwrap_or_default(),
        scopes: p.scopes.clone(),
        show_on_login: p.show_on_login,
        display_order: p.display_order,
        logo_url: p.logo_url.clone().unwrap_or_default(),
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
    }
}

/// What the public sign-in page shows of a provider.
fn provider_to_enabled_info(p: &DomainUpstreamProvider) -> EnabledProviderInfo {
    EnabledProviderInfo {
        id: Some(p.id.into()),
        name: p.name.clone(),
        protocol: protocol_to_proto(p.protocol),
        trust_category: trust_to_proto(p.trust_category),
        logo_url: p.logo_url.clone().unwrap_or_default(),
        display_order: p.display_order,
    }
}

#[cfg(test)]
mod tests;
