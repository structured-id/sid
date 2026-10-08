// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC UpstreamService implementation.
//!
//! Manages upstream identity providers (Google, GitHub, Microsoft, etc.) and
//! handles OAuth2/OIDC flows where SID acts as a Relying Party.
//! Supports provider CRUD, upstream auth initiation, and callback handling
//! with account resolution (returning user, linking, JIT provisioning).

use sid_authn::caller::{Caller, authenticate};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::upstream::oidc::OidcProviderClient;
use sid_core::models::upstream_provider::ProviderTrustCategory;
use sid_core::models::{
    AuditEntry, Profile, UpstreamIdentity, UpstreamLogin,
    UpstreamProtocol as DomainUpstreamProtocol, UpstreamProvider as DomainUpstreamProvider,
    UpstreamProviderId,
};
use sid_keys::KeyManager;
use sid_plugin::UpstreamIdpProvider;
use sid_plugin::storage::StorageBackend;
use sid_plugin::upstream::UpstreamAuthState;
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::{
    self, CreateUpstreamProviderRequest, DeleteUpstreamProviderRequest,
    DeleteUpstreamProviderResponse, EnabledProviderInfo, GetUpstreamProviderRequest,
    HandleUpstreamCallbackRequest, HandleUpstreamCallbackResponse, InitiateUpstreamAuthRequest,
    InitiateUpstreamAuthResponse, ListEnabledProvidersRequest, ListEnabledProvidersResponse,
    ListUpstreamProvidersRequest, ListUpstreamProvidersResponse, UpdateUpstreamProviderRequest,
    UpstreamAuthSuccess, UpstreamLinkingRequired, UpstreamProviderResponse,
    handle_upstream_callback_response,
};
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use sid_core::grpc_error::{ApiError, ErrorReason};

use super::convert;
use sid_core::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, missing_field,
    not_found, storage_failure,
};

/// Proto enum types aliased to avoid collision with domain types.
type ProtoUpstreamProtocol = v1::UpstreamProtocol;
type ProtoTrustCategory = v1::TrustCategory;
type ProtoUpstreamProvider = v1::UpstreamProvider;

/// gRPC service for upstream identity provider management and auth flows.
pub struct UpstreamServiceImpl {
    storage: Arc<dyn StorageBackend>,
    key_manager: Arc<dyn KeyManager>,
    auth_state: ChallengeStore<UpstreamAuthState>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl UpstreamServiceImpl {
    /// Create a new upstream service instance; pending upstream logins live
    /// in the shared `cache` for 10 minutes.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        key_manager: Arc<dyn KeyManager>,
        cache: Arc<dyn sid_plugin::cache::CacheBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            storage,
            auth_state: ChallengeStore::new(
                cache,
                key_manager.clone(),
                "upstream-auth",
                Duration::from_secs(600),
            ),
            key_manager,
        }
    }

    /// Convert proto `UpstreamProtocol` enum to domain `UpstreamProtocol`.
    fn proto_to_domain_protocol(proto: i32) -> Result<DomainUpstreamProtocol, Status> {
        match ProtoUpstreamProtocol::try_from(proto) {
            Ok(ProtoUpstreamProtocol::Oidc) => Ok(DomainUpstreamProtocol::Oidc),
            Ok(ProtoUpstreamProtocol::Oauth2) => Ok(DomainUpstreamProtocol::OAuth2),
            _ => Err(invalid_field("protocol", "must be OIDC or OAuth2")),
        }
    }

    /// Convert domain `UpstreamProtocol` to proto enum value.
    fn domain_to_proto_protocol(protocol: DomainUpstreamProtocol) -> i32 {
        match protocol {
            DomainUpstreamProtocol::Oidc => ProtoUpstreamProtocol::Oidc as i32,
            DomainUpstreamProtocol::OAuth2 => ProtoUpstreamProtocol::Oauth2 as i32,
        }
    }

    /// Convert proto `TrustCategory` enum to domain `ProviderTrustCategory`.
    fn proto_to_domain_trust(proto: i32) -> ProviderTrustCategory {
        match ProtoTrustCategory::try_from(proto) {
            Ok(ProtoTrustCategory::Corporate) => ProviderTrustCategory::Corporate,
            Ok(ProtoTrustCategory::Government) => ProviderTrustCategory::Government,
            Ok(ProtoTrustCategory::Financial) => ProviderTrustCategory::Financial,
            // Default to Social for unspecified or social.
            _ => ProviderTrustCategory::Social,
        }
    }

    /// Convert domain `ProviderTrustCategory` to proto enum value.
    fn domain_to_proto_trust(category: ProviderTrustCategory) -> i32 {
        match category {
            ProviderTrustCategory::Social => ProtoTrustCategory::Social as i32,
            ProviderTrustCategory::Corporate => ProtoTrustCategory::Corporate as i32,
            ProviderTrustCategory::Government => ProtoTrustCategory::Government as i32,
            ProviderTrustCategory::Financial => ProtoTrustCategory::Financial as i32,
        }
    }

    /// Convert a domain `UpstreamProvider` to the proto `UpstreamProvider` message.
    ///
    /// NEVER includes `client_secret` in the response — it is write-only.
    fn provider_to_proto(p: &DomainUpstreamProvider) -> ProtoUpstreamProvider {
        ProtoUpstreamProvider {
            id: p.id.to_string(),
            name: p.name.clone(),
            protocol: Self::domain_to_proto_protocol(p.protocol),
            trust_category: Self::domain_to_proto_trust(p.trust_category),
            enabled: p.enabled,
            client_id: p.client_id.clone(),
            // client_secret: NEVER returned — write-only field
            discovery_url: p.discovery_url.clone().unwrap_or_default(),
            authorization_endpoint: p.authorization_endpoint.clone().unwrap_or_default(),
            token_endpoint: p.token_endpoint.clone().unwrap_or_default(),
            userinfo_endpoint: p.userinfo_endpoint.clone().unwrap_or_default(),
            scopes: p.scopes.clone(),
            show_on_login: p.show_on_login,
            display_order: p.display_order,
            logo_url: p.logo_url.clone().unwrap_or_default(),
            created_at: Some(convert::to_timestamp(p.created_at)),
            updated_at: Some(convert::to_timestamp(p.updated_at)),
        }
    }

    /// Convert a domain `UpstreamProvider` to the minimal `EnabledProviderInfo` message
    /// for the public login screen endpoint.
    fn provider_to_enabled_info(p: &DomainUpstreamProvider) -> EnabledProviderInfo {
        EnabledProviderInfo {
            id: p.id.to_string(),
            name: p.name.clone(),
            protocol: Self::domain_to_proto_protocol(p.protocol),
            trust_category: Self::domain_to_proto_trust(p.trust_category),
            logo_url: p.logo_url.clone().unwrap_or_default(),
            display_order: p.display_order,
        }
    }

    /// Parse a provider ID string into the domain type.
    fn parse_provider_id(id: &str) -> Result<UpstreamProviderId, Status> {
        Uuid::parse_str(id)
            .map(UpstreamProviderId)
            .map_err(|_| invalid_field("provider_id", "not a provider identifier"))
    }

    /// UPSTREAM_PROVIDER_NOT_FOUND for `id`.
    fn provider_not_found(id: UpstreamProviderId) -> Status {
        not_found(
            ErrorReason::UpstreamProviderNotFound,
            "UpstreamProvider",
            id.0.to_string(),
        )
    }

    /// Load provider and decrypt its client secret.
    async fn load_provider_with_secret(
        &self,
        provider_id: UpstreamProviderId,
    ) -> Result<(DomainUpstreamProvider, String), Status> {
        let provider = self
            .storage
            .get_upstream_provider(provider_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| Self::provider_not_found(provider_id))?;

        if !provider.enabled {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "the upstream provider is disabled",
            )
            .with_precondition("PROVIDER_STATE", provider_id.0.to_string(), "disabled")
            .into());
        }

        let secret_bytes = self
            .key_manager
            .decrypt(&provider.client_secret)
            .await
            .map_err(|e| internal("decrypt upstream client secret", e))?;

        let decrypted_secret = String::from_utf8(secret_bytes)
            .map_err(|e| internal("decode upstream client secret", e))?;

        Ok((provider, decrypted_secret))
    }

    /// Authenticate the caller and require the administrator role: which
    /// identity providers the instance trusts is instance administration.
    /// The login screen's provider list and the upstream sign-in flow do not
    /// use this; they serve a user who is not signed in yet.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// Convert an empty proto string to None (proto3 default strings are empty).
    fn optional_string(s: &str) -> Option<String> {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }
}

#[tonic::async_trait]
impl UpstreamService for UpstreamServiceImpl {
    // ── Provider CRUD ──

    async fn create_upstream_provider(
        &self,
        request: Request<CreateUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(missing_field("name"));
        }
        if req.client_id.is_empty() {
            return Err(missing_field("client_id"));
        }
        if req.client_secret.is_empty() {
            return Err(missing_field("client_secret"));
        }

        let protocol = Self::proto_to_domain_protocol(req.protocol)?;
        let trust_category = Self::proto_to_domain_trust(req.trust_category);

        // Generate a new provider ID for context-bound encryption.
        let provider_id = UpstreamProviderId::new();

        // Encrypt client_secret with context binding to this provider.
        let encrypted_secret = self
            .key_manager
            .encrypt(
                req.client_secret.as_bytes(),
                &format!("upstream:{}", provider_id.0),
            )
            .await
            .map_err(|e| internal("encrypt upstream client secret", e))?;

        let mut provider =
            DomainUpstreamProvider::new(&req.name, protocol, &req.client_id, encrypted_secret);
        provider.id = provider_id;
        provider.trust_category = trust_category;
        provider.discovery_url = Self::optional_string(&req.discovery_url);
        provider.authorization_endpoint = Self::optional_string(&req.authorization_endpoint);
        provider.token_endpoint = Self::optional_string(&req.token_endpoint);
        provider.userinfo_endpoint = Self::optional_string(&req.userinfo_endpoint);
        if !req.scopes.is_empty() {
            provider.scopes = req.scopes;
        }
        provider.show_on_login = req.show_on_login;
        provider.display_order = req.display_order;
        provider.logo_url = Self::optional_string(&req.logo_url);

        self.storage
            .create_upstream_provider(
                &provider,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "upstream_provider.create",
                    provider.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => Status::from(
                    ApiError::new(
                        ErrorReason::UpstreamProviderAlreadyExists,
                        "an upstream provider with this name already exists",
                    )
                    .with_resource("UpstreamProvider", provider.name.clone()),
                ),
                other => storage_failure(other),
            })?;

        info!(
            "Created upstream provider {} ({})",
            provider.name, provider.id
        );

        Ok(Response::new(UpstreamProviderResponse {
            provider: Some(Self::provider_to_proto(&provider)),
        }))
    }

    async fn get_upstream_provider(
        &self,
        request: Request<GetUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();
        let provider_id = Self::parse_provider_id(&req.provider_id)?;

        let provider = self
            .storage
            .get_upstream_provider(provider_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| Self::provider_not_found(provider_id))?;

        Ok(Response::new(UpstreamProviderResponse {
            provider: Some(Self::provider_to_proto(&provider)),
        }))
    }

    async fn update_upstream_provider(
        &self,
        request: Request<UpdateUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let provider_id = Self::parse_provider_id(&req.provider_id)?;

        let mut provider = self
            .storage
            .get_upstream_provider(provider_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| Self::provider_not_found(provider_id))?;

        // Apply optional field updates.
        if let Some(name) = req.name {
            provider.name = name;
        }
        if let Some(proto) = req.protocol {
            provider.protocol = Self::proto_to_domain_protocol(proto)?;
        }
        if let Some(tc) = req.trust_category {
            provider.trust_category = Self::proto_to_domain_trust(tc);
        }
        if let Some(enabled) = req.enabled {
            provider.enabled = enabled;
        }
        if let Some(client_id) = req.client_id {
            provider.client_id = client_id;
        }
        // Re-encrypt client_secret if provided.
        if let Some(ref secret) = req.client_secret {
            provider.client_secret = self
                .key_manager
                .encrypt(secret.as_bytes(), &format!("upstream:{}", provider_id.0))
                .await
                .map_err(|e| internal("encrypt upstream client secret", e))?;
        }
        if let Some(url) = req.discovery_url {
            provider.discovery_url = if url.is_empty() { None } else { Some(url) };
        }
        if let Some(ep) = req.authorization_endpoint {
            provider.authorization_endpoint = if ep.is_empty() { None } else { Some(ep) };
        }
        if let Some(ep) = req.token_endpoint {
            provider.token_endpoint = if ep.is_empty() { None } else { Some(ep) };
        }
        if let Some(ep) = req.userinfo_endpoint {
            provider.userinfo_endpoint = if ep.is_empty() { None } else { Some(ep) };
        }
        if !req.scopes.is_empty() {
            provider.scopes = req.scopes;
        }
        if let Some(sol) = req.show_on_login {
            provider.show_on_login = sol;
        }
        if let Some(order) = req.display_order {
            provider.display_order = order;
        }
        if let Some(logo) = req.logo_url {
            provider.logo_url = if logo.is_empty() { None } else { Some(logo) };
        }

        provider.updated_at = chrono::Utc::now();

        let updated = self
            .storage
            .update_upstream_provider(
                &provider,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "upstream_provider.update",
                    provider.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Deleted or changed since it was read: never recreated or overwritten.
            return Err(changed_concurrently());
        }
        provider.revision += 1;

        info!(
            "Updated upstream provider {} ({})",
            provider.name, provider.id
        );

        Ok(Response::new(UpstreamProviderResponse {
            provider: Some(Self::provider_to_proto(&provider)),
        }))
    }

    async fn delete_upstream_provider(
        &self,
        request: Request<DeleteUpstreamProviderRequest>,
    ) -> Result<Response<DeleteUpstreamProviderResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let provider_id = Self::parse_provider_id(&req.provider_id)?;

        self.storage
            .delete_upstream_provider(
                provider_id,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "upstream_provider.delete",
                    provider_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Deleted upstream provider {}", provider_id);

        Ok(Response::new(DeleteUpstreamProviderResponse {}))
    }

    async fn list_upstream_providers(
        &self,
        request: Request<ListUpstreamProvidersRequest>,
    ) -> Result<Response<ListUpstreamProvidersResponse>, Status> {
        self.admin(&request).await?;
        // StorageBackend only has list_enabled_upstream_providers currently.
        // TODO: Add list_all_upstream_providers to StorageBackend for admin use.
        // For now, use list_enabled as a fallback (admin can still see individual
        // providers via GetUpstreamProvider).
        let providers = self
            .storage
            .list_enabled_upstream_providers()
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListUpstreamProvidersResponse {
            providers: providers.iter().map(Self::provider_to_proto).collect(),
        }))
    }

    async fn list_enabled_providers(
        &self,
        _request: Request<ListEnabledProvidersRequest>,
    ) -> Result<Response<ListEnabledProvidersResponse>, Status> {
        let providers = self
            .storage
            .list_enabled_upstream_providers()
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListEnabledProvidersResponse {
            providers: providers
                .iter()
                .map(Self::provider_to_enabled_info)
                .collect(),
        }))
    }

    // ── Upstream Auth Flow ──

    async fn initiate_upstream_auth(
        &self,
        request: Request<InitiateUpstreamAuthRequest>,
    ) -> Result<Response<InitiateUpstreamAuthResponse>, Status> {
        let req = request.into_inner();
        let provider_id = Self::parse_provider_id(&req.provider_id)?;

        if req.redirect_uri.is_empty() {
            return Err(missing_field("redirect_uri"));
        }

        // Load provider and decrypt secret.
        let (provider, decrypted_secret) = self.load_provider_with_secret(provider_id).await?;

        // Create OIDC client and generate authorization URL. The provider's
        // discovery document is fetched here: an unreachable provider is a
        // dependency outage.
        let oidc_client = OidcProviderClient::from_provider(&provider, decrypted_secret)
            .await
            .map_err(|e| dependency_unavailable("upstream provider", e))?;

        let (authorization_url, state_with_verifier) = oidc_client
            .authorization_url(&req.redirect_uri, &provider.scopes)
            .await
            .map_err(|e| internal("build upstream authorization URL", e))?;

        // Parse state_with_verifier: "{state_token}\0{code_verifier}"
        let (state_token, code_verifier) = if let Some(idx) = state_with_verifier.find('\0') {
            (
                state_with_verifier[..idx].to_string(),
                Some(state_with_verifier[idx + 1..].to_string()),
            )
        } else {
            (state_with_verifier, None)
        };

        // Store auth state for CSRF validation on callback.
        let auth_state = UpstreamAuthState {
            provider_id,
            state_token: state_token.clone(),
            redirect_uri: req.redirect_uri,
            code_verifier,
            nonce: None,
        };

        self.auth_state.insert(&state_token, &auth_state).await?;

        Ok(Response::new(InitiateUpstreamAuthResponse {
            authorization_url,
            state_token,
        }))
    }

    async fn handle_upstream_callback(
        &self,
        request: Request<HandleUpstreamCallbackRequest>,
    ) -> Result<Response<HandleUpstreamCallbackResponse>, Status> {
        let req = request.into_inner();

        if req.code.is_empty() {
            return Err(missing_field("code"));
        }
        if req.state.is_empty() {
            return Err(missing_field("state"));
        }
        if req.redirect_uri.is_empty() {
            return Err(missing_field("redirect_uri"));
        }

        // CSRF validation: take auth state from challenge store (single-use).
        let auth_state = self
            .auth_state
            .take(&req.state)
            .await?
            .ok_or_else(|| invalid_field("state", "unknown, expired or already used"))?;

        // Validate redirect_uri matches what was stored during initiation.
        if auth_state.redirect_uri != req.redirect_uri {
            return Err(invalid_field(
                "redirect_uri",
                "does not match the sign-in this state started",
            ));
        }

        let provider_id = auth_state.provider_id;

        // Load provider and decrypt secret.
        let (provider, decrypted_secret) = self.load_provider_with_secret(provider_id).await?;

        // Create OIDC client for token exchange.
        let oidc_client = OidcProviderClient::from_provider(&provider, decrypted_secret)
            .await
            .map_err(|e| dependency_unavailable("upstream provider", e))?;

        // Build redirect_uri with code_verifier for PKCE (convention: "{uri}\0{verifier}").
        let exchange_redirect = if let Some(ref verifier) = auth_state.code_verifier {
            format!("{}\0{}", req.redirect_uri, verifier)
        } else {
            req.redirect_uri.clone()
        };

        // Exchange authorization code for user claims.
        let claims = oidc_client
            .exchange_code(&req.code, &exchange_redirect)
            .await
            .map_err(|e| {
                warn!("Token exchange failed for provider {}: {}", provider_id, e);
                Status::from(ApiError::new(
                    ErrorReason::AuthenticationFailed,
                    "sign-in with the upstream provider failed",
                ))
            })?;

        // ── Account Resolution ──
        //
        // Path A: Match by (provider_id, upstream_subject) → returning user
        // Path B: No subject match, verified email → linking required
        // Path C: No match → JIT provisioning

        // Path A: Check for existing upstream identity.
        if let Some(upstream_identity) = self
            .storage
            .get_upstream_identity_by_provider_subject(provider_id, &claims.upstream_subject)
            .await
            .map_err(storage_failure)?
        {
            // Returning user: the claims replace the cached ones and the login
            // is counted in place, so concurrent logins are all counted.
            let login = UpstreamLogin {
                email: claims.email.clone(),
                name: claims.name.clone(),
                picture: claims.picture.clone(),
                at: chrono::Utc::now(),
            };
            let recorded = self
                .storage
                .record_upstream_login(
                    upstream_identity.id,
                    &login,
                    AuditEntry::user(
                        upstream_identity.profile_id.to_string(),
                        "upstream_identity.login",
                        upstream_identity.id.0.to_string(),
                    )
                    .into(),
                )
                .await
                .map_err(storage_failure)?;
            if !recorded {
                // The link was removed meanwhile: it does not log anyone in.
                return Err(changed_concurrently());
            }

            // TODO: Create a full session via SessionService instead of placeholder UUID.
            let session_id = Uuid::now_v7().to_string();

            info!(
                "Upstream login: profile {} via provider {} (returning user)",
                upstream_identity.profile_id, provider_id
            );

            return Ok(Response::new(HandleUpstreamCallbackResponse {
                result: Some(handle_upstream_callback_response::Result::Success(
                    UpstreamAuthSuccess {
                        session_id,
                        access_token: String::new(), // TODO: Issue JWT access token
                        expires_in: 3600,
                        new_profile_created: false,
                    },
                )),
            }));
        }

        // Path B: No subject match — check for verified email match.
        if claims.has_verified_email()
            && let Some(email) = &claims.email
            && let Ok(Some(_existing_profile)) = self.storage.get_profile_by_email(email).await
        {
            // Profile exists with this email but no upstream identity linked.
            // Return linking_required so the user can confirm account linking.
            let linking_token = Uuid::now_v7().to_string();

            info!(
                "Upstream auth: email {} matched existing profile, linking required (provider {})",
                email, provider_id
            );

            return Ok(Response::new(HandleUpstreamCallbackResponse {
                result: Some(handle_upstream_callback_response::Result::LinkingRequired(
                    UpstreamLinkingRequired {
                        linking_token,
                        upstream_email: email.clone(),
                    },
                )),
            }));
        }

        // Path C: No match at all — JIT provisioning.
        // Create a new profile and link the upstream identity.
        let username = claims
            .email
            .as_deref()
            .or(Some(&claims.upstream_subject))
            .unwrap_or("upstream-user");

        let mut profile = Profile::new(Some(username));
        // Email stored in profile_emails table, not on Profile directly
        // Upstream OIDC `name` claim → given_name (unstructured).
        // TODO: if upstream provides given_name/family_name, map those separately.
        profile.given_name = claims.name.clone();

        self.storage
            .create_profile(
                &profile,
                AuditEntry::system("profile.create.jit", profile.id.to_string()).into(),
            )
            .await
            .map_err(storage_failure)?;

        // Create and save the upstream identity link.
        let mut upstream_identity =
            UpstreamIdentity::new(profile.id, provider_id, &claims.upstream_subject);

        if let Some(ref issuer) = claims.upstream_issuer {
            upstream_identity.upstream_issuer = Some(issuer.clone());
        }
        upstream_identity.update_claims(
            claims.email.clone(),
            claims.name.clone(),
            claims.picture.clone(),
        );
        upstream_identity.record_login();

        self.storage
            .create_upstream_identity(
                &upstream_identity,
                AuditEntry::system(
                    "upstream_identity.create.jit",
                    upstream_identity.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        // TODO: Create a full session via SessionService instead of placeholder UUID.
        let session_id = Uuid::now_v7().to_string();

        info!(
            "JIT provisioned profile {} via upstream provider {} (subject: {})",
            profile.id, provider_id, claims.upstream_subject
        );

        Ok(Response::new(HandleUpstreamCallbackResponse {
            result: Some(handle_upstream_callback_response::Result::Success(
                UpstreamAuthSuccess {
                    session_id,
                    access_token: String::new(), // TODO: Issue JWT access token
                    expires_in: 3600,
                    new_profile_created: true,
                },
            )),
        }))
    }
}
