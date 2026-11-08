// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC UpstreamService implementation.
//!
//! Upstream identity providers (Google, GitHub, Microsoft, etc.) are managed
//! through [`sid::upstream`]; the OAuth2/OIDC flow where SID acts as a
//! Relying Party, upstream auth initiation and the callback with account
//! resolution (returning user, linking, JIT provisioning), runs here with the
//! sign-in service that completes it.

use sid::upstream::{Upstream, UpstreamError};
use sid_authn::caller::Caller;
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::upstream::oidc::OidcProviderClient;
use sid_core::models::{AuditEntry, Profile, UpstreamIdentity, UpstreamLogin};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::ceremony::Respond;
use sid_infra::authn::operation::context;
use sid_keys::KeyManager;
use sid_plugin::UpstreamIdpProvider;
use sid_plugin::storage::StorageBackend;
use sid_plugin::upstream::UpstreamAuthState;
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::{
    CreateUpstreamProviderRequest, DeleteUpstreamProviderRequest, DeleteUpstreamProviderResponse,
    GetUpstreamProviderRequest, HandleUpstreamCallbackRequest, HandleUpstreamCallbackResponse,
    InitiateUpstreamAuthRequest, InitiateUpstreamAuthResponse, ListEnabledProvidersRequest,
    ListEnabledProvidersResponse, ListUpstreamProvidersRequest, ListUpstreamProvidersResponse,
    UpdateUpstreamProviderRequest, UpstreamAuthSuccess, UpstreamLinkingRequired,
    UpstreamProviderResponse, handle_upstream_callback_response,
};
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};

use super::auth_service::AuthServiceImpl;
use super::convert;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, missing_field,
    not_found, storage_failure,
};

/// The status an upstream provider refusal answers with.
fn refusal(e: UpstreamError) -> Status {
    match e {
        UpstreamError::Caller(e) => e.into_status(),
        UpstreamError::Operation(e) => e.into_status(),
        UpstreamError::Store(e) => storage_failure(e),
        UpstreamError::Internal => ApiError::internal().into(),
        UpstreamError::MissingField(field) => missing_field(field),
        UpstreamError::InvalidField { field, reason } => invalid_field(field, reason),
        UpstreamError::NotFound(id) => not_found(
            ErrorReason::UpstreamProviderNotFound,
            "UpstreamProvider",
            id.to_string(),
        ),
        UpstreamError::NameTaken(name) => ApiError::new(
            ErrorReason::UpstreamProviderAlreadyExists,
            "an upstream provider with this name already exists",
        )
        .with_resource("UpstreamProvider", name)
        .into(),
        UpstreamError::Disabled(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the upstream provider is disabled",
        )
        .with_precondition("PROVIDER_STATE", id.to_string(), "disabled")
        .into(),
        UpstreamError::ChangedConcurrently => changed_concurrently(),
    }
}

/// gRPC service for upstream identity provider management and auth flows.
pub struct UpstreamServiceImpl {
    storage: Arc<dyn StorageBackend>,
    providers: Upstream,
    auth_state: ChallengeStore<UpstreamAuthState>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// Admits and completes a verified upstream sign-in as this authority
    /// admits and completes every sign-in: its enrollment policy, sign-in
    /// page, cookie, security rules and session policy.
    auth: Arc<AuthServiceImpl>,
}

impl UpstreamServiceImpl {
    /// Create a new upstream service whose sign-ins `auth` completes;
    /// pending upstream logins live in `storage`'s ceremony state for 10
    /// minutes.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        key_manager: Arc<dyn KeyManager>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        auth: Arc<AuthServiceImpl>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            auth_state: ChallengeStore::new(
                storage.clone(),
                key_manager.clone(),
                "upstream-auth",
                Duration::from_secs(600),
            ),
            providers: Upstream::new(storage.clone(), key_manager),
            storage,
            auth,
        }
    }

    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// The authenticated administrator: checked before the operation
    /// context, so a refused caller learns nothing more about it.
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = self.caller(request).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        Ok(caller)
    }
}

#[tonic::async_trait]
impl UpstreamService for UpstreamServiceImpl {
    // ── Provider administration ──

    async fn create_upstream_provider(
        &self,
        request: Request<CreateUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.providers
            .create(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn get_upstream_provider(
        &self,
        request: Request<GetUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.providers
            .get(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn update_upstream_provider(
        &self,
        request: Request<UpdateUpstreamProviderRequest>,
    ) -> Result<Response<UpstreamProviderResponse>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.providers
            .update(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn delete_upstream_provider(
        &self,
        request: Request<DeleteUpstreamProviderRequest>,
    ) -> Result<Response<DeleteUpstreamProviderResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.providers
            .delete(&caller, request.into_inner())
            .await
            .map(|()| Response::new(DeleteUpstreamProviderResponse {}))
            .map_err(refusal)
    }

    async fn list_upstream_providers(
        &self,
        request: Request<ListUpstreamProvidersRequest>,
    ) -> Result<Response<ListUpstreamProvidersResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.providers
            .list(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_enabled_providers(
        &self,
        _request: Request<ListEnabledProvidersRequest>,
    ) -> Result<Response<ListEnabledProvidersResponse>, Status> {
        self.providers
            .enabled()
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    // ── Upstream Auth Flow ──

    async fn initiate_upstream_auth(
        &self,
        request: Request<InitiateUpstreamAuthRequest>,
    ) -> Result<Response<InitiateUpstreamAuthResponse>, Status> {
        // No sign-in starts during maintenance, as no local one does.
        self.auth.check_maintenance().await?;
        let req = request.into_inner();
        let provider_id = convert::wire_id(req.provider_id.as_ref(), "provider_id")?;

        if req.redirect_uri.is_empty() {
            return Err(missing_field("redirect_uri"));
        }

        let (provider, decrypted_secret) = self
            .providers
            .sign_in_provider(provider_id)
            .await
            .map_err(refusal)?;

        // Create OIDC client and generate authorization URL. The provider's
        // discovery document is fetched here: an unreachable provider is a
        // dependency outage.
        let oidc_client = OidcProviderClient::from_provider(&provider, decrypted_secret)
            .await
            .map_err(|e| dependency_unavailable("upstream provider", e))?;

        let request = oidc_client
            .authorization_request(&req.redirect_uri, &provider.scopes)
            .await
            .map_err(|e| internal("build upstream authorization URL", e))?;

        // The callback continues only this request: its state, verifier and
        // nonce are kept until then.
        let auth_state = UpstreamAuthState {
            provider_id,
            state_token: request.state.clone(),
            redirect_uri: req.redirect_uri,
            code_verifier: request.code_verifier,
            nonce: request.nonce,
        };

        self.auth_state
            .insert(&request.state, &auth_state)
            .await
            .or_status()?;

        Ok(Response::new(InitiateUpstreamAuthResponse {
            authorization_url: request.url,
            state_token: request.state,
        }))
    }

    async fn handle_upstream_callback(
        &self,
        request: Request<HandleUpstreamCallbackRequest>,
    ) -> Result<Response<HandleUpstreamCallbackResponse>, Status> {
        // Refused before the pending sign-in is consumed: it completes once
        // maintenance ends.
        self.auth.check_maintenance().await?;
        // Who completes the sign-in decides how its credential is delivered;
        // a browser off the sign-in page completes nothing.
        let ceremony = self.auth.upstream_ceremony(&request)?;
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
            .await
            .or_status()?
            .ok_or_else(|| invalid_field("state", "unknown, expired or already used"))?;

        // Validate redirect_uri matches what was stored during initiation.
        if auth_state.redirect_uri != req.redirect_uri {
            return Err(invalid_field(
                "redirect_uri",
                "does not match the sign-in this state started",
            ));
        }

        let provider_id = auth_state.provider_id;

        let (provider, decrypted_secret) = self
            .providers
            .sign_in_provider(provider_id)
            .await
            .map_err(refusal)?;

        // Create OIDC client for token exchange.
        let oidc_client = OidcProviderClient::from_provider(&provider, decrypted_secret)
            .await
            .map_err(|e| dependency_unavailable("upstream provider", e))?;

        // Exchange the code for the user's claims: for OIDC, the validated
        // ID Token's identity.
        let claims = oidc_client
            .exchange_code(&req.code, &auth_state.pending())
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
            let profile = self
                .storage
                .get_profile(upstream_identity.profile_id)
                .await
                .map_err(storage_failure)?
                // The linked Profile is gone: nobody is signed in.
                .ok_or_else(changed_concurrently)?;
            let signed_in = self
                .auth
                .complete_upstream_sign_in(&profile, &ceremony)
                .await?;

            info!(
                "Upstream login: profile {} via provider {} (returning user)",
                upstream_identity.profile_id, provider_id
            );

            return success(signed_in, false);
        }

        // Path B: No subject match — check for verified email match.
        // A failed lookup fails the sign-in: it never falls through to
        // provisioning a second account for a user who has one.
        let existing = match (&claims.email, claims.has_verified_email()) {
            (Some(email), true) => self
                .storage
                .get_profile_by_email(email)
                .await
                .map_err(storage_failure)?,
            _ => None,
        };
        if existing.is_some()
            && let Some(email) = &claims.email
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

        // Path C: No match at all — JIT provisioning, only when the
        // installation admits a new account.
        // Create a new profile and link the upstream identity.
        self.auth.admit_upstream_account(&claims).await?;
        let username = claims
            .email
            .as_deref()
            .or(Some(&claims.upstream_subject))
            .unwrap_or("upstream-user");

        let mut profile = Profile::new(Some(username));
        // Email stored in profile_emails table, not on Profile directly
        // Upstream OIDC `name` claim → given_name (unstructured).
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

        let signed_in = self
            .auth
            .complete_upstream_sign_in(&profile, &ceremony)
            .await?;

        info!(
            "JIT provisioned profile {} via upstream provider {} (subject: {})",
            profile.id, provider_id, claims.upstream_subject
        );

        success(signed_in, true)
    }
}

/// The callback's answer for `signed_in`: its session, or its pending context
/// with the second factor it owes, as after a password.
fn success(
    signed_in: sid::sign_in::FirstFactorSignedIn,
    new_profile_created: bool,
) -> Result<Response<HandleUpstreamCallbackResponse>, Status> {
    let sid::sign_in::FirstFactorSignedIn {
        signed_in,
        second_factors,
        enrollable_factors,
        browser_csrf,
    } = signed_in;
    signed_in.respond(|session_id, expires_in| HandleUpstreamCallbackResponse {
        result: Some(handle_upstream_callback_response::Result::Success(
            UpstreamAuthSuccess {
                session_id: Some(session_id.into()),
                expires_in,
                new_profile_created,
                second_factors,
                browser_csrf,
                enrollable_factors,
            },
        )),
    })
}

#[cfg(test)]
mod tests;
