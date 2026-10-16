// SPDX-License-Identifier: AGPL-3.0-only
//! The authorization code and refresh token grants, run by the shared grant
//! engine with this server's storage and its Profile accounts.

use sid_authn::client_auth::ClientAuthentication;
use sid_authn::grant::{AccountClaims, CodeGrant, GrantFailure, GrantHost, IdTokenAccount};
use sid_authn::oauth2::{OAuth2Server, TokenResponse};
use sid_authn::target::Target;
use sid_core::grpc_error::refuse::{internal, storage_failure};
use sid_core::models::dpop::DPopBinding;
use sid_core::models::{
    OAuth2Client, OidcIssuer, Profile, ProfileId, ResourceId, RevocationReason, SessionId,
};
use sid_plugin::GrantStore;
use sid_proto::sid::v1::{OAuth2TokenRequest, OAuth2TokenResponse};
use std::sync::Arc;
use tonic::{Response, Status};

use super::{
    AuthServiceImpl, claims_unavailable, dpop_refusal, missing_parameter, resolve_claims,
    token_refusal,
};

/// One token request of a local Profile's grant, as the grant engine sees it.
struct ProfileGrant<'a> {
    service: &'a AuthServiceImpl,
    request: &'a OAuth2TokenRequest,
    auth: &'a ClientAuthentication,
    proof_target: &'a sid_authn::resource::RequestTarget,
}

#[async_trait::async_trait]
impl GrantHost for ProfileGrant<'_> {
    type Owner = ProfileId;
    type Account = Profile;
    type Error = Status;

    fn store(&self) -> &dyn GrantStore<Owner = ProfileId> {
        self.service.storage.as_ref()
    }

    fn oauth2(&self) -> &OAuth2Server {
        &self.service.oauth2
    }

    async fn client(&self) -> Result<(OAuth2Client, OidcIssuer), Status> {
        self.service
            .authenticated_client(&self.request.issuer_handle, self.auth)
            .await
    }

    async fn resume_target(
        &self,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        bound: ResourceId,
    ) -> Result<Target, Status> {
        self.service
            .resume_target(issuer, client, bound, &self.request.resource)
            .await
    }

    async fn proof(&self) -> Result<Option<DPopBinding>, Status> {
        self.service
            .validate_dpop_proof(&self.request.dpop_proof, self.proof_target)
            .await
    }

    async fn account(&self, owner: &ProfileId) -> Result<Option<Profile>, Status> {
        self.service
            .storage
            .get_profile(*owner)
            .await
            .map_err(storage_failure)
    }

    /// The Profile's primary contacts for the OIDC claims and its client's
    /// claim mappings (AUTH-017); a failed read fails the grant rather than
    /// issue tokens missing the claims.
    async fn claims(
        &self,
        profile: &Profile,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        scopes: &[String],
    ) -> Result<AccountClaims, Status> {
        let (email, phone) = self.service.primary_contacts(profile.id).await?;
        let custom_claims = if client.claim_mappings.is_empty() {
            None
        } else {
            let metadata = self
                .service
                .storage
                .list_profile_metadata(profile.id)
                .await
                .map_err(claims_unavailable)?;
            let resolved = resolve_claims(
                &client.claim_mappings,
                profile,
                &metadata,
                scopes,
                email.as_ref(),
                phone.as_ref(),
            );
            (!resolved.is_empty()).then_some(resolved)
        };
        let sub = self.service.subject_for(issuer, profile.id, client).await?;
        Ok(AccountClaims {
            sub,
            roles: profile.roles.clone(),
            id_token: Some(IdTokenAccount {
                profile: profile.clone(),
                email,
                phone,
            }),
            custom_claims,
        })
    }

    async fn signer(
        &self,
        issuer: &OidcIssuer,
    ) -> Result<Arc<sid_authn::issuer::IssuerSigner>, Status> {
        self.service.issuer_signer(issuer).await
    }

    async fn end_compromised_session(
        &self,
        session: SessionId,
        action: &'static str,
    ) -> Result<(), Status> {
        self.service.end_replayed_session(session, action).await
    }

    fn session_address(&self) -> String {
        "grpc".to_string()
    }
}

/// The token endpoint's answer to a refused or failed grant.
fn grant_status(failure: GrantFailure<Status>) -> Status {
    match failure {
        GrantFailure::MissingParameter(field) => missing_parameter(field),
        GrantFailure::Refused(error, description) => token_refusal(error, description),
        GrantFailure::ProofMismatch => dpop_refusal("refresh token is bound to another key"),
        GrantFailure::Storage(e) => storage_failure(e),
        GrantFailure::Issuance(e) => internal("issue tokens", e),
        GrantFailure::Host(status) => status,
    }
}

fn token_response(response: TokenResponse) -> Response<OAuth2TokenResponse> {
    Response::new(OAuth2TokenResponse {
        access_token: response.access_token,
        token_type: response.token_type,
        expires_in: response.expires_in,
        refresh_token: response.refresh_token,
        id_token: response.id_token,
        scope: response.scope,
        issued_token_type: None,
    })
}

impl AuthServiceImpl {
    pub(super) async fn handle_authorization_code_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let host = ProfileGrant {
            service: self,
            request: req,
            auth,
            proof_target,
        };
        let request = CodeGrant {
            code: req.code.as_deref(),
            redirect_uri: req.redirect_uri.as_deref(),
            code_verifier: req.code_verifier.as_deref(),
        };
        sid_authn::grant::redeem_code(&host, request)
            .await
            .map(token_response)
            .map_err(grant_status)
    }

    pub(super) async fn handle_refresh_token_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let host = ProfileGrant {
            service: self,
            request: req,
            auth,
            proof_target,
        };
        sid_authn::grant::refresh(&host, req.refresh_token.as_deref())
            .await
            .map(token_response)
            .map_err(grant_status)
    }

    /// End a session whose credential was replayed (a reused authorization
    /// code, device code or refresh token): its access tokens, refresh tokens
    /// and the session itself. `action` names the replay in the audit trail.
    pub(super) async fn revoke_compromised_session(
        &self,
        session_id: Option<SessionId>,
        action: &str,
    ) -> Result<(), Status> {
        let Some(session_id) = session_id else {
            return Ok(());
        };
        tracing::warn!(%session_id, action, "credential replayed; revoking its session");
        self.end_replayed_session(session_id, action).await
    }

    async fn end_replayed_session(
        &self,
        session_id: SessionId,
        action: &str,
    ) -> Result<(), Status> {
        self.cascade
            .revoke_session(
                session_id,
                RevocationReason::AnomalyDetected,
                "system",
                action,
            )
            .await
            .map(drop)
            .map_err(|e| internal("revoke a compromised session", e))
    }
}
