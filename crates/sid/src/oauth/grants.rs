// SPDX-License-Identifier: AGPL-3.0-only
//! The token endpoint and its grants, the device authorization endpoint,
//! introspection and revocation.

use std::sync::Arc;

use chrono::{Duration, Utc};
use secrecy::ExposeSecret;
use sid_authn::client_auth::ClientAuthentication;
use sid_authn::device_auth;
use sid_authn::grant::{AccountClaims, CodeGrant, GrantFailure, GrantHost, IdTokenAccount};
use sid_authn::issuer::IssuerSigner;
use sid_authn::oauth2::{IdTokenSource, OAuth2Server, TokenError, TokenResponse};
use sid_authn::resource::RequestTarget;
use sid_authn::target::Target;
use sid_core::Error as SidError;
use sid_core::models::dpop::DPopBinding;
use sid_core::models::{
    AuditEntry, DEVICE_CODE_LIFETIME_SECS, DEVICE_CODE_POLL_INTERVAL_SECS, MachineUser,
    MutationContext, OAuth2Client, OidcIssuer, Profile, ProfileId, ResourceId, SessionId,
};
use sid_plugin::GrantStore;
use sid_proto::sid::v1::{
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, OAuth2IntrospectRequest,
    OAuth2IntrospectResponse, OAuth2RevokeRequest, OAuth2TokenRequest, OAuth2TokenResponse,
};
use tracing::{info, warn};

use super::{OAuth, OAuthError, internal};

/// The grant type a device polls the token endpoint with (RFC 8628 §3.4).
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The token type identifier of an access token (RFC 8693 §3).
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The client authentication a request presents: HTTP Basic in its
/// `authorization` value, or the given body parameters (RFC 6749 §2.3).
fn client_authentication(
    authorization: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
) -> Result<ClientAuthentication, OAuthError> {
    ClientAuthentication::from_request(
        authorization,
        client_id,
        client_secret,
        client_assertion,
        client_assertion_type,
    )
    .map_err(|error| match error {
        TokenError::InvalidRequest => OAuthError::token(
            error,
            "the client must name itself and use one authentication method",
        ),
        _ => OAuthError::ClientRefused,
    })
}

/// A client acting for itself, as its token names it.
#[derive(Clone, Copy)]
struct ClientActor<'a> {
    client_id: &'a str,
    /// Its own principal: a machine user's ID, else the OAuth client's id.
    subject: &'a str,
    /// The credential it authenticated with, checked again by the resource.
    credential: &'a str,
    /// Its own token lifetime cap.
    max_lifetime: Option<Duration>,
}

/// What a token request is answered with.
fn token_response(response: TokenResponse) -> OAuth2TokenResponse {
    OAuth2TokenResponse {
        access_token: response.access_token,
        token_type: response.token_type,
        expires_in: response.expires_in,
        refresh_token: response.refresh_token,
        id_token: response.id_token,
        scope: response.scope,
        issued_token_type: None,
    }
}

/// A grant engine refusal or failure in this endpoint's vocabulary.
fn grant_refusal(failure: GrantFailure<OAuthError>) -> OAuthError {
    match failure {
        GrantFailure::MissingParameter(field) => OAuthError::MissingParameter(field),
        GrantFailure::Refused(error, description) => OAuthError::Token {
            error,
            message: description,
        },
        GrantFailure::ProofMismatch => {
            OAuthError::Dpop("refresh token is bound to another key".into())
        }
        GrantFailure::Storage(e) => OAuthError::Store(e),
        GrantFailure::Issuance(e) => internal("issue tokens", e),
        GrantFailure::Host(e) => e,
    }
}

/// The scopes a machine user's token carries: the requested ones it may
/// have, or all of its own when none are requested. A machine user with no
/// scope list is unrestricted.
fn machine_scopes(mu: &MachineUser, requested: Option<&str>) -> Vec<String> {
    match requested {
        Some(requested) => requested
            .split_whitespace()
            .filter(|s| mu.scopes.is_empty() || mu.scopes.iter().any(|a| a == s))
            .map(String::from)
            .collect(),
        None => mu.scopes.clone(),
    }
}

/// One token request of a local Profile's grant, as the grant engine sees
/// it.
struct ProfileGrant<'a> {
    oauth: &'a OAuth,
    request: &'a OAuth2TokenRequest,
    auth: &'a ClientAuthentication,
    proof_target: &'a RequestTarget,
}

#[async_trait::async_trait]
impl GrantHost for ProfileGrant<'_> {
    type Owner = ProfileId;
    type Account = Profile;
    type Error = OAuthError;

    fn store(&self) -> &dyn GrantStore<Owner = ProfileId> {
        self.oauth.storage.as_ref()
    }

    fn oauth2(&self) -> &OAuth2Server {
        &self.oauth.oauth2
    }

    async fn client(&self) -> Result<(OAuth2Client, OidcIssuer), OAuthError> {
        self.oauth
            .authenticated_client(&self.request.issuer_handle, self.auth)
            .await
    }

    async fn resume_target(
        &self,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        bound: ResourceId,
    ) -> Result<Target, OAuthError> {
        self.oauth
            .resume_target(issuer, client, bound, &self.request.resource)
            .await
    }

    async fn proof(&self) -> Result<Option<DPopBinding>, OAuthError> {
        self.oauth
            .validate_dpop_proof(self.request.dpop_proof.as_deref(), self.proof_target)
            .await
    }

    async fn account(&self, owner: &ProfileId) -> Result<Option<Profile>, OAuthError> {
        Ok(self.oauth.storage.get_profile(*owner).await?)
    }

    /// The Profile's primary contacts for the OIDC claims and its client's
    /// claim mappings; a failed read fails the grant rather than issue
    /// tokens missing the claims.
    async fn claims(
        &self,
        profile: &Profile,
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        scopes: &[String],
    ) -> Result<AccountClaims, OAuthError> {
        let (email, phone) = self.oauth.primary_contacts(profile.id).await?;
        let custom_claims = if client.claim_mappings.is_empty() {
            None
        } else {
            let metadata = self
                .oauth
                .storage
                .list_profile_metadata(profile.id)
                .await
                .map_err(|e| internal("token claims", e))?;
            let resolved = sid_authn::claim_mapping::resolve_claims(
                &client.claim_mappings,
                profile,
                &metadata,
                scopes,
                email.as_ref(),
                phone.as_ref(),
            );
            (!resolved.is_empty()).then_some(resolved)
        };
        let sub = self.oauth.subject_for(issuer, profile.id, client).await?;
        let roles = sid_authn::account_roles::account_roles(self.oauth.storage.as_ref(), profile)
            .await
            .map_err(|e| internal("token claims", e))?;
        Ok(AccountClaims {
            sub,
            roles,
            id_token: Some(IdTokenAccount {
                profile: profile.clone(),
                email,
                phone,
            }),
            custom_claims,
        })
    }

    async fn admit(
        &self,
        client: &OAuth2Client,
        session: &sid_core::models::Session,
    ) -> Result<(), OAuthError> {
        self.oauth.admitted_grant(client, session).await.map(|_| ())
    }

    async fn signer(&self, issuer: &OidcIssuer) -> Result<Arc<IssuerSigner>, OAuthError> {
        self.oauth.issuer_signer(issuer).await
    }

    async fn end_compromised_session(
        &self,
        session: SessionId,
        action: &'static str,
    ) -> Result<(), OAuthError> {
        self.oauth.end_replayed_session(session, action).await
    }
}

impl OAuth {
    /// Whether the login requirements in force for `client`, with the
    /// account protection `session`'s owner has now, still admit the
    /// authentication `session` reports: their fence, which the issuance
    /// commits under, or `invalid_grant` once they ask for more.
    async fn admitted_grant(
        &self,
        client: &OAuth2Client,
        session: &sid_core::models::Session,
    ) -> Result<Option<sid_core::models::ActorFence>, OAuthError> {
        let requirements = self
            .login_requirements(Some(&client.client_id))
            .await?
            .with_client(client, None)
            .for_account(self.storage.as_ref(), session.profile_id)
            .await?;
        match requirements.decide(session, Utc::now()) {
            sid_authn::login_policy::LoginDecision::Allow { .. } => Ok(requirements.fence),
            sid_authn::login_policy::LoginDecision::StepUp(unmet) => {
                info!(client = %client.client_id, ?unmet, "Grant no longer admitted by the login requirements");
                Err(OAuthError::token(
                    TokenError::InvalidGrant,
                    "the grant's authentication no longer meets the login requirements",
                ))
            }
        }
    }

    /// A token request (RFC 6749 §3.2): the grant its `grant_type` names.
    /// `authorization` is the request's `Authorization` value (HTTP Basic),
    /// `client_ip` its client address, `proof_target` the request as
    /// received, which a DPoP proof must name; the proof itself is the
    /// request's `dpop_proof`, from the `DPoP` header only.
    pub async fn token(
        &self,
        req: &OAuth2TokenRequest,
        authorization: Option<&str>,
        client_ip: Option<std::net::IpAddr>,
        proof_target: &RequestTarget,
    ) -> Result<OAuth2TokenResponse, OAuthError> {
        let client = || {
            client_authentication(
                authorization,
                req.client_id.as_deref(),
                req.client_secret.as_deref(),
                req.client_assertion.as_deref(),
                req.client_assertion_type.as_deref(),
            )
        };
        match req.grant_type.as_str() {
            "authorization_code" => {
                let auth = client()?;
                let host = ProfileGrant {
                    oauth: self,
                    request: req,
                    auth: &auth,
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
                    .map_err(grant_refusal)
            }
            "refresh_token" => {
                let auth = client()?;
                let host = ProfileGrant {
                    oauth: self,
                    request: req,
                    auth: &auth,
                    proof_target,
                };
                sid_authn::grant::refresh(&host, req.refresh_token.as_deref())
                    .await
                    .map(token_response)
                    .map_err(grant_refusal)
            }
            "client_credentials" => {
                self.client_credentials(req, &client()?, client_ip, proof_target)
                    .await
            }
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                self.token_exchange(req, &client()?, client_ip).await
            }
            DEVICE_CODE_GRANT => self.device_code(req, &client()?).await,
            _ => Err(OAuthError::token(
                TokenError::UnsupportedGrantType,
                "unsupported grant_type",
            )),
        }
    }

    /// An access token for a client acting for itself (`client_credentials`):
    /// `sub` is the client's own principal and `sid` the credential it used,
    /// `aud` the `target` resource, signed by `issuer`, bound to the
    /// request's DPoP key when it sent a proof.
    async fn client_token(
        &self,
        issuer: &OidcIssuer,
        actor: ClientActor<'_>,
        target: &Target,
        scopes: Vec<String>,
        req: &OAuth2TokenRequest,
        proof_target: &RequestTarget,
    ) -> Result<OAuth2TokenResponse, OAuthError> {
        let dpop_binding = self
            .validate_dpop_proof(req.dpop_proof.as_deref(), proof_target)
            .await?;
        let signer = self.issuer_signer(issuer).await?;
        let client_id = actor.client_id;
        let access_token = self
            .jwt
            .client_access_token_signed_by(
                signer.as_ref(),
                &sid_authn::jwt::ClientGrant {
                    resource: target.audience().as_str(),
                    client_id,
                    subject: actor.subject,
                    credential: actor.credential,
                    scopes: &scopes,
                    dpop: dpop_binding.as_ref(),
                    max_lifetime: actor.max_lifetime,
                },
            )
            .map_err(|e| {
                warn!("Token issuance failed: {}", e);
                OAuthError::Internal
            })?;
        let token_type = if dpop_binding.is_some() {
            "DPoP"
        } else {
            "Bearer"
        };
        info!("Issued client_credentials token for {}", client_id);
        // RFC 6749 §5.1: the lifetime the token actually has.
        let lifetime = self.jwt.access_token_ttl_secs();
        let expires_in = actor
            .max_lifetime
            .map_or(lifetime, |cap| cap.num_seconds().min(lifetime));
        Ok(OAuth2TokenResponse {
            access_token,
            token_type: token_type.to_string(),
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            issued_token_type: None,
        })
    }

    /// A client acting for itself (RFC 6749 §4.4): a registered confidential
    /// client, a provisioning connector, or else a machine user of the
    /// installation.
    async fn client_credentials(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
        proof_target: &RequestTarget,
    ) -> Result<OAuth2TokenResponse, OAuthError> {
        let Some(client) = self.storage.get_oauth2_client(auth.client_id()).await? else {
            if let Some(response) = self.connector_client_credentials(req, auth).await? {
                return Ok(response);
            }
            let (mu, kid, issuer) = self
                .authenticate_machine_user(&req.issuer_handle, auth)
                .await?;
            self.enforce_machine_restrictions(&mu, client_ip).await?;
            let target = self.select_target(&issuer, &mu, &req.resource).await?;
            // Without a requested scope, everything the target grants that
            // the machine user may have (RFC 6749 §3.3).
            let wanted = match req.scope.as_deref() {
                Some(_) => machine_scopes(&mu, req.scope.as_deref()),
                None => target
                    .scopes()
                    .into_iter()
                    .filter(|s| mu.scopes.is_empty() || mu.scopes.contains(s))
                    .collect(),
            };
            let scopes = target.granted_scopes(&wanted);
            let subject = mu.id.to_string();
            let actor = ClientActor {
                client_id: &mu.client_id,
                subject: &subject,
                credential: &kid,
                max_lifetime: mu
                    .max_token_lifetime
                    .map(|seconds| Duration::seconds(i64::from(seconds))),
            };
            return self
                .client_token(&issuer, actor, &target, scopes, req, proof_target)
                .await;
        };
        let issuer = self.client_issuer(&req.issuer_handle, &client).await?;
        self.check_client_authentication(&client, &issuer, auth)
            .await?;
        // RFC 6749 §4.4: only a confidential client may use this grant.
        if client.is_public() || !client.is_grant_type_allowed("client_credentials") {
            return Err(OAuthError::token(
                TokenError::UnauthorizedClient,
                "the client may not use the client_credentials grant",
            ));
        }
        let target = self.select_target(&issuer, &client, &req.resource).await?;
        // The requested scopes the client may have, or all of them when none
        // are requested (RFC 6749 §3.3), limited to what the target grants.
        let requested = match req.scope.as_deref() {
            Some(scope) => {
                let asked: Vec<String> = scope.split_whitespace().map(String::from).collect();
                client.filter_scopes(&asked)
            }
            None => client.allowed_scopes.clone(),
        };
        let scopes = target.granted_scopes(&requested);
        // An OAuth client has one registered credential; its client_id names
        // both the principal and that authentication.
        let actor = ClientActor {
            client_id: &client.client_id,
            subject: &client.client_id,
            credential: &client.client_id,
            max_lifetime: None,
        };
        self.client_token(&issuer, actor, &target, scopes, req, proof_target)
            .await
    }

    /// `client_credentials` for a provisioning connector: `None` when the
    /// client_id names no connector. A connector authenticates with a client
    /// secret of its own (client_secret_basic or client_secret_post) and gets
    /// a token for its SCIM directory resource only, with the provisioning
    /// scopes it asked for that its grants allow now. The token's `sub` is
    /// the connector, `client_id` its client_id and `sid` the credential it
    /// used, so the resource checks all three again on every request.
    async fn connector_client_credentials(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
    ) -> Result<Option<OAuth2TokenResponse>, OAuthError> {
        let caller = match auth {
            ClientAuthentication::Basic { secret, .. }
            | ClientAuthentication::Post { secret, .. } => {
                sid_authn::connector_auth::authenticate_connector_client(
                    self.storage.as_ref(),
                    self.installation_org,
                    auth.client_id(),
                    secret.expose_secret(),
                )
                .await
                .map_err(|e| match e {
                    sid_authn::resource_token::OwnTokenError::Unauthenticated => {
                        OAuthError::ClientRefused
                    }
                    sid_authn::resource_token::OwnTokenError::Storage(e) => OAuthError::Store(e),
                })?
            }
            // A connector has no key credential and is never a public client.
            _ => {
                return if self
                    .storage
                    .get_provisioning_connector_by_client_id(auth.client_id())
                    .await?
                    .is_some()
                {
                    Err(OAuthError::ClientRefused)
                } else {
                    Ok(None)
                };
            }
        };
        let Some(caller) = caller else {
            return Ok(None);
        };
        let issuer = self
            .issuer_serving(&req.issuer_handle, Some(self.installation_org))
            .await?
            .ok_or(OAuthError::ClientRefused)?;
        // The SCIM resource takes no DPoP proof, so a sender-constrained
        // token would be unusable there (RFC 9449 §7.1).
        if req.dpop_proof.as_deref().is_some_and(|p| !p.is_empty()) {
            return Err(OAuthError::token(
                TokenError::InvalidRequest,
                "a provisioning connector's token is a bearer token",
            ));
        }
        let directory = sid_core::models::ResourceIndicator::parse(
            &sid_authn::issuer::scim_endpoint(&issuer.canonical_url),
        )
        .map_err(|e| internal("SCIM resource indicator", e))?;
        let requested =
            sid_authn::target::requested_indicator(&req.resource).map_err(OAuthError::Target)?;
        let resource = sid_authn::target::connector_target(
            self.storage.as_ref(),
            issuer.id,
            &directory,
            requested.as_ref(),
        )
        .await?
        .map_err(OAuthError::Target)?;
        // Without a requested scope, every provisioning scope (RFC 6749
        // §3.3); in any case only those its grants allow now.
        let wanted: Vec<String> = match req.scope.as_deref() {
            Some(scope) => scope.split_whitespace().map(String::from).collect(),
            None => resource.scopes.clone(),
        };
        let mut scopes = Vec::new();
        for scope in wanted {
            if !resource.scopes.contains(&scope) || scopes.contains(&scope) {
                continue;
            }
            let decision = self
                .authz
                .check(&sid_authz::AuthzCheckRequest {
                    subject: format!("provisioning_connector:{}", caller.connector.id),
                    action: scope.clone(),
                    resource: format!("oauth_resource:{}", resource.id),
                    context: Default::default(),
                })
                .await
                .map_err(|e| OAuthError::unavailable("provisioning authorization", e))?;
            if decision.is_allowed() {
                scopes.push(scope);
            }
        }
        if scopes.is_empty() {
            return Err(OAuthError::token(
                TokenError::InvalidScope,
                "the connector is granted none of the requested scopes",
            ));
        }
        let signer = self.issuer_signer(&issuer).await?;
        let access_token = self
            .jwt
            .client_access_token_signed_by(
                signer.as_ref(),
                &sid_authn::jwt::ClientGrant {
                    resource: resource.indicator.as_str(),
                    client_id: caller.connector.client_id.as_str(),
                    subject: &caller.connector.id.to_string(),
                    credential: &caller.credential_id.to_string(),
                    scopes: &scopes,
                    dpop: None,
                    max_lifetime: None,
                },
            )
            .map_err(|e| internal("connector token", e))?;
        info!(connector = %caller.connector.id, "Issued client_credentials token for a provisioning connector");
        Ok(Some(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt.access_token_ttl_secs(),
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            issued_token_type: None,
        }))
    }

    /// The device_code grant (RFC 8628 §3.4): a device's poll, answered with
    /// tokens once, after the user approved, or with the state of the request
    /// as an RFC 8628 §3.5 error.
    async fn device_code(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
    ) -> Result<OAuth2TokenResponse, OAuthError> {
        let raw_code = req
            .device_code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or(OAuthError::MissingParameter("device_code"))?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, auth).await?;
        if !client.is_grant_type_allowed(DEVICE_CODE_GRANT) {
            return Err(OAuthError::token(
                TokenError::UnauthorizedClient,
                "the client may not use the device authorization grant",
            ));
        }
        let code_hash = device_auth::hash_device_code(raw_code);
        let unknown = || OAuthError::token(TokenError::InvalidGrant, "unknown device code");
        let code = self
            .storage
            .get_device_auth_by_device_code_hash(&code_hash)
            .await?
            .ok_or_else(unknown)?;
        // A code issued to another client is unknown to this one (RFC 6749
        // §5.2 `invalid_grant`), and takes no effect here.
        if code.client_id != client.client_id {
            return Err(unknown());
        }
        // A device code grants once, like an authorization code (RFC 6749
        // §4.1.2): a code already exchanged gets nothing, whatever its pace,
        // and the session its first exchange opened is ended.
        if code.status == sid_core::models::DeviceAuthStatus::Redeemed {
            self.revoke_compromised_session(code.redeemed_session_id, "device_code.reuse")
                .await?;
            return Err(OAuthError::token(
                TokenError::InvalidGrant,
                "device code already used",
            ));
        }
        // slow_down (RFC 8628 §3.5): the check and the recorded poll are one
        // step, so concurrent polls cannot both pass.
        let pace = self
            .storage
            .record_device_poll(
                code.id,
                AuditEntry::system("device_auth.poll", code.id.0.to_string()).into(),
            )
            .await?;
        if pace == sid_core::models::DevicePoll::SlowDown {
            return Err(OAuthError::SlowDown {
                interval: code.interval,
            });
        }
        match device_auth::validate_poll(&code) {
            Ok(()) => {}
            Err(device_auth::DeviceAuthError::AuthorizationPending) => {
                return Err(OAuthError::token(
                    TokenError::AuthorizationPending,
                    "the user has not decided yet",
                ));
            }
            Err(device_auth::DeviceAuthError::SlowDown) => {
                return Err(OAuthError::SlowDown {
                    interval: code.interval,
                });
            }
            Err(device_auth::DeviceAuthError::ExpiredToken) => {
                return Err(OAuthError::token(
                    TokenError::ExpiredToken,
                    "the device code expired",
                ));
            }
            Err(device_auth::DeviceAuthError::AccessDenied) => {
                return Err(OAuthError::token(
                    TokenError::AccessDenied,
                    "the user denied the request",
                ));
            }
            Err(e) => {
                warn!(error = %e, "device poll in an unexpected state");
                return Err(OAuthError::Internal);
            }
        }
        // The tokens are for the resource the device transaction is bound to.
        let target = self
            .resume_target(&issuer, &client, code.resource, &req.resource)
            .await?;
        let profile_id = code
            .authorized_by
            .ok_or_else(|| internal("storage", "an approved device code has no approver"))?;
        let profile = self.storage.get_profile(profile_id).await?.ok_or_else(|| {
            OAuthError::token(
                TokenError::InvalidGrant,
                "the approving account no longer exists",
            )
        })?;
        // The device's session reports the authentication approved under; the
        // tokens are issued only while the requirements in force, with the
        // account's protection now, still admit it, and commit under their
        // fence.
        let approved = code
            .authorized_with
            .as_ref()
            .ok_or_else(|| internal("storage", "an approved device code has no authentication"))?;
        let mut session =
            sid_core::models::Session::new(profile.id, None, Utc::now() + Duration::hours(24))
                .with_grant_authentication(approved);
        session.client_id = Some(client.client_id.clone());
        session.scopes = code
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();
        let fence = self.admitted_grant(&client, &session).await?;
        let sub = self.subject_for(&issuer, profile.id, &client).await?;
        let (primary_email, primary_phone) = self.primary_contacts(profile.id).await?;
        let signer = self.issuer_signer(&issuer).await?;
        let roles =
            sid_authn::account_roles::account_roles(self.storage.as_ref(), &profile).await?;
        let (response, refresh_model) = self
            .oauth2
            .issue_tokens(
                &signer,
                &sub,
                &roles,
                &session,
                &client,
                &target,
                &session.scopes,
                None,
                None,
                None,
                Some(IdTokenSource {
                    profile: &profile,
                    email: primary_email.as_ref(),
                    phone: primary_phone.as_ref(),
                }),
            )
            .map_err(|e| internal("issue tokens", e))?;
        // The code, the session and the refresh token are committed
        // together: of concurrent polls exactly one gets tokens.
        let mut ctx: MutationContext = AuditEntry::user(
            profile.id.to_string(),
            "device_code.exchange",
            session.id.to_string(),
        )
        .into();
        if let Some(fence) = fence {
            ctx = ctx.fenced_by(fence);
        }
        let redemption = match self
            .storage
            .redeem_device_code(&code_hash, &session, &refresh_model, ctx)
            .await
        {
            Ok(redemption) => redemption,
            Err(SidError::Fenced(_)) => return Err(OAuthError::PolicyChanged),
            Err(e) => return Err(e.into()),
        };
        match redemption {
            sid_core::models::DeviceCodeRedemption::Redeemed => {}
            sid_core::models::DeviceCodeRedemption::AlreadyRedeemed { session_id } => {
                self.revoke_compromised_session(session_id, "device_code.reuse")
                    .await?;
                return Err(OAuthError::token(
                    TokenError::InvalidGrant,
                    "device code already used",
                ));
            }
            // Expired or decided otherwise between the read and the exchange.
            sid_core::models::DeviceCodeRedemption::NotAuthorized => {
                return Err(OAuthError::token(
                    TokenError::InvalidGrant,
                    "device code is not authorized",
                ));
            }
        }
        info!(
            "Device authorization completed for client={}, profile={}",
            client.client_id, profile.id
        );
        Ok(OAuth2TokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
            refresh_token: response.refresh_token,
            id_token: response.id_token,
            scope: response.scope,
            issued_token_type: None,
        })
    }

    /// RFC 8693 token exchange: an authenticated machine user presents a
    /// `subject_token` of the target user's own sign-in and gets a
    /// short-lived impersonation token with an `act` claim.
    async fn token_exchange(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<OAuth2TokenResponse, OAuthError> {
        use sid_core::models::machine_user::IMPERSONATION_MAX_LIFETIME_SECONDS;

        let (mu, _, _issuer) = self
            .authenticate_machine_user(&req.issuer_handle, auth)
            .await?;
        self.enforce_machine_restrictions(&mu, client_ip).await?;
        // RFC 8693 §2.2.2: an invalid or unacceptable request, subject token
        // included, is `invalid_request`.
        let subject_token = req
            .subject_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or(OAuthError::MissingParameter("subject_token"))?;
        let subject_token_type = req
            .subject_token_type
            .as_deref()
            .unwrap_or(ACCESS_TOKEN_TYPE);
        if subject_token_type != ACCESS_TOKEN_TYPE {
            return Err(OAuthError::token(
                TokenError::InvalidRequest,
                "only subject_token_type=urn:ietf:params:oauth:token-type:access_token is supported",
            ));
        }
        // RFC 8693 §2.1, §2.2.2: only an access token is issued; another
        // requested type is refused, never answered with an access token.
        if req
            .requested_token_type
            .as_deref()
            .is_some_and(|wanted| wanted != ACCESS_TOKEN_TYPE)
        {
            return Err(OAuthError::token(
                TokenError::InvalidRequest,
                "only requested_token_type=urn:ietf:params:oauth:token-type:access_token is supported",
            ));
        }
        // The exchange issues the installation's own impersonation token. A
        // target named by `resource` or `audience` (RFC 8693 §2.1) is refused
        // rather than ignored, so no token is issued for another audience
        // than the client asked for.
        if sid_authn::target::exchange_indicator(&req.resource, &req.audience)
            .map_err(OAuthError::Target)?
            .is_some()
        {
            return Err(OAuthError::Target(
                sid_authn::target::TargetRefusal::NotExchangeable,
            ));
        }
        // The subject token is the target user's own sign-in: verified like
        // any bearer token (revocation included). A PAT-derived or
        // impersonation token is refused, so an impersonation cannot be
        // renewed by exchanging its own token.
        let invalid_subject =
            || OAuthError::token(TokenError::InvalidRequest, "invalid subject_token");
        let target_claims =
            sid_authn::caller::verify_token(subject_token, self.jwt.verifier(), &self.revocation)
                .await
                .map_err(|e| match e {
                    unavailable @ sid_authn::caller::CallerError::Unavailable { .. } => {
                        OAuthError::Caller(unavailable)
                    }
                    _ => invalid_subject(),
                })?;
        let subject = sid_authn::caller::Caller::from_claims(&target_claims)
            .map_err(|_| invalid_subject())?;
        if subject.kind() != sid_authn::caller::TokenKind::Interactive {
            return Err(invalid_subject());
        }
        let profile_id = subject.profile_id;
        let target_profile_id = profile_id.to_string();
        let target_profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or_else(invalid_subject)?;
        // A suspended, closing or closed account cannot be acted for.
        if !target_profile.status.can_authenticate() {
            return Err(invalid_subject());
        }
        let grants = self.storage.list_impersonation_grants(mu.id).await?;
        let grant = grants
            .iter()
            .find(|g| match g.target_type {
                sid_core::models::ImpersonationTargetType::User => g.target == target_profile_id,
                sid_core::models::ImpersonationTargetType::Role => {
                    target_profile.roles.iter().any(|r| r == &g.target)
                }
            })
            // A subject the client may not act for is unacceptable by
            // policy: `invalid_request` (RFC 8693 §2.2.2).
            .ok_or_else(|| {
                OAuthError::token(
                    TokenError::InvalidRequest,
                    "the client may not act for this subject",
                )
            })?;
        // Requested ∩ the machine user's scopes ∩ the grant's ∩ what the
        // target's own token holds: impersonation never exceeds the user.
        let scopes: Vec<String> = machine_scopes(&mu, req.scope.as_deref())
            .into_iter()
            .filter(|s| grant.allows_all_scopes() || grant.allows_scope(s))
            .filter(|s| target_claims.scope.split_whitespace().any(|t| t == s))
            .collect();
        if scopes.is_empty() {
            return Err(OAuthError::token(
                TokenError::InvalidScope,
                "no scopes available for impersonation after intersection",
            ));
        }
        // The impersonation is a session of the target: it shows in the
        // target's sessions, and revoking it or the target's access ends the
        // token. It is recorded together with its audit entry.
        let lifetime = Duration::seconds(i64::from(IMPERSONATION_MAX_LIFETIME_SECONDS));
        let mut session =
            sid_core::models::Session::new(profile_id, client_ip, Utc::now() + lifetime);
        session.client_id = Some(mu.client_id.clone());
        session.scopes = scopes.clone();
        session.amr = vec!["token_exchange".to_string()];
        let audit = AuditEntry::machine(
            mu.id.to_string(),
            "sid.token.impersonation.v1",
            format!("profile:{profile_id}"),
        )
        .with_ip(client_ip)
        .with_metadata(serde_json::json!({
            "actor": { "type": "machine", "id": mu.id.to_string(), "client_id": mu.client_id },
            "target": { "type": "user", "id": target_profile_id },
            "session_id": session.id.to_string(),
            "scopes": scopes,
        }));
        self.storage.create_session(&session, audit.into()).await?;
        // sub = target, act.sub = machine user.
        let access_token = self
            .jwt
            .issue_impersonation_token(&target_profile_id, &session, &mu.client_id, &scopes)
            .map_err(|e| internal("issue impersonation token", e))?;
        Ok(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: lifetime.num_seconds(),
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            // RFC 8693 §2.2.1: required in a token exchange response.
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
        })
    }

    /// The authenticated inspector at `issuer_handle`, as its authorization
    /// subject, with the issuer: a confidential OAuth client, or else a
    /// machine user, resolved as the token endpoint resolves a client id. A
    /// machine user's credentials resolve to that machine user under its
    /// restrictions, never to an OAuth client.
    async fn inspector(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(String, OidcIssuer), OAuthError> {
        if let Some(client) = self.storage.get_oauth2_client(auth.client_id()).await? {
            // A public client has no credential to authenticate with.
            if client.is_public() {
                return Err(OAuthError::ClientRefused);
            }
            let issuer = self.client_issuer(issuer_handle, &client).await?;
            self.check_client_authentication(&client, &issuer, auth)
                .await?;
            return Ok((format!("oauth_client:{}", client.client_id), issuer));
        }
        let (machine, _, issuer) = self.authenticate_machine_user(issuer_handle, auth).await?;
        self.enforce_machine_restrictions(&machine, client_ip)
            .await?;
        Ok((format!("machine:{}", machine.id), issuer))
    }

    /// Token introspection (RFC 7662). Only an authenticated service
    /// identity of this issuer may introspect, so tokens cannot be probed;
    /// a token this issuer does not vouch for, or one the inspector may not
    /// inspect, is only inactive.
    pub async fn introspect(
        &self,
        req: &OAuth2IntrospectRequest,
        authorization: Option<&str>,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<OAuth2IntrospectResponse, OAuthError> {
        let auth = client_authentication(
            authorization,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (inspector, issuer) = self.inspector(&req.issuer_handle, &auth, client_ip).await?;
        let inactive = OAuth2IntrospectResponse::default;
        let verifier = self
            .issuers
            .verifier(&issuer)
            .await
            .map_err(|e| internal("read issuer keys for introspection", e))?;
        // Only this issuer's access tokens are active here (RFC 7662 §2.2).
        let Ok(claims) = verifier.validate_access_token(&req.token) else {
            return Ok(inactive());
        };
        // The token's target is the registered resource its one audience
        // names; the inspector must hold the inspection permission on it.
        let target = match claims.aud.as_slice() {
            [audience] => match sid_core::models::ResourceIndicator::parse(audience) {
                Ok(indicator) => {
                    self.storage
                        .protected_resource_by_indicator(issuer.id, &indicator)
                        .await?
                }
                Err(_) => None,
            },
            _ => None,
        };
        let Some(target) = target else {
            return Ok(inactive());
        };
        let decision = self
            .authz
            .check(&sid_authz::AuthzCheckRequest {
                subject: inspector,
                action: sid_core::models::TOKEN_INTROSPECT.to_string(),
                resource: format!("oauth_resource:{}", target.id),
                context: Default::default(),
            })
            .await
            // Never disclose claims without a decision.
            .map_err(|e| OAuthError::unavailable("inspection permission", e))?;
        if !decision.is_allowed() {
            return Ok(inactive());
        }
        if sid_authn::caller::check_revocation(&self.revocation, &claims)
            .await
            .map_err(OAuthError::Caller)?
        {
            return Ok(inactive());
        }
        // A valid signature says what was true at issuance; the token is
        // active only while the actor it stands for can act now. An
        // unreadable state is an error, never a guess (RFC 7662 §2.2).
        if sid_authn::token_state::current_state(self.storage.as_ref(), &claims)
            .await
            .map_err(|e| OAuthError::unavailable("token state", e))?
            == sid_authn::token_state::TokenState::Inactive
        {
            return Ok(inactive());
        }
        Ok(OAuth2IntrospectResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: claims.client_id,
            username: None,
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
        })
    }

    /// Token revocation (RFC 7009): the client authenticates as at the token
    /// endpoint (a public one only names itself), and only a token issued to
    /// it is revoked; another client's token is refused. An unknown token is
    /// not an error.
    pub async fn revoke(
        &self,
        req: &OAuth2RevokeRequest,
        authorization: Option<&str>,
    ) -> Result<(), OAuthError> {
        let auth = client_authentication(
            authorization,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, &auth).await?;
        let not_its_own = || {
            OAuthError::token(
                TokenError::UnauthorizedClient,
                "the token was issued to another client",
            )
        };
        let verifier = self
            .issuers
            .verifier(&issuer)
            .await
            .map_err(|e| internal("read issuer keys for revocation", e))?;
        // Only this issuer's tokens are revoked here; a token of another
        // issuer is left alone and the answer is still success (RFC 7009
        // §2.2).
        if let Ok(claims) = verifier.validate_access_token(&req.token) {
            if claims.client_id.as_deref() != Some(client.client_id.as_str()) {
                return Err(not_its_own());
            }
            let remaining = claims.exp - Utc::now().timestamp();
            if remaining > 0 {
                self.revocation
                    .revoke_jti(
                        claims.jti.clone(),
                        std::time::Duration::from_secs(remaining as u64),
                    )
                    .await
                    .map_err(|e| OAuthError::unavailable("token revocation", e))?;
            }
            return Ok(());
        }
        // Revoke as a refresh token, found by its value: the whole grant
        // ends with it, the token it replaced still inside its rotation grace
        // window included (RFC 7009 §2.1). An unknown value is not an error
        // (§2.2), a storage fault is.
        let token_hash = OAuth2Server::hash_token(&req.token);
        if let Some(refresh) = self.storage.get_refresh_token_by_hash(&token_hash).await? {
            if refresh.client_id != client.client_id {
                return Err(not_its_own());
            }
            self.storage
                .revoke_refresh_tokens_by_family(
                    refresh.family_id,
                    AuditEntry::system("token.revoke", refresh.id.to_string()).into(),
                )
                .await?;
        }
        Ok(())
    }

    /// Start a device authorization (RFC 8628 §3.1, §3.2): the client
    /// authenticates as at the token endpoint and must be registered for the
    /// device grant; the transaction is bound to the resource its tokens
    /// will be for and records only the scopes the client may have.
    pub async fn start_device_authorization(
        &self,
        req: &DeviceAuthorizationRequest,
        authorization: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse, OAuthError> {
        let auth = client_authentication(
            authorization,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, &auth).await?;
        if !client.is_grant_type_allowed(DEVICE_CODE_GRANT) {
            return Err(OAuthError::token(
                TokenError::UnauthorizedClient,
                "the client may not use the device authorization grant",
            ));
        }
        let target = self.select_target(&issuer, &client, &req.resource).await?;
        let scope = req.scope.as_deref().map(|requested| {
            let requested: Vec<String> = requested.split_whitespace().map(String::from).collect();
            client.filter_scopes(&requested).join(" ")
        });
        // The user sees "WDJB-MJHT"; it is stored as looked up, normalized. A
        // taken code (one in 20^8) is drawn again.
        const CODE_ATTEMPTS: usize = 3;
        let mut issued = None;
        for _ in 0..CODE_ATTEMPTS {
            let user_code = device_auth::generate_user_code();
            let (raw_device_code, device_code_hash) = device_auth::generate_device_code();
            let auth_code = sid_core::models::DeviceAuthorizationCode::new(
                client.client_id.clone(),
                device_code_hash,
                device_auth::normalize_user_code(&user_code),
                scope.clone(),
                target.resource_id(),
                client.project_id,
            );
            let audit = AuditEntry::system(
                "device_authorization.start",
                format!("client_id={}", client.client_id),
            );
            match self
                .storage
                .create_device_auth_code(&auth_code, audit.into())
                .await
            {
                Ok(()) => {
                    issued = Some((user_code, raw_device_code));
                    break;
                }
                Err(SidError::Conflict(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let (user_code, raw_device_code) = issued.ok_or_else(|| {
            internal(
                "storage",
                format!("no free device user code after {CODE_ATTEMPTS} attempts"),
            )
        })?;
        let verification_uri = format!("{}/device", self.installation_url);
        let verification_uri_complete =
            device_auth::build_verification_uri_complete(&verification_uri, &user_code);
        info!(
            "Device authorization started for client={}",
            client.client_id
        );
        Ok(DeviceAuthorizationResponse {
            device_code: raw_device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: DEVICE_CODE_LIFETIME_SECS as i32,
            interval: DEVICE_CODE_POLL_INTERVAL_SECS,
        })
    }
}

#[cfg(test)]
mod tests;
