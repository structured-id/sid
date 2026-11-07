// SPDX-License-Identifier: AGPL-3.0-only
//! The OAuth endpoints of an installation's issuers, transport-free: the token
//! endpoint with every grant it serves (RFC 6749 authorization code, refresh
//! and client credentials, RFC 8628 device code, RFC 8693 token exchange),
//! the device authorization endpoint, introspection (RFC 7662) and revocation
//! (RFC 7009), and what they share with sign-in: the issuer a request
//! reaches, its client's authentication, the target resource, the issuer's
//! signer, the request's sender proof and the subject a token carries. A
//! host parses its transport into the typed requests and answers each
//! [`OAuthError`] in that transport.

use std::borrow::Cow;
use std::sync::Arc;

use secrecy::ExposeSecret;
use sid_authn::caller::CallerError;
use sid_authn::client_auth::ClientAuthentication;
use sid_authn::dpop::DPopValidator;
use sid_authn::issuer::{IssuerRegistry, IssuerSigner};
use sid_authn::jwt::JwtService;
use sid_authn::login_policy::{LoginPolicySource, LoginRequirements};
use sid_authn::oauth2::{OAuth2Server, TokenError};
use sid_authn::resource::RequestTarget;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::subject::{SubjectRule, resolve_subject};
use sid_authn::target::{Requester, Target, TargetRefusal};
use sid_core::Error as SidError;
use sid_core::models::dpop::DPopBinding;
use sid_core::models::{
    MachineUser, OAuth2Client, OidcIssuer, OrgId, ProfileEmail, ProfileId, ProfilePhone,
    ResourceId, RevocationReason, SessionId,
};
use sid_plugin::cache::CacheBackend;
use sid_plugin::storage::StorageBackend;
use tracing::warn;

use crate::rate_limit::{RateLimitStats, RateLimiter};

mod grants;
pub use grants::{ACCESS_TOKEN_TYPE, DEVICE_CODE_GRANT};

/// Why an OAuth endpoint refused or failed a request. Each refusal names the
/// RFC 6749 §5.2 (or RFC 8628 §3.5, RFC 9449 §7.1) error the host answers
/// with; a failure of the installation carries its cause to the log only.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// A token endpoint refusal with `error`.
    #[error("{error:?}: {message}")]
    Token {
        error: TokenError,
        message: Cow<'static, str>,
    },
    /// The device polls faster than its `interval` seconds; it waits five
    /// more (RFC 8628 §3.5 `slow_down`).
    #[error("slow down")]
    SlowDown { interval: i32 },
    /// The client failed to authenticate (`invalid_client`); what failed
    /// goes to the log, never to the client.
    #[error("client authentication failed")]
    ClientRefused,
    /// The target resource is refused (RFC 8707 §2 `invalid_target`).
    #[error(transparent)]
    Target(TargetRefusal),
    /// A required parameter is missing (`invalid_request`).
    #[error("{0} is required")]
    MissingParameter(&'static str),
    /// The DPoP proof is not valid for the request (`invalid_dpop_proof`).
    #[error("invalid DPoP proof: {0}")]
    Dpop(String),
    /// A dependency the decision needs cannot answer now; the client
    /// retries.
    #[error("{what} unavailable: {cause}")]
    Unavailable { what: &'static str, cause: String },
    /// The caller's token could not be checked.
    #[error(transparent)]
    Caller(CallerError),
    /// The machine user exceeded its `rpm` token requests per minute.
    #[error("rate limit exceeded")]
    RateLimited { rpm: u32 },
    /// The login policy changed while the grant was committed; the client
    /// asks again.
    #[error("the login policy changed")]
    PolicyChanged,
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log, not the
    /// refusal.
    #[error("internal error")]
    Internal,
}

impl OAuthError {
    /// A token endpoint refusal with `error` and `message`.
    pub fn token(error: TokenError, message: impl Into<Cow<'static, str>>) -> Self {
        Self::Token {
            error,
            message: message.into(),
        }
    }

    fn unavailable(what: &'static str, cause: impl std::fmt::Display) -> Self {
        Self::Unavailable {
            what,
            cause: cause.to_string(),
        }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> OAuthError {
    tracing::error!(operation, error = %cause, "internal failure");
    OAuthError::Internal
}

/// What the OAuth endpoints of one installation are built from.
pub struct OAuthParts {
    pub storage: Arc<dyn StorageBackend>,
    pub oauth2: Arc<OAuth2Server>,
    pub jwt: Arc<JwtService>,
    pub issuers: Arc<IssuerRegistry>,
    /// The installation's organization: machine users and provisioning
    /// connectors belong to it, and only its issuer serves them.
    pub installation_org: OrgId,
    /// Decides who may inspect a resource's tokens and what a connector is
    /// granted.
    pub authz: Arc<sid_authz::CeAuthzEngine<dyn StorageBackend>>,
    pub revocation: Arc<RevocationCache>,
    /// Ends a session everywhere when one of its credentials is replayed.
    pub cascade: Arc<RevocationCascadeService>,
    /// The cache every replica shares: machine user rate limits count there.
    pub cache: Arc<dyn CacheBackend>,
    /// Where the login requirements come from.
    pub login_policy: Arc<dyn LoginPolicySource>,
    /// The installation URL (`https://sid.example.com`): the device
    /// verification page is under it.
    pub installation_url: String,
}

/// The OAuth endpoints of one installation.
pub struct OAuth {
    storage: Arc<dyn StorageBackend>,
    oauth2: Arc<OAuth2Server>,
    jwt: Arc<JwtService>,
    issuers: Arc<IssuerRegistry>,
    installation_org: OrgId,
    authz: Arc<sid_authz::CeAuthzEngine<dyn StorageBackend>>,
    revocation: Arc<RevocationCache>,
    cascade: Arc<RevocationCascadeService>,
    /// DPoP proofs seen, shared by every replica (RFC 9449 §11.1).
    dpop: DPopValidator,
    /// Client assertion `jti`s seen, shared by every replica (RFC 7523 §3).
    assertion_jti_log: sid_authn::client_assertion::AssertionJtiLog,
    rate_limiter: RateLimiter,
    rate_limit_stats: Arc<RateLimitStats>,
    login_policy: Arc<dyn LoginPolicySource>,
    installation_url: String,
}

impl OAuth {
    pub fn new(parts: OAuthParts) -> Self {
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = parts.storage.clone();
        Self {
            dpop: DPopValidator::new(ceremonies.clone()),
            assertion_jti_log: sid_authn::client_assertion::AssertionJtiLog::new(ceremonies),
            rate_limiter: RateLimiter::new(parts.cache.clone()),
            rate_limit_stats: Arc::new(RateLimitStats::new(parts.cache)),
            storage: parts.storage,
            oauth2: parts.oauth2,
            jwt: parts.jwt,
            issuers: parts.issuers,
            installation_org: parts.installation_org,
            authz: parts.authz,
            revocation: parts.revocation,
            cascade: parts.cascade,
            login_policy: parts.login_policy,
            installation_url: parts.installation_url,
        }
    }

    /// Read the login requirements from `source` from now on.
    pub fn set_login_policy(&mut self, source: Arc<dyn LoginPolicySource>) {
        self.login_policy = source;
    }

    /// Where the login requirements are read from.
    pub fn login_policy(&self) -> &dyn LoginPolicySource {
        self.login_policy.as_ref()
    }

    /// The DPoP validator, whose replay record every endpoint shares.
    pub fn dpop(&self) -> &DPopValidator {
        &self.dpop
    }

    /// The login requirements of an authentication for `client_id` (none:
    /// the organization's). A source that cannot state them refuses rather
    /// than leaving a baseline in their place.
    pub async fn login_requirements(
        &self,
        client_id: Option<&str>,
    ) -> Result<LoginRequirements, OAuthError> {
        self.login_policy
            .requirements(client_id)
            .await
            .map_err(|e| OAuthError::unavailable("login policy", e))
    }

    /// The `sub` a token `issuer` gives `client` carries for `profile_id`,
    /// under the rule of that hop.
    pub async fn subject_for(
        &self,
        issuer: &OidcIssuer,
        profile_id: ProfileId,
        client: &OAuth2Client,
    ) -> Result<String, OAuthError> {
        let rule = SubjectRule::for_hop(issuer, client).map_err(|e| {
            tracing::error!(error = %e, client = %client.client_id, "no subject rule for this hop");
            OAuthError::Internal
        })?;
        resolve_subject(self.storage.as_ref(), profile_id, client, rule)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, client = %client.client_id, "subject not resolved");
                OAuthError::Internal
            })
    }

    /// A Profile's primary email and phone for token claims; a failed read
    /// fails the request rather than issue tokens without them.
    pub async fn primary_contacts(
        &self,
        profile_id: ProfileId,
    ) -> Result<(Option<ProfileEmail>, Option<ProfilePhone>), OAuthError> {
        let email = self
            .storage
            .get_primary_profile_email(profile_id)
            .await
            .map_err(|e| internal("token claims", e))?;
        let phone = self
            .storage
            .get_primary_profile_phone(profile_id)
            .await
            .map_err(|e| internal("token claims", e))?;
        Ok((email, phone))
    }

    /// The DPoP proof of a token request, if present, validated against
    /// `target`, the request as it was received (RFC 9449 §4.3).
    pub async fn validate_dpop_proof(
        &self,
        proof: Option<&str>,
        target: &RequestTarget,
    ) -> Result<Option<DPopBinding>, OAuthError> {
        let Some(proof) = proof.filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        self.dpop
            .validate(proof, &target.method, &target.uri)
            .await
            .map(Some)
            .map_err(|e| match e {
                // An unreachable replay record cannot rule out a replay; the
                // client retries the same request.
                sid_authn::dpop::DPopError::ReplayStoreUnavailable => {
                    OAuthError::unavailable("DPoP replay record", "replay store unreachable")
                }
                other => {
                    warn!("DPoP proof validation failed: {}", other);
                    OAuthError::Dpop(other.to_string())
                }
            })
    }

    /// The issuer a request's path names, when it serves clients of
    /// `client_org`. An unknown handle and a client of another issuer both
    /// yield `None`: to the caller the client is unknown at this endpoint,
    /// and no other issuer stands in.
    pub async fn issuer_serving(
        &self,
        handle: &str,
        client_org: Option<OrgId>,
    ) -> Result<Option<OidcIssuer>, OAuthError> {
        let issuer = self.issuers.by_handle(handle).await.map_err(|e| {
            warn!(error = %e, "reading the request's OIDC issuer");
            OAuthError::Internal
        })?;
        Ok(issuer.filter(|issuer| issuer.serves(client_org)))
    }

    /// The client a request to the endpoint of issuer `issuer_handle`
    /// authenticates as (RFC 6749 §2.3), with that issuer.
    pub async fn authenticated_client(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
    ) -> Result<(OAuth2Client, OidcIssuer), OAuthError> {
        let client = self
            .storage
            .get_oauth2_client(auth.client_id())
            .await?
            .ok_or(OAuthError::ClientRefused)?;
        let issuer = self.client_issuer(issuer_handle, &client).await?;
        self.check_client_authentication(&client, &issuer, auth)
            .await?;
        Ok((client, issuer))
    }

    /// The issuer `issuer_handle` names, when it serves the active `client`.
    /// A client this issuer does not serve is refused exactly like one that
    /// does not exist (`invalid_client`).
    pub async fn client_issuer(
        &self,
        issuer_handle: &str,
        client: &OAuth2Client,
    ) -> Result<OidcIssuer, OAuthError> {
        let issuer = self
            .issuer_serving(issuer_handle, client.org_id)
            .await?
            .ok_or(OAuthError::ClientRefused)?;
        if !client.active {
            return Err(OAuthError::ClientRefused);
        }
        Ok(issuer)
    }

    /// Check the credential a request to `issuer` presents for `client`. A
    /// public client presents none; a confidential one proves itself by the
    /// method it registered (OIDC Dynamic Client Registration 1.0 §2
    /// `token_endpoint_auth_method`), so a secret registered for Basic is
    /// not accepted from the request body, and a `private_key_jwt` client
    /// signs an assertion for this issuer's token endpoint with a registered
    /// key (RFC 7523 §3).
    async fn check_client_authentication(
        &self,
        client: &OAuth2Client,
        issuer: &OidcIssuer,
        auth: &ClientAuthentication,
    ) -> Result<(), OAuthError> {
        auth.verify(
            client,
            &issuer.canonical_url,
            &self.oauth2,
            &self.assertion_jti_log,
        )
        .await
        .map_err(|refusal| match refusal {
            sid_authn::client_auth::ClientRefusal::Refused => OAuthError::ClientRefused,
            sid_authn::client_auth::ClientRefusal::ReplayRecordUnavailable(e) => {
                OAuthError::unavailable("client assertion replay record", e)
            }
        })
    }

    /// The machine user a token request authenticates as, the `kid` of the
    /// credential it used and the issuer its request reached: machine users
    /// belong to the installation, so only the installation organization's
    /// issuer serves them; any other endpoint knows no such client.
    async fn authenticate_machine_user(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
    ) -> Result<(MachineUser, String, OidcIssuer), OAuthError> {
        use sid_core::models::{CredentialStatus, MachineCredentialType};

        let issuer = self
            .issuer_serving(issuer_handle, Some(self.installation_org))
            .await?
            .ok_or(OAuthError::ClientRefused)?;
        let mu = self
            .storage
            .get_machine_user_by_client_id(auth.client_id())
            .await?
            .ok_or(OAuthError::ClientRefused)?;
        if !mu.can_authenticate() {
            warn!(client_id = %mu.client_id, "inactive machine user tried to authenticate");
            return Err(OAuthError::ClientRefused);
        }
        let credentials = self.storage.list_machine_credentials_by_user(mu.id).await?;
        let usable = |c: &&sid_core::models::MachineUserCredential, kind: MachineCredentialType| {
            c.credential_type == kind
                && matches!(
                    c.status,
                    CredentialStatus::Active | CredentialStatus::GracePeriod
                )
                && !c.is_expired()
        };
        let used = match auth {
            ClientAuthentication::Basic { secret, .. }
            | ClientAuthentication::Post { secret, .. } => credentials
                .iter()
                .filter(|c| usable(c, MachineCredentialType::ClientSecret))
                .find(|c| {
                    sid_authn::bearer_secret::matches(secret.expose_secret(), &c.credential_data)
                })
                .map(|c| c.kid.clone()),
            ClientAuthentication::Assertion { assertion, .. } => {
                // The assertion's audience is the token endpoint of the issuer
                // the request reached, so one made for another issuer is
                // refused (RFC 7523 §3).
                let audience = token_endpoint(&issuer);
                let mut valid = None;
                for cred in credentials
                    .iter()
                    .filter(|c| usable(c, MachineCredentialType::PrivateKeyJwt))
                {
                    let Some(alg) = cred.algorithm.as_deref() else {
                        continue;
                    };
                    match sid_authn::client_assertion::validate_client_assertion(
                        assertion,
                        &mu.client_id,
                        &audience,
                        &cred.credential_data,
                        alg,
                        &self.assertion_jti_log,
                    )
                    .await
                    {
                        Ok(_) => {
                            valid = Some(cred.kid.clone());
                            break;
                        }
                        Err(e) => {
                            warn!(client_id = %mu.client_id, error = %e, "client assertion refused");
                        }
                    }
                }
                valid
            }
            ClientAuthentication::None { .. } => None,
        };
        let Some(kid) = used else {
            return Err(OAuthError::ClientRefused);
        };
        Ok((mu, kid, issuer))
    }

    /// The resource a new grant of `requester` under `issuer` is for: the
    /// one the request's `resource` values name, or the requester's default
    /// (RFC 8707 §2).
    pub async fn select_target<'r>(
        &self,
        issuer: &OidcIssuer,
        requester: impl Into<Requester<'r>>,
        resource: &[String],
    ) -> Result<Target, OAuthError> {
        let requested =
            sid_authn::target::requested_indicator(resource).map_err(OAuthError::Target)?;
        sid_authn::target::select_target(
            self.storage.as_ref(),
            issuer.id,
            requester,
            requested.as_ref(),
        )
        .await?
        .map_err(OAuthError::Target)
    }

    /// The resource an existing grant bound to `bound` is redeemed for: the
    /// request may only repeat it, and it must still accept tokens for
    /// `client` (RFC 8707 §2.2).
    pub async fn resume_target<'r>(
        &self,
        issuer: &OidcIssuer,
        client: impl Into<Requester<'r>>,
        bound: ResourceId,
        resource: &[String],
    ) -> Result<Target, OAuthError> {
        let requested =
            sid_authn::target::requested_indicator(resource).map_err(OAuthError::Target)?;
        sid_authn::target::resume_target(
            self.storage.as_ref(),
            issuer.id,
            client,
            bound,
            requested.as_ref(),
        )
        .await?
        .map_err(OAuthError::Target)
    }

    /// The signer of `issuer`; a key that cannot be opened fails the request.
    pub async fn issuer_signer(
        &self,
        issuer: &OidcIssuer,
    ) -> Result<Arc<IssuerSigner>, OAuthError> {
        self.issuers.signer(issuer).await.map_err(|e| {
            warn!(error = %e, issuer = %issuer.canonical_url, "issuer signing key unavailable");
            OAuthError::Internal
        })
    }

    /// End a session whose credential was replayed (a reused authorization
    /// code, device code or refresh token): its access tokens, refresh
    /// tokens and the session itself. `action` names the replay in the audit
    /// trail.
    pub async fn revoke_compromised_session(
        &self,
        session_id: Option<SessionId>,
        action: &str,
    ) -> Result<(), OAuthError> {
        let Some(session_id) = session_id else {
            return Ok(());
        };
        warn!(%session_id, action, "credential replayed; revoking its session");
        self.end_replayed_session(session_id, action).await
    }

    async fn end_replayed_session(
        &self,
        session_id: SessionId,
        action: &str,
    ) -> Result<(), OAuthError> {
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

    /// Enforce a machine user's restrictions (IP allowlist and rate limit)
    /// after it authenticated, before anything is issued.
    async fn enforce_machine_restrictions(
        &self,
        mu: &MachineUser,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(), OAuthError> {
        // A request from elsewhere is a client this endpoint does not
        // authorize (RFC 6749 §5.2 `unauthorized_client`).
        let not_allowed = || {
            OAuthError::token(
                TokenError::UnauthorizedClient,
                "the client may not request tokens from this address",
            )
        };
        if !mu.restrictions.ip_allowlist.is_empty() {
            let addr = client_ip.ok_or_else(not_allowed)?;
            if !mu
                .restrictions
                .ip_allowlist
                .iter()
                .any(|entry| ip_matches(entry, &addr))
            {
                warn!(
                    "Machine user {} request from {} denied by IP allowlist",
                    mu.client_id, addr
                );
                return Err(not_allowed());
            }
        }
        if mu.restrictions.rate_limit_rpm > 0
            && !self
                .rate_limiter
                .check_and_record(&mu.client_id, mu.restrictions.rate_limit_rpm)
                .await
                .map_err(|e| OAuthError::unavailable("machine user rate limit", e))?
        {
            warn!(
                "Machine user {} rate limited ({}rpm)",
                mu.client_id, mu.restrictions.rate_limit_rpm
            );
            let stats = self.rate_limit_stats.clone();
            tokio::spawn(async move {
                stats.record_block(None, "machine_user_token").await;
            });
            return Err(OAuthError::RateLimited {
                rpm: mu.restrictions.rate_limit_rpm,
            });
        }
        Ok(())
    }
}

/// The token endpoint of `issuer`, as its discovery document advertises it:
/// the `htu` of a DPoP proof sent there (RFC 9449 §4.3) and the audience of a
/// client assertion (RFC 7523 §3).
fn token_endpoint(issuer: &OidcIssuer) -> String {
    sid_authn::issuer::token_endpoint(&issuer.canonical_url)
}

/// Whether `addr` is the IP or within the CIDR block `entry` names (IPv4 or
/// IPv6); a malformed entry or a mixed family matches nothing.
fn ip_matches(entry: &str, addr: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let Some((network, prefix)) = entry.split_once('/') else {
        return entry.parse::<IpAddr>() == Ok(*addr);
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<IpAddr>(), prefix.parse::<u32>()) else {
        return false;
    };
    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(*ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(*ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
