// SPDX-License-Identifier: AGPL-3.0-only
//! OAuth 2.0 and OpenID Connect implementation.
//!
//! Supports:
//! - Authorization Code + PKCE (RFC 7636)
//! - Client Credentials
//! - Refresh Token with rotation (theft detection)
//! - Token Introspection (RFC 7662)
//! - Token Revocation (RFC 7009)

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sid_core::models::dpop::DPopBinding;
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AuthorizationCode, ExchangedCode, OAuth2Client, Profile, ProfileEmail, ProfileId,
        ProfilePhone, RefreshToken, RefreshTokenError, Session, ValidatedRefreshToken,
    },
};
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::issuer::IssuerSigner;
use crate::jwt::JwtService;

/// OAuth2 server handling authorization, token exchange, and token management.
pub struct OAuth2Server {
    jwt: Arc<JwtService>,
    auth_code_ttl: Duration,
    refresh_token_ttl: Duration,
}

/// Authorization request (pre-validation).
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Why an authorization request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeError {
    /// The redirect URI is not one the client registered; the error must not
    /// be sent there (RFC 6749 §4.1.2.1).
    #[error("redirect_uri is not registered for this client")]
    UnregisteredRedirectUri,
    #[error("only response_type=code is supported")]
    UnsupportedResponseType,
    #[error("the client may not use the authorization code grant")]
    UnauthorizedClient,
    #[error("PKCE code_challenge is required")]
    PkceRequired,
    #[error("only the S256 code_challenge_method is supported")]
    PkceMethodUnsupported,
    #[error("state is required")]
    StateRequired,
    #[error("nonce is required when openid is requested")]
    NonceRequired,
    /// An unknown `prompt` value, or `none` with another one (OpenID Connect
    /// Core §3.1.2.1).
    #[error("prompt is not a valid combination of none, login, consent, select_account")]
    InvalidPrompt,
}

impl AuthorizeError {
    /// The `error` code sent to the client (RFC 6749 §4.1.2.1).
    pub fn oauth_error(self) -> &'static str {
        match self {
            Self::UnregisteredRedirectUri
            | Self::PkceRequired
            | Self::PkceMethodUnsupported
            | Self::StateRequired
            | Self::NonceRequired
            | Self::InvalidPrompt => "invalid_request",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::UnauthorizedClient => "unauthorized_client",
        }
    }
}

/// The `error` code of a token endpoint refusal (RFC 6749 §5.2;
/// `invalid_dpop_proof` from RFC 9449 §7.1; the device_code grant's own
/// codes from RFC 8628 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// A parameter is missing, repeated or malformed, or the client used more
    /// than one authentication method.
    InvalidRequest,
    /// Client authentication failed: unknown client, no or wrong credentials,
    /// unsupported method.
    InvalidClient,
    /// The grant (code, refresh token, subject token) is invalid, expired,
    /// revoked, or was issued to another client or redirect URI.
    InvalidGrant,
    /// The authenticated client may not use this grant type.
    UnauthorizedClient,
    UnsupportedGrantType,
    /// The requested scope is invalid or exceeds what may be granted.
    InvalidScope,
    /// The requested resource is invalid, unknown, not permitted, more than
    /// one, or not the one the grant was issued for (RFC 8707 §2).
    InvalidTarget,
    InvalidDpopProof,
    /// The user has not decided on the device request yet.
    AuthorizationPending,
    /// The device polls faster than its interval.
    SlowDown,
    /// The user denied the device request.
    AccessDenied,
    /// The device code expired before the user decided.
    ExpiredToken,
}

impl TokenError {
    /// The `error` parameter value.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::AccessDenied => "access_denied",
            Self::ExpiredToken => "expired_token",
        }
    }
}

/// Why a refresh token is refused; every case is `invalid_grant`
/// (RFC 6749 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefreshRefusal {
    #[error("refresh token expired")]
    Expired,
    #[error("refresh token revoked")]
    Revoked,
    /// A rotated token presented after its grace window: someone else holds
    /// the family, so the family and its session must be revoked.
    #[error("refresh token reused")]
    Reused {
        session_id: sid_core::models::SessionId,
        family_id: Uuid,
    },
    #[error("refresh token issued to another client")]
    ClientMismatch,
}

/// Validated authorization request (post-validation).
#[derive(Debug)]
pub struct ValidatedAuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub nonce: Option<String>,
}

/// Token request.
///
/// Custom Debug: `client_secret`, `code`, `refresh_token`, `code_verifier` are redacted.
#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
    pub device_code: Option<String>,
}

impl Drop for TokenRequest {
    fn drop(&mut self) {
        if let Some(ref mut s) = self.client_secret {
            s.zeroize();
        }
        if let Some(ref mut s) = self.code {
            s.zeroize();
        }
        if let Some(ref mut s) = self.refresh_token {
            s.zeroize();
        }
        if let Some(ref mut s) = self.code_verifier {
            s.zeroize();
        }
        if let Some(ref mut s) = self.device_code {
            s.zeroize();
        }
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "device_code",
                &self.device_code.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Token response.
///
/// Custom Debug: `access_token`, `refresh_token`, `id_token` are redacted.
/// Prevents accidental logging of bearer tokens.
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("scope", &self.scope)
            .finish()
    }
}

/// OAuth2 error response.
#[derive(Debug, Serialize)]
pub struct OAuth2Error {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl OAuth2Server {
    /// Create a new OAuth2 server.
    ///
    /// Default TTLs: auth_code = 5 min, refresh_token = 30 days.
    /// Use `with_refresh_token_ttl` to override.
    pub fn new(jwt: Arc<JwtService>) -> Self {
        Self {
            jwt,
            auth_code_ttl: Duration::minutes(5),
            refresh_token_ttl: Duration::days(30),
        }
    }

    /// Set refresh token TTL (default: 30 days, range: 7-30 days per architecture spec).
    pub fn with_refresh_token_ttl(mut self, ttl: Duration) -> Self {
        self.refresh_token_ttl = ttl;
        self
    }

    /// Validate an authorization request.
    pub fn validate_authorize_request(
        &self,
        client: &OAuth2Client,
        req: &AuthorizeRequest,
    ) -> Result<ValidatedAuthorizeRequest, AuthorizeError> {
        // The redirect URI is checked first: every later error is reported by
        // redirecting to it, which is only allowed once it is known to be the
        // client's (RFC 6749 §4.1.2.1).
        if !client.is_redirect_uri_allowed(&req.redirect_uri) {
            return Err(AuthorizeError::UnregisteredRedirectUri);
        }
        if req.response_type != "code" {
            return Err(AuthorizeError::UnsupportedResponseType);
        }
        if !client.is_grant_type_allowed("authorization_code") {
            return Err(AuthorizeError::UnauthorizedClient);
        }
        // PKCE S256: mandatory for ALL authorization code flows (FAPI 2.0 baseline).
        // Not just public clients — confidential clients must also use PKCE.
        if req.code_challenge.is_none() {
            return Err(AuthorizeError::PkceRequired);
        }
        // Only S256. An absent method means `plain` (RFC 7636 §4.3), which is
        // refused like an explicit one.
        if req.code_challenge_method.as_deref() != Some("S256") {
            return Err(AuthorizeError::PkceMethodUnsupported);
        }
        // CSRF protection for the client's redirect.
        if req.state.as_deref().is_none_or(str::is_empty) {
            return Err(AuthorizeError::StateRequired);
        }

        // Parse and filter scopes
        let requested_scopes: Vec<String> = req
            .scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .map(String::from)
            .collect();
        // Replay protection for the ID Token of an OIDC request.
        if requested_scopes.iter().any(|s| s == "openid")
            && req.nonce.as_deref().is_none_or(str::is_empty)
        {
            return Err(AuthorizeError::NonceRequired);
        }
        let scopes = client.filter_scopes(&requested_scopes);

        Ok(ValidatedAuthorizeRequest {
            client_id: client.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            scopes,
            state: req.state.clone(),
            code_challenge: req.code_challenge.clone(),
            nonce: req.nonce.clone(),
        })
    }

    /// Generate an authorization code for `resource`, the target resolved
    /// for the request (RFC 8707); its redemption issues a token for it only.
    /// `authentication` is the authorizing session's evidence, which the
    /// redeemed session carries as its `auth_time`, `amr` and `acr`.
    /// Returns (raw_code, AuthorizationCode model to persist).
    pub fn generate_auth_code(
        &self,
        profile_id: ProfileId,
        req: &ValidatedAuthorizeRequest,
        resource: sid_core::models::ResourceId,
        authentication: sid_core::models::GrantAuthentication,
    ) -> SidResult<(String, AuthorizationCode)> {
        let raw_code = generate_random_token(32);
        let code_hash = sha256_hash(raw_code.as_bytes());
        let now = Utc::now();

        let code = AuthorizationCode {
            code_hash,
            profile_id,
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            scopes: req.scopes.clone(),
            resource,
            code_challenge: req.code_challenge.clone(),
            nonce: req.nonce.clone(),
            expires_at: now + self.auth_code_ttl,
            created_at: now,
            used: false,
            session_id: None,
            authentication,
        };

        Ok((raw_code, code))
    }

    /// Validate and exchange an authorization code (consume-self pattern).
    ///
    /// Takes ownership of `code`, preventing re-validation or replay.
    /// On success, returns `ExchangedCode` with read access to authorization data.
    /// Checks: not used, not expired, PKCE, redirect_uri, client match.
    pub fn validate_code_exchange(
        &self,
        client: &OAuth2Client,
        code: AuthorizationCode,
        code_verifier: Option<&str>,
        redirect_uri: &str,
    ) -> SidResult<ExchangedCode> {
        // Exchange consumes the code — validates not-used and not-expired
        let exchanged = code
            .exchange()
            .map_err(|e| SidError::Validation(format!("invalid_grant: {}", e)))?;

        // Client must match
        if exchanged.client_id() != client.client_id {
            return Err(SidError::Validation(
                "invalid_grant: client mismatch".into(),
            ));
        }

        // Redirect URI must match
        if exchanged.redirect_uri() != redirect_uri {
            return Err(SidError::Validation(
                "invalid_grant: redirect_uri mismatch".into(),
            ));
        }

        // PKCE is mandatory for every code (RFC 7636 §4.6): a code without a
        // challenge cannot be exchanged.
        let challenge = exchanged.code_challenge().ok_or_else(|| {
            SidError::Validation("invalid_grant: code was issued without PKCE".into())
        })?;
        let verifier = code_verifier
            .ok_or_else(|| SidError::Validation("invalid_grant: code_verifier required".into()))?;
        let computed = compute_s256_challenge(verifier);
        // Constant-time comparison prevents timing attacks on PKCE challenges.
        if computed.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() != 1 {
            return Err(SidError::Validation(
                "invalid_grant: code_verifier mismatch".into(),
            ));
        }

        Ok(exchanged)
    }

    /// Issue tokens (access_token, refresh_token, optional id_token) as the
    /// client's `issuer`: its URL is `iss` and its key signs them.
    ///
    /// The access token is for `target` alone: its `aud` is the resource
    /// indicator and its scope the part of `scopes` the target grants
    /// (RFC 8707, auth/oauth-resource-model.md). `scopes` are the client's
    /// granted scopes; `openid` among them adds an ID token for the client.
    /// The refresh token keeps `scopes` and the target.
    ///
    /// When `dpop_binding` is provided, the access token includes `cnf.jkt`
    /// and `token_type` is "DPoP" instead of "Bearer" (RFC 9449).
    ///
    /// When `custom_claims` is provided, they are merged into the access token
    /// JWT payload (AUTH-017: static claim mapping).
    #[allow(clippy::too_many_arguments)]
    pub fn issue_tokens(
        &self,
        issuer: &IssuerSigner,
        sub: &str,
        profile: &Profile,
        session: &Session,
        client: &OAuth2Client,
        target: &crate::target::Target,
        scopes: &[String],
        nonce: Option<&str>,
        dpop_binding: Option<&DPopBinding>,
        custom_claims: Option<&std::collections::HashMap<String, serde_json::Value>>,
        primary_email: Option<&ProfileEmail>,
        primary_phone: Option<&ProfilePhone>,
    ) -> SidResult<(TokenResponse, RefreshToken)> {
        let token_scopes = target.granted_scopes(scopes);
        let access_token = self.jwt.access_token_signed_by(
            issuer,
            crate::jwt::TokenAudience::Resource {
                indicator: target.audience().as_str(),
                client_id: &client.client_id,
            },
            sub,
            None,
            profile,
            session,
            &token_scopes,
            dpop_binding,
            custom_claims,
        )?;

        // Issue ID token if "openid" scope is present
        let id_token = if scopes.iter().any(|s| s == "openid") {
            Some(self.jwt.id_token_signed_by(
                issuer,
                sub,
                profile,
                session,
                &client.client_id,
                nonce,
                primary_email,
                primary_phone,
            )?)
        } else {
            None
        };

        // Generate refresh token
        let raw_refresh = generate_random_token(48);
        let refresh_hash = sha256_hash(raw_refresh.as_bytes());
        let now = Utc::now();
        let token_id = Uuid::now_v7();

        let refresh_model = RefreshToken {
            id: token_id,
            token_hash: refresh_hash,
            session_id: session.id,
            profile_id: profile.id,
            client_id: client.client_id.clone(),
            scopes: scopes.to_vec(),
            resource: target.resource_id(),
            expires_at: now + self.refresh_token_ttl,
            created_at: now,
            revoked: false,
            replaced_by: None,
            family_id: token_id, // First token in chain: family_id == id
            grace_expires_at: None,
            // A public client's refresh token is bound to the DPoP key; a
            // confidential client's is already constrained by its
            // authentication (RFC 9449 §5).
            dpop_jkt: dpop_binding
                .filter(|_| client.is_public())
                .map(|b| b.jkt.clone()),
        };

        let response = TokenResponse {
            access_token,
            token_type: if dpop_binding.is_some() {
                "DPoP"
            } else {
                "Bearer"
            }
            .to_string(),
            expires_in: self.jwt.access_token_ttl_secs(),
            refresh_token: Some(raw_refresh),
            id_token,
            // RFC 6749 §5.1: the scope of the access token.
            scope: Some(token_scopes.join(" ")),
        };

        Ok((response, refresh_model))
    }

    /// Validate a refresh token for rotation (consume-self pattern).
    ///
    /// Takes ownership of `token`, preventing re-validation or reuse.
    /// On success, returns `ValidatedRefreshToken` with read access to token data.
    ///
    /// On `RefreshTokenError::Revoked`, callers should perform cascade revocation
    /// before calling this method — the error includes session_id for that purpose.
    pub fn validate_refresh(
        &self,
        token: RefreshToken,
        client: &OAuth2Client,
    ) -> Result<ValidatedRefreshToken, RefreshRefusal> {
        let validated = token.validate().map_err(|e| match e {
            RefreshTokenError::Expired => RefreshRefusal::Expired,
            RefreshTokenError::Revoked { .. } => RefreshRefusal::Revoked,
            RefreshTokenError::TheftDetected {
                session_id,
                family_id,
            } => RefreshRefusal::Reused {
                session_id,
                family_id,
            },
        })?;

        if validated.client_id() != client.client_id {
            return Err(RefreshRefusal::ClientMismatch);
        }

        Ok(validated)
    }

    /// Hash a client secret using Argon2 for storage.
    ///
    /// Used when creating or rotating OAuth2 client credentials.
    /// The counterpart `authenticate_client` verifies against the stored hash.
    pub fn hash_client_secret(secret: &str) -> SidResult<String> {
        use argon2::password_hash::{PasswordHasher, phc::PasswordHash};
        PasswordHasher::<PasswordHash>::hash_password(&argon2::Argon2::default(), secret.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| SidError::Internal(format!("Argon2 hash failed: {e}")))
    }

    /// Authenticate a confidential client via client_id + client_secret.
    pub fn authenticate_client(
        &self,
        client_secret: &SecretBox<String>,
        stored: &OAuth2Client,
    ) -> SidResult<()> {
        let hash = stored.client_secret_hash.as_ref().ok_or_else(|| {
            SidError::AuthenticationFailed("invalid_client: public client cannot use secret".into())
        })?;

        // Verify Argon2 hash
        let password_hash_str = std::str::from_utf8(hash)
            .map_err(|_| SidError::AuthenticationFailed("invalid_client: corrupt hash".into()))?;

        let parsed_hash = argon2::password_hash::phc::PasswordHash::new(password_hash_str)
            .map_err(|_| SidError::AuthenticationFailed("invalid_client: corrupt hash".into()))?;

        argon2::PasswordVerifier::verify_password(
            &argon2::Argon2::default(),
            client_secret.expose_secret().as_bytes(),
            &parsed_hash,
        )
        .map_err(|_| SidError::AuthenticationFailed("invalid_client: bad secret".into()))
    }

    /// Hash a raw refresh token for storage lookup.
    pub fn hash_token(raw_token: &str) -> Vec<u8> {
        sha256_hash(raw_token.as_bytes())
    }
}

// ─── Utility functions ───

/// Generate a cryptographically secure random token (URL-safe base64).
fn generate_random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

/// SHA-256 hash.
fn sha256_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Compute S256 PKCE challenge from verifier.
pub fn compute_s256_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

pub mod prompt;

#[cfg(test)]
mod tests;
