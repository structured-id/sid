// SPDX-License-Identifier: AGPL-3.0-only
//! JWT Service — EdDSA (Ed25519) access tokens and OIDC ID tokens.
//!
//! Handles signing, validation, and JWK Set generation for StructuredID.
//! Default algorithm: EdDSA (Ed25519) per architecture spec.

use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{Profile, ProfileEmail, ProfilePhone, Session, dpop::DPopBinding},
};

/// Lifetime of a back-channel logout token. It covers the delivery retries
/// (about 90 s with backoff and request timeouts) and nothing more.
const LOGOUT_TOKEN_TTL_SECS: i64 = 120;

/// Who issues a token: the `iss` it carries and the key that signs it.
///
/// SID's own sign-in sessions are issued by the installation ([`JwtService`]);
/// tokens for an application are issued by its OIDC issuer
/// ([`crate::issuer::IssuerSigner`]).
pub trait TokenSigner {
    /// The exact `iss` value.
    fn iss(&self) -> &str;
    /// Sign `claims`, naming the key in `kid`; `typ` sets the JWS type.
    fn sign_claims<T: Serialize>(&self, typ: Option<&str>, claims: &T) -> SidResult<String>;
}

impl TokenSigner for JwtService {
    fn iss(&self) -> &str {
        &self.issuer
    }

    fn sign_claims<T: Serialize>(&self, typ: Option<&str>, claims: &T) -> SidResult<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        if let Some(typ) = typ {
            header.typ = Some(typ.to_owned());
        }
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| SidError::Internal(format!("JWT encoding failed: {}", e)))
    }
}

/// Verifies SID access tokens with the public key alone.
///
/// Services that only accept tokens hold this, never the signing key, so a
/// compromised verifier cannot mint tokens.
pub struct TokenVerifier {
    decoding_key: DecodingKey,
    issuer: String,
    /// The account API's tokens, when this installation serves the account
    /// integration's API.
    account: Option<std::sync::Arc<crate::account_api::AccountApiVerifier>>,
}

impl fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenVerifier")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// A verified access token presented to the installation's services.
#[derive(Debug)]
pub enum VerifiedAccess {
    /// The installation's own token: a sign-in session, PAT or impersonation.
    Session(AccessTokenClaims),
    /// An account API token of the account integration.
    AccountApi(crate::account_api::AccountApiToken),
}

impl TokenVerifier {
    /// Build a verifier from an Ed25519 public key in PEM format.
    pub fn new(public_key_pem: &[u8], issuer: String) -> SidResult<Self> {
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|e| SidError::Internal(format!("Invalid Ed25519 public key: {}", e)))?;
        Ok(Self {
            decoding_key,
            issuer,
            account: None,
        })
    }

    /// Verify `token` as either kind the installation's services accept: an
    /// account API token when its `iss` is the account integration's issuer,
    /// the installation's own token otherwise. The `iss` read before the
    /// signature only picks the verifier; each verifies it exactly.
    pub async fn verify(&self, token: &str) -> SidResult<VerifiedAccess> {
        if let Some(account) = &self.account
            && unverified_issuer(token).as_deref() == Some(account.issuer())
        {
            return account.verify(token).await.map(VerifiedAccess::AccountApi);
        }
        self.validate_access_token(token)
            .map(VerifiedAccess::Session)
    }

    /// Validate an access token JWT and return its claims.
    pub fn validate_access_token(&self, token: &str) -> SidResult<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.issuer]);
        validation.set_required_spec_claims(&["sub", "iss", "exp", "iat"]);

        let token_data: TokenData<AccessTokenClaims> =
            decode(token, &self.decoding_key, &validation)
                .map_err(|e| SidError::AuthenticationFailed(format!("Invalid token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// The issuer this verifier accepts.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// JWT Service for issuing and validating tokens.
///
/// Contains the Ed25519 signing key — custom Debug prints `[REDACTED]`
/// for `encoding_key` to prevent accidental key leakage in logs.
pub struct JwtService {
    encoding_key: EncodingKey,
    verifier: TokenVerifier,
    decoding_key: DecodingKey,
    issuer: String,
    access_token_ttl: Duration,
    id_token_ttl: Duration,
    /// Base64url-encoded SHA-256 thumbprint of the public key (used as `kid`)
    key_id: String,
    /// Raw public key bytes (32 bytes Ed25519) for JWK Set
    public_key_bytes: Vec<u8>,
}

impl fmt::Debug for JwtService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtService")
            .field("encoding_key", &"[REDACTED]")
            .field("decoding_key", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("id_token_ttl", &self.id_token_ttl)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// DPoP confirmation claim (RFC 9449 §7.1).
/// Embedded in access token's `cnf` claim when DPoP-bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnfClaim {
    /// JWK Thumbprint of the client's DPoP key.
    pub jkt: String,
}

/// Access token claims (JWT payload).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject, polymorphic: the ProfileId for the installation's own session
    /// and for its own users at its own applications, the stored BindingId
    /// (opaque UUIDv7, no prefix) for an external or contour recipient, a
    /// client_id for a client acting for itself. Both identifiers are UUIDs,
    /// so the syntax says nothing: never read a ProfileId from `sub`.
    pub sub: String,
    /// The ProfileId, present only in the installation's own tokens (session,
    /// PAT, impersonation); never in a token issued to an application.
    /// Internal gRPC endpoints MUST extract ProfileId from `pid`, never from `sub`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    /// Issuer URL
    pub iss: String,
    /// Audiences: the application's client_id for a token issued to one, the
    /// issuer for the installation's own session token.
    pub aud: Vec<String>,
    /// The client an application token was issued to (RFC 9068 §2.2);
    /// absent in the installation's own session tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Time when the user actually authenticated (Unix timestamp).
    /// Used by sid-proxy for session decay calculation.
    pub auth_time: i64,
    /// Authentication Context Class Reference (OIDC).
    /// Maps to AuthLevel: basic, standard, elevated, critical.
    pub acr: String,
    /// Scopes (space-separated)
    pub scope: String,
    /// Roles (space-separated)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub roles: String,
    /// Session ID
    pub sid: String,
    /// Authentication Methods References (RFC 8176).
    /// Lists the methods used during authentication (e.g., "pwd", "otp", "hwk").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// JWT ID
    pub jti: String,
    /// DPoP confirmation (RFC 9449). Present when token is DPoP-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
    /// RFC 8693 §4.1: Actor claim for token exchange (impersonation/delegation).
    /// Contains `sub` = the acting party (machine user client_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
}

/// Claims SID sets on access tokens (RFC 7519 §4.1 registered claims, OIDC and
/// RFC 8693/9449 claims, and SID's own). Claim mappings may not set any of them.
pub const RESERVED_ACCESS_TOKEN_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "auth_time",
    "acr",
    "amr",
    "scope",
    "roles",
    "sid",
    "pid",
    "cnf",
    "act",
    "azp",
    "client_id",
];

/// JWS `typ` of an access token issued to an application (RFC 9068 §2.1).
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Who an access token is issued to.
#[derive(Debug, Clone, Copy)]
pub enum TokenAudience<'a> {
    /// The installation's own services: `aud` is the issuer.
    Installation,
    /// A protected resource: `aud` is its resource indicator, `client_id` the
    /// requesting client, and the token is typed `at+jwt` (RFC 9068 §2.1,
    /// §2.2). The client is not an audience by requesting the token.
    Resource {
        indicator: &'a str,
        client_id: &'a str,
    },
}

/// What a client acting for itself is issued (OAuth client credentials).
#[derive(Debug, Clone, Copy)]
pub struct ClientGrant<'a> {
    /// The resource indicator the token is for (`aud`, RFC 8707 §2).
    pub resource: &'a str,
    /// The requesting client (RFC 9068 §2.2).
    pub client_id: &'a str,
    /// The client's own principal (`sub`).
    pub subject: &'a str,
    /// The credential the client authenticated with (`sid`).
    pub credential: &'a str,
    pub scopes: &'a [String],
    /// The request's DPoP key, binding the token to it (RFC 9449 §6).
    pub dpop: Option<&'a DPopBinding>,
    /// The client's own lifetime cap; never extends the issuer's.
    pub max_lifetime: Option<Duration>,
}

/// RFC 8693 §4.1 actor claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActClaim {
    /// Subject of the acting party (e.g., machine user client_id).
    pub sub: String,
}

/// ID token claims (OIDC §5.1 Standard Claims).
///
/// Claims are populated from **Profile Fields** (not Principal directly).
/// Principal(Email).verified → email_verified claim.
/// Principal(Phone).verified → phone_number_verified claim.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Time when the user actually authenticated (Unix timestamp).
    pub auth_time: i64,
    /// Authentication Context Class Reference (OIDC).
    pub acr: String,
    /// Authentication Methods References (RFC 8176).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// Session ID (used for back-channel logout and RP-initiated logout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    // ── OIDC §5.1 Standard Claims (from Profile Fields) ──
    /// Full name in displayable form (computed from structured name fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name(s) or first name(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Surname(s) or last name(s). Optional for mononyms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Middle name(s), patronymic, or secondary given name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Shorthand name by which the user wishes to be referred to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// User's email address (from Profile Field, NOT Principal directly).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// True if a verified Principal(Email) exists for this profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// User's phone number in E.164 format (from Profile Field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// True if a verified Principal(Phone) exists for this profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// Time the user's information was last updated (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

/// Back-channel logout token claims (OpenID Connect Back-Channel Logout 1.0).
///
/// Sent to RP's `backchannel_logout_uri` to notify of session termination.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    /// Subject as the RP knows it (pairwise for a pairwise client).
    pub sub: String,
    /// Issuer URL.
    pub iss: String,
    /// Audience (client_id of the RP).
    pub aud: String,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiry (Unix timestamp), OIDC Back-Channel Logout 1.0 §2.4.
    pub exp: i64,
    /// JWT ID (unique, for replay detection by RP).
    pub jti: String,
    /// Logout event claim (required by spec).
    /// Must contain `{"http://schemas.openid.net/event/backchannel-logout": {}}`.
    pub events: serde_json::Value,
    /// Session ID (identifies the specific session being terminated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// JWK Set response for `/.well-known/jwks.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Single JWK entry (EdDSA = Ed25519, OKP key type).
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub alg: String,
    pub kid: String,
    pub crv: String,
    /// Base64url-encoded public key (32 bytes for Ed25519)
    pub x: String,
}

/// Lifetime of an access token: short, to limit the exposure of a stolen one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessTokenTtl(u8);

impl AccessTokenTtl {
    /// Allowed range, in minutes.
    pub const MINUTES: core::ops::RangeInclusive<u8> = 1..=60;

    /// The longest lifetime any deployment may configure: a verifier that
    /// does not know the issuer's setting keeps revocations this long.
    pub const MAX: Self = Self(*Self::MINUTES.end());

    /// A TTL of `minutes`, refused outside [`Self::MINUTES`].
    pub fn from_minutes(minutes: u32) -> SidResult<Self> {
        u8::try_from(minutes)
            .ok()
            .filter(|m| Self::MINUTES.contains(m))
            .map(Self)
            .ok_or_else(|| {
                SidError::Validation(format!(
                    "access token lifetime must be 1 to 60 minutes, got {minutes}"
                ))
            })
    }

    /// The lifetime as a duration.
    pub fn duration(self) -> Duration {
        Duration::minutes(i64::from(self.0))
    }
}

impl Default for AccessTokenTtl {
    /// Five minutes.
    fn default() -> Self {
        Self(5)
    }
}

impl JwtService {
    /// Create a new JWT service from an Ed25519 private key in PEM format.
    ///
    /// Default TTLs: access_token = [`AccessTokenTtl::default`], id_token = 1 hour.
    /// Use `with_access_token_ttl` / `with_id_token_ttl` to override.
    pub fn new(private_key_pem: &[u8], public_key_pem: &[u8], issuer: String) -> SidResult<Self> {
        let encoding_key = EncodingKey::from_ed_pem(private_key_pem)
            .map_err(|e| SidError::Internal(format!("Invalid Ed25519 private key: {}", e)))?;
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|e| SidError::Internal(format!("Invalid Ed25519 public key: {}", e)))?;

        let public_key_bytes = extract_ed25519_pubkey(public_key_pem)?;
        let key_id = compute_key_thumbprint(&public_key_bytes);
        let verifier = TokenVerifier::new(public_key_pem, issuer.clone())?;

        Ok(Self {
            encoding_key,
            verifier,
            decoding_key,
            issuer,
            access_token_ttl: AccessTokenTtl::default().duration(),
            id_token_ttl: Duration::hours(1),
            key_id,
            public_key_bytes,
        })
    }

    /// Accept the account integration's API tokens beside the installation's
    /// own, verified by `account`.
    pub fn with_account_api(
        mut self,
        account: std::sync::Arc<crate::account_api::AccountApiVerifier>,
    ) -> Self {
        self.verifier.account = Some(account);
        self
    }

    /// Set the access token TTL.
    pub fn with_access_token_ttl(mut self, ttl: AccessTokenTtl) -> Self {
        self.access_token_ttl = ttl.duration();
        self
    }

    /// Set ID token TTL (default: 1 hour).
    pub fn with_id_token_ttl(mut self, ttl: Duration) -> Self {
        self.id_token_ttl = ttl;
        self
    }

    /// Get access token TTL in seconds.
    pub fn access_token_ttl_secs(&self) -> i64 {
        self.access_token_ttl.num_seconds()
    }

    /// Issue an access token JWT.
    ///
    /// When `dpop_binding` is provided, the token includes a `cnf.jkt` claim
    /// binding it to the client's DPoP key (RFC 9449).
    ///
    /// When `custom_claims` is provided, those claims are merged into the JWT
    /// payload after the standard claims (AUTH-017: static claim mapping).
    #[allow(clippy::too_many_arguments)]
    pub fn issue_access_token(
        &self,
        sub: &str,
        pid: Option<&str>,
        profile: &Profile,
        session: &Session,
        scopes: &[String],
        dpop_binding: Option<&DPopBinding>,
        custom_claims: Option<&std::collections::HashMap<String, serde_json::Value>>,
    ) -> SidResult<String> {
        self.access_token_signed_by(
            self,
            TokenAudience::Installation,
            sub,
            pid,
            profile,
            session,
            scopes,
            dpop_binding,
            custom_claims,
        )
    }

    /// An access token issued by `signer` (its `iss` and key) to `audience`
    /// with this service's lifetime; otherwise as [`Self::issue_access_token`].
    #[allow(clippy::too_many_arguments)]
    pub fn access_token_signed_by<S: TokenSigner>(
        &self,
        signer: &S,
        audience: TokenAudience<'_>,
        sub: &str,
        pid: Option<&str>,
        profile: &Profile,
        session: &Session,
        scopes: &[String],
        dpop_binding: Option<&DPopBinding>,
        custom_claims: Option<&std::collections::HashMap<String, serde_json::Value>>,
    ) -> SidResult<String> {
        let now = Utc::now();
        let (acr, exp) = token_assurance(session, now, now + self.access_token_ttl);
        let iss = signer.iss().to_owned();
        let (aud, client_id, typ) = match audience {
            TokenAudience::Installation => (iss.clone(), None, None),
            TokenAudience::Resource {
                indicator,
                client_id,
            } => (
                indicator.to_owned(),
                Some(client_id.to_owned()),
                Some(ACCESS_TOKEN_TYP),
            ),
        };

        let claims = AccessTokenClaims {
            sub: sub.to_string(),
            pid: pid.map(|p| p.to_string()),
            aud: vec![aud],
            client_id,
            iss,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: session.authenticated_at.timestamp(),
            acr: acr.acr_value().to_string(),
            scope: scopes.join(" "),
            roles: profile.roles.join(" "),
            amr: session.amr.clone(),
            sid: session.id.to_string(),
            jti: uuid::Uuid::now_v7().to_string(),
            cnf: dpop_binding.map(|b| CnfClaim { jkt: b.jkt.clone() }),
            act: None,
        };

        // Merge custom claims; a registered claim is never replaced or introduced
        // by a mapping, whether or not this token carries it.
        if let Some(custom) = custom_claims
            && !custom.is_empty()
        {
            let mut payload = serde_json::to_value(&claims)
                .map_err(|e| SidError::Internal(format!("Claims serialization failed: {}", e)))?;
            if let serde_json::Value::Object(ref mut map) = payload {
                for (k, v) in custom {
                    if RESERVED_ACCESS_TOKEN_CLAIMS.contains(&k.as_str()) {
                        tracing::warn!(claim = %k, "claim mapping targets a registered claim; ignored");
                        continue;
                    }
                    map.insert(k.clone(), v.clone());
                }
            }
            return signer.sign_claims(typ, &payload);
        }

        signer.sign_claims(typ, &claims)
    }

    /// An access token for a client acting for itself (OAuth client
    /// credentials, RFC 6749 §4.4) signed by `signer`: an `at+jwt` for one
    /// resource (RFC 9068 §2.2) naming the client's own principal and the
    /// credential it authenticated with, which the resource checks again on
    /// every request. It carries no ProfileId, roles or human authentication.
    pub fn client_access_token_signed_by<S: TokenSigner>(
        &self,
        signer: &S,
        grant: &ClientGrant<'_>,
    ) -> SidResult<String> {
        let now = Utc::now();
        let lifetime = grant
            .max_lifetime
            .map_or(self.access_token_ttl, |cap| cap.min(self.access_token_ttl));
        let claims = AccessTokenClaims {
            sub: grant.subject.to_owned(),
            pid: None,
            aud: vec![grant.resource.to_owned()],
            client_id: Some(grant.client_id.to_owned()),
            iss: signer.iss().to_owned(),
            exp: (now + lifetime).timestamp(),
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            acr: sid_core::models::session::AuthLevel::Basic
                .acr_value()
                .to_string(),
            scope: grant.scopes.join(" "),
            roles: String::new(),
            amr: Vec::new(),
            sid: grant.credential.to_owned(),
            jti: uuid::Uuid::now_v7().to_string(),
            cnf: grant.dpop.map(|b| CnfClaim { jkt: b.jkt.clone() }),
            act: None,
        };
        signer.sign_claims(Some(ACCESS_TOKEN_TYP), &claims)
    }

    /// Reissue an access token with updated session state (after step-up elevation).
    ///
    /// Preserves sub, pid, scope, roles, cnf, act from the original claims.
    /// Updates acr, amr, iat, exp, jti from the elevated session.
    pub fn reissue_elevated_token(
        &self,
        original: &AccessTokenClaims,
        session: &Session,
    ) -> SidResult<String> {
        let now = Utc::now();
        let (acr, exp) = token_assurance(session, now, now + self.access_token_ttl);

        let claims = AccessTokenClaims {
            sub: original.sub.clone(),
            pid: original.pid.clone(),
            iss: self.issuer.clone(),
            aud: vec![self.issuer.clone()],
            client_id: None,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: session.authenticated_at.timestamp(),
            acr: acr.acr_value().to_string(),
            scope: original.scope.clone(),
            roles: original.roles.clone(),
            amr: session.amr.clone(),
            sid: session.id.to_string(),
            jti: uuid::Uuid::now_v7().to_string(),
            cnf: original.cnf.clone(),
            act: original.act.clone(),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| SidError::Internal(format!("JWT encoding failed: {}", e)))
    }

    /// Validate an access token JWT and return its claims.
    pub fn validate_access_token(&self, token: &str) -> SidResult<AccessTokenClaims> {
        self.verifier.validate_access_token(token)
    }

    /// The verify-only half of this service, for components that accept tokens.
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }

    /// Issue an OIDC ID token.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_id_token(
        &self,
        sub: &str,
        profile: &Profile,
        session: &Session,
        client_id: &str,
        nonce: Option<&str>,
        primary_email: Option<&ProfileEmail>,
        primary_phone: Option<&ProfilePhone>,
    ) -> SidResult<String> {
        self.id_token_signed_by(
            self,
            sub,
            profile,
            session,
            client_id,
            nonce,
            primary_email,
            primary_phone,
        )
    }

    /// An ID token issued by `signer` with this service's lifetime;
    /// otherwise as [`Self::issue_id_token`].
    #[allow(clippy::too_many_arguments)]
    pub fn id_token_signed_by<S: TokenSigner>(
        &self,
        signer: &S,
        sub: &str,
        profile: &Profile,
        session: &Session,
        client_id: &str,
        nonce: Option<&str>,
        primary_email: Option<&ProfileEmail>,
        primary_phone: Option<&ProfilePhone>,
    ) -> SidResult<String> {
        let now = Utc::now();
        let exp = now + self.id_token_ttl;

        let claims = IdTokenClaims {
            sub: sub.to_string(),
            iss: signer.iss().to_owned(),
            aud: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: session.authenticated_at.timestamp(),
            acr: session.assurance_at(now).acr_value().to_string(),
            amr: session.amr.clone(),
            sid: Some(session.id.to_string()),
            nonce: nonce.map(String::from),
            // OIDC §5.1 Standard Claims — populated from Profile Fields
            name: profile.formatted_name(),
            given_name: profile.given_name.clone(),
            family_name: profile.family_name.clone(),
            middle_name: profile.middle_name.clone(),
            preferred_username: profile.username.clone(),
            email: primary_email.map(|e| e.email.clone()),
            email_verified: primary_email.map(|e| e.verified),
            phone_number: primary_phone.map(|p| p.formatted_e164()),
            phone_number_verified: primary_phone.map(|p| p.verified),
            updated_at: Some(profile.updated_at.timestamp()),
        };

        signer.sign_claims(None, &claims)
    }

    /// Get JWK Set for `/.well-known/jwks.json`.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![Jwk {
                kty: "OKP".to_string(),
                use_field: "sig".to_string(),
                alg: "EdDSA".to_string(),
                kid: self.key_id.clone(),
                crv: "Ed25519".to_string(),
                x: URL_SAFE_NO_PAD.encode(&self.public_key_bytes),
            }],
        }
    }

    /// Decode an ID token without expiry validation.
    ///
    /// Used for RP-Initiated Logout: the ID token may be expired, but we
    /// still need to identify the session to kill. Signature IS verified.
    pub fn decode_id_token_unverified(&self, token: &str) -> SidResult<IdTokenClaims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        // Don't require audience match (RP may have different client_id)
        validation.validate_aud = false;
        // Don't check expiry (token may be expired, but still valid for logout)
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["sub", "iss", "iat"]);

        let token_data: TokenData<IdTokenClaims> =
            decode(token, &self.decoding_key, &validation)
                .map_err(|e| SidError::AuthenticationFailed(format!("Invalid ID token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Issue an impersonation token (RFC 8693 Token Exchange).
    ///
    /// `sub` = target user (who is being impersonated), `actor_sub` = machine
    /// user client_id (who is acting). The token belongs to `session`, the
    /// impersonation session recorded for the target, so revoking that session
    /// or the target's access ends it; it never outlives the session or
    /// `IMPERSONATION_MAX_LIFETIME_SECONDS`.
    pub fn issue_impersonation_token(
        &self,
        sub: &str,
        session: &Session,
        actor_sub: &str,
        scopes: &[String],
    ) -> SidResult<String> {
        use sid_core::models::machine_user::IMPERSONATION_MAX_LIFETIME_SECONDS;

        let now = Utc::now();
        let ttl = Duration::seconds(i64::from(IMPERSONATION_MAX_LIFETIME_SECONDS));
        let exp = (now + ttl).min(session.expires_at);

        let claims = AccessTokenClaims {
            sub: sub.to_string(),
            pid: Some(sub.to_string()),
            iss: self.issuer.clone(),
            aud: vec![self.issuer.clone()],
            client_id: None,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            acr: "urn:sid:acr:impersonation".to_string(),
            scope: scopes.join(" "),
            roles: String::new(),
            amr: vec!["token_exchange".to_string()],
            sid: session.id.to_string(),
            jti: uuid::Uuid::now_v7().to_string(),
            cnf: None,
            act: Some(ActClaim {
                sub: actor_sub.to_string(),
            }),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| SidError::Internal(format!("JWT encoding failed: {}", e)))
    }

    /// Get the issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// A back-channel logout token (OIDC Back-Channel Logout 1.0 §2.4) issued by
/// `signer`: typed `logout+jwt` and short-lived. `sub` is the subject exactly
/// as the client received it in its ID tokens, so the RP can match it.
pub fn logout_token_signed_by<S: TokenSigner>(
    signer: &S,
    sub: &str,
    client_id: &str,
    session_id: Option<&str>,
) -> SidResult<String> {
    let now = Utc::now();
    let claims = LogoutTokenClaims {
        sub: sub.to_string(),
        iss: signer.iss().to_owned(),
        aud: client_id.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(LOGOUT_TOKEN_TTL_SECS)).timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        events: serde_json::Value::Object(serde_json::Map::from_iter([(
            BACKCHANNEL_LOGOUT_EVENT.to_owned(),
            serde_json::json!({}),
        )])),
        sid: session_id.map(String::from),
    };
    signer.sign_claims(Some("logout+jwt"), &claims)
}

/// The event every logout token carries (Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The `iss` a JWT names, read without verifying it: only to choose which
/// verifier checks it.
fn unverified_issuer(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Iss {
        iss: String,
    }
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Iss>(&bytes).ok().map(|i| i.iss)
}

/// Extract the 32-byte Ed25519 public key from a PEM-encoded SubjectPublicKeyInfo.
///
/// Ed25519 SPKI structure (DER):
///   SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00 || 32-byte-key } }
/// Total DER = 12 byte header + 32 byte key = 44 bytes.
fn extract_ed25519_pubkey(pem: &[u8]) -> SidResult<Vec<u8>> {
    let der = pem_to_der(pem)?;

    // Ed25519 SPKI DER is 44 bytes: 12-byte header + 32-byte public key
    if der.len() < 44 {
        return Err(SidError::Internal(
            "Public key DER too short for Ed25519".to_string(),
        ));
    }

    // The last 32 bytes are the raw Ed25519 public key
    Ok(der[der.len() - 32..].to_vec())
}

/// Convert PEM to DER (strip headers, base64 decode).
fn pem_to_der(pem: &[u8]) -> SidResult<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| SidError::Internal(format!("Invalid PEM encoding: {}", e)))?;

    let b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| SidError::Internal(format!("Invalid PEM base64: {}", e)))
}

/// The assurance a token issued at `now` carries, and its expiry: never past
/// `ttl_end`, the session's end, or the step-up it claims.
fn token_assurance(
    session: &Session,
    now: chrono::DateTime<Utc>,
    ttl_end: chrono::DateTime<Utc>,
) -> (sid_core::models::session::AuthLevel, chrono::DateTime<Utc>) {
    let level = session.assurance_at(now);
    let mut exp = ttl_end.min(session.expires_at);
    if let Some(elevation) = session.elevation
        && elevation.until > now
        && level == elevation.level
    {
        exp = exp.min(elevation.until);
    }
    (level, exp)
}

/// Compute SHA-256 thumbprint of a public key (for `kid`).
fn compute_key_thumbprint(key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(key_bytes);
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests;
