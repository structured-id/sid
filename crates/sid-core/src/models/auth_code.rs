// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization code domain model.
//!
//! Short-lived authorization codes for OAuth2 code flow.
//! Uses consume-self pattern: `exchange()` takes ownership, preventing reuse.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{GrantAuthentication, ProfileId, ResourceId, SessionId};

/// Errors during authorization code exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCodeError {
    /// Code has already been exchanged for tokens.
    AlreadyUsed,
    /// Code TTL has expired.
    Expired,
}

impl fmt::Display for AuthCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyUsed => write!(f, "authorization code already used"),
            Self::Expired => write!(f, "authorization code expired"),
        }
    }
}

impl std::error::Error for AuthCodeError {}

/// The identity of an authorization request the issuer kept on its server,
/// given when the request is first kept and unchanged while it is continued
/// under new single-use references. It is drawn by the issuer and never
/// taken from a request, so it names that kept request and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestOrigin(uuid::Uuid);

impl RequestOrigin {
    /// A new origin, for a request kept now.
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    /// The origin a store holds as `id`.
    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }

    pub fn into_uuid(self) -> uuid::Uuid {
        self.0
    }
}

impl fmt::Display for RequestOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What redeeming the code of a kept authorization request committed: who
/// authorized it and how, for which resource, and the session it was
/// redeemed into. An unused code is no such result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedAuthorization<O = ProfileId> {
    /// The user who authorized the request.
    pub profile_id: O,
    /// The resource the authorization was granted for.
    pub resource: ResourceId,
    /// How and when that user authenticated in the authorizing session.
    pub authentication: GrantAuthentication,
    /// The session the code was redeemed into.
    pub session_id: SessionId,
}

/// Authorization code (stored as SHA-256 hash, never plaintext). `O` is how
/// the serving authority represents its stable user: a local Profile by
/// default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCode<O = ProfileId> {
    /// SHA-256 hash of the authorization code string.
    pub code_hash: Vec<u8>,

    /// Profile that authorized this code.
    pub profile_id: O,

    /// OAuth2 client that requested this code.
    pub client_id: String,

    /// Redirect URI used in the authorization request (must match on exchange).
    pub redirect_uri: String,

    /// Granted scopes.
    pub scopes: Vec<String>,

    /// The resource the authorization was granted for (RFC 8707); redeeming
    /// the code issues a token for it and no other.
    pub resource: ResourceId,

    /// PKCE code_challenge (S256 only).
    pub code_challenge: Option<String>,

    /// OIDC `nonce` of the authorization request, returned unchanged in the
    /// ID Token issued for this code (OIDC Core §3.1.3.6).
    #[serde(default)]
    pub nonce: Option<String>,

    /// How the user authenticated in the session that authorized the code.
    pub authentication: GrantAuthentication,

    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,

    /// Whether this code has already been exchanged.
    pub used: bool,

    /// Session the code was redeemed into; a second use revokes it.
    #[serde(default)]
    pub session_id: Option<SessionId>,

    /// The kept authorization request the code was issued from; `None` for
    /// a request that was answered as it arrived.
    #[serde(default)]
    pub request_origin: Option<RequestOrigin>,
}

/// Outcome of redeeming an authorization code in storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCodeRedemption {
    /// This call redeemed the code: the session and refresh token are stored.
    Redeemed,
    /// The code was already redeemed (a concurrent or repeated exchange);
    /// nothing was stored. Carries the session of the first redemption.
    AlreadyRedeemed { session_id: Option<SessionId> },
}

/// Result of a successful code exchange. Consumes the original `AuthorizationCode`.
///
/// Provides read access to authorization data needed for token issuance.
/// Cannot be "un-exchanged" — the original code is consumed by `exchange()`.
#[derive(Debug)]
pub struct ExchangedCode<O = ProfileId> {
    inner: AuthorizationCode<O>,
}

impl<O> ExchangedCode<O> {
    /// Profile that authorized this code.
    pub fn profile_id(&self) -> &O {
        &self.inner.profile_id
    }

    /// OAuth2 client that requested this code.
    pub fn client_id(&self) -> &str {
        &self.inner.client_id
    }

    /// Redirect URI from the authorization request.
    pub fn redirect_uri(&self) -> &str {
        &self.inner.redirect_uri
    }

    /// Granted scopes.
    pub fn scopes(&self) -> &[String] {
        &self.inner.scopes
    }

    /// The resource the authorization was granted for.
    pub fn resource(&self) -> ResourceId {
        self.inner.resource
    }

    /// PKCE code_challenge (S256 only).
    pub fn code_challenge(&self) -> Option<&str> {
        self.inner.code_challenge.as_deref()
    }

    /// OIDC `nonce` of the authorization request.
    pub fn nonce(&self) -> Option<&str> {
        self.inner.nonce.as_deref()
    }

    /// How the user authenticated in the session that authorized the code.
    pub fn authentication(&self) -> &GrantAuthentication {
        &self.inner.authentication
    }

    /// SHA-256 hash of the code (for storage marking).
    pub fn code_hash(&self) -> &[u8] {
        &self.inner.code_hash
    }

    /// Scopes as space-separated string.
    pub fn scopes_string(&self) -> String {
        self.inner.scopes.join(" ")
    }
}

impl<O> AuthorizationCode<O> {
    /// Check if code is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if code is usable (not used, not expired).
    pub fn is_valid(&self) -> bool {
        !self.used && !self.is_expired()
    }

    /// Exchange this authorization code (consume-self pattern).
    ///
    /// On success, returns `ExchangedCode` — the original `AuthorizationCode`
    /// is consumed, preventing accidental re-validation or replay.
    ///
    /// Callers must still redeem it atomically in storage
    /// (`StorageBackend::redeem_auth_code`): this in-memory check alone does
    /// not stop two concurrent exchanges.
    pub fn exchange(self) -> Result<ExchangedCode<O>, AuthCodeError> {
        if self.used {
            return Err(AuthCodeError::AlreadyUsed);
        }
        if self.is_expired() {
            return Err(AuthCodeError::Expired);
        }
        Ok(ExchangedCode {
            inner: AuthorizationCode { used: true, ..self },
        })
    }

    /// Scopes as space-separated string.
    pub fn scopes_string(&self) -> String {
        self.scopes.join(" ")
    }

    /// What this code's redemption committed; `None` for a code that was
    /// not redeemed into a session.
    pub fn redeemed(self) -> Option<RedeemedAuthorization<O>> {
        let session_id = self.session_id.filter(|_| self.used)?;
        Some(RedeemedAuthorization {
            profile_id: self.profile_id,
            resource: self.resource,
            authentication: self.authentication,
            session_id,
        })
    }
}

#[cfg(test)]
mod tests;
