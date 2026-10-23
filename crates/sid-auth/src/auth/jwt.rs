// SPDX-License-Identifier: AGPL-3.0-only
//! Access-token validation for forward auth: the token must be the target
//! issuer's access token for the target resource, checked with that issuer's
//! public keys only.

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use sid_authn::issuer_directory::{IssuedTokenRefusal, IssuerDirectory};

/// Claims extracted from JWT for forward auth decisions.
///
/// Subset of AccessTokenClaims from sid-authn — only fields needed for
/// auth verification and header injection.
///
/// Serializable because a BFF session carries its claims into the shared
/// session store, where another replica reads them back.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForwardAuthClaims {
    /// Subject (profile_id).
    pub sub: String,
    /// Issuer URL.
    pub iss: String,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Time when the user actually authenticated.
    pub auth_time: i64,
    /// Authentication Context Class Reference (maps to AuthLevel).
    pub acr: String,
    /// Scopes (space-separated).
    #[serde(default)]
    pub scope: String,
    /// Roles (space-separated).
    #[serde(default)]
    pub roles: String,
    /// Session ID.
    pub sid: String,
    /// JWT ID (for revocation check).
    pub jti: String,
    /// Primary email.
    #[serde(default)]
    pub email: Option<String>,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Username.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Groups.
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// Key the token is bound to (RFC 9449 §6.1); a bound token is accepted
    /// only with a proof by that key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// `cnf` claim of a DPoP-bound token (RFC 7800 §3.1, RFC 9449 §6.1).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Confirmation {
    /// JWK SHA-256 thumbprint of the bound key (RFC 7638).
    pub jkt: String,
}

impl From<sid_authn::jwt::AccessTokenClaims> for ForwardAuthClaims {
    /// An application access token carries no profile claims (`email`,
    /// `name`, `groups`), so none are disclosed from it.
    fn from(claims: sid_authn::jwt::AccessTokenClaims) -> Self {
        Self {
            sub: claims.sub,
            iss: claims.iss,
            exp: claims.exp,
            iat: claims.iat,
            auth_time: claims.auth_time,
            acr: claims.acr,
            scope: claims.scope,
            roles: claims.roles,
            sid: claims.sid,
            jti: claims.jti,
            email: None,
            name: None,
            preferred_username: None,
            groups: None,
            cnf: claims.cnf.map(|cnf| Confirmation { jkt: cnf.jkt }),
        }
    }
}

/// How a request carries its access token. Only the `Authorization` header:
/// forward auth reads no browser cookie, so the IdP's own session never
/// reaches a protected application (application-protection: browser boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented<'a> {
    /// `Authorization: Bearer` (RFC 6750 §2.1).
    Bearer(&'a str),
    /// `Authorization: DPoP` (RFC 9449 §7.1).
    DPoP(&'a str),
}

impl<'a> Presented<'a> {
    pub fn token(self) -> &'a str {
        match self {
            Self::Bearer(t) | Self::DPoP(t) => t,
        }
    }
}

/// Why a presented token is not accepted.
#[derive(Debug, thiserror::Error)]
pub enum TokenRefusal {
    /// Not a valid access token for the target.
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The issuer registry could not be asked; the token may be valid.
    #[error("issuer registry unavailable: {0}")]
    Unavailable(String),
    /// The target the route names is not a registered, active resource of
    /// its issuer, so no token opens it.
    #[error("no target: {0}")]
    NoTarget(&'static str),
}

/// Validate an access token presented for `target`.
///
/// The target is resolved in the registry before the token is looked at: it
/// must be an active resource registered under exactly `target.issuer`. The
/// token must then be that issuer's access token (`at+jwt`, its keys, exact
/// `iss`) whose `aud` names the resource (RFC 9068 §4). A token of another
/// issuer, the installation's own sign-in token or an ID token is refused,
/// and nothing is looked up for an `iss` other than the target's
/// (oidc-issuer-model: never fetch keys for an arbitrary `iss`).
pub async fn validate_for_target(
    issuers: &IssuerDirectory,
    target: &super::policy::Target,
    token: &str,
) -> Result<TargetAccess, TokenRefusal> {
    let resource = issuers
        .resource(&target.issuer, &target.resource)
        .await
        .map_err(|e| TokenRefusal::Unavailable(e.0))?
        .ok_or(TokenRefusal::NoTarget("resource not registered"))?;
    if !resource.active {
        return Err(TokenRefusal::NoTarget("resource not active"));
    }
    let claims = issuers
        .issued_access_token(&target.issuer, &target.resource, token)
        .await
        .map(ForwardAuthClaims::from)
        .map_err(|refusal| match refusal {
            IssuedTokenRefusal::Invalid(why) => TokenRefusal::Invalid(why),
            IssuedTokenRefusal::Unavailable(e) => TokenRefusal::Unavailable(e.0),
        })?;
    Ok(TargetAccess {
        claims,
        resource: resource.id,
    })
}

/// A token accepted for a target, and the registered resource it opens.
#[derive(Debug)]
pub struct TargetAccess {
    pub claims: ForwardAuthClaims,
    /// The target's registered resource: what permission questions about
    /// this request name.
    pub resource: sid_core::models::ResourceId,
}

/// The access token of a request and how it is presented: the
/// `Authorization` header, `Bearer` or `DPoP`, scheme matched
/// case-insensitively (RFC 7235 §2.1).
pub fn presented_token(headers: &HeaderMap) -> Option<Presented<'_>> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(Presented::Bearer(token))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some(Presented::DPoP(token))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
