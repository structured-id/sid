// SPDX-License-Identifier: AGPL-3.0-only
//! Dynamic Client Registration (RFC 7591 / RFC 7592).
//!
//! Validates client registration requests, enforces IAT constraints,
//! and manages client self-service (read/update/delete via RAT).

use chrono::{DateTime, Utc};
use secrecy::SecretBox;
#[cfg(test)]
use sid_core::models::InitialAccessTokenId;
use sid_core::models::{ApplicationType, InitialAccessToken, SubjectType, TokenEndpointAuthMethod};
use std::fmt;

/// Registration request from `POST /oauth2/register` (RFC 7591 §2).
#[derive(Debug, Clone)]
pub struct ClientRegistrationRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub application_type: ApplicationType,
    pub subject_type: SubjectType,
    pub sector_identifier_uri: Option<String>,
    pub contacts: Vec<String>,
    pub scope: Vec<String>,
    /// Where the end-session endpoint may return the browser after logout
    /// (OIDC RP-Initiated Logout 1.0 §3.1).
    pub post_logout_redirect_uris: Vec<String>,
}

/// Successful registration response (RFC 7591 §3.2.1).
///
/// `client_secret` and `registration_access_token` are wrapped in
/// `SecretBox` — they are shown once to the caller and must not leak
/// into logs or Debug output.
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_secret: Option<SecretBox<String>>,
    pub client_id_issued_at: DateTime<Utc>,
    pub client_secret_expires_at: Option<DateTime<Utc>>,
    pub registration_access_token: SecretBox<String>,
    pub registration_client_uri: String,
}

impl fmt::Debug for ClientRegistrationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistrationResponse")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_id_issued_at", &self.client_id_issued_at)
            .field("client_secret_expires_at", &self.client_secret_expires_at)
            .field("registration_access_token", &"[REDACTED]")
            .field("registration_client_uri", &self.registration_client_uri)
            .finish()
    }
}

/// Errors from DCR operations.
#[derive(Debug, thiserror::Error)]
pub enum DcrError {
    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    /// A post-logout redirect URI a redirect URI of this client type could
    /// not be, or one outside the initial access token's patterns.
    #[error("invalid post-logout redirect URI: {0}")]
    InvalidPostLogoutRedirectUri(String),

    /// Client metadata the issuer does not support: refused as
    /// `invalid_client_metadata`, never replaced by a supported value.
    #[error("{message}")]
    IncompatibleMetadata {
        field: &'static str,
        message: &'static str,
    },

    #[error("client_name is required")]
    MissingClientName,

    #[error("at least one redirect_uri is required for {0} clients")]
    MissingRedirectUris(ApplicationType),

    #[error("invalid grant type: {0}")]
    InvalidGrantType(String),

    #[error("invalid response_type: {0}")]
    InvalidResponseType(String),

    #[error("initial access token required")]
    IatRequired,

    #[error("initial access token expired")]
    IatExpired,

    #[error("initial access token revoked")]
    IatRevoked,

    #[error("initial access token client limit reached ({max})")]
    IatClientLimitReached { max: u32 },

    #[error("scope '{0}' not allowed by initial access token")]
    ScopeNotAllowed(String),

    #[error("grant type '{0}' not allowed by initial access token")]
    GrantTypeNotAllowed(String),

    #[error("redirect URI '{0}' does not match allowed patterns")]
    RedirectPatternMismatch(String),

    #[error("registration access token invalid")]
    InvalidRegistrationAccessToken,

    #[error("client not found: {0}")]
    ClientNotFound(String),

    #[error("client was not dynamically registered")]
    NotDynamicallyRegistered,

    #[error("storage error: {0}")]
    Storage(#[from] sid_core::Error),
}

impl DcrError {
    /// The registration error code (RFC 7591 §3.2.2) and the metadata field
    /// of a refusal of the requested metadata; `None` for the other errors
    /// (credentials, lookups, storage), which carry their own protocol errors.
    pub fn metadata_error(&self) -> Option<(&'static str, &'static str)> {
        const REDIRECT: &str = "invalid_redirect_uri";
        const METADATA: &str = "invalid_client_metadata";
        match self {
            Self::InvalidRedirectUri(_)
            | Self::MissingRedirectUris(_)
            | Self::RedirectPatternMismatch(_) => Some((REDIRECT, "redirect_uris")),
            // RFC 7591 §3.2.2 reserves `invalid_redirect_uri` for
            // `redirect_uris`; other metadata is `invalid_client_metadata`.
            Self::InvalidPostLogoutRedirectUri(_) => Some((METADATA, "post_logout_redirect_uris")),
            Self::IncompatibleMetadata { field, .. } => Some((METADATA, field)),
            Self::MissingClientName => Some((METADATA, "client_name")),
            Self::InvalidGrantType(_) | Self::GrantTypeNotAllowed(_) => {
                Some((METADATA, "grant_types"))
            }
            Self::InvalidResponseType(_) => Some((METADATA, "response_types")),
            Self::ScopeNotAllowed(_) => Some((METADATA, "scope")),
            Self::IatRequired
            | Self::IatExpired
            | Self::IatRevoked
            | Self::IatClientLimitReached { .. }
            | Self::InvalidRegistrationAccessToken
            | Self::ClientNotFound(_)
            | Self::NotDynamicallyRegistered
            | Self::Storage(_) => None,
        }
    }
}

/// Valid grant types per RFC 7591 §2.
const VALID_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
];

/// Valid response types per RFC 7591 §2.
const VALID_RESPONSE_TYPES: &[&str] = &["code"];

/// Fill metadata a request left out with its RFC 7591 §2 default: omitted
/// `grant_types` mean `authorization_code`, omitted `response_types` mean
/// `code`.
pub fn apply_metadata_defaults(grant_types: &mut Vec<String>, response_types: &mut Vec<String>) {
    if grant_types.is_empty() {
        grant_types.push("authorization_code".into());
    }
    if response_types.is_empty() {
        response_types.push("code".into());
    }
}

/// Subject metadata a scoped issuer accepts: `public` only, and no sector.
///
/// The issuer advertises `subject_types_supported: ["public"]`; the subject a
/// user gets is decided by the subject-resolution contract, not by client
/// metadata, and a sector document never selects the grouping. OIDC
/// Registration 1.0 §3.3 lets the server refuse metadata it does not support,
/// which SID does rather than substitute a value (registration metadata A).
pub fn check_subject_metadata(
    subject_type: SubjectType,
    sector_identifier_uri: Option<&str>,
) -> Result<(), DcrError> {
    if subject_type != SubjectType::Public {
        return Err(DcrError::IncompatibleMetadata {
            field: "subject_type",
            message: "subject_type 'pairwise' is not supported by this issuer. \
                      Supported value: 'public'.",
        });
    }
    if sector_identifier_uri.is_some() {
        return Err(DcrError::IncompatibleMetadata {
            field: "sector_identifier_uri",
            message: "sector_identifier_uri is not supported by this issuer: \
                      its subjects are public within the issuer and need no sector.",
        });
    }
    Ok(())
}

/// Validate a client registration request (RFC 7591 §2): subject metadata
/// the issuer supports ([`check_subject_metadata`]), then
/// [`validate_client_metadata`].
pub fn validate_registration_request(req: &ClientRegistrationRequest) -> Result<(), DcrError> {
    check_subject_metadata(req.subject_type, req.sector_identifier_uri.as_deref())?;
    validate_client_metadata(req)
}

/// Validate a client's metadata other than its subject metadata, which an
/// update checks only where the request sets it.
///
/// Checks:
/// - Required fields present
/// - Redirect URIs are valid HTTPS URLs (or http://localhost for native)
/// - Grant types are valid
/// - Response types are valid
pub fn validate_client_metadata(req: &ClientRegistrationRequest) -> Result<(), DcrError> {
    // Client name required
    if req.client_name.trim().is_empty() {
        return Err(DcrError::MissingClientName);
    }

    // Redirect URIs required for non-API clients
    if req.application_type.uses_redirect_uris() && req.redirect_uris.is_empty() {
        return Err(DcrError::MissingRedirectUris(req.application_type));
    }

    // Validate redirect URIs
    for uri in &req.redirect_uris {
        validate_redirect_uri(uri, req.application_type)?;
    }
    validate_post_logout_redirect_uris(&req.post_logout_redirect_uris, req.application_type)?;

    // Validate grant types
    for gt in &req.grant_types {
        if !VALID_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(DcrError::InvalidGrantType(gt.clone()));
        }
    }

    // Validate response types
    for rt in &req.response_types {
        if !VALID_RESPONSE_TYPES.contains(&rt.as_str()) {
            return Err(DcrError::InvalidResponseType(rt.clone()));
        }
    }

    Ok(())
}

/// Validate post-logout redirect URIs: each must be one a redirect URI of
/// `app_type` could be, since the browser is sent there the same way (OIDC
/// RP-Initiated Logout 1.0 §3.1 defines them as redirection URI values).
pub fn validate_post_logout_redirect_uris(
    uris: &[String],
    app_type: ApplicationType,
) -> Result<(), DcrError> {
    for uri in uris {
        validate_redirect_uri(uri, app_type)
            .map_err(|_| DcrError::InvalidPostLogoutRedirectUri(uri.clone()))?;
    }
    Ok(())
}

/// Validate a single redirect URI.
fn validate_redirect_uri(uri: &str, app_type: ApplicationType) -> Result<(), DcrError> {
    let parsed = url::Url::parse(uri).map_err(|_| DcrError::InvalidRedirectUri(uri.to_string()))?;

    match app_type {
        ApplicationType::Native => {
            // Native apps: allow http://localhost, http://127.0.0.1, custom scheme
            let scheme = parsed.scheme();
            if scheme == "http" {
                let host = parsed.host_str().unwrap_or("");
                if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
                    return Err(DcrError::InvalidRedirectUri(format!(
                        "native app http redirect must be localhost, got: {host}"
                    )));
                }
            }
            // Custom schemes and https are always ok for native
        }
        _ => {
            // Web, SPA: must be HTTPS (except localhost for dev)
            if parsed.scheme() != "https" {
                let host = parsed.host_str().unwrap_or("");
                if host != "localhost" && host != "127.0.0.1" {
                    return Err(DcrError::InvalidRedirectUri(format!(
                        "redirect URI must use HTTPS: {uri}"
                    )));
                }
            }
            // Fragment not allowed per RFC 6749 §3.1.2
            if parsed.fragment().is_some() {
                return Err(DcrError::InvalidRedirectUri(
                    "redirect URI must not contain fragment".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate Initial Access Token constraints against registration request.
pub fn validate_iat_constraints(
    iat: &InitialAccessToken,
    req: &ClientRegistrationRequest,
) -> Result<(), DcrError> {
    // Token expired?
    if iat.expires_at < Utc::now() {
        return Err(DcrError::IatExpired);
    }

    // Token revoked?
    if iat.revoked {
        return Err(DcrError::IatRevoked);
    }

    // Client limit reached?
    if iat.max_clients > 0 && iat.clients_registered >= iat.max_clients {
        return Err(DcrError::IatClientLimitReached {
            max: iat.max_clients,
        });
    }

    validate_iat_policy(iat, req)
}

/// Check `req` against what `iat` allows (scopes, grant types, redirect URI
/// patterns), without the token's own state. A dynamically registered client
/// stays within the token it was registered with for every later update
/// (RFC 7592 §2.2), even after that token expired or was used up.
pub fn validate_iat_policy(
    iat: &InitialAccessToken,
    req: &ClientRegistrationRequest,
) -> Result<(), DcrError> {
    // Check scopes
    if !iat.allowed_scopes.is_empty() {
        for scope in &req.scope {
            if !iat.allowed_scopes.contains(scope) {
                return Err(DcrError::ScopeNotAllowed(scope.clone()));
            }
        }
    }

    // Check grant types
    if !iat.allowed_grant_types.is_empty() {
        for gt in &req.grant_types {
            if !iat.allowed_grant_types.contains(gt) {
                return Err(DcrError::GrantTypeNotAllowed(gt.clone()));
            }
        }
    }

    // Check redirect URI patterns
    if !iat.allowed_redirect_patterns.is_empty() {
        for uri in &req.redirect_uris {
            if !matches_any_pattern(uri, &iat.allowed_redirect_patterns) {
                return Err(DcrError::RedirectPatternMismatch(uri.clone()));
            }
        }
        // The browser is sent there too, so the token bounds them alike.
        for uri in &req.post_logout_redirect_uris {
            if !matches_any_pattern(uri, &iat.allowed_redirect_patterns) {
                return Err(DcrError::InvalidPostLogoutRedirectUri(uri.clone()));
            }
        }
    }

    Ok(())
}

/// Whether `uri` matches one of `patterns`.
fn matches_any_pattern(uri: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| redirect_pattern_matches(pattern, uri))
}

/// Whether `uri` is a redirect URI `pattern` allows. Both are compared as
/// parsed URLs, component by component: scheme, port and query exactly; `*`
/// matches within one host label or one path segment and never crosses into
/// another component, so it cannot carry the URI to another host. A URI with
/// userinfo or a fragment matches nothing (RFC 6749 §3.1.2).
fn redirect_pattern_matches(pattern: &str, uri: &str) -> bool {
    let (Ok(pattern), Ok(uri)) = (url::Url::parse(pattern), url::Url::parse(uri)) else {
        return false;
    };
    if !uri.username().is_empty() || uri.password().is_some() || uri.fragment().is_some() {
        return false;
    }
    if pattern.scheme() != uri.scheme()
        || pattern.port_or_known_default() != uri.port_or_known_default()
        || pattern.query() != uri.query()
    {
        return false;
    }
    let hosts_match = match (pattern.host_str(), uri.host_str()) {
        (Some(pattern), Some(host)) => components_match(pattern, host, '.'),
        // A custom-scheme URI of a native application has no host.
        (None, None) => true,
        _ => false,
    };
    hosts_match && components_match(pattern.path(), uri.path(), '/')
}

/// Whether `value` has as many `separator`-delimited components as `pattern`
/// and each matches its pattern component.
fn components_match(pattern: &str, value: &str, separator: char) -> bool {
    let mut patterns = pattern.split(separator);
    let mut values = value.split(separator);
    loop {
        match (patterns.next(), values.next()) {
            (None, None) => return true,
            (Some(pattern), Some(value)) if glob_match(pattern, value) => {}
            _ => return false,
        }
    }
}

/// Whether one URI component `value` matches `pattern`, where `*` matches any
/// run of characters. Callers pass a single component, so the run never
/// includes a separator.
fn glob_match(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut remaining = value;

    // First part must be a prefix
    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        if !remaining.starts_with(first) {
            return false;
        }
        remaining = &remaining[first.len()..];
    }

    // Last part must be a suffix
    if let Some(last) = parts.last()
        && !last.is_empty()
    {
        if !remaining.ends_with(last) {
            return false;
        }
        remaining = &remaining[..remaining.len() - last.len()];
    }

    // Middle parts must appear in order
    for part in &parts[1..parts.len().saturating_sub(1)] {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(pos) => remaining = &remaining[pos + part.len()..],
            None => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests;
