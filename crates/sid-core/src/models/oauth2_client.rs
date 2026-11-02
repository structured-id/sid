// SPDX-License-Identifier: AGPL-3.0-only
//! OAuth2 Client domain model.
//!
//! Represents a registered OAuth2/OIDC client (relying party).
//! Includes per-application security policy overrides and
//! Dynamic Client Registration (RFC 7591/7592) support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::claim_mapping::ClaimMapping;
use super::device::DeviceAssurance;
use super::security_policy::EnforcementMode;
use super::session::AuthLevel;
use super::{ApplicationId, ProjectId, ResourceId};

mod keys;
pub use keys::ClientKeySet;

fn default_true() -> bool {
    true
}
fn default_federation_timeout() -> u32 {
    500
}

/// Site login strategy — determines how the login page routes identifiers.
///
/// Configurable per-site (OAuth2Client). Determines whether the login UI shows
/// local-only form, federation button, unified input, or federation-only mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoginStrategy {
    /// Check local DB first → if not found → offer "Sign in with structured.id" button.
    /// Best for Level 0 sites with mostly local users.
    #[default]
    LocalFirst,
    /// Local login form + "Sign in with structured.id" button side by side.
    /// User explicitly chooses. Good for Level 0 sites wanting both visible.
    ShowBoth,
    /// Unified input field → federation lookup → if found: federated auth → else: local fallback.
    /// Default for Level 1+ federation members.
    FederationFirst,
    /// No local accounts. All login goes through federation (SaaS).
    /// Admin opt-in only. Requires all users migrated to federation.
    FederationOnly,
}

impl LoginStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalFirst => "local_first",
            Self::ShowBoth => "show_both",
            Self::FederationFirst => "federation_first",
            Self::FederationOnly => "federation_only",
        }
    }
}

parse_stored!(
    LoginStrategy,
    "login strategy",
    [LocalFirst, ShowBoth, FederationFirst, FederationOnly]
);
parse_stored!(SubjectType, "subject type", [Public, Pairwise]);
parse_stored!(
    TokenEndpointAuthMethod,
    "token endpoint auth method",
    [ClientSecretPost, ClientSecretBasic, None, PrivateKeyJwt]
);
parse_stored!(
    RegistrationPolicy,
    "registration policy",
    [AdminApproval, Authenticated]
);
parse_stored!(ApplicationType, "application type", [Web, Native, Api, Spa]);

impl std::fmt::Display for LoginStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Subject identifier type (RFC 8176 / OpenID Connect Core §8).
///
/// Determines how `sub` claim is generated for this client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    /// All clients see the same `sub` (profile ID). CE default.
    #[default]
    Public,
    /// Each client sees a different `sub` for the same user (privacy-preserving).
    /// Sector-scoped: clients sharing a `sector_identifier_uri` see the same `sub`.
    Pairwise,
}

impl SubjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pairwise => "pairwise",
            Self::Public => "public",
        }
    }
}

impl std::fmt::Display for SubjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Token endpoint authentication method (RFC 7591 §2); the default when a
/// registration names none is `client_secret_basic` (RFC 7591 §2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// Client authenticates via client_secret in POST body.
    ClientSecretPost,
    /// Client authenticates via HTTP Basic Authentication.
    #[default]
    ClientSecretBasic,
    /// No authentication (public client — SPA, mobile).
    None,
    /// Client authenticates via signed JWT (RFC 7523).
    PrivateKeyJwt,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::None => "none",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

impl std::fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Dynamic Client Registration policy (RFC 7591 §1.2).
///
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    /// Requires admin approval after registration request (CE default).
    #[default]
    AdminApproval,
    /// Any authenticated profile with `client:register` scope can register.
    Authenticated,
}

impl RegistrationPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdminApproval => "admin_approval",
            Self::Authenticated => "authenticated",
        }
    }
}

/// Unique identifier for an Initial Access Token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InitialAccessTokenId(pub Uuid);

impl Default for InitialAccessTokenId {
    fn default() -> Self {
        Self(Uuid::now_v7())
    }
}

impl InitialAccessTokenId {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Initial Access Token (IAT) for Dynamic Client Registration.
///
/// Created by admins, used as bearer token in `POST /oauth2/register`.
/// Constrains what the registering client can request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccessToken {
    pub id: InitialAccessTokenId,
    /// SHA-256 of the token value; the token is looked up by it.
    pub token_hash: Vec<u8>,
    /// Project this IAT belongs to.
    pub project_id: ProjectId,
    /// Maximum number of clients that can be registered with this token.
    /// 0 = unlimited.
    pub max_clients: u32,
    /// Number of clients already registered with this token.
    pub clients_registered: u32,
    /// Scopes the registered client is allowed to request.
    pub allowed_scopes: Vec<String>,
    /// Grant types the registered client may use.
    pub allowed_grant_types: Vec<String>,
    /// Glob patterns for allowed redirect URIs (e.g., `https://*.example.com/callback`).
    pub allowed_redirect_patterns: Vec<String>,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// Who created this token.
    pub created_by: String,
    /// Whether this token has been revoked.
    pub revoked: bool,
}

/// Application type determines client behavior and security constraints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    /// Browser-based app (authorization code + PKCE).
    #[default]
    Web,
    /// Mobile/desktop app (authorization code + PKCE, no secret).
    Native,
    /// Machine client (client credentials only).
    Api,
    /// Single-page app (authorization code + PKCE, no secret, no redirect).
    Spa,
}

impl ApplicationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
            Self::Api => "api",
            Self::Spa => "spa",
        }
    }

    /// Whether this app type should have a client secret.
    pub fn requires_secret(&self) -> bool {
        matches!(self, Self::Web | Self::Api)
    }

    /// Whether this app type uses redirect URIs.
    pub fn uses_redirect_uris(&self) -> bool {
        matches!(self, Self::Web | Self::Native | Self::Spa)
    }
}

impl std::fmt::Display for ApplicationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OAuth2 client (relying party).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    /// Client identifier (opaque string, not UUID).
    pub client_id: String,

    /// Project this client belongs to: its application's project.
    pub project_id: ProjectId,

    /// The application whose client role this is.
    pub application_id: ApplicationId,

    /// The resource a token is issued for when a request names none. Only
    /// effective while the client has access to it; without one, a request
    /// naming no resource is refused, never given a substitute audience.
    #[serde(default)]
    pub default_resource: Option<ResourceId>,

    /// Application type (web, native, api, spa).
    pub application_type: ApplicationType,

    /// Argon2 hash of client_secret, held by a client authenticating with a
    /// secret method.
    pub client_secret_hash: Option<Vec<u8>>,

    /// Public keys a `private_key_jwt` client signs its assertions with
    /// (RFC 7591 §2 `jwks`).
    #[serde(default)]
    pub jwks: Option<ClientKeySet>,

    /// Allowed redirect URIs (exact match required).
    pub redirect_uris: Vec<String>,

    /// Scopes this client is allowed to request.
    pub allowed_scopes: Vec<String>,

    /// Grant types this client may use.
    /// Values: "authorization_code", "client_credentials", "refresh_token"
    pub grant_types: Vec<String>,

    /// Human-readable client name.
    pub client_name: String,

    /// Logo URI for the client (OIDC Dynamic Client Registration §2).
    /// Used for consent screen and app launcher favicon.
    #[serde(default)]
    pub logo_uri: Option<String>,

    /// Whether this client is active.
    pub active: bool,

    // ─── Dynamic Client Registration (RFC 7591/7592) ────────────
    /// How this client authenticates at the token endpoint.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,

    /// Response types this client may use (e.g., "code").
    pub response_types: Vec<String>,

    /// Subject identifier type (pairwise or public).
    pub subject_type: SubjectType,

    /// Sector identifier URI for pairwise subject calculation.
    /// All redirect_uris must belong to this sector's host.
    pub sector_identifier_uri: Option<String>,

    /// Contact email addresses for the client owner.
    pub contacts: Vec<String>,

    /// When the client_id was issued (= created_at for static clients).
    pub client_id_issued_at: DateTime<Utc>,

    /// When the client_secret expires. None = no expiry.
    pub client_secret_expires_at: Option<DateTime<Utc>>,

    /// The initial access token this client was dynamically registered
    /// with; `None` for an administrator-created client. Its constraints
    /// bound every later self-service update (RFC 7592 §2.2).
    #[serde(default)]
    pub registration_iat: Option<InitialAccessTokenId>,

    /// Argon2 hash of the Registration Access Token (RFC 7592).
    /// Used for client self-management (GET/PUT/DELETE /oauth2/register/{client_id}).
    pub registration_access_token_hash: Option<Vec<u8>>,

    // ─── Per-application security policy overrides ───────────────
    // These override the org-wide SecurityPolicy for this specific client.
    // `None` = inherit from org policy. `Some(x)` = override (strictest wins).
    /// Minimum authentication context class (ACR) required.
    /// Maps to AuthLevel: Basic=aal1, Standard=aal2, Elevated=aal2+, Critical=aal3.
    pub required_acr: Option<AuthLevel>,

    /// Required authentication methods (RFC 8176 `amr` claim).
    /// All listed methods must be present in the session's amr.
    pub required_amr: Vec<String>,

    /// Enforcement mode for this application's policy requirements.
    pub enforcement_mode: EnforcementMode,

    /// Minimum device assurance level for access.
    pub min_device_assurance: Option<DeviceAssurance>,

    /// Override: require verified email for access to this application.
    pub require_verified_email: Option<bool>,

    /// Override: require verified phone for access to this application.
    pub require_verified_phone: Option<bool>,

    // ─── OIDC Back-Channel Logout (RFC 7009 / OpenID Connect) ────
    /// URI to receive logout_token POST when session is revoked.
    pub backchannel_logout_uri: Option<String>,

    /// Whether the RP requires `sid` (session ID) in logout_token.
    /// If true and no session_id available, skip notification for this client.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,

    /// Where the end-session endpoint may send the browser after logout
    /// (OIDC RP-Initiated Logout 1.0 §3.1); exact match required.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,

    // ─── Claim Mappings (AUTH-017) ────────────────────────────────
    /// Per-client claim mappings: profile field → JWT claim.
    /// CE: static YAML config, stored as JSON in DB.
    #[serde(default)]
    pub claim_mappings: Vec<ClaimMapping>,

    // ─── Site Login Policy ─────────────────────────────────────
    /// Login strategy for this site's login page.
    /// Determines routing: local-first, show both, federation-first, federation-only.
    #[serde(default)]
    pub login_strategy: LoginStrategy,

    /// Whether to show explicit "Sign in with structured.id" button.
    /// Relevant for local_first and show_both strategies.
    #[serde(default = "default_true")]
    pub show_federation_button: bool,

    /// Timeout for federation lookup (ms). Fallback to local on timeout.
    /// Only used by federation_first strategy.
    #[serde(default = "default_federation_timeout")]
    pub federation_timeout_ms: u32,

    /// Whether to show unified input (single field, auto-routing).
    /// Used by federation_first. False = separate local/federation forms.
    #[serde(default)]
    pub unified_input: bool,

    // ─── Organization ──────────────────────────────────────────
    /// Organization this client belongs to: the grouping key of its pairwise
    /// subjects, so every client of one organization gives a profile the
    /// same BindingId, whatever its domain. Registration assigns the
    /// instance organization; a client without one has no pairwise subject.
    pub org_id: Option<crate::models::OrgId>,

    /// Stored revision: 0 for a new client, moved on by every update. An
    /// update applies only over the revision it was read at.
    pub revision: u64,

    pub created_at: DateTime<Utc>,
}

impl OAuth2Client {
    /// Whether this is a public client: one registered to authenticate with
    /// nothing (RFC 7591 §2 `none`). Every other method names a credential it
    /// must present, so a confidential client without one cannot authenticate.
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == TokenEndpointAuthMethod::None
    }

    /// Why this client cannot authenticate by its registered method, if it
    /// cannot: a secret method needs a secret, `private_key_jwt` needs keys.
    pub fn credential_problem(&self) -> Option<&'static str> {
        match self.token_endpoint_auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost
                if self.client_secret_hash.is_none() =>
            {
                Some("a secret-based token_endpoint_auth_method needs a client secret")
            }
            TokenEndpointAuthMethod::PrivateKeyJwt if self.jwks.is_none() => {
                Some("private_key_jwt needs the client's jwks")
            }
            _ => None,
        }
    }

    /// Check if a redirect_uri is allowed.
    pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// Whether `uri` is one of the client's post-logout redirect URIs, by
    /// exact match (OIDC RP-Initiated Logout 1.0 §3).
    pub fn is_post_logout_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris.iter().any(|u| u == uri)
    }

    /// Check if a grant type is allowed.
    pub fn is_grant_type_allowed(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|g| g == grant_type)
    }

    /// Check if a scope is allowed. Returns filtered scopes.
    pub fn filter_scopes(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|s| self.allowed_scopes.iter().any(|a| a == *s))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests;
