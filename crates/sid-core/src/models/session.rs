// SPDX-License-Identifier: AGPL-3.0-only
//! Session domain model.
//!
//! Represents an active user session with scopes, assurance level, and metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Authentication assurance level.
///
/// Determines what operations are allowed in the current session.
/// Levels decay over time (see Session Management Architecture).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AuthLevel {
    /// Single factor (password or passkey). Read-only operations.
    #[default]
    Basic,
    /// MFA verified (password + TOTP/WebAuthn). Normal operations.
    Standard,
    /// Step-up challenge (phishing-resistant). Admin operations.
    Elevated,
    /// Re-authentication + hardware key. Account deletion, key rotation.
    Critical,
}

impl AuthLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    /// OIDC `acr` claim value.
    ///
    /// Uses `urn:sid:acr:` namespace with human-readable level names.
    /// Also supports NIST AAL aliases for interoperability.
    pub fn acr_value(&self) -> &'static str {
        match self {
            Self::Basic => "urn:sid:acr:basic",
            Self::Standard => "urn:sid:acr:standard",
            Self::Elevated => "urn:sid:acr:elevated",
            Self::Critical => "urn:sid:acr:critical",
        }
    }

    /// Parse an ACR value string into an AuthLevel.
    ///
    /// Supports:
    /// - SID canonical: `urn:sid:acr:basic`, `urn:sid:acr:standard`, etc.
    /// - Plain names: `basic`, `standard`, `elevated`, `critical`
    pub fn from_acr_value(s: &str) -> Option<Self> {
        match s {
            "urn:sid:acr:basic" | "basic" => Some(Self::Basic),
            "urn:sid:acr:standard" | "standard" => Some(Self::Standard),
            "urn:sid:acr:elevated" | "elevated" => Some(Self::Elevated),
            "urn:sid:acr:critical" | "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Session decay level — trust degrades over time since authentication.
///
/// Based on `authenticated_at` timestamp. sid-proxy computes decay level
/// from JWT claims without DB call.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionDecayLevel {
    /// 0-1h since authentication. Everything allowed including admin.
    #[default]
    Full,
    /// 1-4h. Normal operations, no critical admin.
    High,
    /// 4-12h. Read + basic writes. Step-up needed for sensitive ops.
    Medium,
    /// 12h+. Read-only. Full re-authentication required.
    Low,
}

impl SessionDecayLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl std::fmt::Display for SessionDecayLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How long a step-up to `Elevated` or `Critical` lasts before the session
/// falls back to the level it holds without it.
pub const ELEVATION_TTL_MINUTES: i64 = 15;

/// A time-bound step-up of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Elevation {
    /// `Elevated` or `Critical`.
    pub level: AuthLevel,
    /// When it lapses.
    pub until: DateTime<Utc>,
}

/// What a completed authentication changes on a session: its own level, its
/// step-up, when it last authenticated and the methods used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthentication {
    pub assurance_level: AuthLevel,
    pub elevation: Option<Elevation>,
    pub authenticated_at: DateTime<Utc>,
    pub amr: Vec<String>,
}

/// What an explicitly trusted issuer's validated ID Token attests about its
/// holder's authentication, as the receiving authority accepts it: the shared
/// SID ACR, the methods and the real authentication time (OpenID Connect Core
/// 1.0 §2: `acr`, `amr`, `auth_time`). An ACR that is no shared SID URN is no
/// level: it is never ordered or read as `Basic`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedEvidence {
    /// The attested level, `None` when the token named none or one SID does
    /// not define.
    pub acr: Option<AuthLevel>,
    /// The attested methods (RFC 8176), kept as the issuer stated them.
    pub amr: Vec<String>,
    /// When the holder actually authenticated at the issuer.
    pub auth_time: DateTime<Utc>,
}

impl AcceptedEvidence {
    /// The evidence with the ACR the token names: a shared SID URN, or no
    /// level for any other string.
    pub fn new(acr: Option<&str>, amr: Vec<String>, auth_time: DateTime<Utc>) -> Self {
        Self {
            acr: acr.and_then(|value| {
                value
                    .starts_with("urn:sid:acr:")
                    .then(|| AuthLevel::from_acr_value(value))
                    .flatten()
            }),
            amr,
            auth_time,
        }
    }

    /// The authentication a session admitted on this evidence holds at
    /// `now`, or `None` when it attests no level. Up to `Standard` the level
    /// is the session's own. `Elevated` and `Critical` are a step-up bounded
    /// as every step-up is, counted from `auth_time`: admitting the evidence
    /// later, again or on a refresh never restarts the window, and a window
    /// that already ended grants nothing.
    pub fn authentication(&self, now: DateTime<Utc>) -> Option<SessionAuthentication> {
        let level = self.acr?;
        let elevation = (level >= AuthLevel::Elevated)
            .then(|| Elevation {
                level,
                until: self.auth_time + chrono::Duration::minutes(ELEVATION_TTL_MINUTES),
            })
            .filter(|e| e.until > now);
        Some(SessionAuthentication {
            assurance_level: level.min(AuthLevel::Standard),
            elevation,
            authenticated_at: self.auth_time,
            amr: self.amr.clone(),
        })
    }
}

/// When and how the user behind a grant authenticated: an authorization
/// code carries it from the session that authorized it to the tokens it
/// redeems into (`auth_time`, `amr`, `acr`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAuthentication {
    /// The IdP session that authenticated; never disclosed to the recipient,
    /// it links the redeemed session to it for logout.
    pub session: SessionId,
    pub authenticated_at: DateTime<Utc>,
    pub amr: Vec<String>,
    /// The session's own level.
    pub assurance_level: AuthLevel,
    /// Its step-up, still bound to the time it lapses.
    pub elevation: Option<Elevation>,
}

/// SHA-256 of the random secret in a browser's IdP session cookie; the
/// secret itself is never stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrowserSecretHash([u8; 32]);

impl BrowserSecretHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for BrowserSecretHash {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| crate::Error::Storage("browser secret hash is not 32 bytes".into()))
    }
}

impl std::fmt::Debug for BrowserSecretHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserSecretHash(..)")
    }
}

/// The CSRF token of a browser session: random, generated with its secret
/// and stored with the session, read by the page through the session's
/// origin-checked context and echoed on every cookie-authenticated call.
/// Unlike the secret it is kept as is, since the context read returns it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BrowserCsrfToken([u8; 32]);

impl BrowserCsrfToken {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for BrowserCsrfToken {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| crate::Error::Storage("browser CSRF token is not 32 bytes".into()))
    }
}

impl std::fmt::Debug for BrowserCsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserCsrfToken(..)")
    }
}

/// CE hardcoded session decay thresholds (hours).
pub const FULL_TRUST_HOURS: i64 = 1;
pub const HIGH_TRUST_HOURS: i64 = 4;
pub const MEDIUM_TRUST_HOURS: i64 = 12;

/// Validated UUIDv7 identifier of a session; construction and decoding go through `sid_ids`.
pub use sid_ids::SessionId;

/// Session represents an active user session. `O` is how the serving
/// authority represents its stable user: a local Profile by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session<O = ProfileId> {
    pub id: SessionId,
    pub profile_id: O,

    /// OAuth2 client that initiated this session (None for direct auth).
    pub client_id: Option<String>,

    /// Device identifier for session binding.
    pub device_id: Option<Uuid>,

    /// Client IP address.
    pub ip_address: String,

    /// User-Agent header.
    pub user_agent: Option<String>,

    /// Granted scopes (parsed from space-separated string).
    pub scopes: Vec<String>,

    /// The assurance the session holds without a time-bound step-up:
    /// `Basic` (single factor) or `Standard` (MFA). Read the level in force
    /// with [`Session::assurance_at`].
    pub assurance_level: AuthLevel,

    /// A step-up to `Elevated`/`Critical`, in force until it lapses.
    pub elevation: Option<Elevation>,

    /// When authentication actually happened (for session decay).
    /// Used by sid-proxy to compute decay level from JWT claims.
    pub authenticated_at: DateTime<Utc>,

    /// Authentication methods used (RFC 8176 `amr` claim).
    /// Cumulative within session — step-up adds methods, never removes.
    pub amr: Vec<String>,

    /// Whether this is a provisional session (from OTP/passwordless).
    /// Provisional sessions have restricted scopes and short TTL.
    pub is_provisional: bool,

    /// Whether the site wants the user to register a passkey.
    /// Set on provisional sessions from passwordless onboarding.
    pub passkey_prompt: bool,

    /// Whether this session is in security policy grace mode.
    ///
    /// When `true`, the user doesn't meet the current security policy
    /// (e.g., MFA not enrolled, password too old) but is allowed to
    /// continue under soft enforcement. The `grace_deadline` indicates
    /// when the grace period expires and enforcement becomes hard.
    pub policy_grace: bool,

    /// When the policy grace period expires.
    ///
    /// After this deadline, the session should be blocked or require
    /// step-up authentication to comply with the security policy.
    /// Only meaningful when `policy_grace` is `true`.
    pub grace_deadline: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Set when a browser signed in with this session: the hash of the
    /// secret its IdP session cookie holds.
    #[serde(skip)]
    pub browser_secret_hash: Option<BrowserSecretHash>,

    /// Set with `browser_secret_hash`: the CSRF token of that browser session.
    #[serde(skip)]
    pub browser_csrf: Option<BrowserCsrfToken>,

    /// For a session redeemed from a grant: the IdP session whose
    /// authentication it reuses. Ending that session ends this one; this
    /// session's own `id` is the `sid` its recipient sees.
    pub authenticated_by: Option<SessionId>,
}

impl<O> Session<O> {
    /// Create a new session.
    pub fn new(profile_id: O, ip_address: String, expires_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            profile_id,
            client_id: None,
            device_id: None,
            ip_address,
            user_agent: None,
            scopes: Vec::new(),
            assurance_level: AuthLevel::Basic,
            elevation: None,
            authenticated_at: now,
            amr: Vec::new(),
            is_provisional: false,
            passkey_prompt: false,
            policy_grace: false,
            grace_deadline: None,
            created_at: now,
            expires_at,
            last_activity_at: None,
            browser_secret_hash: None,
            browser_csrf: None,
            authenticated_by: None,
        }
    }
}

impl Session {
    /// Create a provisional session (from OTP/passwordless).
    /// TTL: 15 minutes, restricted scopes, passkey prompt enabled.
    pub fn new_provisional(profile_id: ProfileId, ip_address: String) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            profile_id,
            client_id: None,
            device_id: None,
            ip_address,
            user_agent: None,
            scopes: vec![
                "profile:read".to_string(),
                "profile:update".to_string(),
                "consent:manage".to_string(),
                "mfa:enroll".to_string(),
            ],
            assurance_level: AuthLevel::Basic,
            elevation: None,
            authenticated_at: now,
            amr: vec!["mca".to_string()], // Multi-channel auth (passwordless onboarding).
            is_provisional: true,
            passkey_prompt: true,
            policy_grace: false,
            grace_deadline: None,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(15),
            last_activity_at: None,
            browser_secret_hash: None,
            browser_csrf: None,
            authenticated_by: None,
        }
    }

    /// The pending context of a sign-in that proved its first factor (at
    /// `assurance`, with `amr`) while the login requirements still need a
    /// second: provisional, for [`PENDING_SECOND_FACTOR_TTL_MINUTES`], its
    /// only scope [`SECOND_FACTOR_SCOPE`]. It authorizes nothing but
    /// completing that sign-in.
    pub fn new_awaiting_second_factor(
        profile_id: ProfileId,
        ip_address: String,
        assurance: AuthLevel,
        amr: Vec<String>,
    ) -> Self {
        let mut session = Self::new(
            profile_id,
            ip_address,
            Utc::now() + chrono::Duration::minutes(PENDING_SECOND_FACTOR_TTL_MINUTES),
        );
        session.scopes = vec![SECOND_FACTOR_SCOPE.to_string()];
        session.assurance_level = assurance;
        session.amr = amr;
        session.is_provisional = true;
        session
    }

    /// Whether this is the pending context of a sign-in owing its second
    /// factor, as opposed to a channel-proof provisional session, which no
    /// factor ever completes into a full one.
    pub fn awaits_second_factor(&self) -> bool {
        self.is_provisional && self.scopes == [SECOND_FACTOR_SCOPE]
    }
}

/// The only scope of a sign-in's pending second-factor context.
pub const SECOND_FACTOR_SCOPE: &str = "sign_in:second_factor";

/// How long a sign-in waits for its second factor.
pub const PENDING_SECOND_FACTOR_TTL_MINUTES: i64 = 5;

impl<O> Session<O> {
    /// When and how this session authenticated, as a grant made from it
    /// carries it.
    pub fn grant_authentication(&self) -> GrantAuthentication {
        GrantAuthentication {
            session: self.authenticated_by.unwrap_or(self.id),
            authenticated_at: self.authenticated_at,
            amr: self.amr.clone(),
            assurance_level: self.assurance_level,
            elevation: self.elevation,
        }
    }

    /// This session, created from a grant, reporting the authentication the
    /// grant carries instead of its own creation.
    pub fn with_grant_authentication(mut self, grant: &GrantAuthentication) -> Self {
        self.authenticated_by = Some(grant.session);
        self.authenticated_at = grant.authenticated_at;
        self.amr = grant.amr.clone();
        self.assurance_level = grant.assurance_level;
        self.elevation = grant.elevation;
        self
    }

    /// Whether the session has ended: at its `expires_at` and after. A token
    /// it bounds is valid only before that instant (RFC 7519 §4.1.4).
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity_at = Some(Utc::now());
    }

    /// Raise the assurance (after MFA or a step-up); never lowers it.
    /// `Standard` is kept for the session; `Elevated`/`Critical` last
    /// [`ELEVATION_TTL_MINUTES`] from now.
    /// Use `as_active().elevate()` from outside this crate.
    pub(crate) fn elevate(&mut self, level: AuthLevel) {
        let now = Utc::now();
        if level < AuthLevel::Elevated {
            if level > self.assurance_level {
                self.assurance_level = level;
            }
            return;
        }
        let current = self.elevation.filter(|e| e.until > now).map(|e| e.level);
        if current.is_none_or(|held| level >= held) {
            self.elevation = Some(Elevation {
                level,
                until: now + chrono::Duration::minutes(ELEVATION_TTL_MINUTES),
            });
        }
    }

    /// The assurance in force at `now`: the step-up while it lasts, the
    /// session's own level otherwise.
    pub fn assurance_at(&self, now: DateTime<Utc>) -> AuthLevel {
        match self.elevation {
            Some(e) if e.until > now => e.level.max(self.assurance_level),
            _ => self.assurance_level,
        }
    }

    /// Add authentication method to `amr` claim (cumulative, deduplicated).
    /// Use `as_active().add_amr()` from outside this crate.
    pub(crate) fn add_amr(&mut self, method: &str) {
        if !self.amr.iter().any(|m| m == method) {
            self.amr.push(method.to_string());
        }
    }

    /// Compute session decay level based on time since authentication.
    pub fn decay_level(&self) -> SessionDecayLevel {
        let hours = (Utc::now() - self.authenticated_at).num_hours();
        if hours < FULL_TRUST_HOURS {
            SessionDecayLevel::Full
        } else if hours < HIGH_TRUST_HOURS {
            SessionDecayLevel::High
        } else if hours < MEDIUM_TRUST_HOURS {
            SessionDecayLevel::Medium
        } else {
            SessionDecayLevel::Low
        }
    }

    /// Reset `authenticated_at` after re-authentication (restores full trust).
    /// Use `as_active().refresh_authentication()` from outside this crate.
    pub(crate) fn refresh_authentication(&mut self) {
        self.authenticated_at = Utc::now();
    }

    /// Check if the session has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Whether the grace period has expired (enforcement should become hard).
    pub fn grace_expired(&self) -> bool {
        match self.grace_deadline {
            Some(deadline) => Utc::now() >= deadline,
            None => false,
        }
    }

    /// Enter policy grace mode with a deadline.
    /// Use `as_active().enter_grace()` from outside this crate.
    pub(crate) fn enter_grace(&mut self, deadline: DateTime<Utc>) {
        self.policy_grace = true;
        self.grace_deadline = Some(deadline);
    }

    /// Gateway: obtain typed wrapper if session is active (not expired, not provisional).
    ///
    /// Returns `None` if the session is expired or provisional.
    /// This is the safe way to perform state-mutating operations on a session.
    pub fn as_active(&mut self) -> Option<ActiveSession<'_, O>> {
        if !self.is_expired() && !self.is_provisional {
            Some(ActiveSession(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if session is expired.
    ///
    /// Returns `None` if the session is still active.
    pub fn as_expired(&self) -> Option<ExpiredSession<'_, O>> {
        if self.is_expired() {
            Some(ExpiredSession(self))
        } else {
            None
        }
    }

    /// The session's authentication state, as a completed authentication
    /// changes it.
    pub fn authentication(&self) -> SessionAuthentication {
        SessionAuthentication {
            assurance_level: self.assurance_level,
            elevation: self.elevation,
            authenticated_at: self.authenticated_at,
            amr: self.amr.clone(),
        }
    }

    /// Scopes as space-separated string (for DB storage).
    pub fn scopes_string(&self) -> String {
        self.scopes.join(" ")
    }
}

impl Session {
    /// Parse scopes from space-separated string.
    pub fn parse_scopes(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }
}

/// Typed wrapper for an active (non-expired, non-provisional) session.
///
/// Guards state-mutating operations: elevate, enter_grace, revoke.
/// Only obtainable through `Session::as_active()` gateway.
pub struct ActiveSession<'a, O = ProfileId>(&'a mut Session<O>);

impl<'a, O> ActiveSession<'a, O> {
    /// Elevate assurance level (e.g., after MFA verification).
    /// Only allows upgrading — never downgrades.
    pub fn elevate(&mut self, level: AuthLevel) {
        self.0.elevate(level);
    }

    /// Enter policy grace mode with a deadline.
    pub fn enter_grace(&mut self, deadline: DateTime<Utc>) {
        self.0.enter_grace(deadline);
    }

    /// Add an authentication method reference (e.g., "otp" after step-up).
    pub fn add_amr(&mut self, method: &str) {
        self.0.add_amr(method);
    }

    /// Reset `authenticated_at` after re-authentication (restores full trust).
    pub fn refresh_authentication(&mut self) {
        self.0.refresh_authentication();
    }

    /// Read-only access to the inner session.
    pub fn inner(&self) -> &Session<O> {
        self.0
    }
}

/// Typed wrapper for a revoked/expired session.
///
/// Read-only — no state mutations allowed.
/// Represents a session that can only be inspected (for audit) or deleted.
pub struct ExpiredSession<'a, O = ProfileId>(&'a Session<O>);

impl<'a, O> ExpiredSession<'a, O> {
    /// Read-only access to the inner session.
    pub fn inner(&self) -> &Session<O> {
        self.0
    }

    /// How long ago the session expired.
    pub fn expired_since(&self) -> chrono::Duration {
        Utc::now() - self.0.expires_at
    }
}

#[cfg(test)]
mod tests;
