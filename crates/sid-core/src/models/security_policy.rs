// SPDX-License-Identifier: AGPL-3.0-only
//! Security Policy domain model.
//!
//! Defines the organizational security policy with sub-policies for
//! authentication, identifiers, passwords, devices, sessions, and enforcement.
//!
//! The policy is hardcoded via constants.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::device::DeviceAssurance;
use super::mfa::MfaMethod;
use super::session::AuthLevel;

// ── CE hardcoded security policy constants ──────────────────────

/// CE: Minimum authentication context class.
pub const CE_MIN_ACR: AuthLevel = AuthLevel::Basic;

/// CE: MFA is optional (user can enable voluntarily).
pub const CE_MFA_ENFORCEMENT: MfaEnforcement = MfaEnforcement::Optional;

/// CE: Phishing-resistant MFA not required.
pub const CE_REQUIRE_PHISHING_RESISTANT: bool = false;

/// CE: Single passkey with user verification satisfies MFA (NIST-aligned default).
/// When true: passkey login → standard assurance (no second factor needed).
/// When false: passkey login → basic, then require TOTP/second passkey for standard.
pub const CE_PASSKEY_SATISFIES_MFA: bool = true;

/// CE: Verified email required for access.
pub const CE_REQUIRE_VERIFIED_EMAIL: bool = true;

/// CE: Verified phone not required.
pub const CE_REQUIRE_VERIFIED_PHONE: bool = false;

/// CE: Phone verification expires after 180 days.
pub const CE_PHONE_VERIFICATION_TTL_DAYS: u32 = 180;

/// CE: Email verification never expires (0 = no expiry).
pub const CE_EMAIL_VERIFICATION_TTL_DAYS: u32 = 0;

/// CE: Accept federated OTP prolongation for identifier verification.
pub const CE_ACCEPT_FEDERATED_PROLONGATION: bool = true;

/// CE: Minimum password length.
pub const CE_PASSWORD_MIN_LENGTH: u32 = 8;

/// CE: Minimum uppercase characters.
pub const CE_PASSWORD_MIN_UPPERCASE: u32 = 1;

/// CE: Minimum lowercase characters.
pub const CE_PASSWORD_MIN_LOWERCASE: u32 = 1;

/// CE: Minimum digit characters.
pub const CE_PASSWORD_MIN_DIGITS: u32 = 1;

/// CE: Minimum symbol characters.
pub const CE_PASSWORD_MIN_SYMBOLS: u32 = 0;

/// CE: No forced password rotation (0 = disabled).
pub const CE_PASSWORD_MAX_AGE_DAYS: u32 = 0;

/// CE: Retained password history does not expire by age (0 = no limit).
pub const CE_PASSWORD_HISTORY_MAX_AGE_DAYS: u32 = 0;

/// CE: Every password change proves the current password (OWASP ASVS V6.2.3).
pub const CE_PASSWORD_CHANGE_CURRENT_PASSWORD: CurrentPasswordRule = CurrentPasswordRule::Always;

/// CE: No session lifetime limit (0 = unlimited).
pub const CE_SESSION_MAX_LIFETIME_HOURS: u32 = 0;

/// CE: No idle timeout (0 = unlimited).
pub const CE_SESSION_IDLE_TIMEOUT_HOURS: u32 = 0;

/// CE: No concurrent session limit (0 = unlimited).
pub const CE_SESSION_MAX_CONCURRENT: u32 = 0;

/// CE: Session decay — full trust for 1 hour.
pub const CE_SESSION_DECAY_FULL_TRUST_HOURS: u32 = 1;

/// CE: Session decay — high trust for 4 hours.
pub const CE_SESSION_DECAY_HIGH_TRUST_HOURS: u32 = 4;

/// CE: Session decay — medium trust for 12 hours.
pub const CE_SESSION_DECAY_MEDIUM_TRUST_HOURS: u32 = 12;

/// CE: Passkey prompt mode (encouraged = allow skip).
pub const CE_PASSKEY_PROMPT_MODE: PasskeyPromptMode = PasskeyPromptMode::Encouraged;

/// CE: Max skip count before prompts stop (5 skips).
pub const CE_PASSKEY_PROMPT_SKIP_LIMIT: u32 = 5;

/// CE: Skip counter resets after 14 days of inactivity.
pub const CE_PASSKEY_PROMPT_SKIP_COOLDOWN_DAYS: u32 = 14;

/// CE: Open enrollment — anyone can register.
pub const CE_ENROLLMENT_MODE: EnrollmentMode = EnrollmentMode::Open;

/// CE: Default invite max uses (1 = single-use).
pub const CE_INVITE_DEFAULT_MAX_USES: u32 = 1;

/// CE: Default invite expiry (72 hours = 3 days).
pub const CE_INVITE_DEFAULT_EXPIRY_HOURS: u32 = 72;

/// CE: Track registration source metadata.
pub const CE_ENROLLMENT_TRACK_SOURCE: bool = true;

// ── ID type ─────────────────────────────────────────────────────

/// Unique identifier for a security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecurityPolicyId(pub Uuid);

impl SecurityPolicyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SecurityPolicyId {
    fn default() -> Self {
        Self::new()
    }
}

// ── Enums ───────────────────────────────────────────────────────

/// Security policy enforcement mode.
///
/// Determines how policy violations are handled.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Don't enforce — log violations only (monitoring mode).
    #[default]
    Audit,
    /// Soft enforcement — allow with grace period, notify user to comply.
    Soft,
    /// Hard enforcement — block immediately if policy not met.
    Hard,
}

impl EnforcementMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }
}

parse_stored!(EnforcementMode, "enforcement mode", [Audit, Soft, Hard]);

impl std::fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MFA enforcement level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaEnforcement {
    /// User can enable MFA voluntarily.
    #[default]
    Optional,
    /// MFA is mandatory for all users.
    Required,
    /// Risk-based: MFA required when risk signals are elevated.
    Adaptive,
}

impl MfaEnforcement {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
            Self::Adaptive => "adaptive",
        }
    }
}

impl std::fmt::Display for MfaEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Action taken when a soft-enforcement grace period expires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraceExpiryAction {
    /// Block access until policy is met.
    #[default]
    Block,
    /// Suspend the profile.
    Suspend,
    /// Restrict to read-only access.
    ReadOnly,
}

impl GraceExpiryAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Suspend => "suspend",
            Self::ReadOnly => "read_only",
        }
    }
}

impl std::fmt::Display for GraceExpiryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Passkey registration prompt mode.
///
/// Controls whether and how users are prompted to register a passkey.
/// The default is `Encouraged` (allow skip, escalate).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyPromptMode {
    /// Show prompt, allow skip (max N times with escalation).
    #[default]
    Encouraged,
    /// Must register passkey for full session (password = limited scope).
    Required,
    /// No prompts (voluntary only).
    None,
}

impl PasskeyPromptMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encouraged => "encouraged",
            Self::Required => "required",
            Self::None => "none",
        }
    }
}

impl std::fmt::Display for PasskeyPromptMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Passkey prompt configuration.
///
/// Defines how the system prompts users to register passkeys
/// after password-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyPromptConfig {
    /// Prompt mode.
    pub mode: PasskeyPromptMode,

    /// Maximum times user can dismiss prompt before escalation stops.
    pub skip_limit: u32,

    /// Days after last skip before counter resets.
    pub skip_cooldown_days: u32,
}

/// Configuration for the invite system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteConfig {
    /// Default max uses for new invite codes. 1 = single-use.
    pub default_max_uses: u32,

    /// Default expiration duration in hours. 0 = no expiry.
    pub default_expiry_hours: u32,
}

/// Enrollment (registration) policy.
///
/// Controls who can create profiles and how registration is tracked.
/// Sub-policy of `SecurityPolicy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentPolicy {
    /// Registration gating mode.
    pub mode: EnrollmentMode,

    /// Invite configuration (used when mode = InviteOnly).
    pub invite: InviteConfig,

    /// Allowed email domains (used when mode = DomainRestricted).
    pub allowed_domains: Vec<String>,

    /// Whether to track registration source metadata on profiles.
    pub track_source: bool,
}

// ── Network policy ──────────────────────────────────────────────

/// Network access restrictions.
///
/// Controls which IPs/locations can authenticate.
/// Sub-policy of `SecurityPolicy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Country restriction mode.
    pub country_mode: CountryMode,

    /// ISO 3166-1 alpha-2 country codes (used with AllowList/BlockList modes).
    pub countries: Vec<String>,

    /// Block logins from known Tor exit nodes.
    pub block_tor: bool,

    /// Block logins from datacenter/hosting provider IPs (ASN-based).
    pub block_datacenter_ips: bool,

    /// Reaction when a network policy violation is detected.
    pub violation_reaction: NetworkViolationReaction,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            country_mode: CountryMode::None,
            countries: Vec::new(),
            block_tor: false,
            block_datacenter_ips: false,
            violation_reaction: NetworkViolationReaction::Block,
        }
    }
}

/// Country restriction mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountryMode {
    /// No country restrictions (default).
    #[default]
    None,
    /// Only listed countries are allowed.
    AllowList,
    /// Listed countries are blocked.
    BlockList,
}

impl CountryMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AllowList => "allow_list",
            Self::BlockList => "block_list",
        }
    }
}

impl std::fmt::Display for CountryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reaction when a network policy violation is detected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkViolationReaction {
    /// Block the request (deny login).
    #[default]
    Block,
    /// Require step-up authentication (MFA re-verification).
    StepUp,
    /// Allow but alert the admin.
    Alert,
}

impl NetworkViolationReaction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::StepUp => "step_up",
            Self::Alert => "alert",
        }
    }
}

impl std::fmt::Display for NetworkViolationReaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Registration gating mode.
///
/// Controls who can self-register on the instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentMode {
    /// Anyone can register. Default for new instances.
    #[default]
    Open,
    /// Registration only with a valid invite code.
    InviteOnly,
    /// Only admin can create profiles (SCIM, admin-ui, API).
    AdminOnly,
    /// Only users with email in allowed domains can self-register.
    DomainRestricted,
}

impl EnrollmentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InviteOnly => "invite_only",
            Self::AdminOnly => "admin_only",
            Self::DomainRestricted => "domain_restricted",
        }
    }
}

impl std::fmt::Display for EnrollmentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Sub-policy structs ──────────────────────────────────────────

/// Authentication policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPolicy {
    /// Minimum authentication context class (maps to NIST AAL).
    pub min_acr: AuthLevel,

    /// MFA enforcement level.
    pub mfa_enforcement: MfaEnforcement,

    /// Allowed MFA methods for enrollment.
    pub allowed_mfa_methods: Vec<MfaMethod>,

    /// Required authentication methods (RFC 8176 `amr` claim).
    /// All listed methods must be present in the session's amr.
    pub required_amr: Vec<String>,

    /// Whether at least one enrolled MFA factor must be phishing-resistant.
    pub require_phishing_resistant: bool,

    /// Whether a single passkey with user verification satisfies MFA requirement.
    /// When true (default): passkey login → standard assurance (inherent MFA:
    /// possession of device + biometric/PIN = two NIST factors).
    /// When false: passkey login → basic, requires additional factor for standard.
    pub passkey_satisfies_mfa: bool,
}

/// Principal verification policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalPolicy {
    /// Require a verified email address for access.
    pub require_verified_email: bool,

    /// Require a verified phone number for access.
    pub require_verified_phone: bool,

    /// Phone verification expiry (days). 0 = never expires.
    pub phone_verification_ttl_days: u32,

    /// Email verification expiry (days). 0 = never expires.
    pub email_verification_ttl_days: u32,

    /// Whether to accept federated OTP prolongation as re-verification.
    pub accept_federated_prolongation: bool,
}

/// Password complexity and rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length.
    pub min_length: u32,

    /// Minimum uppercase characters.
    pub min_uppercase: u32,

    /// Minimum lowercase characters.
    pub min_lowercase: u32,

    /// Minimum digit characters.
    pub min_digits: u32,

    /// Minimum symbol characters.
    pub min_symbols: u32,

    /// Maximum password age in days. 0 = no forced rotation.
    pub max_age_days: u32,

    /// When a password change must prove the current password.
    pub change_current_password: CurrentPasswordRule,

    /// Days an accepted password is kept in its owner's history, counted
    /// from its acceptance; the owner's newest accepted password always
    /// stays. Applied when the owner next installs a password. 0 = no limit.
    #[serde(default)]
    pub history_max_age_days: u32,
}

/// When a password change must prove the current password. A reset under a
/// verified reset session never does: that session is its authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurrentPasswordRule {
    /// Every change.
    Always,
    /// Only once this many minutes have passed since the session last
    /// authenticated. The credential-binding freshness window still bounds
    /// it: a longer value behaves as that window.
    AfterMinutes(u32),
}

/// Device trust policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicy {
    /// Minimum device assurance level for access.
    pub min_assurance: DeviceAssurance,

    /// Maximum number of trusted devices per profile.
    pub max_trusted_devices: u32,

    /// Days of inactivity before a device is untrusted.
    pub inactivity_days: u32,
}

/// Session decay configuration.
///
/// Defines how long each trust level lasts after authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDecayConfig {
    /// Hours of full trust after authentication.
    pub full_trust_hours: u32,

    /// Hours of high trust after authentication.
    pub high_trust_hours: u32,

    /// Hours of medium trust after authentication. Beyond this = low trust.
    pub medium_trust_hours: u32,
}

/// Session lifetime and concurrency policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// Maximum session lifetime in hours. 0 = unlimited.
    pub max_lifetime_hours: u32,

    /// Idle timeout in hours. 0 = unlimited.
    pub idle_timeout_hours: u32,

    /// Session trust decay thresholds.
    pub decay: SessionDecayConfig,

    /// Maximum concurrent sessions per profile. 0 = unlimited.
    pub max_concurrent_sessions: u32,
}

/// Enforcement configuration.
///
/// Controls how policy violations are handled.
/// In CE, enforcement is always `Hard` with no grace periods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    /// Enforcement mode (audit / soft / hard).
    pub mode: EnforcementMode,

    /// Grace period in days for soft enforcement. 0 = no grace (CE default).
    pub grace_period_days: u32,

    /// Action when grace period expires.
    pub on_grace_expiry: GraceExpiryAction,

    /// Reminder schedule (days before grace expiry to send reminders).
    /// Example: `[14, 7, 3, 1]` means reminders at 14, 7, 3, and 1 days before expiry.
    pub reminder_schedule: Vec<u32>,
}

// ── SecurityPolicy (aggregate) ──────────────────────────────────

/// Organization-level security policy.
///
/// Aggregates all sub-policies into a single configuration.
/// A single hardcoded policy is used (via `ce_default()`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub id: SecurityPolicyId,

    /// Human-readable policy name (e.g., "Default", "NIST AAL2", "PCI DSS v4").
    pub name: String,

    /// Authentication requirements.
    pub auth: AuthPolicy,

    /// Principal verification requirements.
    pub principal: PrincipalPolicy,

    /// Password complexity and rotation rules.
    pub password: PasswordPolicy,

    /// Device trust requirements.
    pub device: DevicePolicy,

    /// Session lifetime and decay rules.
    pub session: SessionPolicy,

    /// Passkey registration prompt behavior.
    pub passkey_prompt: PasskeyPromptConfig,

    /// Enforcement behavior.
    pub enforcement: EnforcementConfig,

    /// Enrollment (registration) policy.
    pub enrollment: EnrollmentPolicy,

    /// Network access restrictions (country, Tor, datacenter IPs).
    pub network: NetworkPolicy,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecurityPolicy {
    /// Whether this policy allows magic links: they are weak possession, so only
    /// a site that requires no more than basic assurance may enable them.
    pub fn permits_magic_links(&self) -> bool {
        self.auth.min_acr <= AuthLevel::Basic
    }

    /// CE hardcoded security policy with sensible defaults.
    ///
    /// In CE, this is the only policy — not configurable via UI or API.
    /// Equivalent to NIST SP 800-63B AAL1 baseline.
    pub fn ce_default() -> Self {
        let now = Utc::now();
        Self {
            id: SecurityPolicyId(Uuid::nil()),
            name: "CE Default".to_string(),
            auth: AuthPolicy {
                min_acr: CE_MIN_ACR,
                mfa_enforcement: CE_MFA_ENFORCEMENT,
                allowed_mfa_methods: vec![
                    MfaMethod::WebAuthn,
                    MfaMethod::Totp,
                    MfaMethod::SmsOtp,
                    MfaMethod::Recovery,
                ],
                required_amr: Vec::new(),
                require_phishing_resistant: CE_REQUIRE_PHISHING_RESISTANT,
                passkey_satisfies_mfa: CE_PASSKEY_SATISFIES_MFA,
            },
            principal: PrincipalPolicy {
                require_verified_email: CE_REQUIRE_VERIFIED_EMAIL,
                require_verified_phone: CE_REQUIRE_VERIFIED_PHONE,
                phone_verification_ttl_days: CE_PHONE_VERIFICATION_TTL_DAYS,
                email_verification_ttl_days: CE_EMAIL_VERIFICATION_TTL_DAYS,
                accept_federated_prolongation: CE_ACCEPT_FEDERATED_PROLONGATION,
            },
            password: PasswordPolicy {
                min_length: CE_PASSWORD_MIN_LENGTH,
                min_uppercase: CE_PASSWORD_MIN_UPPERCASE,
                min_lowercase: CE_PASSWORD_MIN_LOWERCASE,
                min_digits: CE_PASSWORD_MIN_DIGITS,
                min_symbols: CE_PASSWORD_MIN_SYMBOLS,
                max_age_days: CE_PASSWORD_MAX_AGE_DAYS,
                change_current_password: CE_PASSWORD_CHANGE_CURRENT_PASSWORD,
                history_max_age_days: CE_PASSWORD_HISTORY_MAX_AGE_DAYS,
            },
            device: DevicePolicy {
                min_assurance: DeviceAssurance::Unknown,
                max_trusted_devices: 10,
                inactivity_days: 90,
            },
            session: SessionPolicy {
                max_lifetime_hours: CE_SESSION_MAX_LIFETIME_HOURS,
                idle_timeout_hours: CE_SESSION_IDLE_TIMEOUT_HOURS,
                decay: SessionDecayConfig {
                    full_trust_hours: CE_SESSION_DECAY_FULL_TRUST_HOURS,
                    high_trust_hours: CE_SESSION_DECAY_HIGH_TRUST_HOURS,
                    medium_trust_hours: CE_SESSION_DECAY_MEDIUM_TRUST_HOURS,
                },
                max_concurrent_sessions: CE_SESSION_MAX_CONCURRENT,
            },
            passkey_prompt: PasskeyPromptConfig {
                mode: CE_PASSKEY_PROMPT_MODE,
                skip_limit: CE_PASSKEY_PROMPT_SKIP_LIMIT,
                skip_cooldown_days: CE_PASSKEY_PROMPT_SKIP_COOLDOWN_DAYS,
            },
            enforcement: EnforcementConfig {
                mode: EnforcementMode::Hard,
                grace_period_days: 0,
                on_grace_expiry: GraceExpiryAction::Block,
                reminder_schedule: Vec::new(),
            },
            enrollment: EnrollmentPolicy {
                mode: CE_ENROLLMENT_MODE,
                invite: InviteConfig {
                    default_max_uses: CE_INVITE_DEFAULT_MAX_USES,
                    default_expiry_hours: CE_INVITE_DEFAULT_EXPIRY_HOURS,
                },
                allowed_domains: Vec::new(),
                track_source: CE_ENROLLMENT_TRACK_SOURCE,
            },
            network: NetworkPolicy::default(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CE default policy tests ──────────────────────────────────

    #[test]
    fn test_ce_default_auth_policy() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.auth.min_acr, AuthLevel::Basic);
        assert_eq!(policy.auth.mfa_enforcement, MfaEnforcement::Optional);
        assert!(!policy.auth.require_phishing_resistant);
        assert!(policy.auth.passkey_satisfies_mfa);
        assert!(policy.auth.required_amr.is_empty());
        assert_eq!(policy.auth.allowed_mfa_methods.len(), 4);
        assert!(
            policy
                .auth
                .allowed_mfa_methods
                .contains(&MfaMethod::WebAuthn)
        );
        assert!(policy.auth.allowed_mfa_methods.contains(&MfaMethod::Totp));
        assert!(policy.auth.allowed_mfa_methods.contains(&MfaMethod::SmsOtp));
        assert!(
            policy
                .auth
                .allowed_mfa_methods
                .contains(&MfaMethod::Recovery)
        );
    }

    #[test]
    fn test_ce_default_identifier_policy() {
        let policy = SecurityPolicy::ce_default();
        assert!(policy.principal.require_verified_email);
        assert!(!policy.principal.require_verified_phone);
        assert_eq!(policy.principal.phone_verification_ttl_days, 180);
        assert_eq!(policy.principal.email_verification_ttl_days, 0);
        assert!(policy.principal.accept_federated_prolongation);
    }

    #[test]
    fn test_ce_default_password_policy() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.password.min_length, 8);
        assert_eq!(policy.password.min_uppercase, 1);
        assert_eq!(policy.password.min_lowercase, 1);
        assert_eq!(policy.password.min_digits, 1);
        assert_eq!(policy.password.min_symbols, 0);
        assert_eq!(policy.password.max_age_days, 0);
    }

    #[test]
    fn test_ce_default_device_policy() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.device.min_assurance, DeviceAssurance::Unknown);
        assert_eq!(policy.device.max_trusted_devices, 10);
        assert_eq!(policy.device.inactivity_days, 90);
    }

    #[test]
    fn test_ce_default_session_policy() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.session.max_lifetime_hours, 0);
        assert_eq!(policy.session.idle_timeout_hours, 0);
        assert_eq!(policy.session.max_concurrent_sessions, 0);
        assert_eq!(policy.session.decay.full_trust_hours, 1);
        assert_eq!(policy.session.decay.high_trust_hours, 4);
        assert_eq!(policy.session.decay.medium_trust_hours, 12);
    }

    #[test]
    fn test_ce_default_enforcement() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.enforcement.mode, EnforcementMode::Hard);
        assert_eq!(policy.enforcement.grace_period_days, 0);
        assert_eq!(policy.enforcement.on_grace_expiry, GraceExpiryAction::Block);
        assert!(policy.enforcement.reminder_schedule.is_empty());
    }

    #[test]
    fn test_ce_default_uses_nil_uuid() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.id.0, Uuid::nil());
    }

    // ── Enum serde roundtrip tests ───────────────────────────────

    #[test]
    fn test_enforcement_mode_serde() {
        let m = EnforcementMode::Hard;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"hard\"");
        let parsed: EnforcementMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EnforcementMode::Hard);
    }

    #[test]
    fn test_enforcement_mode_default() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Audit);
    }

    #[test]
    fn test_enforcement_mode_as_str() {
        assert_eq!(EnforcementMode::Audit.as_str(), "audit");
        assert_eq!(EnforcementMode::Soft.as_str(), "soft");
        assert_eq!(EnforcementMode::Hard.as_str(), "hard");
    }

    #[test]
    fn test_mfa_enforcement_serde() {
        let m = MfaEnforcement::Adaptive;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"adaptive\"");
        let parsed: MfaEnforcement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MfaEnforcement::Adaptive);
    }

    #[test]
    fn test_mfa_enforcement_default() {
        assert_eq!(MfaEnforcement::default(), MfaEnforcement::Optional);
    }

    #[test]
    fn test_mfa_enforcement_as_str() {
        assert_eq!(MfaEnforcement::Optional.as_str(), "optional");
        assert_eq!(MfaEnforcement::Required.as_str(), "required");
        assert_eq!(MfaEnforcement::Adaptive.as_str(), "adaptive");
    }

    #[test]
    fn test_grace_expiry_action_serde() {
        let a = GraceExpiryAction::ReadOnly;
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"read_only\"");
        let parsed: GraceExpiryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, GraceExpiryAction::ReadOnly);
    }

    #[test]
    fn test_grace_expiry_action_default() {
        assert_eq!(GraceExpiryAction::default(), GraceExpiryAction::Block);
    }

    #[test]
    fn test_grace_expiry_action_as_str() {
        assert_eq!(GraceExpiryAction::Block.as_str(), "block");
        assert_eq!(GraceExpiryAction::Suspend.as_str(), "suspend");
        assert_eq!(GraceExpiryAction::ReadOnly.as_str(), "read_only");
    }

    // ── Policy serde roundtrip ───────────────────────────────────

    #[test]
    fn test_security_policy_serde_roundtrip() {
        let policy = SecurityPolicy::ce_default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: SecurityPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "CE Default");
        assert_eq!(parsed.auth.min_acr, AuthLevel::Basic);
        assert_eq!(parsed.password.min_length, 8);
        assert_eq!(parsed.enforcement.mode, EnforcementMode::Hard);
        assert_eq!(parsed.enrollment.mode, EnrollmentMode::Open);
        assert!(parsed.enrollment.track_source);
    }

    #[test]
    fn test_security_policy_id_unique() {
        let id1 = SecurityPolicyId::new();
        let id2 = SecurityPolicyId::new();
        assert_ne!(id1, id2);
    }

    // ── Passkey prompt tests ────────────────────────────────────

    #[test]
    fn test_passkey_prompt_mode_default() {
        assert_eq!(PasskeyPromptMode::default(), PasskeyPromptMode::Encouraged);
    }

    #[test]
    fn test_passkey_prompt_mode_serde() {
        let m = PasskeyPromptMode::Required;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"required\"");
        let parsed: PasskeyPromptMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PasskeyPromptMode::Required);
    }

    #[test]
    fn test_passkey_prompt_mode_as_str() {
        assert_eq!(PasskeyPromptMode::Encouraged.as_str(), "encouraged");
        assert_eq!(PasskeyPromptMode::Required.as_str(), "required");
        assert_eq!(PasskeyPromptMode::None.as_str(), "none");
    }

    #[test]
    fn test_passkey_prompt_config_serde_roundtrip() {
        let cfg = PasskeyPromptConfig {
            mode: PasskeyPromptMode::Encouraged,
            skip_limit: 5,
            skip_cooldown_days: 14,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: PasskeyPromptConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, PasskeyPromptMode::Encouraged);
        assert_eq!(parsed.skip_limit, 5);
        assert_eq!(parsed.skip_cooldown_days, 14);
    }

    #[test]
    fn test_ce_default_passkey_prompt() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.passkey_prompt.mode, PasskeyPromptMode::Encouraged);
        assert_eq!(policy.passkey_prompt.skip_limit, 5);
        assert_eq!(policy.passkey_prompt.skip_cooldown_days, 14);
    }

    // ── Enrollment policy tests ──────────────────────────────────

    #[test]
    fn test_enrollment_mode_default() {
        assert_eq!(EnrollmentMode::default(), EnrollmentMode::Open);
    }

    #[test]
    fn test_enrollment_mode_serde() {
        let m = EnrollmentMode::InviteOnly;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"invite_only\"");
        let parsed: EnrollmentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EnrollmentMode::InviteOnly);
    }

    #[test]
    fn test_enrollment_mode_as_str() {
        assert_eq!(EnrollmentMode::Open.as_str(), "open");
        assert_eq!(EnrollmentMode::InviteOnly.as_str(), "invite_only");
        assert_eq!(EnrollmentMode::AdminOnly.as_str(), "admin_only");
        assert_eq!(
            EnrollmentMode::DomainRestricted.as_str(),
            "domain_restricted"
        );
    }

    #[test]
    fn test_enrollment_mode_display() {
        assert_eq!(
            format!("{}", EnrollmentMode::DomainRestricted),
            "domain_restricted"
        );
    }

    #[test]
    fn test_invite_config_serde_roundtrip() {
        let cfg = InviteConfig {
            default_max_uses: 5,
            default_expiry_hours: 168,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: InviteConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_max_uses, 5);
        assert_eq!(parsed.default_expiry_hours, 168);
    }

    #[test]
    fn test_enrollment_policy_serde_roundtrip() {
        let policy = EnrollmentPolicy {
            mode: EnrollmentMode::DomainRestricted,
            invite: InviteConfig {
                default_max_uses: 1,
                default_expiry_hours: 72,
            },
            allowed_domains: vec!["acme.corp".into(), "partner.org".into()],
            track_source: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: EnrollmentPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, EnrollmentMode::DomainRestricted);
        assert_eq!(parsed.allowed_domains.len(), 2);
        assert_eq!(parsed.allowed_domains[0], "acme.corp");
        assert!(parsed.track_source);
    }

    #[test]
    fn test_ce_default_enrollment() {
        let policy = SecurityPolicy::ce_default();
        assert_eq!(policy.enrollment.mode, EnrollmentMode::Open);
        assert_eq!(policy.enrollment.invite.default_max_uses, 1);
        assert_eq!(policy.enrollment.invite.default_expiry_hours, 72);
        assert!(policy.enrollment.allowed_domains.is_empty());
        assert!(policy.enrollment.track_source);
    }

    // ── CE constants tests ───────────────────────────────────────

    #[test]
    fn test_ce_constants() {
        assert_eq!(CE_MIN_ACR, AuthLevel::Basic);
        assert_eq!(CE_MFA_ENFORCEMENT, MfaEnforcement::Optional);
        const { assert!(!CE_REQUIRE_PHISHING_RESISTANT) };
        const { assert!(CE_REQUIRE_VERIFIED_EMAIL) };
        const { assert!(!CE_REQUIRE_VERIFIED_PHONE) };
        assert_eq!(CE_PHONE_VERIFICATION_TTL_DAYS, 180);
        assert_eq!(CE_EMAIL_VERIFICATION_TTL_DAYS, 0);
        const { assert!(CE_ACCEPT_FEDERATED_PROLONGATION) };
        assert_eq!(CE_PASSWORD_MIN_LENGTH, 8);
        assert_eq!(CE_PASSWORD_MIN_UPPERCASE, 1);
        assert_eq!(CE_PASSWORD_MIN_LOWERCASE, 1);
        assert_eq!(CE_PASSWORD_MIN_DIGITS, 1);
        assert_eq!(CE_PASSWORD_MIN_SYMBOLS, 0);
        assert_eq!(CE_PASSWORD_MAX_AGE_DAYS, 0);
        assert_eq!(
            CE_PASSWORD_CHANGE_CURRENT_PASSWORD,
            CurrentPasswordRule::Always
        );
        assert_eq!(CE_SESSION_MAX_LIFETIME_HOURS, 0);
        assert_eq!(CE_SESSION_IDLE_TIMEOUT_HOURS, 0);
        assert_eq!(CE_SESSION_MAX_CONCURRENT, 0);
        assert_eq!(CE_SESSION_DECAY_FULL_TRUST_HOURS, 1);
        assert_eq!(CE_SESSION_DECAY_HIGH_TRUST_HOURS, 4);
        assert_eq!(CE_SESSION_DECAY_MEDIUM_TRUST_HOURS, 12);
        assert_eq!(CE_ENROLLMENT_MODE, EnrollmentMode::Open);
        assert_eq!(CE_INVITE_DEFAULT_MAX_USES, 1);
        assert_eq!(CE_INVITE_DEFAULT_EXPIRY_HOURS, 72);
        const { assert!(CE_ENROLLMENT_TRACK_SOURCE) };
        const { assert!(CE_PASSKEY_SATISFIES_MFA) };
    }

    // ── Sub-policy struct tests ──────────────────────────────────

    #[test]
    fn test_auth_policy_serde_roundtrip() {
        let auth = AuthPolicy {
            min_acr: AuthLevel::Standard,
            mfa_enforcement: MfaEnforcement::Required,
            allowed_mfa_methods: vec![MfaMethod::WebAuthn],
            required_amr: vec!["hwk".into()],
            require_phishing_resistant: true,
            passkey_satisfies_mfa: false,
        };
        let json = serde_json::to_string(&auth).unwrap();
        let parsed: AuthPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_acr, AuthLevel::Standard);
        assert_eq!(parsed.mfa_enforcement, MfaEnforcement::Required);
        assert!(parsed.require_phishing_resistant);
        assert!(!parsed.passkey_satisfies_mfa);
        assert_eq!(parsed.required_amr, vec!["hwk"]);
    }

    #[test]
    fn test_password_policy_serde_roundtrip() {
        let pwd = PasswordPolicy {
            min_length: 12,
            min_uppercase: 2,
            min_lowercase: 2,
            min_digits: 2,
            min_symbols: 1,
            max_age_days: 90,
            change_current_password: CurrentPasswordRule::AfterMinutes(5),
            history_max_age_days: 183,
        };
        let json = serde_json::to_string(&pwd).unwrap();
        let parsed: PasswordPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_length, 12);
        assert_eq!(parsed.max_age_days, 90);
        assert_eq!(parsed.history_max_age_days, 183);
        assert_eq!(
            parsed.change_current_password,
            CurrentPasswordRule::AfterMinutes(5)
        );
    }

    #[test]
    fn test_session_decay_config_serde_roundtrip() {
        let decay = SessionDecayConfig {
            full_trust_hours: 2,
            high_trust_hours: 8,
            medium_trust_hours: 24,
        };
        let json = serde_json::to_string(&decay).unwrap();
        let parsed: SessionDecayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.full_trust_hours, 2);
        assert_eq!(parsed.high_trust_hours, 8);
        assert_eq!(parsed.medium_trust_hours, 24);
    }

    #[test]
    fn test_enforcement_config_serde_roundtrip() {
        let cfg = EnforcementConfig {
            mode: EnforcementMode::Soft,
            grace_period_days: 30,
            on_grace_expiry: GraceExpiryAction::Suspend,
            reminder_schedule: vec![14, 7, 3, 1],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: EnforcementConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, EnforcementMode::Soft);
        assert_eq!(parsed.grace_period_days, 30);
        assert_eq!(parsed.on_grace_expiry, GraceExpiryAction::Suspend);
        assert_eq!(parsed.reminder_schedule, vec![14, 7, 3, 1]);
    }
}
