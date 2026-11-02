// SPDX-License-Identifier: AGPL-3.0-only
//! MFA (Multi-Factor Authentication) domain models.
//!
//! Enrollment, challenge/response lifecycle, and recovery codes.
//! MFA methods are extensible via `MfaProvider` trait (in sid-plugin).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use subtle::ConstantTimeEq;

use super::{AuthLevel, CredentialId, ProfileId};

/// Phishing resistance class for authentication factors.
///
/// Determines where a factor can be used in policy.
/// See Factor Strength Taxonomy in MFA & Step-Up Architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhishingResistance {
    /// Origin-bound + replay-resistant. Cannot be relayed by phishing proxy.
    PhishingResistant,
    /// Bearer token or shared secret. Can be intercepted and replayed.
    Phishable,
    /// One-time use emergency recovery. Not a security factor for policy.
    Fallback,
}

impl PhishingResistance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PhishingResistant => "phishing_resistant",
            Self::Phishable => "phishable",
            Self::Fallback => "fallback",
        }
    }
}

impl std::fmt::Display for PhishingResistance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// NIST SP 800-63B factor category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorCategory {
    /// Password, PIN, recovery code.
    SomethingYouKnow,
    /// Security key, phone (TOTP), authenticator app.
    SomethingYouHave,
    /// Biometric (used BY platform authenticator, not directly).
    SomethingYouAre,
}

impl FactorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SomethingYouKnow => "something_you_know",
            Self::SomethingYouHave => "something_you_have",
            Self::SomethingYouAre => "something_you_are",
        }
    }
}

impl std::fmt::Display for FactorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured factor properties — security metadata for an MFA method.
///
/// Used by the enforcement engine to determine whether a factor
/// satisfies policy requirements (e.g., phishing-resistant, device-bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorProperties {
    /// Phishing resistance class.
    pub resistance: PhishingResistance,

    /// NIST SP 800-63B factor category.
    pub category: FactorCategory,

    /// Factor is bound to a specific device (cannot be transferred).
    pub device_bound: bool,

    /// Factor verifies origin (e.g., WebAuthn checks RP ID).
    pub origin_bound: bool,

    /// Factor is resistant to replay attacks.
    pub replay_resistant: bool,
}

/// MFA method identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaMethod {
    /// WebAuthn / Passkeys (CE, primary).
    WebAuthn,
    /// TOTP — Google Authenticator, Authy, etc. (CE).
    Totp,
    /// SMS OTP via configurable HTTP gateway (CE).
    /// Phishable + SIM-swap risk. Offered only when no stronger method is enrolled.
    SmsOtp,
    /// One-time recovery codes (CE, fallback).
    Recovery,
    /// Hardware security key via plugin.
    HardwareKey,
    /// Custom MFA via plugin.
    Custom,
}

impl MfaMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WebAuthn => "webauthn",
            Self::Totp => "totp",
            Self::SmsOtp => "sms_otp",
            Self::Recovery => "recovery",
            Self::HardwareKey => "hardware_key",
            Self::Custom => "custom",
        }
    }

    /// Phishing resistance class for this method.
    pub fn phishing_resistance(&self) -> PhishingResistance {
        match self {
            Self::WebAuthn | Self::HardwareKey => PhishingResistance::PhishingResistant,
            Self::Totp | Self::SmsOtp | Self::Custom => PhishingResistance::Phishable,
            Self::Recovery => PhishingResistance::Fallback,
        }
    }

    /// Whether this method is phishing-resistant.
    pub fn is_phishing_resistant(&self) -> bool {
        self.phishing_resistance() == PhishingResistance::PhishingResistant
    }

    /// NIST SP 800-63B factor category.
    pub fn factor_category(&self) -> FactorCategory {
        match self {
            Self::Recovery => FactorCategory::SomethingYouKnow,
            Self::Totp | Self::SmsOtp | Self::WebAuthn | Self::HardwareKey | Self::Custom => {
                FactorCategory::SomethingYouHave
            }
        }
    }

    /// Whether this is a built-in method (not provided by a plugin).
    pub fn is_builtin(&self) -> bool {
        matches!(
            self,
            Self::WebAuthn | Self::Totp | Self::SmsOtp | Self::Recovery
        )
    }

    /// Whether this method should only be offered when no stronger method is enrolled.
    /// SMS OTP has SIM-swap risk — prefer WebAuthn or TOTP when available.
    pub fn offer_only_as_fallback(&self) -> bool {
        matches!(self, Self::SmsOtp)
    }

    /// Structured factor properties for policy evaluation.
    pub fn factor_properties(&self) -> FactorProperties {
        match self {
            Self::WebAuthn => FactorProperties {
                resistance: PhishingResistance::PhishingResistant,
                category: FactorCategory::SomethingYouHave,
                device_bound: true,
                origin_bound: true,
                replay_resistant: true,
            },
            Self::Totp => FactorProperties {
                resistance: PhishingResistance::Phishable,
                category: FactorCategory::SomethingYouHave,
                device_bound: false,
                origin_bound: false,
                replay_resistant: false,
            },
            Self::SmsOtp => FactorProperties {
                resistance: PhishingResistance::Phishable,
                category: FactorCategory::SomethingYouHave,
                device_bound: false,
                origin_bound: false,
                replay_resistant: false,
            },
            Self::Recovery => FactorProperties {
                resistance: PhishingResistance::Fallback,
                category: FactorCategory::SomethingYouKnow,
                device_bound: false,
                origin_bound: false,
                replay_resistant: true, // one-time use
            },
            Self::HardwareKey => FactorProperties {
                resistance: PhishingResistance::PhishingResistant,
                category: FactorCategory::SomethingYouHave,
                device_bound: true,
                origin_bound: true,
                replay_resistant: true,
            },
            Self::Custom => FactorProperties {
                resistance: PhishingResistance::Phishable,
                category: FactorCategory::SomethingYouHave,
                device_bound: false,
                origin_bound: false,
                replay_resistant: false,
            },
        }
    }
}

impl std::fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MFA enrollment status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatus {
    /// Enrollment started, awaiting verification.
    #[default]
    Pending,
    /// Enrollment verified and active.
    Active,
    /// Enrollment disabled by user or admin.
    Disabled,
}

impl EnrollmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for EnrollmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MFA enrollment — tracks which methods a profile has enrolled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollment {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub method: MfaMethod,

    /// Reference to the credential storing method-specific data.
    pub credential_id: CredentialId,

    pub status: EnrollmentStatus,

    pub enrolled_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl MfaEnrollment {
    pub fn new(profile_id: ProfileId, method: MfaMethod, credential_id: CredentialId) -> Self {
        Self {
            id: Uuid::now_v7(),
            profile_id,
            method,
            credential_id,
            status: EnrollmentStatus::Pending,
            enrolled_at: Utc::now(),
            last_used_at: None,
        }
    }

    /// Gateway: obtain typed wrapper if enrollment is in Pending state.
    pub fn as_pending(&mut self) -> Option<PendingEnrollment<'_>> {
        if self.status == EnrollmentStatus::Pending {
            Some(PendingEnrollment(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if enrollment is Active.
    pub fn as_active(&mut self) -> Option<ActiveEnrollment<'_>> {
        if self.status == EnrollmentStatus::Active {
            Some(ActiveEnrollment(self))
        } else {
            None
        }
    }

    pub fn record_use(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    pub fn is_active(&self) -> bool {
        self.status == EnrollmentStatus::Active
    }

    pub fn status(&self) -> EnrollmentStatus {
        self.status
    }
}

/// Typed wrapper for Pending enrollment.
pub struct PendingEnrollment<'a>(&'a mut MfaEnrollment);

impl<'a> PendingEnrollment<'a> {
    /// Verification succeeded. Consumes wrapper.
    pub fn activate(self) {
        self.0.status = EnrollmentStatus::Active;
    }

    pub fn inner(&self) -> &MfaEnrollment {
        self.0
    }
}

/// Typed wrapper for Active enrollment.
pub struct ActiveEnrollment<'a>(&'a mut MfaEnrollment);

impl<'a> ActiveEnrollment<'a> {
    /// Disable by user or admin. Consumes wrapper.
    pub fn disable(self) {
        self.0.status = EnrollmentStatus::Disabled;
    }

    pub fn inner(&self) -> &MfaEnrollment {
        self.0
    }
}

/// MFA challenge status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    /// Challenge issued, awaiting response.
    #[default]
    Pending,
    /// Challenge successfully verified.
    Verified,
    /// Challenge verification failed.
    Failed,
    /// Challenge expired (TTL exceeded).
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Verified | Self::Failed | Self::Expired)
    }
}

impl std::fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MFA challenge — issued when step-up or MFA verification is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub method: MfaMethod,

    pub status: ChallengeStatus,

    /// Challenge-specific data (e.g., WebAuthn challenge bytes, TOTP window).
    pub challenge_data: Vec<u8>,

    /// Number of verification attempts.
    pub attempt_count: u32,

    /// Auth level that will be granted on success.
    pub target_level: AuthLevel,

    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

/// CE hardcoded MFA policy constants.
pub const MFA_CHALLENGE_TTL_SECONDS: u32 = 300; // 5 minutes
pub const MFA_MAX_ATTEMPTS: u32 = 5;
pub const RECOVERY_CODE_COUNT: usize = 10;

impl MfaChallenge {
    pub fn new(
        profile_id: ProfileId,
        method: MfaMethod,
        challenge_data: Vec<u8>,
        target_level: AuthLevel,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            profile_id,
            method,
            status: ChallengeStatus::Pending,
            challenge_data,
            attempt_count: 0,
            target_level,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(MFA_CHALLENGE_TTL_SECONDS as i64),
            verified_at: None,
        }
    }

    /// Whether this challenge has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Whether more attempts are allowed.
    pub fn attempts_remaining(&self) -> bool {
        self.attempt_count < MFA_MAX_ATTEMPTS
    }

    /// Gateway: obtain typed wrapper if challenge is in Pending state.
    ///
    /// Returns `None` if the challenge is already in a terminal state
    /// (Verified, Failed, Expired). This is the ONLY way to transition
    /// a challenge — direct status mutation is not exposed.
    pub fn as_pending(&mut self) -> Option<PendingChallenge<'_>> {
        if self.status == ChallengeStatus::Pending {
            Some(PendingChallenge(self))
        } else {
            None
        }
    }

    /// Whether the challenge can still accept responses.
    pub fn is_actionable(&self) -> bool {
        self.status == ChallengeStatus::Pending && !self.is_expired() && self.attempts_remaining()
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> ChallengeStatus {
        self.status
    }
}

/// Typed wrapper for a challenge in Pending state.
///
/// All transition methods consume `self`, preventing:
/// - Calling both `verify()` and `expire()` on the same challenge
/// - Transitioning from a terminal state
pub struct PendingChallenge<'a>(&'a mut MfaChallenge);

impl<'a> PendingChallenge<'a> {
    /// Record a failed attempt. Does NOT consume — may still verify or fail.
    pub fn record_failure(&mut self) {
        self.0.attempt_count += 1;
        if !self.0.attempts_remaining() {
            self.0.status = ChallengeStatus::Failed;
        }
    }

    /// Mark as successfully verified. Consumes wrapper.
    pub fn verify(self) {
        self.0.status = ChallengeStatus::Verified;
        self.0.verified_at = Some(Utc::now());
    }

    /// Mark as expired (TTL exceeded). Consumes wrapper.
    pub fn expire(self) {
        self.0.status = ChallengeStatus::Expired;
    }

    /// Read-only access to the inner challenge.
    pub fn inner(&self) -> &MfaChallenge {
        self.0
    }
}

/// A single recovery code (one-time use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// SHA-256 hash of the recovery code (plaintext never stored).
    pub code_hash: String,

    /// Whether this code has been used.
    pub used: bool,

    /// When this code was used (if used).
    pub used_at: Option<DateTime<Utc>>,
}

impl RecoveryCode {
    pub fn new(code_hash: impl Into<String>) -> Self {
        Self {
            code_hash: code_hash.into(),
            used: false,
            used_at: None,
        }
    }

    /// Mark as used. Returns `true` if it was unused, `false` if already used.
    pub fn consume(&mut self) -> bool {
        if self.used {
            return false;
        }
        self.used = true;
        self.used_at = Some(Utc::now());
        true
    }
}

/// Recovery code set — 10 one-time codes generated at MFA enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeSet {
    pub profile_id: ProfileId,
    pub codes: Vec<RecoveryCode>,
    pub generated_at: DateTime<Utc>,
}

impl RecoveryCodeSet {
    pub fn new(profile_id: ProfileId, code_hashes: Vec<String>) -> Self {
        Self {
            profile_id,
            codes: code_hashes.into_iter().map(RecoveryCode::new).collect(),
            generated_at: Utc::now(),
        }
    }

    /// Number of unused codes remaining.
    pub fn remaining(&self) -> usize {
        self.codes.iter().filter(|c| !c.used).count()
    }

    /// Whether the user should be warned to regenerate.
    pub fn needs_regeneration(&self) -> bool {
        self.remaining() <= RECOVERY_CODE_WARNING_THRESHOLD
    }

    /// Try to consume a code by its hash. Returns `true` if found and consumed.
    ///
    /// Uses constant-time comparison to prevent timing side-channels
    /// that could reveal which recovery code is valid.
    pub fn consume(&mut self, code_hash: &str) -> bool {
        for code in &mut self.codes {
            let hashes_match = code.code_hash.as_bytes().ct_eq(code_hash.as_bytes()).into();
            if hashes_match && !code.used {
                return code.consume();
            }
        }
        false
    }
}

pub const RECOVERY_CODE_WARNING_THRESHOLD: usize = 3;

/// SMS OTP code length (digits).
pub const SMS_OTP_CODE_LENGTH: u32 = 6;

/// SMS OTP code TTL (seconds). Code expires after this.
pub const SMS_OTP_CODE_TTL_SECONDS: u32 = 300;

/// Maximum SMS OTP requests per hour per profile.
pub const SMS_OTP_MAX_PER_HOUR: u32 = 5;

/// Maximum SMS OTP requests per day per profile.
pub const SMS_OTP_MAX_PER_DAY: u32 = 10;

/// Cooldown between SMS OTP requests (seconds).
pub const SMS_OTP_COOLDOWN_SECONDS: u32 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_method_properties() {
        assert!(MfaMethod::WebAuthn.is_phishing_resistant());
        assert!(MfaMethod::HardwareKey.is_phishing_resistant());
        assert!(!MfaMethod::Totp.is_phishing_resistant());
        assert!(!MfaMethod::SmsOtp.is_phishing_resistant());
        assert!(!MfaMethod::Recovery.is_phishing_resistant());

        assert!(MfaMethod::WebAuthn.is_builtin());
        assert!(MfaMethod::Totp.is_builtin());
        assert!(MfaMethod::SmsOtp.is_builtin());
        assert!(MfaMethod::Recovery.is_builtin());
        assert!(!MfaMethod::HardwareKey.is_builtin());
        assert!(!MfaMethod::Custom.is_builtin());
    }

    #[test]
    fn test_phishing_resistance_classes() {
        assert_eq!(
            MfaMethod::WebAuthn.phishing_resistance(),
            PhishingResistance::PhishingResistant
        );
        assert_eq!(
            MfaMethod::HardwareKey.phishing_resistance(),
            PhishingResistance::PhishingResistant
        );
        assert_eq!(
            MfaMethod::Totp.phishing_resistance(),
            PhishingResistance::Phishable
        );
        assert_eq!(
            MfaMethod::SmsOtp.phishing_resistance(),
            PhishingResistance::Phishable
        );
        assert_eq!(
            MfaMethod::Custom.phishing_resistance(),
            PhishingResistance::Phishable
        );
        assert_eq!(
            MfaMethod::Recovery.phishing_resistance(),
            PhishingResistance::Fallback
        );
    }

    #[test]
    fn test_factor_categories() {
        assert_eq!(
            MfaMethod::Recovery.factor_category(),
            FactorCategory::SomethingYouKnow
        );
        assert_eq!(
            MfaMethod::Totp.factor_category(),
            FactorCategory::SomethingYouHave
        );
        assert_eq!(
            MfaMethod::SmsOtp.factor_category(),
            FactorCategory::SomethingYouHave
        );
        assert_eq!(
            MfaMethod::WebAuthn.factor_category(),
            FactorCategory::SomethingYouHave
        );
        assert_eq!(
            MfaMethod::HardwareKey.factor_category(),
            FactorCategory::SomethingYouHave
        );
    }

    #[test]
    fn test_sms_otp_fallback_only() {
        assert!(MfaMethod::SmsOtp.offer_only_as_fallback());
        assert!(!MfaMethod::WebAuthn.offer_only_as_fallback());
        assert!(!MfaMethod::Totp.offer_only_as_fallback());
        assert!(!MfaMethod::Recovery.offer_only_as_fallback());
        assert!(!MfaMethod::HardwareKey.offer_only_as_fallback());
        assert!(!MfaMethod::Custom.offer_only_as_fallback());
    }

    #[test]
    fn test_sms_otp_serde() {
        let m = MfaMethod::SmsOtp;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"sms_otp\"");
        let parsed: MfaMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MfaMethod::SmsOtp);
    }

    #[test]
    fn test_phishing_resistance_serde() {
        let r = PhishingResistance::PhishingResistant;
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"phishing_resistant\"");
        let parsed: PhishingResistance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PhishingResistance::PhishingResistant);
    }

    #[test]
    fn test_factor_category_serde() {
        let c = FactorCategory::SomethingYouHave;
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"something_you_have\"");
        let parsed: FactorCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, FactorCategory::SomethingYouHave);
    }

    #[test]
    fn test_enrollment_lifecycle() {
        let mut e = MfaEnrollment::new(ProfileId::generate(), MfaMethod::Totp, CredentialId::new());
        assert_eq!(e.status(), EnrollmentStatus::Pending);
        assert!(!e.is_active());

        e.as_pending().unwrap().activate();
        assert!(e.is_active());

        e.record_use();
        assert!(e.last_used_at.is_some());

        e.as_active().unwrap().disable();
        assert_eq!(e.status(), EnrollmentStatus::Disabled);
        assert!(!e.is_active());
    }

    #[test]
    fn test_enrollment_gateway_pending_returns_none_for_active() {
        let mut e = MfaEnrollment::new(ProfileId::generate(), MfaMethod::Totp, CredentialId::new());
        e.as_pending().unwrap().activate();
        assert!(e.as_pending().is_none());
    }

    #[test]
    fn test_enrollment_gateway_active_returns_none_for_disabled() {
        let mut e = MfaEnrollment::new(ProfileId::generate(), MfaMethod::Totp, CredentialId::new());
        e.as_pending().unwrap().activate();
        e.as_active().unwrap().disable();
        assert!(e.as_active().is_none());
    }

    #[test]
    fn test_enrollment_gateway_pending_returns_none_for_disabled() {
        let mut e = MfaEnrollment::new(ProfileId::generate(), MfaMethod::Totp, CredentialId::new());
        e.as_pending().unwrap().activate();
        e.as_active().unwrap().disable();
        assert!(e.as_pending().is_none());
    }

    #[test]
    fn test_challenge_lifecycle() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::WebAuthn,
            vec![1, 2, 3],
            AuthLevel::Elevated,
        );
        assert_eq!(c.status(), ChallengeStatus::Pending);
        assert!(c.is_actionable());
        assert!(c.attempts_remaining());

        c.as_pending().unwrap().verify();
        assert_eq!(c.status(), ChallengeStatus::Verified);
        assert!(c.verified_at.is_some());
        assert!(!c.is_actionable()); // Terminal.
    }

    #[test]
    fn test_challenge_max_attempts() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::Totp,
            vec![],
            AuthLevel::Standard,
        );

        for _ in 0..MFA_MAX_ATTEMPTS - 1 {
            let mut pending = c.as_pending().unwrap();
            pending.record_failure();
            assert!(c.is_actionable());
        }

        c.as_pending().unwrap().record_failure(); // 5th attempt.
        assert_eq!(c.status(), ChallengeStatus::Failed);
        assert!(!c.is_actionable());
    }

    #[test]
    fn test_challenge_expire() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::Totp,
            vec![],
            AuthLevel::Standard,
        );
        c.as_pending().unwrap().expire();
        assert_eq!(c.status(), ChallengeStatus::Expired);
        assert!(!c.is_actionable());
    }

    #[test]
    fn test_challenge_expire_no_override_terminal() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::Totp,
            vec![],
            AuthLevel::Standard,
        );
        c.as_pending().unwrap().verify();
        // as_pending() returns None for terminal state — can't expire.
        assert!(c.as_pending().is_none());
        assert_eq!(c.status(), ChallengeStatus::Verified);
    }

    #[test]
    fn test_challenge_gateway_pending_returns_none_after_verify() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::WebAuthn,
            vec![],
            AuthLevel::Standard,
        );
        c.as_pending().unwrap().verify();
        assert!(c.as_pending().is_none());
    }

    #[test]
    fn test_challenge_gateway_pending_returns_none_after_fail() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::Totp,
            vec![],
            AuthLevel::Standard,
        );
        // Exhaust attempts
        for _ in 0..MFA_MAX_ATTEMPTS {
            if let Some(mut p) = c.as_pending() {
                p.record_failure();
            }
        }
        assert!(c.as_pending().is_none());
    }

    #[test]
    fn test_challenge_expired_by_time() {
        let mut c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::Totp,
            vec![],
            AuthLevel::Standard,
        );
        c.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(c.is_expired());
        assert!(!c.is_actionable());
    }

    #[test]
    fn test_recovery_code_consume() {
        let mut code = RecoveryCode::new("hash_abc");
        assert!(!code.used);

        assert!(code.consume());
        assert!(code.used);
        assert!(code.used_at.is_some());

        // Double consume returns false.
        assert!(!code.consume());
    }

    #[test]
    fn test_recovery_code_set() {
        let hashes: Vec<String> = (0..10).map(|i| format!("hash_{i}")).collect();
        let mut set = RecoveryCodeSet::new(ProfileId::generate(), hashes);

        assert_eq!(set.remaining(), 10);
        assert!(!set.needs_regeneration());

        // Use 7 codes.
        for i in 0..7 {
            assert!(set.consume(&format!("hash_{i}")));
        }
        assert_eq!(set.remaining(), 3);
        assert!(set.needs_regeneration()); // <= 3 remaining.

        // Use one more.
        assert!(set.consume("hash_7"));
        assert_eq!(set.remaining(), 2);
    }

    #[test]
    fn test_recovery_code_set_invalid_hash() {
        let mut set = RecoveryCodeSet::new(
            ProfileId::generate(),
            vec!["hash_1".into(), "hash_2".into()],
        );
        assert!(!set.consume("hash_nonexistent"));
        assert_eq!(set.remaining(), 2);
    }

    #[test]
    fn test_recovery_code_set_double_consume() {
        let mut set = RecoveryCodeSet::new(ProfileId::generate(), vec!["hash_1".into()]);
        assert!(set.consume("hash_1"));
        assert!(!set.consume("hash_1")); // Already used.
        assert_eq!(set.remaining(), 0);
    }

    #[test]
    fn test_mfa_method_serde() {
        let m = MfaMethod::HardwareKey;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"hardware_key\"");
        let parsed: MfaMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MfaMethod::HardwareKey);
    }

    #[test]
    fn test_challenge_status_serde() {
        let s = ChallengeStatus::Verified;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"verified\"");
        let parsed: ChallengeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ChallengeStatus::Verified);
    }

    #[test]
    fn test_enrollment_status_serde() {
        let s = EnrollmentStatus::Active;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"active\"");
        let parsed: EnrollmentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EnrollmentStatus::Active);
    }

    #[test]
    fn test_challenge_serde_roundtrip() {
        let c = MfaChallenge::new(
            ProfileId::generate(),
            MfaMethod::WebAuthn,
            vec![42, 43],
            AuthLevel::Critical,
        );
        let json = serde_json::to_string(&c).unwrap();
        let parsed: MfaChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, MfaMethod::WebAuthn);
        assert_eq!(parsed.target_level, AuthLevel::Critical);
        assert_eq!(parsed.challenge_data, vec![42, 43]);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MFA_CHALLENGE_TTL_SECONDS, 300);
        assert_eq!(MFA_MAX_ATTEMPTS, 5);
        assert_eq!(RECOVERY_CODE_COUNT, 10);
        assert_eq!(RECOVERY_CODE_WARNING_THRESHOLD, 3);
    }

    // ── SMS OTP constants ────────────────────────────────────────

    #[test]
    fn test_sms_otp_constants() {
        assert_eq!(SMS_OTP_CODE_LENGTH, 6);
        assert_eq!(SMS_OTP_CODE_TTL_SECONDS, 300);
        assert_eq!(SMS_OTP_MAX_PER_HOUR, 5);
        assert_eq!(SMS_OTP_MAX_PER_DAY, 10);
        assert_eq!(SMS_OTP_COOLDOWN_SECONDS, 60);
    }

    // ── FactorProperties tests ───────────────────────────────────

    #[test]
    fn test_webauthn_factor_properties() {
        let props = MfaMethod::WebAuthn.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::PhishingResistant);
        assert_eq!(props.category, FactorCategory::SomethingYouHave);
        assert!(props.device_bound);
        assert!(props.origin_bound);
        assert!(props.replay_resistant);
    }

    #[test]
    fn test_totp_factor_properties() {
        let props = MfaMethod::Totp.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::Phishable);
        assert_eq!(props.category, FactorCategory::SomethingYouHave);
        assert!(!props.device_bound);
        assert!(!props.origin_bound);
        assert!(!props.replay_resistant);
    }

    #[test]
    fn test_sms_otp_factor_properties() {
        let props = MfaMethod::SmsOtp.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::Phishable);
        assert_eq!(props.category, FactorCategory::SomethingYouHave);
        assert!(!props.device_bound);
        assert!(!props.origin_bound);
        assert!(!props.replay_resistant);
    }

    #[test]
    fn test_recovery_factor_properties() {
        let props = MfaMethod::Recovery.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::Fallback);
        assert_eq!(props.category, FactorCategory::SomethingYouKnow);
        assert!(!props.device_bound);
        assert!(!props.origin_bound);
        assert!(props.replay_resistant); // one-time use
    }

    #[test]
    fn test_hardware_key_factor_properties() {
        let props = MfaMethod::HardwareKey.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::PhishingResistant);
        assert_eq!(props.category, FactorCategory::SomethingYouHave);
        assert!(props.device_bound);
        assert!(props.origin_bound);
        assert!(props.replay_resistant);
    }

    #[test]
    fn test_custom_factor_properties() {
        let props = MfaMethod::Custom.factor_properties();
        assert_eq!(props.resistance, PhishingResistance::Phishable);
        assert!(!props.device_bound);
    }

    #[test]
    fn test_factor_properties_serde_roundtrip() {
        let props = MfaMethod::WebAuthn.factor_properties();
        let json = serde_json::to_string(&props).unwrap();
        let parsed: FactorProperties = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, props);
    }

    #[test]
    fn test_factor_properties_consistency_with_existing_methods() {
        // Verify factor_properties is consistent with existing phishing_resistance() and factor_category()
        for method in [
            MfaMethod::WebAuthn,
            MfaMethod::Totp,
            MfaMethod::SmsOtp,
            MfaMethod::Recovery,
            MfaMethod::HardwareKey,
            MfaMethod::Custom,
        ] {
            let props = method.factor_properties();
            assert_eq!(props.resistance, method.phishing_resistance());
            assert_eq!(props.category, method.factor_category());
        }
    }
}
