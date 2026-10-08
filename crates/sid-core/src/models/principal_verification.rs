// SPDX-License-Identifier: AGPL-3.0-only
//! Principal Verification domain model.
//!
//! Tracks HOW a Principal was verified, by WHOM, and trust decay over time.
//! Each Principal can have multiple verification records (re-verification
//! creates new record with new TTL, old one expires).
//!
//! See: arch/identity/identity-model.md §PrincipalVerification

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::PrincipalId;

/// Unique identifier for a verification record.
///
/// Named `VerificationId` (not `BindingId`) to free `BindingId` for
/// the pairwise service binding concept (see pairwise-binding.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerificationId(pub Uuid);

impl VerificationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for VerificationId {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export AssuranceLevel and VerificationSource from identifier_binding
// (shared types, no rename needed — they describe verification, not identity)
/// Level of Assurance — how strongly the principal was verified.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// Self-asserted, no verification.
    #[default]
    Loa0,
    /// Basic verification (e.g., email confirmation link, SMS OTP).
    Loa1,
    /// Remote verification with document (e.g., KYC with photo ID scan).
    Loa2,
    /// In-person or hardware-attested verification (e.g., NFC passport read).
    Loa3,
    /// Government-issued, cryptographically verified (e.g., eIDAS qualified).
    Loa4,
}

impl AssuranceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loa0 => "loa0",
            Self::Loa1 => "loa1",
            Self::Loa2 => "loa2",
            Self::Loa3 => "loa3",
            Self::Loa4 => "loa4",
        }
    }

    pub fn level(&self) -> u8 {
        match self {
            Self::Loa0 => 0,
            Self::Loa1 => 1,
            Self::Loa2 => 2,
            Self::Loa3 => 3,
            Self::Loa4 => 4,
        }
    }

    pub fn satisfies(&self, minimum: AssuranceLevel) -> bool {
        self.level() >= minimum.level()
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the principal was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationSource {
    /// Email confirmation link / SMS OTP.
    OtpConfirmation,
    /// Remote document verification (KYC provider API).
    RemoteDocument,
    /// NFC read of ePassport / national ID.
    NfcDocument,
    /// In-person verification by operator.
    InPerson,
    /// Government API (eIDAS, DigiD, etc.).
    GovernmentApi,
    /// Federated assertion from trusted IdP.
    FederatedAssertion,
    /// Manual admin override.
    AdminOverride,
    /// Federated org confirmed OTP — extends verification TTL.
    FederatedOtpProlongation,
}

impl VerificationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OtpConfirmation => "otp_confirmation",
            Self::RemoteDocument => "remote_document",
            Self::NfcDocument => "nfc_document",
            Self::InPerson => "in_person",
            Self::GovernmentApi => "government_api",
            Self::FederatedAssertion => "federated_assertion",
            Self::AdminOverride => "admin_override",
            Self::FederatedOtpProlongation => "federated_otp_prolongation",
        }
    }

    pub fn default_assurance(&self) -> AssuranceLevel {
        match self {
            Self::OtpConfirmation => AssuranceLevel::Loa1,
            Self::RemoteDocument => AssuranceLevel::Loa2,
            Self::NfcDocument => AssuranceLevel::Loa3,
            Self::InPerson => AssuranceLevel::Loa3,
            Self::GovernmentApi => AssuranceLevel::Loa4,
            Self::FederatedAssertion => AssuranceLevel::Loa2,
            Self::AdminOverride => AssuranceLevel::Loa1,
            Self::FederatedOtpProlongation => AssuranceLevel::Loa1,
        }
    }
}

impl std::fmt::Display for VerificationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Principal verification — provenance and trust metadata.
///
/// Each `Principal` can have one or more verifications over time
/// (re-verification creates new record, old one expires).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalVerification {
    pub id: VerificationId,

    /// The principal this verification belongs to.
    pub principal_id: PrincipalId,

    /// How the principal was verified.
    pub source: VerificationSource,

    /// Resulting assurance level.
    pub assurance: AssuranceLevel,

    /// Verification provider (e.g., "Netverify", "eIDAS Gateway", "admin@example.com").
    pub provider: Option<String>,

    /// Reference to the verification proof/receipt (opaque ID).
    pub proof_reference: Option<String>,

    /// Document metadata (e.g., passport country, expiry) — encrypted.
    pub document_metadata: Option<String>,

    /// When verification was performed.
    pub verified_at: DateTime<Utc>,

    /// When this verification expires (trust decay).
    /// After expiry, the principal reverts to Loa0 until re-verified.
    pub expires_at: Option<DateTime<Utc>>,
}

impl PrincipalVerification {
    pub fn new(principal_id: PrincipalId, source: VerificationSource) -> Self {
        Self {
            id: VerificationId::new(),
            principal_id,
            source,
            assurance: source.default_assurance(),
            provider: None,
            proof_reference: None,
            document_metadata: None,
            verified_at: Utc::now(),
            expires_at: None,
        }
    }

    pub fn with_assurance(mut self, assurance: AssuranceLevel) -> Self {
        self.assurance = assurance;
        self
    }

    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }

    pub fn effective_assurance(&self) -> AssuranceLevel {
        if self.is_expired() {
            AssuranceLevel::Loa0
        } else {
            self.assurance
        }
    }

    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|exp| (exp - Utc::now()).num_days())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verification() -> PrincipalVerification {
        PrincipalVerification::new(PrincipalId::new(), VerificationSource::OtpConfirmation)
    }

    #[test]
    fn test_verification_new_defaults() {
        let v = make_verification();
        assert_eq!(v.source, VerificationSource::OtpConfirmation);
        assert_eq!(v.assurance, AssuranceLevel::Loa1);
        assert!(v.provider.is_none());
        assert!(v.expires_at.is_none());
        assert!(!v.is_expired());
    }

    #[test]
    fn test_verification_with_assurance() {
        let v = PrincipalVerification::new(PrincipalId::new(), VerificationSource::NfcDocument)
            .with_assurance(AssuranceLevel::Loa4);
        assert_eq!(v.assurance, AssuranceLevel::Loa4);
    }

    #[test]
    fn test_verification_with_provider() {
        let v = make_verification().with_provider("Netverify");
        assert_eq!(v.provider.as_deref(), Some("Netverify"));
    }

    #[test]
    fn test_verification_expired() {
        let v = make_verification().with_expires_at(Utc::now() - chrono::Duration::hours(1));
        assert!(v.is_expired());
        assert_eq!(v.effective_assurance(), AssuranceLevel::Loa0);
    }

    #[test]
    fn test_verification_not_expired() {
        let v = make_verification().with_expires_at(Utc::now() + chrono::Duration::days(30));
        assert!(!v.is_expired());
        assert_eq!(v.effective_assurance(), AssuranceLevel::Loa1);
    }

    #[test]
    fn test_verification_no_expiry_never_expires() {
        let v = make_verification();
        assert!(!v.is_expired());
        assert!(v.days_until_expiry().is_none());
    }

    #[test]
    fn test_verification_serde_roundtrip() {
        let v = PrincipalVerification::new(PrincipalId::new(), VerificationSource::GovernmentApi)
            .with_provider("eIDAS Gateway")
            .with_assurance(AssuranceLevel::Loa4);

        let json = serde_json::to_string(&v).unwrap();
        let parsed: PrincipalVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source, VerificationSource::GovernmentApi);
        assert_eq!(parsed.assurance, AssuranceLevel::Loa4);
        assert_eq!(parsed.provider.as_deref(), Some("eIDAS Gateway"));
    }

    #[test]
    fn test_verification_id_unique() {
        let id1 = VerificationId::new();
        let id2 = VerificationId::new();
        assert_ne!(id1, id2);
    }
}
