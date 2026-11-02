// SPDX-License-Identifier: AGPL-3.0-only
//! MFA provider plugin traits.
//!
//! Extensible multi-factor authentication: implement `MfaProvider` to add
//! new MFA methods (TOTP, hardware keys, etc.) to StructuredID.
//! SID ships with built-in WebAuthn, TOTP, and Recovery code providers.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sid_core::models::{CredentialId, ProfileId};
use uuid::Uuid;

/// Error during MFA operations.
#[derive(Debug, thiserror::Error)]
pub enum MfaError {
    #[error("enrollment failed: {0}")]
    EnrollmentFailed(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("credential not found")]
    CredentialNotFound,
    #[error("method not available")]
    MethodNotAvailable,
    #[error("rate limited")]
    RateLimited,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Context provided to MFA providers during operations.
#[derive(Debug, Clone)]
pub struct MfaContext {
    /// Client IP address.
    pub client_ip: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Current session ID (if exists).
    pub session_id: Option<Uuid>,
}

/// Data returned to the user during enrollment setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    /// Unique enrollment ID (expires after completion or timeout).
    pub enrollment_id: Uuid,
    /// Method-specific setup data (e.g., TOTP secret, QR code URI).
    pub data: serde_json::Value,
}

/// User's response to complete enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// Enrollment ID from the challenge.
    pub enrollment_id: Uuid,
    /// Method-specific verification (e.g., TOTP code to confirm setup).
    pub response: serde_json::Value,
}

/// Stored MFA credential (returned after successful enrollment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaCredential {
    /// Credential ID in the storage.
    pub credential_id: CredentialId,
    /// Method identifier (matches `MfaProvider::method_id()`).
    pub method: String,
    /// User-provided label ("iPhone", "YubiKey 5C", etc.).
    pub label: Option<String>,
}

/// Challenge sent to user for authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Unique challenge ID (expires after verification or timeout).
    pub challenge_id: Uuid,
    /// Method-specific challenge data.
    pub data: serde_json::Value,
}

/// User's response to an MFA challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Challenge ID from the challenge.
    pub challenge_id: Uuid,
    /// Method-specific response (e.g., 6-digit TOTP code).
    pub response: serde_json::Value,
}

/// Result of a successful MFA verification.
#[derive(Debug, Clone)]
pub struct MfaVerification {
    /// The credential that was verified.
    pub credential_id: CredentialId,
    /// The MFA method used.
    pub method: String,
    /// Resulting assurance level after this verification.
    pub assurance_level: AuthLevel,
}

// Re-export from sid-core for convenience.
pub use sid_core::models::AuthLevel;
pub use sid_core::models::FactorProperties;

/// MFA provider plugin trait.
///
/// Implement this trait to add new MFA methods to StructuredID.
/// SID includes built-in providers for WebAuthn, TOTP, and Recovery codes.
///
/// Every implementation MUST declare its `factor_properties()` for the policy
/// engine to classify phishing resistance, factor category, and binding.
#[async_trait]
pub trait MfaProvider: Send + Sync {
    /// Unique identifier for this MFA method (e.g., "totp", "webauthn", "yubikey").
    fn method_id(&self) -> &str;

    /// Human-readable name for UI display (e.g., "Time-based One-Time Password").
    fn display_name(&self) -> &str;

    /// Factor properties for policy engine classification.
    ///
    /// Used by the enforcement engine to determine phishing resistance,
    /// factor category (knowledge/possession/inherence), and binding properties.
    fn factor_properties(&self) -> FactorProperties;

    /// Start enrollment — returns challenge/setup data for the user.
    async fn begin_enrollment(
        &self,
        profile_id: &ProfileId,
        ctx: &MfaContext,
    ) -> Result<EnrollmentChallenge, MfaError>;

    /// Complete enrollment — verify user's response and produce credential.
    async fn complete_enrollment(
        &self,
        profile_id: &ProfileId,
        response: &EnrollmentResponse,
        ctx: &MfaContext,
    ) -> Result<MfaCredential, MfaError>;

    /// Generate authentication challenge for an existing credential.
    async fn challenge(
        &self,
        profile_id: &ProfileId,
        credential: &MfaCredential,
        ctx: &MfaContext,
    ) -> Result<MfaChallenge, MfaError>;

    /// Verify challenge response.
    async fn verify(
        &self,
        profile_id: &ProfileId,
        credential: &MfaCredential,
        response: &ChallengeResponse,
        ctx: &MfaContext,
    ) -> Result<MfaVerification, MfaError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_error_display() {
        let err = MfaError::VerificationFailed("invalid code".to_string());
        assert_eq!(err.to_string(), "verification failed: invalid code");
    }

    #[test]
    fn test_mfa_error_variants() {
        assert_eq!(
            MfaError::EnrollmentFailed("test".into()).to_string(),
            "enrollment failed: test"
        );
        assert_eq!(
            MfaError::CredentialNotFound.to_string(),
            "credential not found"
        );
        assert_eq!(MfaError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            MfaError::MethodNotAvailable.to_string(),
            "method not available"
        );
    }
}
