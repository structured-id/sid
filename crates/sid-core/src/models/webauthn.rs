// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn credential domain model.
//!
//! Typed representation of WebAuthn/Passkey credential data.
//! The raw `Credential` stores this as opaque bytes in `data`;
//! this module provides structured access for WebAuthn-specific fields.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::CredentialId;

/// Transport hint — how the authenticator communicates with the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnTransport {
    /// USB (e.g., YubiKey plugged in).
    Usb,
    /// NFC (tap security key).
    Nfc,
    /// BLE (Bluetooth Low Energy).
    Ble,
    /// Internal / platform authenticator (Touch ID, Windows Hello).
    Internal,
    /// Hybrid (cross-device, e.g., phone as authenticator via QR).
    Hybrid,
}

impl WebAuthnTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Nfc => "nfc",
            Self::Ble => "ble",
            Self::Internal => "internal",
            Self::Hybrid => "hybrid",
        }
    }
}

impl std::fmt::Display for WebAuthnTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attestation format (how the authenticator proves its identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationFormat {
    /// No attestation (anonymous authenticator).
    None,
    /// FIDO U2F attestation.
    FidoU2f,
    /// Packed (FIDO2 standard format).
    Packed,
    /// TPM (Trusted Platform Module).
    Tpm,
    /// Android Key Attestation.
    AndroidKey,
    /// Apple Anonymous Attestation.
    Apple,
}

impl AttestationFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FidoU2f => "fido-u2f",
            Self::Packed => "packed",
            Self::Tpm => "tpm",
            Self::AndroidKey => "android-key",
            Self::Apple => "apple",
        }
    }
}

impl std::fmt::Display for AttestationFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// WebAuthn credential — typed representation of passkey/security key data.
///
/// Stored serialized inside `Credential.data` (credential_type = WebAuthn).
/// This struct provides typed access for WebAuthn operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// References the parent `Credential.id`.
    pub credential_id: CredentialId,

    /// Raw credential ID from the authenticator (base64url-encoded).
    pub authenticator_id: Vec<u8>,

    /// COSE-encoded public key from the authenticator.
    pub public_key_cose: Vec<u8>,

    /// Signature counter — incremented on each use.
    /// If the counter goes backwards, it indicates cloning.
    pub sign_count: u32,

    /// How the authenticator communicates with the client.
    pub transports: Vec<WebAuthnTransport>,

    /// Attestation format used during registration.
    pub attestation_format: AttestationFormat,

    /// Whether this is a platform authenticator (Touch ID, Windows Hello)
    /// or cross-platform (USB key, phone).
    pub platform_authenticator: bool,

    /// Whether this credential supports discoverable (resident key) flows.
    /// Discoverable credentials enable usernameless authentication.
    pub discoverable: bool,

    /// Whether the credential is backed up (e.g., synced via iCloud Keychain).
    /// Affects security posture — backed-up keys may be on multiple devices.
    pub backed_up: bool,

    /// AAGUID — authenticator model identifier (16 bytes).
    /// Can identify the make/model of the authenticator.
    pub aaguid: Option<[u8; 16]>,

    /// User-visible name for this authenticator.
    pub display_name: Option<String>,

    pub registered_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl WebAuthnCredential {
    pub fn new(
        credential_id: CredentialId,
        authenticator_id: Vec<u8>,
        public_key_cose: Vec<u8>,
    ) -> Self {
        Self {
            credential_id,
            authenticator_id,
            public_key_cose,
            sign_count: 0,
            transports: vec![],
            attestation_format: AttestationFormat::None,
            platform_authenticator: false,
            discoverable: false,
            backed_up: false,
            aaguid: None,
            display_name: None,
            registered_at: Utc::now(),
            last_used_at: None,
        }
    }

    /// Update sign count after successful authentication.
    /// Returns `true` if the counter is valid (monotonically increasing).
    /// Returns `false` if counter went backwards — possible cloning detected.
    pub fn update_sign_count(&mut self, new_count: u32) -> bool {
        if new_count > self.sign_count {
            self.sign_count = new_count;
            self.last_used_at = Some(Utc::now());
            true
        } else if new_count == 0 && self.sign_count == 0 {
            // Some authenticators always report 0 — allow it.
            self.last_used_at = Some(Utc::now());
            true
        } else {
            // Counter went backwards or stayed the same (>0) — suspicious.
            false
        }
    }

    /// Whether this is a phishing-resistant credential.
    /// Hardware-bound, non-backed-up credentials are phishing-resistant.
    pub fn is_phishing_resistant(&self) -> bool {
        !self.backed_up
    }

    /// Whether this credential satisfies hardware key requirements.
    pub fn is_hardware_bound(&self) -> bool {
        !self.backed_up && !self.platform_authenticator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_webauthn() -> WebAuthnCredential {
        WebAuthnCredential::new(CredentialId::new(), vec![1, 2, 3, 4], vec![5, 6, 7, 8])
    }

    #[test]
    fn test_webauthn_new_defaults() {
        let wc = make_webauthn();
        assert_eq!(wc.sign_count, 0);
        assert!(wc.transports.is_empty());
        assert_eq!(wc.attestation_format, AttestationFormat::None);
        assert!(!wc.platform_authenticator);
        assert!(!wc.discoverable);
        assert!(!wc.backed_up);
        assert!(wc.aaguid.is_none());
        assert!(wc.last_used_at.is_none());
    }

    #[test]
    fn test_sign_count_increment() {
        let mut wc = make_webauthn();
        assert!(wc.update_sign_count(1));
        assert_eq!(wc.sign_count, 1);
        assert!(wc.last_used_at.is_some());

        assert!(wc.update_sign_count(5));
        assert_eq!(wc.sign_count, 5);
    }

    #[test]
    fn test_sign_count_zero_allowed() {
        let mut wc = make_webauthn();
        // Some authenticators always report 0.
        assert!(wc.update_sign_count(0));
    }

    #[test]
    fn test_sign_count_backwards_rejected() {
        let mut wc = make_webauthn();
        wc.sign_count = 10;
        // Counter went backwards — cloning suspected.
        assert!(!wc.update_sign_count(5));
        assert_eq!(wc.sign_count, 10); // Not updated.
    }

    #[test]
    fn test_sign_count_same_nonzero_rejected() {
        let mut wc = make_webauthn();
        wc.sign_count = 3;
        // Same non-zero counter — suspicious.
        assert!(!wc.update_sign_count(3));
    }

    #[test]
    fn test_phishing_resistant() {
        let mut wc = make_webauthn();
        assert!(wc.is_phishing_resistant());

        wc.backed_up = true;
        assert!(!wc.is_phishing_resistant());
    }

    #[test]
    fn test_hardware_bound() {
        let mut wc = make_webauthn();
        assert!(wc.is_hardware_bound()); // Not backed up, not platform.

        wc.platform_authenticator = true;
        assert!(!wc.is_hardware_bound()); // Platform = not hardware key.

        wc.platform_authenticator = false;
        wc.backed_up = true;
        assert!(!wc.is_hardware_bound()); // Backed up = synced.
    }

    #[test]
    fn test_transport_as_str() {
        assert_eq!(WebAuthnTransport::Usb.as_str(), "usb");
        assert_eq!(WebAuthnTransport::Internal.as_str(), "internal");
        assert_eq!(WebAuthnTransport::Hybrid.as_str(), "hybrid");
    }

    #[test]
    fn test_attestation_format_as_str() {
        assert_eq!(AttestationFormat::Packed.as_str(), "packed");
        assert_eq!(AttestationFormat::Tpm.as_str(), "tpm");
        assert_eq!(AttestationFormat::Apple.as_str(), "apple");
    }

    #[test]
    fn test_webauthn_serde_roundtrip() {
        let mut wc = make_webauthn();
        wc.transports = vec![WebAuthnTransport::Usb, WebAuthnTransport::Nfc];
        wc.attestation_format = AttestationFormat::Packed;
        wc.discoverable = true;
        wc.display_name = Some("YubiKey 5".into());

        let json = serde_json::to_string(&wc).unwrap();
        let parsed: WebAuthnCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.transports,
            vec![WebAuthnTransport::Usb, WebAuthnTransport::Nfc]
        );
        assert_eq!(parsed.attestation_format, AttestationFormat::Packed);
        assert!(parsed.discoverable);
        assert_eq!(parsed.display_name.as_deref(), Some("YubiKey 5"));
    }

    #[test]
    fn test_transport_serde_roundtrip() {
        let t = WebAuthnTransport::Hybrid;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"hybrid\"");
        let parsed: WebAuthnTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, WebAuthnTransport::Hybrid);
    }

    #[test]
    fn test_attestation_serde_roundtrip() {
        let a = AttestationFormat::AndroidKey;
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"android_key\"");
        let parsed: AttestationFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, AttestationFormat::AndroidKey);
    }
}
