// SPDX-License-Identifier: AGPL-3.0-only
//! OPAQUE protocol abstractions.
//!
//! [`OpaqueOperations`] is the trait boundary for OPAQUE operations bound to a
//! specific elliptic curve; implementations live in `sid-authn`, which also
//! holds the router that dispatches by curve.
//!
//! The low-level primitives are not here: `CryptoPrimitives` and its errors
//! belong to `sid-keys`, which an application can link for field encryption
//! without taking any of the identity engine with it.

use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sid_keys::CryptoError;
use thiserror::Error;

// ---------------------------------------------------------------------------
// CurveId
// ---------------------------------------------------------------------------

/// Elliptic curve identifier for OPAQUE cipher suite selection.
///
/// Stored alongside each profile's OPAQUE credential to enable
/// multi-curve dispatch by `OpaqueRouter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CurveId {
    /// Pallas curve (Pasta pair). CE default — native Halo2 field.
    Pallas = 0,
    /// Ristretto255 (Curve25519). RFC 9807 standard OPAQUE suite.
    Ristretto255 = 1,
    /// NIST P-256 (secp256r1). FIPS 186-4.
    P256 = 2,
    /// NIST P-384 (secp384r1). CNSA 1.0.
    P384 = 3,
    /// NIST P-521 (secp521r1). CNSA 2.0 / maximum classical security.
    P521 = 4,
}

impl CurveId {
    /// Security level in bits.
    pub fn security_bits(self) -> u32 {
        match self {
            Self::Pallas | Self::Ristretto255 | Self::P256 => 128,
            Self::P384 => 192,
            Self::P521 => 256,
        }
    }

    /// Whether this curve is FIPS-approved (NIST curves only).
    pub fn is_fips_curve(self) -> bool {
        matches!(self, Self::P256 | Self::P384 | Self::P521)
    }
}

impl fmt::Display for CurveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pallas => write!(f, "pallas"),
            Self::Ristretto255 => write!(f, "ristretto255"),
            Self::P256 => write!(f, "p256"),
            Self::P384 => write!(f, "p384"),
            Self::P521 => write!(f, "p521"),
        }
    }
}

impl TryFrom<u8> for CurveId {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Pallas),
            1 => Ok(Self::Ristretto255),
            2 => Ok(Self::P256),
            3 => Ok(Self::P384),
            4 => Ok(Self::P521),
            _ => Err(CryptoError::Provider(format!(
                "unknown curve id: {}",
                value
            ))),
        }
    }
}

impl std::str::FromStr for CurveId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pallas" => Ok(Self::Pallas),
            "ristretto255" | "ristretto" => Ok(Self::Ristretto255),
            "p256" | "p-256" | "secp256r1" => Ok(Self::P256),
            "p384" | "p-384" | "secp384r1" => Ok(Self::P384),
            "p521" | "p-521" | "secp521r1" => Ok(Self::P521),
            _ => Err(CryptoError::Provider(format!("unknown curve: {}", s))),
        }
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from OPAQUE protocol operations.
#[derive(Debug, Error)]
pub enum OpaqueError {
    #[error("OPAQUE protocol error: {0}")]
    Protocol(String),

    #[error("unsupported curve: {0}")]
    UnsupportedCurve(CurveId),

    #[error("curve mismatch: expected {expected}, got {actual}")]
    CurveMismatch { expected: CurveId, actual: CurveId },

    #[error("invalid server setup: {0}")]
    InvalidSetup(String),

    #[error("deserialization failed: {0}")]
    Deserialization(String),
}

// ---------------------------------------------------------------------------
// Opaque types (curve-erased wrappers)
// ---------------------------------------------------------------------------

/// Handle to a serialized `ServerSetup` (curve-erased).
///
/// Internally contains the curve-specific `ServerSetup` bytes.
/// Contains the server's long-term key pair — debug prints `[REDACTED]`.
pub struct OpaqueSetupHandle(pub Vec<u8>);

impl fmt::Debug for OpaqueSetupHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OpaqueSetupHandle")
            .field(&format_args!("[REDACTED {} bytes]", self.0.len()))
            .finish()
    }
}

/// Stored credential for a profile (curve-erased).
///
/// Contains the serialized `ServerRegistration<CS>` + curve identifier.
pub struct StoredCredential {
    /// Which curve this credential was registered under.
    pub curve: CurveId,
    /// Serialized `ServerRegistration<CS>` bytes.
    pub data: Vec<u8>,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("curve", &self.curve)
            .field(
                "data",
                &format_args!("[REDACTED {} bytes]", self.data.len()),
            )
            .finish()
    }
}

/// Login state between `login_start` and `login_finish` (curve-erased).
///
/// First byte is the `CurveId` discriminator for dispatch in `login_finish`.
/// Contains ephemeral server key material — debug prints `[REDACTED]`; kept
/// between replicas only sealed.
#[derive(Serialize, Deserialize)]
pub struct LoginState(pub Vec<u8>);

impl fmt::Debug for LoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LoginState")
            .field(&format_args!("[REDACTED {} bytes]", self.0.len()))
            .finish()
    }
}

/// Session key material from successful OPAQUE login.
///
/// Wrapped in `Secret` — zeroed on drop, `[REDACTED]` in Debug.
/// Access raw bytes via `expose_secret()`.
pub struct SessionKey(SecretBox<Vec<u8>>);

impl SessionKey {
    /// Create a new session key from raw bytes.
    ///
    /// The bytes are moved into `Secret` for zeroize-on-drop protection.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Access the raw session key bytes.
    ///
    /// Explicit access via `expose_secret()` pattern — visible in code review.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionKey").field(&"[REDACTED]").finish()
    }
}

// ---------------------------------------------------------------------------
// OpaqueOperations trait
// ---------------------------------------------------------------------------

/// OPAQUE protocol operations for a specific curve.
///
/// Each implementation wraps a typed `opaque_ke::CipherSuite` internally:
/// - `RistrettoOpaque` wraps `OpaqueServer<DefaultCipherSuite>`
/// - `PallasOpaque` wraps `OpaqueServer<PallasCipherSuite>`
/// - `P256Opaque` wraps `OpaqueServer<P256CipherSuite>`
/// - `P384Opaque` wraps `OpaqueServer<P384CipherSuite>`
/// - `P521Opaque` wraps `OpaqueServer<P521CipherSuite>`
pub trait OpaqueOperations: Send + Sync {
    /// Which curve this provider handles.
    fn curve_id(&self) -> CurveId;

    /// Security level in bits.
    fn security_bits(&self) -> u32;

    /// Whether the underlying crypto is FIPS-validated.
    fn is_fips(&self) -> bool;

    /// KSF (Key Stretching Function) used: `"argon2"` or `"pbkdf2"`.
    fn ksf_id(&self) -> &'static str;

    /// Create a new `ServerSetup` (keypair generation).
    ///
    /// If `rng_seed` is `Some`, seeds a deterministic CSPRNG from the first 32 bytes
    /// (for reproducible testing / setup persistence). If `None`, uses OS entropy.
    fn create_setup(&self, rng_seed: Option<&[u8]>) -> Result<OpaqueSetupHandle, OpaqueError>;

    /// Deserialize a `ServerSetup` from storage.
    fn setup_from_bytes(&self, bytes: &[u8]) -> Result<OpaqueSetupHandle, OpaqueError>;

    /// OPAQUE registration: process client's `RegistrationRequest`.
    ///
    /// Returns `(response_bytes, state_bytes)`.
    fn registration_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), OpaqueError>;

    /// OPAQUE registration: finalize with client's `RegistrationUpload`.
    fn registration_finish(&self, upload_bytes: &[u8]) -> Result<StoredCredential, OpaqueError>;

    /// OPAQUE login: process client's `CredentialRequest` under `context`
    /// (RFC 9807 §6: empty for an ordinary sign-in, the purpose's binding for
    /// a sign-in inside another operation; the client must use the same).
    ///
    /// Returns `(response_bytes, login_state)`.
    fn login_start(
        &self,
        setup: &OpaqueSetupHandle,
        credential: &StoredCredential,
        request_bytes: &[u8],
        credential_id: &[u8],
        context: &[u8],
    ) -> Result<(Vec<u8>, LoginState), OpaqueError>;

    /// Fake OPAQUE login start for nonexistent users (anti-enumeration).
    ///
    /// Calls `ServerLogin::start` with `None` password file — produces a
    /// credential response with identical timing to a real login, but the
    /// client will inevitably fail at `login_finish`.
    fn fake_login_start(
        &self,
        setup: &OpaqueSetupHandle,
        request_bytes: &[u8],
        credential_id: &[u8],
    ) -> Result<Vec<u8>, OpaqueError>;

    /// OPAQUE login: finalize with client's `CredentialFinalization` under the
    /// `context` the login started with.
    fn login_finish(
        &self,
        state: &LoginState,
        finalization_bytes: &[u8],
        context: &[u8],
    ) -> Result<SessionKey, OpaqueError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_id_display() {
        assert_eq!(CurveId::Pallas.to_string(), "pallas");
        assert_eq!(CurveId::Ristretto255.to_string(), "ristretto255");
        assert_eq!(CurveId::P256.to_string(), "p256");
        assert_eq!(CurveId::P384.to_string(), "p384");
        assert_eq!(CurveId::P521.to_string(), "p521");
    }

    #[test]
    fn test_curve_id_try_from_u8() {
        assert_eq!(CurveId::try_from(0u8).unwrap(), CurveId::Pallas);
        assert_eq!(CurveId::try_from(1u8).unwrap(), CurveId::Ristretto255);
        assert_eq!(CurveId::try_from(2u8).unwrap(), CurveId::P256);
        assert_eq!(CurveId::try_from(3u8).unwrap(), CurveId::P384);
        assert_eq!(CurveId::try_from(4u8).unwrap(), CurveId::P521);
        assert!(CurveId::try_from(5u8).is_err());
        assert!(CurveId::try_from(255u8).is_err());
    }

    #[test]
    fn test_curve_id_from_str() {
        assert_eq!("pallas".parse::<CurveId>().unwrap(), CurveId::Pallas);
        assert_eq!(
            "ristretto255".parse::<CurveId>().unwrap(),
            CurveId::Ristretto255
        );
        assert_eq!("p256".parse::<CurveId>().unwrap(), CurveId::P256);
        assert_eq!("P-256".parse::<CurveId>().unwrap(), CurveId::P256);
        assert_eq!("secp256r1".parse::<CurveId>().unwrap(), CurveId::P256);
        assert_eq!("p384".parse::<CurveId>().unwrap(), CurveId::P384);
        assert_eq!("p521".parse::<CurveId>().unwrap(), CurveId::P521);
        assert!("unknown".parse::<CurveId>().is_err());
    }

    #[test]
    fn test_curve_id_security_bits() {
        assert_eq!(CurveId::Pallas.security_bits(), 128);
        assert_eq!(CurveId::Ristretto255.security_bits(), 128);
        assert_eq!(CurveId::P256.security_bits(), 128);
        assert_eq!(CurveId::P384.security_bits(), 192);
        assert_eq!(CurveId::P521.security_bits(), 256);
    }

    #[test]
    fn test_curve_id_is_fips() {
        assert!(!CurveId::Pallas.is_fips_curve());
        assert!(!CurveId::Ristretto255.is_fips_curve());
        assert!(CurveId::P256.is_fips_curve());
        assert!(CurveId::P384.is_fips_curve());
        assert!(CurveId::P521.is_fips_curve());
    }

    #[test]
    fn test_curve_id_serde_roundtrip() {
        let curve = CurveId::P384;
        let json = serde_json::to_string(&curve).unwrap();
        let back: CurveId = serde_json::from_str(&json).unwrap();
        assert_eq!(curve, back);
    }

    #[test]
    fn test_curve_id_repr_matches_discriminant() {
        assert_eq!(CurveId::Pallas as u8, 0);
        assert_eq!(CurveId::Ristretto255 as u8, 1);
        assert_eq!(CurveId::P256 as u8, 2);
        assert_eq!(CurveId::P384 as u8, 3);
        assert_eq!(CurveId::P521 as u8, 4);
    }

    #[test]
    fn test_session_key_expose_secret() {
        let key = SessionKey::new(vec![1, 2, 3, 4]);
        assert_eq!(key.expose_secret(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_session_key_debug_redacted() {
        let key = SessionKey::new(vec![0xAB; 32]);
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("171")); // 0xAB = 171, must not appear
    }

    #[test]
    fn test_opaque_setup_handle_debug_redacted() {
        let handle = OpaqueSetupHandle(vec![0xCD; 128]);
        let debug = format!("{:?}", handle);
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("128 bytes"));
    }

    #[test]
    fn test_login_state_debug_redacted() {
        let state = LoginState(vec![0xEF; 64]);
        let debug = format!("{:?}", state);
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("64 bytes"));
    }

    #[test]
    fn test_stored_credential_debug_redacted() {
        let cred = StoredCredential {
            curve: CurveId::P256,
            data: vec![0xAB; 64],
        };
        let debug = format!("{:?}", cred);
        assert!(debug.contains("P256"));
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("171")); // 0xAB = 171
    }

    #[test]
    fn test_stored_credential_fields() {
        let cred = StoredCredential {
            curve: CurveId::P256,
            data: vec![0xAB; 64],
        };
        assert_eq!(cred.curve, CurveId::P256);
        assert_eq!(cred.data.len(), 64);
    }
}
