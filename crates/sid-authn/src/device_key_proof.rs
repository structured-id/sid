// SPDX-License-Identifier: AGPL-3.0-only
//! Device-key proofs of the enrollment ceremony
//! (`sid.v1.attestation.AttestationService`): a compact JWS of `typ`
//! `sid-device-key+jwt` signed by the key it speaks for, whose claims bind
//! one ceremony's challenge, its purpose, the issuer, the device and the
//! proposed key. The proofs are checked against the ceremony the server
//! keeps, never against values a request repeats.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sid_core::models::DeviceId;

use crate::dpop::{DPopError, canonical_jwk, compute_jwk_thumbprint, verify_key_jws};

/// JWS `typ` of a device-key proof: distinct from DPoP and native proofs,
/// so none is accepted as another.
pub const DEVICE_KEY_PROOF_TYPE: &str = "sid-device-key+jwt";

/// What a proof speaks for; a proof made for one purpose is refused for
/// every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPurpose {
    /// The proposed key of an enrollment proves its possession.
    Enroll,
    /// The proposed key of a rotation proves its possession.
    RotateNew,
    /// The current key of a rotation approves the proposed key.
    RotateCurrent,
}

impl ProofPurpose {
    /// The `purpose` claim naming it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::RotateNew => "rotate-new",
            Self::RotateCurrent => "rotate-current",
        }
    }
}

/// Why a device-key proof is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceKeyProofError {
    /// Not a well-formed proof signed by its own key.
    #[error("invalid device-key proof: {0}")]
    Invalid(String),
    /// A well-formed proof for another ceremony, purpose, issuer, device or
    /// key; the claim it fails is named, never its value.
    #[error("the device-key proof does not bind this ceremony ({0})")]
    Mismatch(&'static str),
}

impl From<DPopError> for DeviceKeyProofError {
    fn from(e: DPopError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// The ceremony a proof must bind, as the server keeps it.
#[derive(Debug, Clone, Copy)]
pub struct Ceremony<'a> {
    pub challenge: &'a [u8],
    pub issuer: &'a str,
    pub device: DeviceId,
}

/// A key whose possession a proof established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenKey {
    /// Its public members in their canonical form (RFC 7638 §3.2), the form
    /// it is stored in.
    pub public_jwk: String,
    /// Its RFC 7638 SHA-256 thumbprint, base64url.
    pub thumbprint: String,
}

#[derive(serde::Deserialize)]
struct Claims {
    chl: String,
    purpose: String,
    iss: String,
    dev: String,
    key: String,
}

/// Check `proof`'s signature by its own key and its claims against
/// `ceremony` and `purpose`; the signer's key and the `key` claim.
fn checked(
    proof: &str,
    ceremony: Ceremony<'_>,
    purpose: ProofPurpose,
) -> Result<(ProvenKey, String), DeviceKeyProofError> {
    let (claims, jwk) = verify_key_jws::<Claims>(proof, DEVICE_KEY_PROOF_TYPE)?;
    if claims.purpose != purpose.as_str() {
        return Err(DeviceKeyProofError::Mismatch("purpose"));
    }
    if claims.chl != URL_SAFE_NO_PAD.encode(ceremony.challenge) {
        return Err(DeviceKeyProofError::Mismatch("chl"));
    }
    if claims.iss != ceremony.issuer {
        return Err(DeviceKeyProofError::Mismatch("iss"));
    }
    if DeviceId::parse(&claims.dev).ok() != Some(ceremony.device) {
        return Err(DeviceKeyProofError::Mismatch("dev"));
    }
    let signer = ProvenKey {
        public_jwk: canonical_jwk(&jwk)?,
        thumbprint: compute_jwk_thumbprint(&jwk)?,
    };
    Ok((signer, claims.key))
}

/// The proposed key, proven by its own `proof` for `ceremony`: an
/// enrollment's (`Enroll`) or a rotation's new key (`RotateNew`). Its `key`
/// claim must name the very key that signed it.
pub fn verify_proposed_key(
    proof: &str,
    ceremony: Ceremony<'_>,
    purpose: ProofPurpose,
) -> Result<ProvenKey, DeviceKeyProofError> {
    if purpose == ProofPurpose::RotateCurrent {
        return Err(DeviceKeyProofError::Mismatch("purpose"));
    }
    let (signer, key) = checked(proof, ceremony, purpose)?;
    if key != signer.thumbprint {
        return Err(DeviceKeyProofError::Mismatch("key"));
    }
    Ok(signer)
}

/// The current key's approval of replacing it with `proposed` in
/// `ceremony`: signed by the key whose thumbprint is `current`, naming
/// `proposed` in its `key` claim, so it approves that exact replacement.
pub fn verify_current_key(
    proof: &str,
    ceremony: Ceremony<'_>,
    current: &str,
    proposed: &str,
) -> Result<(), DeviceKeyProofError> {
    let (signer, key) = checked(proof, ceremony, ProofPurpose::RotateCurrent)?;
    if signer.thumbprint != current {
        return Err(DeviceKeyProofError::Mismatch("signer"));
    }
    if key != proposed {
        return Err(DeviceKeyProofError::Mismatch("key"));
    }
    Ok(())
}

/// The RFC 7638 thumbprint of a stored public key, `public_jwk` in the form
/// [`ProvenKey::public_jwk`] holds.
pub fn stored_key_thumbprint(public_jwk: &str) -> Result<String, DeviceKeyProofError> {
    let jwk: serde_json::Value = serde_json::from_str(public_jwk)
        .map_err(|e| DeviceKeyProofError::Invalid(format!("stored key: {e}")))?;
    Ok(compute_jwk_thumbprint(&jwk)?)
}

#[cfg(test)]
mod tests;
