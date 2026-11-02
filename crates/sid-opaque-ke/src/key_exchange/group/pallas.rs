//! The key-exchange group and the OPAQUE cipher suite on Pallas, over the
//! Pallas VOPRF suite of `sid-voprf`.

use ff::{Field, PrimeField};
use group::{Group as _, GroupEncoding};
use hybrid_array::Array;
use hybrid_array::typenum::U32;
use pasta_curves::pallas;
use rand_core::CryptoRng;
use sid_voprf::pallas::{PallasElem, PallasScalar, PallasVoprf};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::tripledh::{DiffieHellman, TripleDh};

/// The key-exchange secret key.
///
/// Distinct from [`PallasScalar`] on purpose: a VOPRF scalar has to be
/// `Copy`, and a value that can be copied cannot wipe itself when the last
/// holder drops it.
#[derive(Clone, Debug)]
pub struct PallasSecretKey(pub PallasScalar);

impl Drop for PallasSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PallasSecretKey {}

impl ConstantTimeEq for PallasSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Take the leading 32 bytes, leaving the rest for the next field.
fn take_32(bytes: &mut &[u8]) -> Result<[u8; 32], ProtocolError> {
    let (head, rest) = bytes
        .split_first_chunk::<32>()
        .ok_or(ProtocolError::SerializationError)?;
    *bytes = rest;
    Ok(*head)
}

/// The Pallas key-exchange group. Its own type: `sid-voprf`'s
/// [`sid_voprf::pallas::PallasGroup`] would meet this crate's blanket impl for elliptic curves.
#[derive(Debug)]
pub struct Pallas;

impl Group for Pallas {
    type Pk = PallasElem;
    type PkLen = U32;
    type Sk = PallasSecretKey;
    type SkLen = U32;

    fn serialize_pk(pk: &Self::Pk) -> Array<u8, Self::PkLen> {
        Array::from(pk.0.to_bytes())
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        let repr = take_32(bytes)?;
        let point: pallas::Point = Option::from(pallas::Point::from_bytes(&repr))
            .ok_or(ProtocolError::SerializationError)?;
        // RFC 9807 §6.4.1: the identity is not a valid public key.
        if bool::from(point.is_identity()) {
            return Err(ProtocolError::SerializationError);
        }
        Ok(PallasElem(point))
    }

    fn random_sk<R: CryptoRng>(rng: &mut R) -> Self::Sk {
        PallasSecretKey(PallasScalar(pallas::Scalar::random(rng)))
    }

    fn derive_scalar(seed: Array<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        // RFC 9807 §6.4.2 `DeriveDiffieHellmanKeyPair`, as the built-in groups.
        let scalar = sid_voprf::derive_key::<PallasVoprf>(
            &seed,
            &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR,
            sid_voprf::Mode::Oprf,
        )
        .map_err(InternalError::OprfError)?;
        Ok(PallasSecretKey(scalar))
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        PallasElem(pallas::Point::generator() * (sk.0).0)
    }

    fn serialize_sk(sk: &Self::Sk) -> Array<u8, Self::SkLen> {
        Array::from((sk.0).0.to_repr())
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        let repr = take_32(bytes)?;
        let scalar: pallas::Scalar = Option::from(pallas::Scalar::from_repr(repr))
            .ok_or(ProtocolError::SerializationError)?;
        // A zero scalar has the identity as its public key and no secret.
        if bool::from(scalar.ct_eq(&pallas::Scalar::ZERO)) {
            return Err(ProtocolError::SerializationError);
        }
        Ok(PallasSecretKey(PallasScalar(scalar)))
    }
}

impl DiffieHellman<Pallas> for PallasSecretKey {
    fn diffie_hellman(&self, pk: &PallasElem) -> Array<u8, U32> {
        Array::from((pk.0 * (self.0).0).to_bytes())
    }
}

/// OPAQUE on Pallas: the Poseidon-hashed Pallas OPRF, 3DH over Pallas with
/// SHA-256 and Argon2 as the KSF.
#[derive(Debug)]
pub struct PallasCipherSuite;

impl crate::CipherSuite for PallasCipherSuite {
    type OprfCs = PallasVoprf;
    type KeyExchange = TripleDh<Pallas, sha2::Sha256>;
    type Ksf = argon2::Argon2<'static>;
}

#[cfg(test)]
mod tests;
