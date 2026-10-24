// SPDX-License-Identifier: Apache-2.0
//! Bounded public RSA decoding shared by independently selected protocol adapters.

use crypto_bigint::BoxedUint;
use der::Decode;
use rsa::RsaPublicKey;

#[derive(Clone, Copy, Debug)]
pub(crate) struct InvalidPublicKey;

pub(crate) fn rsa_from_pkcs1(bytes: &[u8]) -> Result<RsaPublicKey, InvalidPublicKey> {
    let key = rsa::pkcs1::RsaPublicKeyRef::from_der(bytes).map_err(|_| InvalidPublicKey)?;
    rsa_from_components(key.modulus.as_bytes(), key.public_exponent.as_bytes())
}

pub(crate) fn rsa_from_components(n: &[u8], e: &[u8]) -> Result<RsaPublicKey, InvalidPublicKey> {
    // RFC 7518 sections 3.3 and 6.3.1 require minimal unsigned components.
    // Bound the public modulus and exponent before allocating their integers.
    if n.len() < 256 || n.len() > 1024 || e.is_empty() || e.len() > 8 {
        return Err(InvalidPublicKey);
    }
    if n[0] == 0 || e[0] == 0 {
        return Err(InvalidPublicKey);
    }
    let n = BoxedUint::from_be_slice_vartime(n);
    if n.bits() < 2048 {
        return Err(InvalidPublicKey);
    }
    let e = BoxedUint::from_be_slice_vartime(e);
    RsaPublicKey::new(n, e).map_err(|_| InvalidPublicKey)
}
