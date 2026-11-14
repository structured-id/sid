// SPDX-License-Identifier: AGPL-3.0-only
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use super::*;

// A generated key is read back from its sealed bytes as the same key, its
// signatures verify under the public half it states, and two generated keys
// differ. Bytes that are not a P-256 private key are refused. Bug
// prevented: a site signing with a key other than the one whose public half
// it gave the platform to certify, or every site drawing the same key.
#[test]
fn a_site_key_signs_under_the_public_half_it_states() {
    let sealed = SiteKey::generate().unwrap();
    let key = SiteKey::read(&sealed).unwrap();
    let public = key.public_key().unwrap();
    assert_eq!(
        SiteKey::read(&sealed).unwrap().public_key().unwrap(),
        public
    );

    let input = b"protected.payload";
    let signature = Signature::from_slice(&key.sign(input)).unwrap();
    let verifier = VerifyingKey::from_public_key_der(&public).unwrap();
    verifier.verify(input, &signature).unwrap();
    assert!(verifier.verify(b"protected.other", &signature).is_err());

    let other = SiteKey::read(&SiteKey::generate().unwrap()).unwrap();
    assert_ne!(other.public_key().unwrap(), public);
    for refused in [&[][..], &[0x30, 0x00], &public] {
        assert_eq!(SiteKey::read(refused).err(), Some(SiteKeyError::Malformed));
    }
}
