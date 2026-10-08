// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use std::vec;

use digest::Digest;
use p256::ecdsa::signature::{DigestVerifier, RandomizedDigestSigner};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{NistP256, PublicKey};
use rand_core::Rng;
use sha2::Sha256;

use super::{sign, verify};
use crate::key_exchange::group::Group;
use crate::tests::mock_rng::CycleRng;

/// The pre-hash signing and verification used by SIGMA-I produce and accept
/// exactly what the `ecdsa` crate's digest signer does for the same nonce
/// randomness, so signatures interoperate with standard ECDSA verifiers.
#[test]
fn ecdsa() {
    let mut rng = CycleRng::new(vec![1; 32]);
    let mut system_rng = rand::rng();

    let mut message = [0; 1024];
    system_rng.fill_bytes(&mut message);

    let sk = NistP256::random_sk(&mut system_rng);
    let signing_key = SigningKey::from(sk.clone());

    let signature: Signature = signing_key.sign_digest_with_rng(&mut rng, |digest: &mut Sha256| {
        Digest::update(digest, message)
    });
    let custom_signature = sign::<_, _, Sha256>(&sk, &mut rng, &Sha256::digest(message));

    assert_eq!(signature, custom_signature);

    let pk = NistP256::public_key(&sk);
    let verifying_key = VerifyingKey::from(PublicKey::from(pk.0));

    verifying_key
        .verify_digest(
            |digest: &mut Sha256| {
                Digest::update(digest, message);
                Ok(())
            },
            &signature,
        )
        .unwrap();
    verify(&pk, &Sha256::digest(message), &custom_signature).unwrap();
}
