// SPDX-License-Identifier: Apache-2.0
#![cfg(all(
    feature = "jwt",
    feature = "jwt-rustcrypto",
    feature = "tls-rustcrypto",
    feature = "tls-aws-lc",
    feature = "primitives",
    feature = "aws-lc"
))]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use p256::pkcs8::EncodePrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use sid_crypto::{AwsLcPrimitives, CryptoPrimitives, RustCryptoPrimitives};

// Factories and primitive operations must leave both global slots to the host.
#[test]
fn provider_factories_leave_process_slots_unclaimed() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let tls = sid_crypto::tls::rustcrypto::provider();
    let aws_tls = sid_crypto::tls::aws_lc::provider();
    assert!(!tls.cipher_suites.is_empty());
    assert!(!aws_tls.cipher_suites.is_empty());
    let jwt = sid_crypto::jwt::rustcrypto::provider();
    let key = EncodingKey::from_secret(&[4; 64]);
    let signer = (jwt.signer_factory)(&Algorithm::HS256, &key).unwrap();
    assert_eq!(signer.try_sign(b"test").unwrap().len(), 32);
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    assert!(tls.install_default().is_ok());
    // This is the first JWT installation even after a factory actually signed.
    assert!(
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .is_ok()
    );
}

// Compare independent backend signatures in both directions. RSA remains
// verification-only in RustCrypto while the selected AWS backend can sign it.
#[test]
fn jwt_signatures_interoperate_with_independent_backend() {
    let ec256 = p256::SecretKey::from_slice(&[1; 32]).unwrap();
    let ec384 = p384::SecretKey::from_slice(&[2; 48]).unwrap();
    let ed = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let rsa = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let rsa_private = rsa.to_pkcs1_der().unwrap();
    let rsa_public = rsa.to_public_key().to_pkcs1_der().unwrap();
    let mut cases = vec![
        (
            Algorithm::HS256,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::HS384,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::HS512,
            EncodingKey::from_secret(&[4; 64]),
            DecodingKey::from_secret(&[4; 64]),
        ),
        (
            Algorithm::ES256,
            EncodingKey::from_ec_der(ec256.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ec_der(&ec256.public_key().to_sec1_bytes()),
        ),
        (
            Algorithm::ES384,
            EncodingKey::from_ec_der(ec384.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ec_der(&ec384.public_key().to_sec1_bytes()),
        ),
        (
            Algorithm::EdDSA,
            EncodingKey::from_ed_der(ed.to_pkcs8_der().unwrap().as_bytes()),
            DecodingKey::from_ed_der(ed.verifying_key().as_bytes()),
        ),
    ];
    for alg in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        cases.push((
            alg,
            EncodingKey::from_rsa_der(rsa_private.as_bytes()),
            DecodingKey::from_rsa_der(rsa_public.as_bytes()),
        ));
    }
    let rc = sid_crypto::jwt::rustcrypto::provider();
    let aws = &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER;
    let message = b"eyJhbGciOiJ0ZXN0In0.eyJzdWIiOiJ0ZXN0In0";
    for (alg, sign_key, verify_key) in cases {
        let aws_signer = (aws.signer_factory)(&alg, &sign_key).unwrap();
        let rc_verify = (rc.verifier_factory)(&alg, &verify_key).unwrap();
        let signature = aws_signer.try_sign(message).unwrap();
        assert_eq!(rc_verify.algorithm(), alg);
        assert!(rc_verify.verify(message, &signature).is_ok(), "{alg:?}");
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(rc_verify.verify(message, &changed).is_err(), "{alg:?}");
        assert!(
            rc_verify.verify(b"different message", &signature).is_err(),
            "{alg:?}"
        );
        if alg.family() == jsonwebtoken::AlgorithmFamily::Rsa {
            assert!((rc.signer_factory)(&alg, &sign_key).is_err());
        } else {
            let rc_signer = (rc.signer_factory)(&alg, &sign_key).unwrap();
            let aws_verify = (aws.verifier_factory)(&alg, &verify_key).unwrap();
            assert_eq!(rc_signer.algorithm(), alg);
            let signature = rc_signer.try_sign(message).unwrap();
            assert!(aws_verify.verify(message, &signature).is_ok(), "{alg:?}");
        }
    }
}

// Both runtime choices must have the same exact KDF boundaries and must
// refuse bad parameters before overwriting caller-owned output.
#[test]
fn both_backends_preserve_kdf_boundary_contracts() {
    let aws = AwsLcPrimitives::new();
    let rc = RustCryptoPrimitives::new();
    for length in [0, 1, 32, 8160] {
        let a = aws
            .hkdf_sha256(b"ikm", b"salt", b"context", length)
            .unwrap();
        let b = rc.hkdf_sha256(b"ikm", b"salt", b"context", length).unwrap();
        assert_eq!(a.len(), length);
        assert_eq!(a, b);
    }
    for backend in [&aws as &dyn CryptoPrimitives, &rc] {
        for length in [8161, usize::MAX] {
            assert!(
                backend
                    .hkdf_sha256(b"key", b"salt", b"context", length)
                    .is_err()
            );
        }
        let mut output = [0xa5; 33];
        assert!(
            backend
                .pbkdf2_sha256(b"password", b"salt", 0, &mut output)
                .is_err()
        );
        assert_eq!(output, [0xa5; 33]);
        assert!(
            backend
                .pbkdf2_sha256(b"password", b"salt", 1, &mut [])
                .is_err()
        );
    }
}
