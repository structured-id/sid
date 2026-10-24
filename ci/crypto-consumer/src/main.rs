// SPDX-License-Identifier: Apache-2.0

fn main() {
    #[cfg(feature = "tls")]
    {
        let provider = sid_crypto::tls::rustcrypto::provider();
        assert_eq!(provider.cipher_suites.len(), 9);
        assert_eq!(provider.kx_groups.len(), 3);
        for group in &provider.kx_groups {
            let left = group.start().unwrap();
            let right = group.start().unwrap();
            // Completion consumes the exchange, so retain its public bytes.
            let left_public = left.pub_key().to_vec();
            let left_secret = left.complete(right.pub_key()).unwrap();
            let right_secret = right.complete(&left_public).unwrap();
            assert_eq!(left_secret.secret_bytes(), right_secret.secret_bytes());
        }
    }

    #[cfg(feature = "jwt")]
    {
        use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
        let provider = sid_crypto::jwt::rustcrypto::provider();
        let key = [7; 64];
        let signer =
            (provider.signer_factory)(&Algorithm::HS256, &EncodingKey::from_secret(&key)).unwrap();
        let verifier =
            (provider.verifier_factory)(&Algorithm::HS256, &DecodingKey::from_secret(&key))
                .unwrap();
        let message = b"external consumer";
        let signature = signer.try_sign(message).unwrap();
        verifier.verify(message, &signature).unwrap();
        assert!(verifier.verify(b"different message", &signature).is_err());
    }

    #[cfg(feature = "primitives")]
    {
        use sid_crypto::{CryptoPrimitives, RustCryptoPrimitives};
        let provider = RustCryptoPrimitives::new();
        let nonce = provider.random_nonce().unwrap();
        let key = [7; 32];
        let ciphertext = provider
            .aes_256_gcm_encrypt(&key, &nonce, b"external consumer", b"context")
            .unwrap();
        assert_eq!(
            provider
                .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"context")
                .unwrap(),
            b"external consumer",
        );
        assert!(
            provider
                .aes_256_gcm_decrypt(&key, &nonce, &ciphertext, b"wrong")
                .is_err()
        );
    }
}
