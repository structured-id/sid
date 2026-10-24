//! After the host installed aws-lc, every algorithm SID admits signs and
//! verifies through it, and altered or misattributed tokens are refused.

mod common;

use common::{Claims, claims, keys};
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use sid_crypto::jwt::install_jwt_provider;

#[test]
fn installed_provider_signs_and_verifies() {
    install_jwt_provider().unwrap();

    for alg in [
        Algorithm::ES256,
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::EdDSA,
    ] {
        let (sign, verify) = keys(alg);
        let token = encode(&Header::new(alg), &claims(), &sign).unwrap();
        let read = decode::<Claims>(&token, &verify, &Validation::new(alg)).unwrap();
        assert_eq!(read.claims, claims(), "{alg:?}");
    }

    // A changed signature byte is refused, not accepted by a lenient verifier.
    let (sign, verify) = keys(Algorithm::ES256);
    let token = encode(&Header::new(Algorithm::ES256), &claims(), &sign).unwrap();
    let (body, signature) = token.rsplit_once('.').unwrap();
    let mut bytes = signature.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
    let tampered = format!("{body}.{}", String::from_utf8(bytes).unwrap());
    assert!(decode::<Claims>(&tampered, &verify, &Validation::new(Algorithm::ES256)).is_err());

    // A token verified under another algorithm than it was signed with is
    // refused.
    let (sign, _) = keys(Algorithm::RS256);
    let (_, verify) = keys(Algorithm::PS256);
    let token = encode(&Header::new(Algorithm::RS256), &claims(), &sign).unwrap();
    assert!(decode::<Claims>(&token, &verify, &Validation::new(Algorithm::PS256)).is_err());
}
