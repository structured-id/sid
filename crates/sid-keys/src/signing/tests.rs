use super::*;
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use p256::pkcs8::der::Encode;

fn key_id() -> SigningKeyId {
    SigningKeyId(Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_8d9e))
}

fn verifying_key(signer: &SoftwareP256Signer) -> VerifyingKey {
    let der = signer.public_key().to_der().expect("SPKI encodes");
    VerifyingKey::from_public_key_der(&der).expect("the reported key is a P-256 key")
}

// The signature verifies under the public key the signer reports, over the
// exact message; this is what a certificate verifier checks.
#[tokio::test]
async fn signature_verifies_under_the_reported_public_key() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let message = b"tbsCertificate bytes";
    let signature = Signature::from_der(&signer.sign(message).await.unwrap()).unwrap();
    verifying_key(&signer).verify(message, &signature).unwrap();
}

// A signature binds its message: another message does not verify.
#[tokio::test]
async fn signature_does_not_verify_another_message() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let signature = Signature::from_der(&signer.sign(b"one").await.unwrap()).unwrap();
    assert!(verifying_key(&signer).verify(b"two", &signature).is_err());
}

// A signature binds its key: another key's public key does not verify it.
#[tokio::test]
async fn signature_does_not_verify_under_another_key() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let (other, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let signature = Signature::from_der(&signer.sign(b"m").await.unwrap()).unwrap();
    assert!(verifying_key(&other).verify(b"m", &signature).is_err());
}

// RFC 5758 §3.2: ecdsa-with-SHA256 with the parameters field absent, exactly
// this DER, so inner and outer certificate algorithm fields agree.
#[test]
fn algorithm_identifier_is_ecdsa_with_sha256_without_parameters() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    assert_eq!(
        signer.signature_algorithm().to_der().unwrap(),
        [
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
        ]
    );
}

// The signature value is the DER `Ecdsa-Sig-Value` SEQUENCE of r and s, not a
// fixed-width 64-byte concatenation.
#[tokio::test]
async fn signature_value_is_der_r_and_s() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let value = signer.sign(b"m").await.unwrap();
    assert_eq!(value[0], 0x30, "a DER SEQUENCE");
    assert_eq!(
        usize::from(value[1]) + 2,
        value.len(),
        "one SEQUENCE, nothing after it"
    );
    Signature::from_der(&value).expect("r and s decode");
}

// The public key is an id-ecPublicKey SPKI on prime256v1.
#[test]
fn public_key_is_a_p256_subject_public_key_info() {
    let (signer, _) = SoftwareP256Signer::generate(key_id()).unwrap();
    let spki = signer.public_key();
    assert_eq!(
        spki.algorithm.oid,
        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
    );
    let curve = spki.algorithm.parameters.as_ref().expect("the named curve");
    assert_eq!(
        curve.decode_as::<ObjectIdentifier>().unwrap(),
        ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
    );
}

// The key the custody stores opens to the same key: same public key, and a
// signature of one verifies under the other.
#[tokio::test]
async fn pkcs8_reopens_the_same_key() {
    let (signer, pkcs8) = SoftwareP256Signer::generate(key_id()).unwrap();
    let reopened = SoftwareP256Signer::from_pkcs8(key_id(), &pkcs8).unwrap();
    assert_eq!(reopened.public_key(), signer.public_key());
    let signature = Signature::from_der(&reopened.sign(b"m").await.unwrap()).unwrap();
    verifying_key(&signer).verify(b"m", &signature).unwrap();
}

// The signer reports the key generation it was opened for.
#[test]
fn signer_reports_its_key_generation() {
    let (signer, pkcs8) = SoftwareP256Signer::generate(key_id()).unwrap();
    assert_eq!(signer.key_id(), key_id());
    let other = SigningKeyId(Uuid::from_u128(7));
    assert_eq!(
        SoftwareP256Signer::from_pkcs8(other, &pkcs8)
            .unwrap()
            .key_id(),
        other
    );
}

// Bytes that are not a PKCS#8 key are refused, never signed with.
#[test]
fn malformed_pkcs8_is_refused() {
    let garbage = SecretBox::new(Box::new(vec![0x30, 0x03, 0x02, 0x01, 0x00]));
    assert!(matches!(
        SoftwareP256Signer::from_pkcs8(key_id(), &garbage),
        Err(SigningError::InvalidKey(_))
    ));
}

// A well-formed PKCS#8 key of another curve is not a P-256 key: refused.
#[test]
fn another_curves_key_is_refused() {
    let p384 = p384::ecdsa::SigningKey::try_generate_from_rng(&mut rand::rngs::SysRng).unwrap();
    let der = p384.to_pkcs8_der().unwrap();
    let pkcs8 = SecretBox::new(Box::new(der.as_bytes().to_vec()));
    assert!(matches!(
        SoftwareP256Signer::from_pkcs8(key_id(), &pkcs8),
        Err(SigningError::InvalidKey(_))
    ));
}
