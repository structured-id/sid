use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use super::*;

const ISSUER: &str = "https://sid.example.com/i/0123";
const CHALLENGE: [u8; 32] = [7u8; 32];

/// A signing key of the fixtures and its public JWK.
struct Key {
    alg: Algorithm,
    private: EncodingKey,
    jwk: serde_json::Value,
}

fn ec_key() -> Key {
    Key {
        alg: Algorithm::ES256,
        private: EncodingKey::from_ec_pem(include_bytes!(
            "../../tests/fixtures/test_es256_private.pem"
        ))
        .unwrap(),
        jwk: serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
            "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
        }),
    }
}

fn ed_key() -> Key {
    // The raw 32-byte public key is the end of the SPKI DER.
    let pem = include_str!("../../tests/fixtures/test_ed25519_public.pem");
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(body).unwrap();
    let raw = &der[der.len() - 32..];
    Key {
        alg: Algorithm::EdDSA,
        private: EncodingKey::from_ed_pem(include_bytes!(
            "../../tests/fixtures/test_ed25519_private.pem"
        ))
        .unwrap(),
        jwk: serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(raw),
        }),
    }
}

fn thumbprint(key: &Key) -> String {
    compute_jwk_thumbprint(&key.jwk).unwrap()
}

/// A proof signed by `signer` with the given claims.
fn proof(signer: &Key, typ: &str, claims: serde_json::Value) -> String {
    let mut header = Header::new(signer.alg);
    header.typ = Some(typ.to_string());
    header.jwk = Some(serde_json::from_value(signer.jwk.clone()).unwrap());
    encode(&header, &claims, &signer.private).unwrap()
}

fn claims(purpose: &str, device: DeviceId, key: &str) -> serde_json::Value {
    serde_json::json!({
        "chl": URL_SAFE_NO_PAD.encode(CHALLENGE),
        "purpose": purpose,
        "iss": ISSUER,
        "dev": device.to_string(),
        "key": key,
    })
}

fn ceremony(device: DeviceId) -> Ceremony<'static> {
    Ceremony {
        challenge: &CHALLENGE,
        issuer: ISSUER,
        device,
    }
}

// A proposed key proves its possession for its own ceremony; the proven key
// is its canonical public JWK and thumbprint.
#[test]
fn the_proposed_key_proves_possession() {
    let device = DeviceId::generate();
    let key = ec_key();
    let jws = proof(
        &key,
        DEVICE_KEY_PROOF_TYPE,
        claims("enroll", device, &thumbprint(&key)),
    );

    let proven = verify_proposed_key(&jws, ceremony(device), ProofPurpose::Enroll).unwrap();

    assert_eq!(proven.thumbprint, thumbprint(&key));
    assert_eq!(
        stored_key_thumbprint(&proven.public_jwk).unwrap(),
        proven.thumbprint
    );
}

// The proof names the key that signed it: a proof whose `key` claim names
// another key does not bind the proposed key.
#[test]
fn a_proof_naming_another_key_is_refused() {
    let device = DeviceId::generate();
    let jws = proof(
        &ec_key(),
        DEVICE_KEY_PROOF_TYPE,
        claims("enroll", device, &thumbprint(&ed_key())),
    );

    assert_eq!(
        verify_proposed_key(&jws, ceremony(device), ProofPurpose::Enroll),
        Err(DeviceKeyProofError::Mismatch("key"))
    );
}

// A proof cannot be transplanted to another device, challenge, issuer or
// purpose.
#[test]
fn a_proof_binds_its_ceremony() {
    let device = DeviceId::generate();
    let key = ec_key();
    let jws = proof(
        &key,
        DEVICE_KEY_PROOF_TYPE,
        claims("enroll", device, &thumbprint(&key)),
    );

    let other_device =
        verify_proposed_key(&jws, ceremony(DeviceId::generate()), ProofPurpose::Enroll);
    assert_eq!(other_device, Err(DeviceKeyProofError::Mismatch("dev")));

    let other_challenge = verify_proposed_key(
        &jws,
        Ceremony {
            challenge: &[8u8; 32],
            ..ceremony(device)
        },
        ProofPurpose::Enroll,
    );
    assert_eq!(other_challenge, Err(DeviceKeyProofError::Mismatch("chl")));

    let other_issuer = verify_proposed_key(
        &jws,
        Ceremony {
            issuer: "https://sid.example.com/i/9999",
            ..ceremony(device)
        },
        ProofPurpose::Enroll,
    );
    assert_eq!(other_issuer, Err(DeviceKeyProofError::Mismatch("iss")));

    let as_rotation = verify_proposed_key(&jws, ceremony(device), ProofPurpose::RotateNew);
    assert_eq!(as_rotation, Err(DeviceKeyProofError::Mismatch("purpose")));
}

// The current key approves exactly the proposed replacement: its proof
// names the proposed key and is signed by the current one.
#[test]
fn the_current_key_approves_the_exact_replacement() {
    let device = DeviceId::generate();
    let (current, proposed) = (ec_key(), ed_key());
    let approval = proof(
        &current,
        DEVICE_KEY_PROOF_TYPE,
        claims("rotate-current", device, &thumbprint(&proposed)),
    );

    verify_current_key(
        &approval,
        ceremony(device),
        &thumbprint(&current),
        &thumbprint(&proposed),
    )
    .unwrap();

    // Another proposed key is not what the current key approved.
    let substituted = verify_current_key(
        &approval,
        ceremony(device),
        &thumbprint(&current),
        &thumbprint(&current),
    );
    assert_eq!(substituted, Err(DeviceKeyProofError::Mismatch("key")));

    // An approval by a key other than the current one approves nothing.
    let by_proposed = proof(
        &proposed,
        DEVICE_KEY_PROOF_TYPE,
        claims("rotate-current", device, &thumbprint(&proposed)),
    );
    let refused = verify_current_key(
        &by_proposed,
        ceremony(device),
        &thumbprint(&current),
        &thumbprint(&proposed),
    );
    assert_eq!(refused, Err(DeviceKeyProofError::Mismatch("signer")));
}

// A new-key proof of a rotation is not an approval by the current key, and
// an approval cannot stand in for the new key's proof.
#[test]
fn rotation_proofs_do_not_substitute() {
    let device = DeviceId::generate();
    let proposed = ed_key();
    let new_key = proof(
        &proposed,
        DEVICE_KEY_PROOF_TYPE,
        claims("rotate-new", device, &thumbprint(&proposed)),
    );
    let as_approval = verify_current_key(
        &new_key,
        ceremony(device),
        &thumbprint(&proposed),
        &thumbprint(&proposed),
    );
    assert_eq!(as_approval, Err(DeviceKeyProofError::Mismatch("purpose")));

    assert_eq!(
        verify_proposed_key(&new_key, ceremony(device), ProofPurpose::RotateCurrent),
        Err(DeviceKeyProofError::Mismatch("purpose"))
    );
    verify_proposed_key(&new_key, ceremony(device), ProofPurpose::RotateNew).unwrap();
}

// A DPoP-typed JWS with the same claims is not a device-key proof.
#[test]
fn another_proof_type_is_refused() {
    let device = DeviceId::generate();
    let key = ec_key();
    let jws = proof(
        &key,
        "dpop+jwt",
        claims("enroll", device, &thumbprint(&key)),
    );

    assert!(matches!(
        verify_proposed_key(&jws, ceremony(device), ProofPurpose::Enroll),
        Err(DeviceKeyProofError::Invalid(_))
    ));
}

// A proof signed by another key than its `jwk` header is refused.
#[test]
fn a_forged_signature_is_refused() {
    let device = DeviceId::generate();
    let claimed = ec_key();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(DEVICE_KEY_PROOF_TYPE.to_string());
    // The header names the Ed25519 public key of nothing that signs here.
    let mut forged_jwk = ed_key().jwk;
    forged_jwk["x"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode([9u8; 32]));
    header.jwk = Some(serde_json::from_value(forged_jwk).unwrap());
    let jws = encode(
        &header,
        &claims("enroll", device, &thumbprint(&claimed)),
        &ed_key().private,
    )
    .unwrap();

    assert!(matches!(
        verify_proposed_key(&jws, ceremony(device), ProofPurpose::Enroll),
        Err(DeviceKeyProofError::Invalid(_))
    ));
}
