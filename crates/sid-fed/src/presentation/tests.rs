// SPDX-License-Identifier: AGPL-3.0-only
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use serde_json::json;

use super::*;
use crate::binding_passport::{AssuranceLevel, DEVELOPMENT_PASSPORT, Passport};
use crate::passport_path::Classical;
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{
    Stated, authority, current, key, name, purposes, signs, signs_certificates,
};

const ROOT: u8 = 1;
const INTERMEDIATE: u8 = 2;
const HOLDER: u8 = 4;
const INTERMEDIATE_NAME: &str = "CN=SID Platform Intermediate";

const HEADER: &str = r#"{"alg":"ES256","typ":"sid-binding-presentation+jws"}"#;
const CHALLENGE: &str = "nonce-of-the-pending-entry";
const DOMAIN: &str = "login.recipient.sid.example.com";

fn recipient() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0b0b)
}

fn binding() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_8d9e)
}

/// The platform intermediate a recipient admits.
fn anchor() -> Vec<u8> {
    Stated::new(
        INTERMEDIATE_NAME,
        vec![
            authority(Some(1)),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
        ],
    )
    .signed(&key(INTERMEDIATE), &name("CN=SID Root"), &key(ROOT))
}

/// A Personal passport of the holder's key, issued by the intermediate.
fn passport() -> Vec<u8> {
    passport_with(Some(signs()))
}

/// The same passport with the key usage `usage`, or with none stated.
fn passport_with(usage: Option<x509_cert::ext::Extension>) -> Vec<u8> {
    let stated = Passport {
        binding_id: binding(),
        source_org: None,
        recipient_org: recipient(),
        merkle_root: [7; 32],
        instance_id: "instance.sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa2,
    };
    let mut extensions = vec![purposes(&[DEVELOPMENT_PASSPORT.key_usage])];
    extensions.extend(usage);
    extensions.extend(stated.extensions(&DEVELOPMENT_PASSPORT).unwrap());
    Stated {
        subject: stated.subject().unwrap(),
        serial: 9,
        validity: current(),
        extensions,
    }
    .signed(&key(HOLDER), &name(INTERMEDIATE_NAME), &key(INTERMEDIATE))
}

/// The statement the holder signs, after `edit`.
fn statement(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let holder = format!("did:sid:{}", binding());
    let mut value = json!({
        "type": "SIDBindingPresentation",
        "version": 1,
        "purpose": "authentication",
        "recipient_org": recipient().to_string(),
        "created": 1_771_063_260,
        "challenge": CHALLENGE,
        "domain": DOMAIN,
        "holder": holder,
        "credential": {
            "subject": holder,
            "disclosed_fields": {},
            "attestations": {},
            "merkle_root": format!("0x{}", hex::encode([7u8; 32])),
            "proof": {
                "type": "X509CertificateChain",
                "x5c": [STANDARD.encode(passport())]
            }
        }
    });
    edit(&mut value);
    value.to_string().into_bytes()
}

/// One signature entry over `payload` under `header`, by `signer`.
fn signed(header: &str, payload: &[u8], signer: &SigningKey) -> Value {
    let protected = URL_SAFE_NO_PAD.encode(header);
    let signature: p256::ecdsa::Signature =
        signer.sign(&signing_input(&protected, &URL_SAFE_NO_PAD.encode(payload)));
    json!({
        "protected": protected,
        "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn envelope(payload: &[u8], signatures: Vec<Value>) -> Vec<u8> {
    json!({ "payload": URL_SAFE_NO_PAD.encode(payload), "signatures": signatures })
        .to_string()
        .into_bytes()
}

/// A presentation of `payload` signed by the holder.
fn presented(payload: &[u8]) -> Vec<u8> {
    envelope(payload, vec![signed(HEADER, payload, &key(HOLDER))])
}

fn expected() -> Expected<'static> {
    Expected {
        recipient: recipient(),
        challenge: CHALLENGE,
        domain: DOMAIN,
    }
}

fn verify(jws: &[u8], expected: &Expected<'_>) -> Result<VerifiedPresentation, PresentationError> {
    verify_presentation(
        &Classical,
        &DEVELOPMENT_PASSPORT,
        &DEVELOPMENT_PURPOSES,
        jws,
        &[anchor()],
        expected,
        SystemTime::now(),
    )
}

// A presentation signed by the passport's holder for the pending request is
// verified, and what is returned is what the certificate and the signed
// statement say. A proof of an algorithm this verifier does not use is
// carried and changes nothing. Bug prevented: a verifier that cannot accept
// the hybrid envelope the private issuer produces.
#[test]
fn the_holders_presentation_for_the_pending_request_is_verified() {
    let payload = statement(|_| {});
    let verified = verify(&presented(&payload), &expected()).unwrap();
    assert_eq!(verified.accepted.passport.binding_id, binding());
    assert_eq!(verified.accepted.passport.recipient_org, recipient());
    assert_eq!(verified.created, 1_771_063_260);

    let other_algorithm = json!({
        "protected": URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ML-DSA-65","typ":"sid-binding-presentation+jws"}"#),
        "signature": URL_SAFE_NO_PAD.encode([0u8; 3309]),
    });
    let hybrid = envelope(
        &payload,
        vec![other_algorithm, signed(HEADER, &payload, &key(HOLDER))],
    );
    assert!(verify(&hybrid, &expected()).is_ok());
}

// The signature is the holder's, over the bytes as received. Bug prevented:
// a copied passport presented by someone without its key, a payload changed
// after signing (even to JSON that parses the same), or a signature in
// another encoding accepted.
#[test]
fn only_the_passport_key_over_the_received_bytes_signs() {
    let payload = statement(|_| {});

    let stolen = envelope(&payload, vec![signed(HEADER, &payload, &key(9))]);
    assert_eq!(
        verify(&stolen, &expected()),
        Err(PresentationError::Signature)
    );

    // The same statement with one more space: equal JSON, other bytes.
    let mut respaced = payload.clone();
    respaced.push(b' ');
    let moved = envelope(&respaced, vec![signed(HEADER, &payload, &key(HOLDER))]);
    assert_eq!(
        verify(&moved, &expected()),
        Err(PresentationError::Signature)
    );

    // A DER signature is not the 64 bytes R || S.
    let protected = URL_SAFE_NO_PAD.encode(HEADER);
    let der: p256::ecdsa::DerSignature = key(HOLDER).sign(&signing_input(
        &protected,
        &URL_SAFE_NO_PAD.encode(&payload),
    ));
    let encoded = envelope(
        &payload,
        vec![json!({
            "protected": protected,
            "signature": URL_SAFE_NO_PAD.encode(der.as_bytes()),
        })],
    );
    assert_eq!(
        verify(&encoded, &expected()),
        Err(PresentationError::Signature)
    );
}

// The issuer's key usage binds the holder's key (RFC 5280 §4.2.1.3): a
// passport whose key usage is stated and does not include digitalSignature
// cannot sign a presentation, while one that states no key usage is not
// restricted. Bug prevented: a key certified for key agreement or for
// signing certificates accepted as the holder's authentication key.
#[test]
fn a_key_not_certified_to_sign_makes_no_presentation() {
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    let present = |certificate: Vec<u8>| {
        let payload = statement(|v| {
            v["credential"]["proof"]["x5c"] = json!([STANDARD.encode(certificate)]);
        });
        verify(&presented(&payload), &expected())
    };
    for usage in [
        KeyUsage(KeyUsages::KeyAgreement.into()),
        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
    ] {
        let restricted = crate::test_certificates::extension(
            <KeyUsage as der::oid::AssociatedOid>::OID,
            true,
            &usage,
        );
        assert_eq!(
            present(passport_with(Some(restricted))).unwrap_err(),
            PresentationError::KeyUsage
        );
    }
    assert!(present(passport_with(None)).is_ok());
}

// A presentation answers one pending request of one recipient. Bug
// prevented: a presentation made for another challenge, verifier context or
// organization replayed here, or a statement naming a connection or
// recipient other than the certificate's.
#[test]
fn a_presentation_for_another_request_is_refused() {
    let jws = presented(&statement(|_| {}));
    let context = |edit: &dyn Fn(&mut Expected<'_>)| {
        let mut other = expected();
        edit(&mut other);
        verify(&jws, &other).unwrap_err()
    };
    assert_eq!(
        context(&|e| e.challenge = "another-nonce"),
        PresentationError::Context("request")
    );
    assert_eq!(
        context(&|e| e.domain = "login.other.sid.example.com"),
        PresentationError::Context("verifier")
    );
    assert_eq!(
        context(&|e| e.recipient = binding()),
        PresentationError::Path(PathError::Recipient)
    );

    let stated = |edit: &dyn Fn(&mut Value)| {
        verify(&presented(&statement(|v| edit(v))), &expected()).unwrap_err()
    };
    assert_eq!(
        stated(&|v| v["recipient_org"] = json!(binding().to_string())),
        PresentationError::Context("recipient")
    );
    let other = format!("did:sid:{}", recipient());
    assert_eq!(
        stated(&|v| {
            v["holder"] = json!(other);
            v["credential"]["subject"] = json!(other);
        }),
        PresentationError::Context("connection")
    );
    assert_eq!(
        stated(&|v| v["credential"]["merkle_root"] = json!(format!("0x{}", hex::encode([8u8; 32])))),
        PresentationError::Context("passport")
    );
}

// The envelope is exactly this profile's: one payload, protected headers of
// alg and typ only, one proof of the required algorithm. Bug prevented: a
// key or option supplied by the sender (jwk, an unprotected header), a
// duplicate name read differently by two parsers, or the sender choosing
// which of two proofs counts.
#[test]
fn only_the_profiles_envelope_is_read() {
    let payload = statement(|_| {});
    let good = signed(HEADER, &payload, &key(HOLDER));
    let refused = |jws: &[u8]| verify(jws, &expected()).unwrap_err();

    assert_eq!(
        refused(&envelope(&payload, vec![])),
        PresentationError::Envelope("without signatures")
    );
    assert_eq!(
        refused(&envelope(&payload, vec![good.clone(), good.clone()])),
        PresentationError::AmbiguousProof(ES256)
    );
    let other = r#"{"alg":"ML-DSA-65","typ":"sid-binding-presentation+jws"}"#;
    assert_eq!(
        refused(&envelope(
            &payload,
            vec![signed(other, &payload, &key(HOLDER))]
        )),
        PresentationError::NoRequiredProof(ES256)
    );

    for header in [
        r#"{"alg":"ES256"}"#,
        r#"{"alg":"ES256","typ":"JWT"}"#,
        r#"{"alg":"ES256","typ":"sid-binding-presentation+jws","jwk":{}}"#,
        r#"{"alg":"ES256","alg":"none","typ":"sid-binding-presentation+jws"}"#,
    ] {
        let jws = envelope(&payload, vec![signed(header, &payload, &key(HOLDER))]);
        assert!(
            matches!(refused(&jws), PresentationError::Envelope(_)),
            "{header}"
        );
    }

    // An unprotected header beside the protected one.
    let mut with_header = good.clone();
    with_header["header"] = json!({ "kid": "a-key" });
    assert!(matches!(
        refused(&envelope(&payload, vec![with_header])),
        PresentationError::Envelope(_)
    ));

    // A second payload member, and padded base64url.
    let encoded = URL_SAFE_NO_PAD.encode(&payload);
    let twice = format!(r#"{{"payload":"{encoded}","payload":"{encoded}","signatures":[{good}]}}"#);
    assert!(matches!(
        refused(twice.as_bytes()),
        PresentationError::Envelope(_)
    ));
    let padded = format!(r#"{{"payload":"{encoded}==","signatures":[{good}]}}"#);
    assert!(matches!(
        refused(padded.as_bytes()),
        PresentationError::Envelope(_)
    ));
}

// The statement is exactly a version 1 authentication statement. Bug
// prevented: a statement of another purpose or version taken as a sign-in,
// a member this verifier cannot interpret silently ignored, a lossy number,
// a duplicate name, or disclosed content returned as checked when it was not.
#[test]
fn only_a_version_1_authentication_statement_is_read() {
    let refused = |edit: &dyn Fn(&mut Value)| {
        verify(&presented(&statement(|v| edit(v))), &expected()).unwrap_err()
    };
    for edit in [
        (&|v: &mut Value| v["version"] = json!(2)) as &dyn Fn(&mut Value),
        &|v| v["version"] = json!(1.0),
        &|v| v["purpose"] = json!("consent"),
        &|v| v["type"] = json!("VerifiablePresentation"),
        &|v| v["created"] = json!(1_771_063_260.5),
        &|v| v["created"] = json!(-1),
        &|v| v["recipient_org"] = json!(recipient().simple().to_string()),
        &|v| v["holder"] = json!(binding().to_string()),
        &|v| v["extra"] = json!(true),
        &|v| v["credential"]["extra"] = json!(true),
        &|v| v["credential"]["proof"]["x5c"] = json!([]),
        &|v| v["credential"]["proof"]["type"] = json!("JsonWebSignature2020"),
    ] {
        assert!(matches!(refused(edit), PresentationError::Statement(_)));
    }
    assert_eq!(
        refused(&|v| v["credential"]["disclosed_fields"] = json!({
            "f1_email": { "value": "alice@sid.example.com" }
        })),
        PresentationError::UnsupportedDisclosure
    );
    assert_eq!(
        refused(&|v| v["credential"]["attestations"] = json!({ "f3": { "verified": true } })),
        PresentationError::UnsupportedDisclosure
    );

    // The same name twice in the signed statement.
    let duplicated =
        String::from_utf8(statement(|_| {}))
            .unwrap()
            .replacen("{", r#"{"version":2,"#, 1);
    assert!(matches!(
        verify(&presented(duplicated.as_bytes()), &expected()),
        Err(PresentationError::Statement(_))
    ));
}
