// SPDX-License-Identifier: AGPL-3.0-only
//! A development platform for tests of whatever receives Binding Passports:
//! a Root, one platform intermediate, an authority per source organization
//! and one holder key, all classical (ECDSA P-256) and derived from fixed
//! seeds. It issues real passports and holder presentations, so a test of a
//! recipient exercises the real verification and not a stand-in.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer;
use serde_json::json;
use sid_plugin::platform_ca::{PlatformCa, PlatformCaSet, PlatformCaState};
use uuid::Uuid;

use crate::binding_passport::{AssuranceLevel, DEVELOPMENT_PASSPORT, Passport};
use crate::presentation::signing_input;
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{
    Stated, StatedList, authority, current, key, key_id, name, permits, purposes, signs,
    signs_certificates,
};

const ROOT: u8 = 1;
const INTERMEDIATE: u8 = 2;
const ORGANIZATION: u8 = 3;
const HOLDER: u8 = 4;

const ROOT_NAME: &str = "CN=SID Root";
const INTERMEDIATE_NAME: &str = "CN=SID Platform Intermediate";

/// The serial every organization authority carries.
pub const ORGANIZATION_SERIAL: u32 = 3;

/// The serial every passport carries.
pub const PASSPORT_SERIAL: u32 = 9;

/// The Merkle root every passport states.
const MERKLE_ROOT: [u8; 32] = [7; 32];

fn epoch(at: SystemTime) -> i64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .expect("a time after the epoch")
        .as_secs() as i64
}

fn organization_name(source: Uuid) -> String {
    format!("O={source}")
}

/// The platform intermediate, built once per process: a certificate is named
/// by its exact bytes, so every use of it must be the same certificate.
fn intermediate() -> Vec<u8> {
    static INTERMEDIATE_CERTIFICATE: OnceLock<Vec<u8>> = OnceLock::new();
    INTERMEDIATE_CERTIFICATE
        .get_or_init(|| {
            Stated {
                subject: name(INTERMEDIATE_NAME),
                serial: 2,
                validity: current(),
                extensions: vec![
                    authority(Some(1)),
                    signs_certificates(),
                    purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
                    key_id(&[2; 20]),
                ],
            }
            .signed(&key(INTERMEDIATE), &name(ROOT_NAME), &key(ROOT))
        })
        .clone()
}

/// The authority of organization `source` under the platform intermediate,
/// the same certificate on every call.
pub fn organization_ca(source: Uuid) -> Vec<u8> {
    static AUTHORITIES: OnceLock<Mutex<HashMap<Uuid, Vec<u8>>>> = OnceLock::new();
    AUTHORITIES
        .get_or_init(Mutex::default)
        .lock()
        .expect("the fixture's authorities")
        .entry(source)
        .or_insert_with(|| {
            Stated {
                subject: name(&organization_name(source)),
                serial: ORGANIZATION_SERIAL,
                validity: current(),
                extensions: vec![
                    authority(Some(0)),
                    signs_certificates(),
                    purposes(&[DEVELOPMENT_PURPOSES.organization_ca]),
                    permits(&[&organization_name(source)], true),
                    key_id(&[3; 20]),
                ],
            }
            .signed(
                &key(ORGANIZATION),
                &name(INTERMEDIATE_NAME),
                &key(INTERMEDIATE),
            )
        })
        .clone()
}

/// The platform's set at `revision`: the intermediate as generation 1,
/// active, publishing a revocation list that revokes the organization
/// authorities whose serials are `revoked`.
pub fn platform_cas(revision: u64, revoked: &[u32]) -> PlatformCaSet {
    let now = SystemTime::now();
    PlatformCaSet {
        revision,
        generations: vec![PlatformCa {
            generation: 1,
            certificate: intermediate(),
            state: PlatformCaState::Active,
            overlap_end: None,
            crl: Some(
                StatedList::new(INTERMEDIATE_NAME, &[2; 20], 1, revoked).signed(&key(INTERMEDIATE)),
            ),
        }],
        issued_at: epoch(now) - 60,
        next_update: epoch(now) + 3600,
    }
}

/// List `number` of the authority of organization `source`, revoking the
/// passports whose serials are `revoked`.
pub fn organization_status(source: Uuid, number: u8, revoked: &[u32]) -> Vec<u8> {
    StatedList::new(&organization_name(source), &[3; 20], number, revoked)
        .signed(&key(ORGANIZATION))
}

/// A passport issued to the fixture's holder, with the chain above it.
#[derive(Debug, Clone)]
pub struct Issued {
    /// The passport certificate (DER).
    pub certificate: Vec<u8>,
    /// The certificates between it and the platform intermediate: the
    /// organization's authority for a Corporate passport, none for a
    /// Personal one.
    pub chain: Vec<Vec<u8>>,
    /// What the passport states.
    pub passport: Passport,
}

fn issued(passport: Passport, issuer: &str, issuer_key: u8, chain: Vec<Vec<u8>>) -> Issued {
    let mut extensions = vec![signs(), purposes(&[DEVELOPMENT_PASSPORT.key_usage])];
    extensions.extend(
        passport
            .extensions(&DEVELOPMENT_PASSPORT)
            .expect("the passport's extensions"),
    );
    let certificate = Stated {
        subject: passport.subject().expect("the passport's subject"),
        serial: PASSPORT_SERIAL,
        validity: current(),
        extensions,
    }
    .signed(&key(HOLDER), &name(issuer), &key(issuer_key));
    Issued {
        certificate,
        chain,
        passport,
    }
}

fn stated(source_org: Option<Uuid>, binding: Uuid, recipient: Uuid) -> Passport {
    Passport {
        binding_id: binding,
        source_org,
        recipient_org: recipient,
        merkle_root: MERKLE_ROOT,
        instance_id: "instance.sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa2,
    }
}

/// A Personal passport of `binding` for `recipient`: issued by the platform
/// intermediate itself.
pub fn personal(binding: Uuid, recipient: Uuid) -> Issued {
    issued(
        stated(None, binding, recipient),
        INTERMEDIATE_NAME,
        INTERMEDIATE,
        Vec::new(),
    )
}

/// A Corporate passport of `binding` for `recipient`: issued by the
/// authority of organization `source`.
pub fn corporate(source: Uuid, binding: Uuid, recipient: Uuid) -> Issued {
    issued(
        stated(Some(source), binding, recipient),
        &organization_name(source),
        ORGANIZATION,
        vec![organization_ca(source)],
    )
}

impl Issued {
    /// The holder's presentation of this passport for one pending request:
    /// its `challenge` and the verifier's `domain`.
    pub fn presentation(&self, challenge: &str, domain: &str) -> Vec<u8> {
        let holder = format!("did:sid:{}", self.passport.binding_id);
        let x5c: Vec<String> = std::iter::once(&self.certificate)
            .chain(&self.chain)
            .map(|der| STANDARD.encode(der))
            .collect();
        let payload = json!({
            "type": "SIDBindingPresentation",
            "version": 1,
            "purpose": "authentication",
            "recipient_org": self.passport.recipient_org.to_string(),
            "created": epoch(SystemTime::now()),
            "challenge": challenge,
            "domain": domain,
            "holder": holder,
            "credential": {
                "subject": holder,
                "disclosed_fields": {},
                "attestations": {},
                "merkle_root": format!("0x{}", hex::encode(MERKLE_ROOT)),
                "proof": { "type": "X509CertificateChain", "x5c": x5c }
            }
        })
        .to_string();
        let protected =
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"sid-binding-presentation+jws"}"#);
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let signature: p256::ecdsa::Signature =
            key(HOLDER).sign(&signing_input(&protected, &encoded));
        json!({
            "payload": encoded,
            "signatures": [{
                "protected": protected,
                "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            }]
        })
        .to_string()
        .into_bytes()
    }
}
