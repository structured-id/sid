// SPDX-License-Identifier: AGPL-3.0-only
//! A software WebAuthn authenticator for tests: ES256 keys, `none`
//! attestation, discoverable credentials, and the Level 3 JSON a browser's
//! `PublicKeyCredential.toJSON()` returns. Every value a relying party checks
//! can be changed through [`Behavior`], so a test breaks one check at a time.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// DER prefix of a P-256 `SubjectPublicKeyInfo` (RFC 5480 §2), followed by
/// the 65-byte uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Authenticator data flags (WebAuthn Level 3 §6.1).
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// What the next response reports or breaks. The default is an honest
/// synced passkey on a platform authenticator that verified the user.
#[derive(Clone, Debug)]
pub struct Behavior {
    pub origin: String,
    pub rp_id: String,
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub transports: Vec<&'static str>,
    pub attachment: &'static str,
    /// Answer this challenge instead of the one in the options.
    pub challenge: Option<String>,
    /// Report this user handle instead of the credential's.
    pub user_handle: Option<Vec<u8>>,
    /// Report this signature counter instead of advancing the stored one.
    pub counter: Option<u32>,
    /// Sign something other than what the relying party verifies.
    pub corrupt_signature: bool,
}

impl Behavior {
    fn new(origin: &str, rp_id: &str) -> Self {
        Self {
            origin: origin.to_string(),
            rp_id: rp_id.to_string(),
            user_present: true,
            user_verified: true,
            backup_eligible: true,
            backed_up: true,
            transports: vec!["internal", "hybrid"],
            attachment: "platform",
            challenge: None,
            user_handle: None,
            counter: None,
            corrupt_signature: false,
        }
    }
}

/// One credential the authenticator holds.
pub struct SoftCredential {
    pub id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub rp_id: String,
    key: SigningKey,
    counter: u32,
}

/// The authenticator: its credentials and how it behaves.
pub struct SoftAuthenticator {
    pub credentials: Vec<SoftCredential>,
    pub behavior: Behavior,
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn unb64(field: &Value, what: &str) -> Vec<u8> {
    B64.decode(
        field
            .as_str()
            .unwrap_or_else(|| panic!("options carry no {what}")),
    )
    .unwrap_or_else(|e| panic!("{what} is not base64url: {e}"))
}

fn public_key(options: &[u8]) -> Value {
    let options: Value = serde_json::from_slice(options).expect("options are JSON");
    options["publicKey"].clone()
}

impl SoftAuthenticator {
    /// An authenticator answering for `origin` and relying party `rp_id`.
    pub fn new(origin: &str, rp_id: &str) -> Self {
        Self {
            credentials: Vec::new(),
            behavior: Behavior::new(origin, rp_id),
        }
    }

    fn client_data(&self, kind: &str, challenge: &Value) -> Vec<u8> {
        let challenge = self.behavior.challenge.clone().unwrap_or_else(|| {
            challenge
                .as_str()
                .expect("options carry a challenge")
                .into()
        });
        // The member order a browser serializes (WebAuthn Level 3 §5.8.1.2).
        format!(
            r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{}","crossOrigin":false}}"#,
            self.behavior.origin
        )
        .into_bytes()
    }

    fn flags(&self) -> u8 {
        let b = &self.behavior;
        let mut flags = 0;
        for (on, bit) in [
            (b.user_present, UP),
            (b.user_verified, UV),
            (b.backup_eligible, BE),
            (b.backed_up, BS),
        ] {
            if on {
                flags |= bit;
            }
        }
        flags
    }

    fn rp_id_hash(&self) -> [u8; 32] {
        Sha256::digest(self.behavior.rp_id.as_bytes()).into()
    }

    /// Create a credential for the creation `options` (the server's JSON,
    /// `publicKey` inside) and return the registration response JSON.
    pub fn register(&mut self, options: &[u8]) -> Vec<u8> {
        let pk = public_key(options);
        let excluded: Vec<Vec<u8>> = pk["excludeCredentials"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|c| unb64(&c["id"], "excluded id"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !self.credentials.iter().any(|c| excluded.contains(&c.id)),
            "the authenticator already holds an excluded credential"
        );
        let user_handle = unb64(&pk["user"]["id"], "user.id");
        let client_data = self.client_data("webauthn.create", &pk["challenge"]);

        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x().expect("x"), point.y().expect("y"));
        let id = uuid::Uuid::now_v7().as_bytes().to_vec();
        let counter = self.behavior.counter.unwrap_or(0);

        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(x);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(y);

        let mut auth_data = self.rp_id_hash().to_vec();
        auth_data.push(self.flags() | AT);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&u16::try_from(id.len()).unwrap().to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(&cose);

        // {"fmt": "none", "attStmt": {}, "authData": h'...'} in CTAP2 canonical order.
        let mut attestation = vec![0xa3, 0x63];
        attestation.extend_from_slice(b"fmt");
        attestation.push(0x64);
        attestation.extend_from_slice(b"none");
        attestation.push(0x67);
        attestation.extend_from_slice(b"attStmt");
        attestation.push(0xa0);
        attestation.push(0x68);
        attestation.extend_from_slice(b"authData");
        // A byte string head in its shortest form (RFC 8949 §4.2.1).
        match u8::try_from(auth_data.len()) {
            Ok(len) => attestation.extend_from_slice(&[0x58, len]),
            Err(_) => {
                attestation.push(0x59);
                attestation
                    .extend_from_slice(&u16::try_from(auth_data.len()).unwrap().to_be_bytes());
            }
        }
        attestation.extend_from_slice(&auth_data);

        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(point.as_bytes());

        let response = json!({
            "id": b64(&id),
            "rawId": b64(&id),
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "transports": self.behavior.transports,
                "publicKey": b64(&spki),
                "publicKeyAlgorithm": -7,
                "attestationObject": b64(&attestation),
            },
            "authenticatorAttachment": self.behavior.attachment,
            "clientExtensionResults": {},
            "type": "public-key",
        });
        self.credentials.push(SoftCredential {
            id,
            user_handle,
            rp_id: self.behavior.rp_id.clone(),
            key,
            counter,
        });
        serde_json::to_vec(&response).unwrap()
    }

    /// Answer the request `options` with the first credential they allow (any
    /// credential of the relying party when they list none) and return the
    /// assertion response JSON.
    pub fn assert(&mut self, options: &[u8]) -> Vec<u8> {
        let pk = public_key(options);
        let allowed: Vec<Vec<u8>> = pk["allowCredentials"]
            .as_array()
            .map(|list| list.iter().map(|c| unb64(&c["id"], "allowed id")).collect())
            .unwrap_or_default();
        let rp_id = pk["rpId"].as_str().expect("options carry rpId").to_string();
        let client_data = self.client_data("webauthn.get", &pk["challenge"]);
        let flags = self.flags();
        let rp_id_hash = self.rp_id_hash();
        let behavior = self.behavior.clone();

        let credential = self
            .credentials
            .iter_mut()
            .find(|c| c.rp_id == rp_id && (allowed.is_empty() || allowed.contains(&c.id)))
            .expect("the authenticator holds no credential the options allow");
        credential.counter = behavior.counter.unwrap_or(credential.counter + 1);

        let mut auth_data = rp_id_hash.to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&credential.counter.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        if behavior.corrupt_signature {
            signed.push(0);
        }
        let signature: Signature = credential.key.sign(&signed);

        let user_handle = behavior
            .user_handle
            .clone()
            .unwrap_or_else(|| credential.user_handle.clone());
        let response = json!({
            "id": b64(&credential.id),
            "rawId": b64(&credential.id),
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(signature.to_der().as_bytes()),
                "userHandle": b64(&user_handle),
            },
            "authenticatorAttachment": behavior.attachment,
            "clientExtensionResults": {},
            "type": "public-key",
        });
        serde_json::to_vec(&response).unwrap()
    }
}
