// SPDX-License-Identifier: AGPL-3.0-only
//! Verification of a `SIDBindingPresentation`: the proof that the holder of
//! a Binding is present at this very sign-in.
//!
//! In plain words: a Binding Passport is a certificate, and a certificate
//! can be copied. So at every sign-in the holder also signs a short
//! statement with the key the passport certifies: "this is my connection,
//! for this organization, answering this one-time challenge". A recipient
//! that checks the passport's path and this signature knows the holder was
//! there for this request and not for another one.
//!
//! The statement travels as a General JWS JSON Serialization (RFC 7515
//! §7.2.1): one `payload` and a `signatures` array. Each signature covers
//! `ASCII(BASE64URL(protected) || "." || BASE64URL(payload))` (RFC 7515
//! §5.1), over the bytes as they were received; nothing is re-serialized.
//! The classical proof is `ES256`: ECDSA P-256 with SHA-256, the signature
//! 64 bytes `R || S` (RFC 7518 §3.4).
//!
//! This module VERIFIES, in this order: the envelope's form, the passport's
//! path (through [`crate::passport_path`]), the holder's signature with the
//! key of that exact passport, and that the statement names this recipient,
//! this pending challenge and this verifier context.
//!
//! What it leaves to its caller: revocation and status, consuming the
//! challenge once, and whether the recipient admits this identity at all.
//! It gives a classical verdict only: a signature of another algorithm in
//! the envelope is carried and not looked at.

use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::{Decode, Encode};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::binding_passport::PassportProfile;
use crate::passport_path::{AcceptedPassport, PathError, PathPolicy, accept_passport};
use crate::purpose::PurposeProfile;

/// The `typ` of a version 1 protected header: the profile's discriminator.
pub const PRESENTATION_TYP: &str = "sid-binding-presentation+jws";

/// The classical proof's algorithm (RFC 7518 §3.4).
pub const ES256: &str = "ES256";

/// The `type` of the statement.
pub const STATEMENT_TYPE: &str = "SIDBindingPresentation";

/// The statement's purpose at a sign-in.
pub const AUTHENTICATION: &str = "authentication";

/// The largest integer JSON carries exactly (RFC 8259 §6).
const MAX_EXACT_INTEGER: i64 = (1 << 53) - 1;

/// Why a presentation was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PresentationError {
    /// The envelope is not this profile's General JWS JSON Serialization.
    #[error("the presentation envelope is {0}")]
    Envelope(&'static str),
    /// The envelope carries no proof of the required algorithm.
    #[error("the presentation carries no {0} proof")]
    NoRequiredProof(&'static str),
    /// The envelope carries the required algorithm more than once.
    #[error("the presentation carries more than one {0} proof")]
    AmbiguousProof(&'static str),
    /// The signed statement is not a version 1 authentication statement.
    #[error("the presentation statement is {0}")]
    Statement(&'static str),
    /// The statement discloses content this verifier cannot check, so none
    /// of it may become an accepted claim.
    #[error("the presentation discloses content this verifier does not check")]
    UnsupportedDisclosure,
    /// The passport the statement presents was not accepted.
    #[error(transparent)]
    Path(#[from] PathError),
    /// The holder's signature does not verify with the passport's key.
    #[error("the holder's signature does not verify")]
    Signature,
    /// The statement is for another request, recipient or connection.
    #[error("the presentation is for another {0}")]
    Context(&'static str),
}

/// A JSON value read with duplicate property names refused: with a
/// duplicate, two readers of the same bytes can see two different
/// statements (RFC 8259 §4, RFC 7515 §10.12).
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;
        impl<'de> serde::de::Visitor<'de> for Reader {
            type Value = Strict;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value without duplicate property names")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Strict, A::Error> {
                let mut members = Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    let Strict(value) = map.next_value()?;
                    if members.insert(name, value).is_some() {
                        return Err(serde::de::Error::custom("a duplicate property name"));
                    }
                }
                Ok(Strict(Value::Object(members)))
            }
        }
        deserializer.deserialize_any(Reader)
    }
}

/// The object `value` is, holding exactly the members `names`.
fn exactly<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)))
        .then_some(object)
}

/// One signature of the envelope, as it was received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The protected header's `alg`.
    pub algorithm: String,
    /// The protected header as received: `BASE64URL(H)`.
    pub protected: String,
    /// The decoded signature.
    pub signature: Vec<u8>,
}

/// The envelope of a presentation: one payload and its signatures, kept as
/// they were received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The payload as received: `BASE64URL(P)`.
    pub encoded_payload: String,
    /// The payload's bytes `P`.
    pub payload: Vec<u8>,
    pub proofs: Vec<Proof>,
}

/// The bytes a signature covers (RFC 7515 §5.1).
pub fn signing_input(protected: &str, encoded_payload: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(protected.len() + 1 + encoded_payload.len());
    input.extend_from_slice(protected.as_bytes());
    input.push(b'.');
    input.extend_from_slice(encoded_payload.as_bytes());
    input
}

impl Envelope {
    /// Parse `jws`: exactly a `payload` and a non-empty `signatures` array
    /// whose members hold exactly `protected` and `signature`, each
    /// protected header exactly `alg` and this profile's `typ`. An
    /// unprotected header, a key-discovery header or any other option is
    /// refused before the statement is looked at. Nothing is verified here.
    pub fn parse(jws: &[u8]) -> Result<Self, PresentationError> {
        let Strict(document) = serde_json::from_slice(jws)
            .map_err(|_| PresentationError::Envelope("not JSON without duplicate names"))?;
        let envelope = exactly(&document, &["payload", "signatures"]).ok_or(
            PresentationError::Envelope("not exactly a payload and signatures"),
        )?;
        let encoded_payload = envelope["payload"]
            .as_str()
            .ok_or(PresentationError::Envelope("without a text payload"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .map_err(|_| PresentationError::Envelope("not an unpadded base64url payload"))?;
        let signatures = envelope["signatures"]
            .as_array()
            .filter(|signatures| !signatures.is_empty())
            .ok_or(PresentationError::Envelope("without signatures"))?;
        let proofs = signatures
            .iter()
            .map(Self::proof)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            encoded_payload: encoded_payload.to_owned(),
            payload,
            proofs,
        })
    }

    fn proof(entry: &Value) -> Result<Proof, PresentationError> {
        let entry = exactly(entry, &["protected", "signature"]).ok_or(
            PresentationError::Envelope("a signature with other than protected and signature"),
        )?;
        let text = |name: &str| {
            entry[name].as_str().ok_or(PresentationError::Envelope(
                "a signature member that is not text",
            ))
        };
        let protected = text("protected")?;
        let header = URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(|_| PresentationError::Envelope("not an unpadded base64url header"))?;
        let Strict(header) = serde_json::from_slice(&header)
            .map_err(|_| PresentationError::Envelope("a header with duplicate names"))?;
        let header = exactly(&header, &["alg", "typ"]).ok_or(PresentationError::Envelope(
            "a protected header with other than alg and typ",
        ))?;
        if header["typ"].as_str() != Some(PRESENTATION_TYP) {
            return Err(PresentationError::Envelope("of another type"));
        }
        let algorithm = header["alg"]
            .as_str()
            .ok_or(PresentationError::Envelope("without an algorithm"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(text("signature")?)
            .map_err(|_| PresentationError::Envelope("not an unpadded base64url signature"))?;
        Ok(Proof {
            algorithm: algorithm.to_owned(),
            protected: protected.to_owned(),
            signature,
        })
    }

    /// The one proof of `algorithm`. The required algorithm is the
    /// verifier's, never whichever proof the envelope happens to carry; a
    /// second proof of it is refused, since which one counts would be the
    /// sender's choice.
    pub fn required(&self, algorithm: &'static str) -> Result<&Proof, PresentationError> {
        let mut found = self.proofs.iter().filter(|p| p.algorithm == algorithm);
        let proof = found
            .next()
            .ok_or(PresentationError::NoRequiredProof(algorithm))?;
        if found.next().is_some() {
            return Err(PresentationError::AmbiguousProof(algorithm));
        }
        Ok(proof)
    }

    /// The bytes `proof` covers.
    pub fn signing_input(&self, proof: &Proof) -> Vec<u8> {
        signing_input(&proof.protected, &self.encoded_payload)
    }
}

/// What a version 1 authentication statement says, as parsed from the
/// payload. Parsed is not verified: nothing here is trusted until the
/// passport's path and the holder's signature were checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// When the holder signed, in Unix seconds. Signed, and not a freshness
    /// rule: the pending challenge is what makes a presentation current.
    pub created: i64,
    pub challenge: String,
    pub domain: String,
    pub recipient_org: Uuid,
    /// The Binding named as holder and as the credential's subject.
    pub binding: Uuid,
    pub merkle_root: [u8; 32],
    /// The presented passport (DER): `x5c[0]`.
    pub certificate: Vec<u8>,
    /// The certificates presented above it (DER), its issuer first.
    pub chain: Vec<Vec<u8>>,
}

/// The UUID `text` spells in its canonical form (RFC 9562 §4).
fn canonical_uuid(text: &str) -> Option<Uuid> {
    let uuid = Uuid::parse_str(text).ok()?;
    (uuid.hyphenated().to_string() == text).then_some(uuid)
}

impl Statement {
    /// Parse the payload `P`: exactly the members of a version 1
    /// authentication statement, each in its exact form. A member this
    /// verifier does not know is refused, since it could not check what it
    /// means; so is disclosed content, which it does not check.
    pub fn read(payload: &[u8]) -> Result<Self, PresentationError> {
        let malformed = PresentationError::Statement;
        let Strict(document) = serde_json::from_slice(payload)
            .map_err(|_| malformed("not JSON without duplicate names"))?;
        let statement = exactly(
            &document,
            &[
                "type",
                "version",
                "purpose",
                "recipient_org",
                "created",
                "challenge",
                "domain",
                "holder",
                "credential",
            ],
        )
        .ok_or(malformed("not exactly the version 1 members"))?;
        if statement["type"].as_str() != Some(STATEMENT_TYPE) {
            return Err(malformed("of another type"));
        }
        if statement["version"].as_u64() != Some(1) {
            return Err(malformed("of another version"));
        }
        if statement["purpose"].as_str() != Some(AUTHENTICATION) {
            return Err(malformed("for another purpose"));
        }
        let text = |object: &Map<String, Value>, name: &str| {
            object[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(malformed("a member that is not text"))
        };
        let created = statement["created"]
            .as_i64()
            .filter(|created| (0..=MAX_EXACT_INTEGER).contains(created))
            .ok_or(malformed("without an exact integer time"))?;
        let recipient_org = canonical_uuid(&text(statement, "recipient_org")?)
            .ok_or(malformed("without a canonical recipient"))?;
        let holder = text(statement, "holder")?;
        let binding = holder
            .strip_prefix("did:sid:")
            .and_then(canonical_uuid)
            .ok_or(malformed("without a holder identifier"))?;

        let credential = exactly(
            &statement["credential"],
            &[
                "subject",
                "disclosed_fields",
                "attestations",
                "merkle_root",
                "proof",
            ],
        )
        .ok_or(malformed("without exactly the credential members"))?;
        if text(credential, "subject")? != holder {
            return Err(malformed("for a subject other than its holder"));
        }
        for disclosed in ["disclosed_fields", "attestations"] {
            let content = credential[disclosed]
                .as_object()
                .ok_or(malformed("without its disclosure maps"))?;
            if !content.is_empty() {
                return Err(PresentationError::UnsupportedDisclosure);
            }
        }
        let merkle_root = text(credential, "merkle_root")?
            .strip_prefix("0x")
            .and_then(|digits| hex::decode(digits).ok())
            .and_then(|root| <[u8; 32]>::try_from(root).ok())
            .ok_or(malformed("without a 32-byte root"))?;

        let proof = exactly(&credential["proof"], &["type", "x5c"])
            .ok_or(malformed("without exactly a certificate chain"))?;
        if proof["type"].as_str() != Some("X509CertificateChain") {
            return Err(malformed("with another credential proof"));
        }
        // Certificates in `x5c` are base64, not base64url (RFC 7515 §4.1.6).
        let mut certificates = proof["x5c"]
            .as_array()
            .ok_or(malformed("without certificates"))?
            .iter()
            .map(|certificate| {
                certificate
                    .as_str()
                    .and_then(|text| STANDARD.decode(text).ok())
                    .ok_or(malformed("with a certificate that is not base64"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();
        let certificate = certificates.next().ok_or(malformed("without a passport"))?;

        Ok(Self {
            created,
            challenge: text(statement, "challenge")?,
            domain: text(statement, "domain")?,
            recipient_org,
            binding,
            merkle_root,
            certificate,
            chain: certificates.collect(),
        })
    }

    /// The statement is the accepted passport's own, for the request the
    /// recipient is holding: the same Binding, recipient and root as the
    /// certificate, and the pending challenge and verifier context exactly.
    /// The challenge is compared in constant time; the caller consumes it.
    pub fn admit(
        &self,
        accepted: &AcceptedPassport,
        expected: &Expected<'_>,
    ) -> Result<(), PresentationError> {
        let passport = &accepted.passport;
        if self.binding != passport.binding_id {
            return Err(PresentationError::Context("connection"));
        }
        if self.recipient_org != passport.recipient_org || self.recipient_org != expected.recipient
        {
            return Err(PresentationError::Context("recipient"));
        }
        if self.merkle_root != passport.merkle_root {
            return Err(PresentationError::Context("passport"));
        }
        let pending: bool = self
            .challenge
            .as_bytes()
            .ct_eq(expected.challenge.as_bytes())
            .into();
        if !pending {
            return Err(PresentationError::Context("request"));
        }
        if self.domain != expected.domain {
            return Err(PresentationError::Context("verifier"));
        }
        Ok(())
    }
}

/// The request a recipient is holding, which a presentation must answer.
/// All three come from the recipient's own pending entry, never from the
/// presentation.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// This recipient's registered organization.
    pub recipient: Uuid,
    /// The one-time challenge of the pending entry.
    pub challenge: &'a str,
    /// The verifier context recorded with that entry.
    pub domain: &'a str,
}

/// A presentation verified for one pending request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    /// The passport and the path it was accepted on.
    pub accepted: AcceptedPassport,
    /// When the holder signed, in Unix seconds.
    pub created: i64,
}

/// The holder's ES256 signature over `input` verifies with the key of the
/// passport `certificate` (DER): 64 bytes `R || S`, not DER (RFC 7518 §3.4).
pub fn verify_es256(
    certificate: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<(), PresentationError> {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    let key = x509_cert::Certificate::from_der(certificate)
        .ok()
        .and_then(|certificate| {
            certificate
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .ok()
        })
        .and_then(|spki| p256::ecdsa::VerifyingKey::from_public_key_der(&spki).ok())
        .ok_or(PresentationError::Signature)?;
    let signature =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| PresentationError::Signature)?;
    key.verify(input, &signature)
        .map_err(|_| PresentationError::Signature)
}

/// Verify the presentation `jws` for the pending request `expected` at
/// `at`, to one of the `anchors` the recipient admits: the passport's path
/// under `policy`, the holder's ES256 signature with that passport's key,
/// then the statement's context. Only what the verified payload states is
/// returned.
#[allow(clippy::too_many_arguments)]
pub fn verify_presentation(
    policy: &impl PathPolicy,
    profile: &PassportProfile,
    purposes: &PurposeProfile,
    jws: &[u8],
    anchors: &[Vec<u8>],
    expected: &Expected<'_>,
    at: SystemTime,
) -> Result<VerifiedPresentation, PresentationError> {
    let envelope = Envelope::parse(jws)?;
    let proof = envelope.required(ES256)?;
    let statement = Statement::read(&envelope.payload)?;
    let accepted = accept_passport(
        policy,
        profile,
        purposes,
        &statement.certificate,
        &statement.chain,
        anchors,
        expected.recipient,
        at,
    )?;
    verify_es256(
        &statement.certificate,
        &envelope.signing_input(proof),
        &proof.signature,
    )?;
    statement.admit(&accepted, expected)?;
    Ok(VerifiedPresentation {
        accepted,
        created: statement.created,
    })
}

#[cfg(test)]
mod tests;
