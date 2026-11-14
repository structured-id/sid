// SPDX-License-Identifier: AGPL-3.0-only
//! A site's signed statement of whom it admits at one of its entries.
//!
//! In plain words: an installation that receives people from elsewhere
//! decides for itself whose people it lets in. It writes that decision down
//! (which entry, whether individuals may come, which organizations'
//! employees may come) and signs it with the key the platform enrolled its
//! site with. Whoever is asked to send people there reads this statement
//! and learns, from the receiving site itself, where its entry is and that
//! it expects them.
//!
//! The statement proves that the named site published these conditions. It
//! proves nothing about any particular user, gives nobody a role, and is
//! not the receiving site's live decision: that site decides again, from
//! its own current settings, each time someone arrives.
//!
//! This module VERIFIES: the site's participant certificate on its path to
//! an admitted platform intermediate, the site's signature over the exact
//! statement bytes, that the statement speaks for that certificate's
//! organization and site at an entry the certificate lists, and its time
//! bounds. Which revision is the newest one seen, and the status of the
//! certificate, are the caller's.

use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::participant::Mount;
use crate::passport_path::{AcceptedParticipant, PathError, PathPolicy, accept_participant};
use crate::presentation::{
    ES256, Envelope, MAX_EXACT_INTEGER, PresentationError, Strict, canonical_uuid, exactly,
    signing_input, verify_es256,
};
use crate::purpose::PurposeProfile;

/// The `typ` of the protected header: the statement kind's discriminator.
pub const ADMISSION_TYP: &str = "sid-login-admission+jws";

/// The `type` of the statement.
pub const STATEMENT_TYPE: &str = "SIDLoginAdmission";

/// The statement's purpose: whom a site admits to sign in.
pub const LOGIN_ADMISSION: &str = "login-admission";

/// The most source organizations one statement names.
pub const MAX_SOURCES: usize = 1024;

/// Why an admission statement was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// The envelope or the site's signature.
    #[error(transparent)]
    Envelope(#[from] PresentationError),
    /// The signed statement is not a version 1 login admission.
    #[error("the admission statement is {0}")]
    Statement(&'static str),
    /// The site's participant certificate was not accepted.
    #[error(transparent)]
    Path(#[from] PathError),
    /// The statement speaks for another organization, site or entry than
    /// its certificate enrolls.
    #[error("the admission is outside its site's {0}")]
    Scope(&'static str),
    /// The statement is not in its time.
    #[error("the admission is not valid at that time")]
    Time,
}

/// What a site states about one of its entries. Parsed is not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// The receiving organization.
    pub recipient_org: Uuid,
    /// Its site that signs.
    pub site: Uuid,
    /// The entry this statement is about.
    pub mount: Mount,
    /// The revision of the settings it was derived from.
    pub revision: u64,
    /// Whether individuals' own identities are admitted.
    pub allow_personal_profiles: bool,
    /// Whether other organizations' employees are admitted at all.
    pub allow_foreign_corporate_profiles: bool,
    /// Every organization whose employees are admitted, ascending, each
    /// once: the complete set, so an organization absent from it is not
    /// admitted and an empty set admits none.
    pub admitted_sources: Vec<Uuid>,
    /// The first and last second the statement speaks for.
    pub not_before: i64,
    pub not_after: i64,
    /// The site's participant certificate (DER): `x5c[0]`.
    pub certificate: Vec<u8>,
    /// The certificates presented above it (DER), its issuer first.
    pub chain: Vec<Vec<u8>>,
}

impl Admission {
    /// Whether employees of `organization` are admitted by this statement.
    pub fn admits_source(&self, organization: Uuid) -> bool {
        self.allow_foreign_corporate_profiles
            && self.admitted_sources.binary_search(&organization).is_ok()
    }

    /// The statement's bytes, as they are signed. One statement has one
    /// spelling: [`Admission::read`] accepts only these bytes for it.
    pub fn payload(&self) -> Vec<u8> {
        let mut statement = Map::new();
        let mut put = |name: &str, value: Value| {
            statement.insert(name.to_owned(), value);
        };
        put("type", json!(STATEMENT_TYPE));
        put("version", json!(1));
        put("purpose", json!(LOGIN_ADMISSION));
        put("recipient_org", json!(self.recipient_org.to_string()));
        put("site", json!(self.site.to_string()));
        put("mount", json!(self.mount.as_str()));
        put("revision", json!(self.revision));
        put(
            "allow_personal_profiles",
            json!(self.allow_personal_profiles),
        );
        put(
            "allow_foreign_corporate_profiles",
            json!(self.allow_foreign_corporate_profiles),
        );
        put(
            "admitted_sources",
            Value::Array(
                self.admitted_sources
                    .iter()
                    .map(|source| json!(source.to_string()))
                    .collect(),
            ),
        );
        put("not_before", json!(self.not_before));
        put("not_after", json!(self.not_after));
        // Certificates in `x5c` are base64, not base64url (RFC 7515 §4.1.6).
        put(
            "x5c",
            Value::Array(
                std::iter::once(&self.certificate)
                    .chain(&self.chain)
                    .map(|certificate| json!(STANDARD.encode(certificate)))
                    .collect(),
            ),
        );
        // A map of text names and plain values always serializes.
        serde_json::to_vec(&Value::Object(statement)).unwrap_or_default()
    }

    /// Parse the payload `P`: exactly the members of a version 1 login
    /// admission, each in its exact form, and in the one spelling
    /// [`Admission::payload`] writes. A member this verifier does not know
    /// is refused, since it could not check what it means.
    pub fn read(payload: &[u8]) -> Result<Self, AdmissionError> {
        let malformed = AdmissionError::Statement;
        let Strict(document) = serde_json::from_slice(payload)
            .map_err(|_| malformed("not JSON without duplicate names"))?;
        let statement = exactly(
            &document,
            &[
                "type",
                "version",
                "purpose",
                "recipient_org",
                "site",
                "mount",
                "revision",
                "allow_personal_profiles",
                "allow_foreign_corporate_profiles",
                "admitted_sources",
                "not_before",
                "not_after",
                "x5c",
            ],
        )
        .ok_or(malformed("not exactly the version 1 members"))?;
        if statement["type"].as_str() != Some(STATEMENT_TYPE) {
            return Err(malformed("of another type"));
        }
        if statement["version"].as_u64() != Some(1) {
            return Err(malformed("of another version"));
        }
        if statement["purpose"].as_str() != Some(LOGIN_ADMISSION) {
            return Err(malformed("for another purpose"));
        }
        let identifier = |name: &str| {
            statement[name]
                .as_str()
                .and_then(canonical_uuid)
                .ok_or(malformed("without a canonical identifier"))
        };
        let switch = |name: &str| {
            statement[name]
                .as_bool()
                .ok_or(malformed("without its admission switches"))
        };
        let second = |name: &str| {
            statement[name]
                .as_i64()
                .filter(|second| (0..=MAX_EXACT_INTEGER).contains(second))
                .ok_or(malformed("without exact integer times"))
        };
        let mount = statement["mount"]
            .as_str()
            .and_then(Mount::parse)
            .ok_or(malformed("without an entry mount"))?;
        let revision = statement["revision"]
            .as_u64()
            .filter(|revision| *revision <= MAX_EXACT_INTEGER.unsigned_abs())
            .ok_or(malformed("without an exact integer revision"))?;
        let admitted_sources = statement["admitted_sources"]
            .as_array()
            .filter(|sources| sources.len() <= MAX_SOURCES)
            .ok_or(malformed("without its admitted sources"))?
            .iter()
            .map(|source| {
                source
                    .as_str()
                    .and_then(canonical_uuid)
                    .ok_or(malformed("with a source that is not an organization"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !admitted_sources.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(malformed("with sources out of order or repeated"));
        }
        let (not_before, not_after) = (second("not_before")?, second("not_after")?);
        if not_before > not_after {
            return Err(malformed("with an empty time"));
        }
        let mut certificates = statement["x5c"]
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
        let certificate = certificates
            .next()
            .ok_or(malformed("without a site certificate"))?;
        let read = Self {
            recipient_org: identifier("recipient_org")?,
            site: identifier("site")?,
            mount,
            revision,
            allow_personal_profiles: switch("allow_personal_profiles")?,
            allow_foreign_corporate_profiles: switch("allow_foreign_corporate_profiles")?,
            admitted_sources,
            not_before,
            not_after,
            certificate,
            chain: certificates.collect(),
        };
        // One statement, one spelling: two documents that differ only in
        // spacing, member order or number form are not both this statement.
        if read.payload() != payload {
            return Err(malformed("not in its one spelling"));
        }
        Ok(read)
    }
}

/// The envelope carrying `payload` under one ES256 proof: `sign` gets the
/// bytes to sign (RFC 7515 §5.1) and answers the signature, 64 bytes
/// `R || S` (RFC 7518 §3.4). The key stays with the caller.
pub fn sealed<E>(
    payload: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<Vec<u8>, E> {
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({ "alg": ES256, "typ": ADMISSION_TYP })).unwrap_or_default(),
    );
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signature = sign(&signing_input(&protected, &encoded_payload))?;
    Ok(serde_json::to_vec(&json!({
        "payload": encoded_payload,
        "signatures": [{
            "protected": protected,
            "signature": URL_SAFE_NO_PAD.encode(signature),
        }],
    }))
    .unwrap_or_default())
}

/// An admission statement verified as its site's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmission {
    pub admission: Admission,
    /// The site that signed, and the path it was accepted on.
    pub participant: AcceptedParticipant,
}

/// Verify the admission statement `jws` at `at`, to one of the platform
/// intermediates `anchors` the verifier admits: the site's participant
/// certificate on its path under `policy`, the site's ES256 signature with
/// that certificate's key, that the statement speaks for exactly that
/// organization and site at an entry the certificate lists, and its time.
pub fn verify_admission(
    policy: &impl PathPolicy,
    purposes: &PurposeProfile,
    jws: &[u8],
    anchors: &[Vec<u8>],
    at: SystemTime,
) -> Result<VerifiedAdmission, AdmissionError> {
    let envelope = Envelope::parse_typed(jws, ADMISSION_TYP)?;
    let proof = envelope.required(ES256)?;
    let admission = Admission::read(&envelope.payload)?;
    let participant = accept_participant(
        policy,
        purposes,
        &admission.certificate,
        &admission.chain,
        anchors,
        at,
    )?;
    verify_es256(
        &admission.certificate,
        &envelope.signing_input(proof),
        &proof.signature,
    )?;
    if admission.recipient_org != participant.participant.organization {
        return Err(AdmissionError::Scope("organization"));
    }
    if admission.site != participant.participant.site {
        return Err(AdmissionError::Scope("site"));
    }
    // Exactly a listed entry: the same host with another port or path is
    // another site's.
    if !participant.participant.admits(&admission.mount) {
        return Err(AdmissionError::Scope("entry mounts"));
    }
    let now = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or(AdmissionError::Time)?;
    if now < admission.not_before || now > admission.not_after {
        return Err(AdmissionError::Time);
    }
    Ok(VerifiedAdmission {
        admission,
        participant,
    })
}

#[cfg(test)]
mod tests;
