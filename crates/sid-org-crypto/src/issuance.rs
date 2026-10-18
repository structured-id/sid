// SPDX-License-Identifier: AGPL-3.0-only
//! CA certificate issuance through a key-bound signer.
//!
//! The certificate is encoded by RustCrypto `x509-cert`; the issuer's
//! [`CaSigner`] signs the exact DER `TBSCertificate` the builder produces, so a
//! key held outside this process (hardware, external custody) issues the same
//! way as a software key. Every check on the issuer happens before signing: a
//! refused request never reaches the signer.

use sid_keys::{CaSigner, SigningError};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{AsyncBuilder, CertificateBuilder};
use x509_cert::der::asn1::BitString;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
};
use x509_cert::time::Validity;

/// Who signs the certificate.
pub enum Issuer<'a> {
    /// The certificate is signed with the key it certifies: the root of a
    /// perimeter. Its subject is also its issuer.
    SelfIssued(&'a dyn CaSigner),
    /// An issuing CA: its certificate and the signer of the key it certifies.
    Ca {
        certificate: &'a Certificate,
        signer: &'a dyn CaSigner,
    },
}

/// The CA certificate requested.
pub struct CaRequest {
    pub subject: Name,
    pub public_key: SubjectPublicKeyInfoOwned,
    pub serial_number: SerialNumber,
    pub validity: Validity,
    /// `pathLenConstraint`: how many CA certificates may follow this one;
    /// `None` leaves it unlimited (RFC 5280 §4.2.1.9).
    pub path_len: Option<u8>,
    /// Further extensions, added after the CA profile's own.
    pub extensions: Vec<Extension>,
}

/// Why a CA certificate was not issued.
#[derive(Debug, Error)]
pub enum IssuanceError {
    /// The signer does not hold the key the issuing certificate (or, when
    /// self-issued, the request) certifies.
    #[error("the signer's key is not the issuer's key")]
    WrongKey,
    /// The issuing certificate is not a CA allowed to sign certificates.
    #[error("the issuing certificate is not a certificate-signing CA")]
    IssuerNotCa,
    /// The issuing CA's path length allows no CA below it, or not one with
    /// the requested path length.
    #[error("the issuing CA's path length does not allow this CA")]
    PathLength,
    /// The requested validity is not within the issuing certificate's.
    #[error("the requested validity exceeds the issuer's")]
    Validity,
    /// The requested validity ends before it begins.
    #[error("the requested validity ends before it begins")]
    ReversedValidity,
    /// A CA certificate needs a subject (RFC 5280 §4.1.2.6).
    #[error("a CA certificate needs a non-empty subject")]
    EmptySubject,
    /// The issuing CA would certify a subject of its own name: a replacement
    /// signed by the CA it replaces, which SID never accepts as delegation.
    #[error("an issuing CA cannot certify a CA of its own name")]
    SameSubjectAsIssuer,
    /// One extension would appear twice (RFC 5280 §4.2).
    #[error("extension {0} would appear more than once")]
    DuplicateExtension(x509_cert::der::asn1::ObjectIdentifier),
    /// An extension of the issuing certificate does not decode.
    #[error("malformed issuing certificate: {0}")]
    MalformedIssuer(String),
    /// Certificate encoding failed.
    #[error("certificate encoding: {0}")]
    Encoding(String),
    /// The signer refused or failed.
    #[error(transparent)]
    Signing(#[from] SigningError),
}

/// Issues the CA certificate `request` under `issuer`.
pub async fn issue_ca_certificate(
    issuer: Issuer<'_>,
    request: CaRequest,
) -> Result<Certificate, IssuanceError> {
    prepare_ca_certificate(issuer, request)?.sign().await
}

/// A CA certificate with every field final and not yet signed.
pub struct PreparedCertificate<'a> {
    builder: CertificateBuilder<CaProfile>,
    tbs: Vec<u8>,
    signer: &'a dyn CaSigner,
}

impl PreparedCertificate<'_> {
    /// The exact DER `TBSCertificate` the issuer's signature will cover. An
    /// additional signature over a projection of it (an alternative signature,
    /// X.509 §7.2.2) is computed from these bytes before [`Self::sign`].
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs
    }

    /// Signs the prepared `TBSCertificate` with the issuer's signer.
    pub async fn sign(self) -> Result<Certificate, IssuanceError> {
        let signature = self.signer.sign(&self.tbs).await?;
        let signature = BitString::from_bytes(&signature)
            .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
        self.builder
            .assemble(signature, &SignerKey(self.signer))
            .map_err(|e| IssuanceError::Encoding(e.to_string()))
    }
}

/// Checks `request` under `issuer` and fixes every field of the certificate;
/// nothing is signed. The same checks as [`issue_ca_certificate`] apply.
pub fn prepare_ca_certificate<'a>(
    issuer: Issuer<'a>,
    request: CaRequest,
) -> Result<PreparedCertificate<'a>, IssuanceError> {
    admit_request(&request)?;
    let (signer, issuer_name, issuer_key_id) = match issuer {
        Issuer::SelfIssued(signer) => {
            if signer.public_key() != &request.public_key {
                return Err(IssuanceError::WrongKey);
            }
            (signer, request.subject.clone(), None)
        }
        Issuer::Ca {
            certificate,
            signer,
        } => {
            let tbs = certificate.tbs_certificate();
            if signer.public_key() != tbs.subject_public_key_info() {
                return Err(IssuanceError::WrongKey);
            }
            // A CA of the issuer's own name signed by the issuer is a
            // replacement certified by the key it replaces: SID admits a
            // replacement only from the parent, so this is no rollover path
            // (and RFC 5280 §6.1.4 (l)'s self-issued exemption never applies).
            if &request.subject == tbs.subject() {
                return Err(IssuanceError::SameSubjectAsIssuer);
            }
            admit_issuer(certificate, &request)?;
            let key_id = tbs
                .get_extension::<SubjectKeyIdentifier>()
                .map_err(|e| IssuanceError::MalformedIssuer(e.to_string()))?
                .map(|(_, ski)| ski);
            (signer, tbs.subject().clone(), key_id)
        }
    };

    let profile = CaProfile {
        subject: request.subject,
        issuer: issuer_name,
        path_len: request.path_len,
        issuer_key_id,
        extensions: request.extensions,
    };
    let mut builder = CertificateBuilder::new(
        profile,
        request.serial_number,
        request.validity,
        request.public_key,
    )
    .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
    // Finalized once: the builder appends the profile's extensions here.
    let tbs = builder
        .finalize(&SignerKey(signer))
        .map_err(|e| IssuanceError::Encoding(e.to_string()))?;
    Ok(PreparedCertificate {
        builder,
        tbs,
        signer,
    })
}

/// The request itself is a conforming CA certificate: a subject (RFC 5280
/// §4.1.2.6), a validity that does not end before it begins, and no extension
/// twice, neither among the caller's nor against the profile's (RFC 5280 §4.2).
fn admit_request(request: &CaRequest) -> Result<(), IssuanceError> {
    if request.subject == Name::default() {
        return Err(IssuanceError::EmptySubject);
    }
    if request.validity.not_after.to_unix_duration()
        < request.validity.not_before.to_unix_duration()
    {
        return Err(IssuanceError::ReversedValidity);
    }
    let mut seen = vec![
        BasicConstraints::OID,
        KeyUsage::OID,
        SubjectKeyIdentifier::OID,
        AuthorityKeyIdentifier::OID,
    ];
    for extension in &request.extensions {
        if seen.contains(&extension.extn_id) {
            return Err(IssuanceError::DuplicateExtension(extension.extn_id));
        }
        seen.push(extension.extn_id);
    }
    Ok(())
}

/// The issuing certificate may sign this CA: it is a CA with `keyCertSign`,
/// its path length leaves room for the request (RFC 5280 §4.2.1.9), and the
/// request's validity lies within its own.
fn admit_issuer(certificate: &Certificate, request: &CaRequest) -> Result<(), IssuanceError> {
    let tbs = certificate.tbs_certificate();
    let malformed = |e: x509_cert::der::Error| IssuanceError::MalformedIssuer(e.to_string());
    let constraints = tbs
        .get_extension::<BasicConstraints>()
        .map_err(malformed)?
        .map(|(_, c)| c)
        .filter(|c| c.ca)
        .ok_or(IssuanceError::IssuerNotCa)?;
    // Key usage is required, not only checked when present: a CA whose key
    // signs certificates MUST carry it (RFC 5280 §4.2.1.3), and every issuer
    // here is a SID CA of this profile, never a CA from outside the hierarchy.
    let signs_certificates = tbs
        .get_extension::<KeyUsage>()
        .map_err(malformed)?
        .is_some_and(|(_, usage)| usage.key_cert_sign());
    if !signs_certificates {
        return Err(IssuanceError::IssuerNotCa);
    }
    if let Some(issuer_len) = constraints.path_len_constraint {
        // A CA below a CA of path length n has at most n - 1, and is limited.
        let allowed = issuer_len.checked_sub(1).ok_or(IssuanceError::PathLength)?;
        match request.path_len {
            Some(len) if len <= allowed => {}
            _ => return Err(IssuanceError::PathLength),
        }
    }
    let within = |t: &x509_cert::time::Time| {
        let t = t.to_unix_duration();
        tbs.validity().not_before.to_unix_duration() <= t
            && t <= tbs.validity().not_after.to_unix_duration()
    };
    if !within(&request.validity.not_before) || !within(&request.validity.not_after) {
        return Err(IssuanceError::Validity);
    }
    Ok(())
}

/// The SID CA profile: subject and issuer, and the extensions of a CA
/// certificate (RFC 5280 §4.2.1.1, §4.2.1.2, §4.2.1.3, §4.2.1.9).
struct CaProfile {
    subject: Name,
    issuer: Name,
    path_len: Option<u8>,
    issuer_key_id: Option<SubjectKeyIdentifier>,
    extensions: Vec<Extension>,
}

impl BuilderProfile for CaProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut extensions: Vec<Extension> = Vec::new();
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: self.path_len,
        };
        extensions.push(constraints.to_extension(subject, &extensions)?);
        let usage =
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature);
        extensions.push(usage.to_extension(subject, &extensions)?);
        let ski = SubjectKeyIdentifier::try_from(spk)?;
        extensions.push(ski.to_extension(subject, &extensions)?);
        // RFC 5280 §4.2.1.1: the issuer's subject key identifier; a self-issued
        // certificate's is its own key's.
        let issuer_ski = match &self.issuer_key_id {
            Some(ski) => ski.clone(),
            None => SubjectKeyIdentifier::try_from(issuer_spk)?,
        };
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(issuer_ski.0),
            ..Default::default()
        };
        extensions.push(aki.to_extension(subject, &extensions)?);
        extensions.extend(self.extensions.iter().cloned());
        Ok(extensions)
    }
}

/// The issuer's signer as the builder sees it: its public key and its complete
/// signature algorithm. The builder takes both from here, so the certificate's
/// `signature` and `signatureAlgorithm` fields are the signer's.
struct SignerKey<'a>(&'a dyn CaSigner);

#[derive(Clone)]
struct ReportedKey(SubjectPublicKeyInfoOwned);

impl EncodePublicKey for ReportedKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::der::Document> {
        Ok(x509_cert::der::Document::encode_msg(&self.0)?)
    }
}

impl signature::Keypair for SignerKey<'_> {
    type VerifyingKey = ReportedKey;

    fn verifying_key(&self) -> ReportedKey {
        ReportedKey(self.0.public_key().clone())
    }
}

impl DynSignatureAlgorithmIdentifier for SignerKey<'_> {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.0.signature_algorithm().clone())
    }
}

#[cfg(test)]
mod tests;
