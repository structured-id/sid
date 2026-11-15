// SPDX-License-Identifier: AGPL-3.0-only
//! The status an authority publishes of the certificates it issued.
//!
//! In plain words: a certificate that was valid yesterday may have been
//! withdrawn today. Its issuer says so in a signed list of the serial
//! numbers it revoked (a CRL, RFC 5280 §5). A recipient relies on a
//! certificate only while it holds such a list from the certificate's own
//! issuer, still within its time, that does not name the certificate.
//!
//! This module VERIFIES one list under one issuer certificate: that this
//! issuer signed it (ECDSA P-256 over the signed fields, with a key usage
//! that allows signing such lists), that it names this issuer by name and by
//! key identifier, and that it is a complete list with a number and an end
//! of its time. It gives a classical verdict only: a further signature the
//! list may carry in its extensions is not looked at.
//!
//! What it leaves to its caller: that the issuer certificate itself is
//! accepted on a path, whether the list is still within its time, and
//! keeping what was seen revoked.

use std::sync::Arc;
use std::time::SystemTime;

use der::Decode;
use der::asn1::Uint;
use der::oid::AssociatedOid;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::crl::{Authentication, AuthenticationFailure};
use structured_pkix::path::EffectiveKey;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, CrlNumber, SubjectKeyIdentifier};

use crate::passport_path::EcdsaP256;

/// What one accepted list states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedStatus {
    /// The list's number: greater than every earlier list's of the issuer
    /// (RFC 5280 §5.2.3).
    pub number: u64,
    pub this_update: SystemTime,
    /// After this moment the list is no evidence of status.
    pub next_update: SystemTime,
    /// The serials revoked, as their DER INTEGER contents.
    pub revoked: Vec<Vec<u8>>,
}

impl IssuedStatus {
    /// Whether the certificate with serial `serial` is revoked.
    pub fn revokes(&self, serial: &[u8]) -> bool {
        self.revoked.iter().any(|r| r.as_slice() == serial)
    }
}

/// Why a list was not accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StatusError {
    #[error("not a DER certificate or revocation list: {0}")]
    Encoding(String),
    /// The list names another issuer, by name or key identifier, or was
    /// signed with another key.
    #[error("the revocation list is another issuer's")]
    OtherIssuer,
    /// The issuer's certificate does not allow it to sign revocation lists
    /// (RFC 5280 §4.2.1.3, cRLSign).
    #[error("the issuer's certificate does not allow signing revocation lists")]
    NotAuthorized,
    /// The issuer's signature over the list does not verify.
    #[error("the issuer's signature over the revocation list does not verify")]
    Signature,
    /// The list is signed with an algorithm this verifier does not check.
    #[error("the revocation list is signed with an algorithm that is not checked here")]
    UnsupportedSignature,
    /// A field required of a complete list is absent.
    #[error("the revocation list has no {0}")]
    Missing(&'static str),
    /// The same extension twice: which one applies has no answer.
    #[error("the revocation list repeats an extension")]
    DuplicateExtension,
    /// A critical extension this verifier does not process (RFC 5280 §5.2),
    /// which includes the ones that would make the list partial.
    #[error("the revocation list has a critical extension that is not processed here")]
    UnrecognizedCritical,
    #[error("the revocation list's next update is not after its issue time")]
    UpdateOrder,
}

fn encoding(e: impl std::fmt::Display) -> StatusError {
    StatusError::Encoding(e.to_string())
}

/// A list number that fits the 64 bits issuers number their lists with.
fn number_of(value: &Uint) -> Result<u64, StatusError> {
    let bytes = value.as_bytes();
    if bytes.len() > 8 {
        return Err(StatusError::Encoding("a list number above 64 bits".into()));
    }
    let mut wide = [0u8; 8];
    wide[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(wide))
}

/// What the DER list `crl` states as a complete list of `issuer`, without
/// any signature checked: it names the issuer by name and key identifier,
/// carries a number and a next update after its issue time, and holds no
/// critical extension this verifier does not process, on the list or on an
/// entry. A verifier calls this only beside its own check of the issuer's
/// signature: [`verify_status`] for the classical one.
pub fn read_status(crl: &[u8], issuer: &Certificate) -> Result<IssuedStatus, StatusError> {
    let list = <CertificateList>::from_der(crl).map_err(encoding)?;
    let tbs = &list.tbs_cert_list;
    // RFC 5280 §5.1.1.2: the outer algorithm is the signed one.
    if list.signature_algorithm != tbs.signature {
        return Err(StatusError::Encoding("signatureAlgorithm differs".into()));
    }
    let issuer_tbs = issuer.tbs_certificate();
    if &tbs.issuer != issuer_tbs.subject() {
        return Err(StatusError::OtherIssuer);
    }
    let extensions = tbs
        .crl_extensions
        .as_deref()
        .ok_or(StatusError::Missing("extensions"))?;
    let mut number = None;
    let mut authority = None;
    for (at, extension) in extensions.iter().enumerate() {
        if extensions[..at]
            .iter()
            .any(|earlier| earlier.extn_id == extension.extn_id)
        {
            return Err(StatusError::DuplicateExtension);
        }
        let value = extension.extn_value.as_bytes();
        if extension.extn_id == CrlNumber::OID {
            number = Some(CrlNumber::from_der(value).map_err(encoding)?);
        } else if extension.extn_id == AuthorityKeyIdentifier::OID {
            authority = Some(AuthorityKeyIdentifier::from_der(value).map_err(encoding)?);
        } else if extension.critical {
            return Err(StatusError::UnrecognizedCritical);
        }
    }
    // RFC 5280 §5.2.1: the list names the key that signed it.
    let authority = authority.ok_or(StatusError::Missing("authority key identifier"))?;
    let (_, SubjectKeyIdentifier(issuer_key)) = issuer_tbs
        .get_extension::<SubjectKeyIdentifier>()
        .map_err(encoding)?
        .ok_or(StatusError::OtherIssuer)?;
    if authority.key_identifier.as_ref() != Some(&issuer_key) {
        return Err(StatusError::OtherIssuer);
    }
    let number = number.ok_or(StatusError::Missing("number"))?;
    let this_update = tbs.this_update.to_system_time();
    let next_update = tbs
        .next_update
        .ok_or(StatusError::Missing("next update"))?
        .to_system_time();
    if next_update <= this_update {
        return Err(StatusError::UpdateOrder);
    }
    let mut revoked = Vec::new();
    for entry in tbs.revoked_certificates.iter().flatten() {
        if entry
            .crl_entry_extensions
            .iter()
            .flatten()
            .any(|extension| extension.critical)
        {
            return Err(StatusError::UnrecognizedCritical);
        }
        revoked.push(entry.serial_number.as_bytes().to_vec());
    }
    Ok(IssuedStatus {
        number: number_of(&number.0)?,
        this_update,
        next_update,
        revoked,
    })
}

/// The DER list `crl` accepted under the DER certificate `issuer`: signed
/// with that certificate's ECDSA P-256 key, which its key usage allows to
/// sign such lists, and a complete list of that issuer as [`read_status`]
/// requires. Whether it is still within its time is the caller's.
pub fn verify_status(crl: &[u8], issuer: &[u8]) -> Result<IssuedStatus, StatusError> {
    // Bounds far above one list of a SID authority.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 26)));
    let parser = Parser::der(memory.clone());
    let authority = structured_pkix::Certificate::read(&parser, issuer, 0).map_err(encoding)?;
    let list = structured_pkix::crl::CertificateList::read(&parser, crl, 0).map_err(encoding)?;
    // The issuer's key carries its own parameters (a named curve): nothing
    // is inherited from above it.
    let key = EffectiveKey::standing(authority.tbs().public_key());
    match list
        .authenticate(&authority, key, &EcdsaP256, &memory)
        .map_err(|e| StatusError::Encoding(format!("{e:?}")))?
    {
        Authentication::Authenticated(_) => {}
        Authentication::Rejected(
            AuthenticationFailure::KeyBinding | AuthenticationFailure::IssuerName,
        ) => return Err(StatusError::OtherIssuer),
        Authentication::Rejected(AuthenticationFailure::KeyUsage) => {
            return Err(StatusError::NotAuthorized);
        }
        Authentication::Rejected(AuthenticationFailure::Signature) => {
            return Err(StatusError::Signature);
        }
        Authentication::Unsupported => return Err(StatusError::UnsupportedSignature),
    }
    read_status(crl, &Certificate::from_der(issuer).map_err(encoding)?)
}

#[cfg(test)]
mod tests;
