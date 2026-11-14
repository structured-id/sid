// SPDX-License-Identifier: AGPL-3.0-only
//! A published revocation list is accepted only as its issuer's complete,
//! signed statement. Each test builds exactly the list it states, a wrong
//! one included.

use std::time::{Duration, SystemTime};

use der::asn1::{BitString, OctetString, Uint};
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use x509_cert::certificate::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use super::{IssuedStatus, StatusError, verify_status};
use crate::test_certificates::{Stated, authority, extension, key, name, read, signs_certificates};

const ISSUER: &str = "CN=Organization CA,O=Example";
/// `ecdsa-with-SHA256` (RFC 5758 §3.2).
const ECDSA_WITH_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

fn key_id(id: &[u8]) -> Extension {
    extension(
        SubjectKeyIdentifier::OID,
        false,
        &SubjectKeyIdentifier(OctetString::new(id).unwrap()),
    )
}

/// The issuer's certificate: an authority that signs certificates and
/// revocation lists, naming its key `[7; 20]`.
fn issuer() -> Vec<u8> {
    Stated::new(
        ISSUER,
        vec![authority(Some(0)), signs_certificates(), key_id(&[7; 20])],
    )
    .self_signed(&key(1))
}

fn time(at: SystemTime) -> Time {
    Time::try_from(at).unwrap()
}

/// One list as a test states it.
struct List {
    issuer: &'static str,
    next_update: Option<SystemTime>,
    this_update: SystemTime,
    revoked: Vec<RevokedCert>,
    extensions: Vec<Extension>,
}

fn number(n: u8) -> Extension {
    extension(CrlNumber::OID, false, &CrlNumber(Uint::new(&[n]).unwrap()))
}

fn names_key(id: &[u8]) -> Extension {
    extension(
        AuthorityKeyIdentifier::OID,
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(id).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )
}

fn entry(serial: u32, extensions: Option<Vec<Extension>>) -> RevokedCert {
    RevokedCert {
        serial_number: SerialNumber::from(serial),
        revocation_date: time(SystemTime::now() - Duration::from_secs(60)),
        crl_entry_extensions: extensions,
    }
}

impl List {
    /// List number 5 of the issuer, an hour of evidence left, revoking
    /// serials 7 and 9.
    fn new() -> Self {
        let now = SystemTime::now();
        Self {
            issuer: ISSUER,
            this_update: now - Duration::from_secs(60),
            next_update: Some(now + Duration::from_secs(3600)),
            revoked: vec![entry(7, None), entry(9, None)],
            extensions: vec![number(5), names_key(&[7; 20])],
        }
    }

    fn tbs(&self) -> TbsCertList {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        };
        TbsCertList {
            version: Version::V2,
            signature: algorithm,
            issuer: name(self.issuer),
            this_update: time(self.this_update),
            next_update: self.next_update.map(time),
            revoked_certificates: (!self.revoked.is_empty()).then(|| self.revoked.clone()),
            crl_extensions: (!self.extensions.is_empty()).then(|| self.extensions.clone()),
        }
    }

    /// The list (DER) signed with `key`.
    fn signed(&self, key: &SigningKey) -> Vec<u8> {
        let tbs = self.tbs();
        let signature: p256::ecdsa::DerSignature = key.sign(&tbs.to_der().unwrap());
        CertificateList {
            signature_algorithm: tbs.signature.clone(),
            tbs_cert_list: tbs,
            signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    }
}

fn accepted(list: &List) -> Result<IssuedStatus, StatusError> {
    verify_status(&list.signed(&key(1)), &issuer())
}

/// The accepted list states its number, the end of its evidence and every
/// serial it revokes, as the certificates carry them.
#[test]
fn an_issuers_list_states_what_it_revoked() {
    let list = List::new();
    let status = accepted(&list).unwrap();
    assert_eq!(status.number, 5);
    assert_eq!(status.revoked, vec![vec![7u8], vec![9u8]]);
    assert!(status.revokes(&[9]));
    assert!(!status.revokes(&[8]));
    assert!(status.next_update > SystemTime::now());
    assert!(status.this_update < status.next_update);
}

/// A list that revokes nothing is still the issuer's statement: absence of
/// a revocation is shown only by such a list.
#[test]
fn an_empty_list_is_a_statement() {
    let mut list = List::new();
    list.revoked.clear();
    assert!(accepted(&list).unwrap().revoked.is_empty());
}

/// Bug prevented: anyone can write a list naming an issuer. One signed with
/// another key is not that issuer's, whatever it names.
#[test]
fn a_list_signed_with_another_key_is_refused() {
    let list = List::new();
    assert_eq!(
        verify_status(&list.signed(&key(2)), &issuer()),
        Err(StatusError::Signature)
    );
}

/// Bug prevented: a list changed after it was signed (a revocation taken
/// out) must not be read as the issuer's.
#[test]
fn a_list_changed_after_signing_is_refused() {
    let list = List::new();
    let signed = CertificateList::from_der(&list.signed(&key(1))).unwrap();
    let mut shorter = List::new();
    shorter.this_update = list.this_update;
    shorter.next_update = list.next_update;
    shorter.revoked = vec![list.revoked[0].clone()];
    let forged = CertificateList {
        tbs_cert_list: shorter.tbs(),
        ..signed
    }
    .to_der()
    .unwrap();
    assert_eq!(
        verify_status(&forged, &issuer()),
        Err(StatusError::Signature)
    );
}

/// A list of another issuer's name, or naming another key of the same
/// name, says nothing of this issuer's certificates.
#[test]
fn another_issuers_list_is_refused() {
    let mut named = List::new();
    named.issuer = "CN=Another CA,O=Example";
    assert_eq!(accepted(&named), Err(StatusError::OtherIssuer));

    let mut keyed = List::new();
    keyed.extensions = vec![number(5), names_key(&[8; 20])];
    assert_eq!(accepted(&keyed), Err(StatusError::OtherIssuer));
}

/// A list without a number cannot be ordered against the one held, without
/// a next update has no end of evidence, and without the issuer's key
/// identifier does not name the key that signed it.
#[test]
fn an_incomplete_list_is_refused() {
    let mut unnumbered = List::new();
    unnumbered.extensions = vec![names_key(&[7; 20])];
    assert_eq!(accepted(&unnumbered), Err(StatusError::Missing("number")));

    let mut endless = List::new();
    endless.next_update = None;
    assert_eq!(accepted(&endless), Err(StatusError::Missing("next update")));

    let mut unkeyed = List::new();
    unkeyed.extensions = vec![number(5)];
    assert_eq!(
        accepted(&unkeyed),
        Err(StatusError::Missing("authority key identifier"))
    );

    let mut backwards = List::new();
    backwards.next_update = Some(backwards.this_update - Duration::from_secs(1));
    assert_eq!(accepted(&backwards), Err(StatusError::UpdateOrder));
}

/// Bug prevented: a critical extension changes what a list means (a delta
/// or a partial list, RFC 5280 §§5.2.4, 5.2.5). One this verifier does not
/// process is refused, on the list and on an entry, never read as a
/// complete list.
#[test]
fn an_unprocessed_critical_extension_is_refused() {
    // deltaCRLIndicator (RFC 5280 §5.2.4): the list holds only changes.
    let delta = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");
    let mut partial = List::new();
    partial
        .extensions
        .push(extension(delta, true, &Uint::new(&[4]).unwrap()));
    assert_eq!(accepted(&partial), Err(StatusError::UnrecognizedCritical));

    // The same extension not critical does not change this list's meaning
    // for a verifier that may ignore it (RFC 5280 §5.2).
    let unknown = der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");
    let mut noted = List::new();
    noted
        .extensions
        .push(extension(unknown, false, &Uint::new(&[4]).unwrap()));
    assert_eq!(accepted(&noted).unwrap().number, 5);

    let mut entry_demand = List::new();
    entry_demand.revoked = vec![entry(
        7,
        Some(vec![extension(unknown, true, &Uint::new(&[1]).unwrap())]),
    )];
    assert_eq!(
        accepted(&entry_demand),
        Err(StatusError::UnrecognizedCritical)
    );
}

/// The same extension twice has no single answer.
#[test]
fn a_repeated_extension_is_refused() {
    let mut list = List::new();
    list.extensions.push(number(6));
    assert!(matches!(
        accepted(&list),
        Err(StatusError::DuplicateExtension | StatusError::Encoding(_))
    ));
}

/// Bug prevented: a certificate whose key usage does not allow signing
/// revocation lists (RFC 5280 §4.2.1.3) revoking its issuer's other
/// certificates, or hiding their revocation.
#[test]
fn an_issuer_not_allowed_to_sign_lists_is_refused() {
    let signs_only_certificates = extension(
        KeyUsage::OID,
        true,
        &KeyUsage(KeyUsages::KeyCertSign.into()),
    );
    let issuer = Stated::new(
        ISSUER,
        vec![
            extension(
                BasicConstraints::OID,
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: Some(0),
                },
            ),
            signs_only_certificates,
            key_id(&[7; 20]),
        ],
    )
    .self_signed(&key(1));
    assert_eq!(
        verify_status(&List::new().signed(&key(1)), &issuer),
        Err(StatusError::NotAuthorized)
    );
    // The issuer's own certificate reads as the test built it.
    assert_eq!(read(&issuer).tbs_certificate().subject(), &name(ISSUER));
}

/// Bytes that are no list, and a certificate that is none, are refused as
/// such.
#[test]
fn what_is_not_a_list_is_refused() {
    assert!(matches!(
        verify_status(b"not a list", &issuer()),
        Err(StatusError::Encoding(_))
    ));
    assert!(matches!(
        verify_status(&List::new().signed(&key(1)), b"not a certificate"),
        Err(StatusError::Encoding(_))
    ));
}
