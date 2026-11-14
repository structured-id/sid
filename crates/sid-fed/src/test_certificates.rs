// SPDX-License-Identifier: AGPL-3.0-only
//! Certificates the tests build for themselves: any subject, issuer,
//! extension set and validity, signed with ECDSA P-256 keys derived from a
//! seed. Nothing here follows an issuance policy; a test states exactly the
//! certificate it wants, a wrong one included.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use der::Encode;
use der::asn1::{BitString, ObjectIdentifier, OctetString, Uint};
use der::oid::AssociatedOid;
use p256::ecdsa::SigningKey;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

/// The key of `seed`: the same seed is the same key in every test.
pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed.max(1); 32]).expect("a nonzero scalar")
}

/// The name `text` spells (RFC 4514).
pub(crate) fn name(text: &str) -> Name {
    Name::from_str(text).expect("a distinguished name")
}

/// An extension `oid` carrying the DER of `value`.
pub(crate) fn extension(oid: ObjectIdentifier, critical: bool, value: &impl Encode) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().expect("an encodable value"))
            .expect("an octet string"),
    }
}

/// Basic constraints of an authority with `path_len`, critical.
pub(crate) fn authority(path_len: Option<u8>) -> Extension {
    extension(
        BasicConstraints::OID,
        true,
        &BasicConstraints {
            ca: true,
            path_len_constraint: path_len,
        },
    )
}

/// The key usage of an authority: it signs certificates and CRLs.
pub(crate) fn signs_certificates() -> Extension {
    extension(
        KeyUsage::OID,
        true,
        &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
    )
}

/// The key usage of an end entity: it signs.
pub(crate) fn signs() -> Extension {
    extension(
        KeyUsage::OID,
        true,
        &KeyUsage(KeyUsages::DigitalSignature.into()),
    )
}

/// The extended key usage naming `purposes`.
pub(crate) fn purposes(purposes: &[ObjectIdentifier]) -> Extension {
    extension(
        ExtendedKeyUsage::OID,
        false,
        &ExtendedKeyUsage(purposes.to_vec()),
    )
}

/// Name constraints permitting exactly the subtrees `permitted`.
pub(crate) fn permits(permitted: &[&str], critical: bool) -> Extension {
    extension(
        NameConstraints::OID,
        critical,
        &NameConstraints {
            permitted_subtrees: Some(
                permitted
                    .iter()
                    .map(|subtree| GeneralSubtree {
                        base: GeneralName::DirectoryName(name(subtree)),
                        minimum: 0,
                        maximum: None,
                    })
                    .collect(),
            ),
            excluded_subtrees: None,
        },
    )
}

/// The interval from `before` ago to `after` from now.
pub(crate) fn valid(before: Duration, after: Duration) -> Validity {
    let now = SystemTime::now();
    let time = |at: SystemTime| Time::try_from(at).expect("a certificate time");
    Validity::new(time(now - before), time(now + after))
}

/// An interval around now, a day each way.
pub(crate) fn current() -> Validity {
    let day = Duration::from_secs(86_400);
    valid(day, day)
}

/// One certificate as a test states it.
pub(crate) struct Stated {
    pub subject: Name,
    pub serial: u32,
    pub validity: Validity,
    pub extensions: Vec<Extension>,
}

impl Stated {
    /// `subject` with `extensions`, valid now.
    pub(crate) fn new(subject: &str, extensions: Vec<Extension>) -> Self {
        Self {
            subject: name(subject),
            serial: 1,
            validity: current(),
            extensions,
        }
    }

    /// The certificate (DER) of `subject_key`, signed by `issuer_key` under
    /// the issuer name `issuer`.
    pub(crate) fn signed(
        &self,
        subject_key: &SigningKey,
        issuer: &Name,
        issuer_key: &SigningKey,
    ) -> Vec<u8> {
        struct Exactly<'a>(&'a Stated, &'a Name);
        impl BuilderProfile for Exactly<'_> {
            fn get_issuer(&self, _: &Name) -> Name {
                self.1.clone()
            }
            fn get_subject(&self) -> Name {
                self.0.subject.clone()
            }
            fn build_extensions(
                &self,
                _: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _: &x509_cert::TbsCertificate,
            ) -> x509_cert::builder::Result<Vec<Extension>> {
                Ok(self.0.extensions.clone())
            }
        }
        let spki = SubjectPublicKeyInfoOwned::from_key(subject_key.verifying_key())
            .expect("a P-256 public key");
        CertificateBuilder::new(
            Exactly(self, issuer),
            SerialNumber::from(self.serial),
            self.validity,
            spki,
        )
        .expect("a certificate builder")
        .build::<_, p256::ecdsa::DerSignature>(issuer_key)
        .expect("a signed certificate")
        .to_der()
        .expect("a DER certificate")
    }

    /// The certificate signed by its own key: a self-signed one.
    pub(crate) fn self_signed(&self, key: &SigningKey) -> Vec<u8> {
        self.signed(key, &self.subject, key)
    }
}

/// The certificate `der` decodes to.
pub(crate) fn read(der: &[u8]) -> x509_cert::Certificate {
    use der::Decode;
    x509_cert::Certificate::from_der(der).expect("a DER certificate")
}

/// `ecdsa-with-SHA256` (RFC 5758 §3.2).
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The subject key identifier `id`, by which a list names its issuer's key.
pub(crate) fn key_id(id: &[u8]) -> Extension {
    extension(
        SubjectKeyIdentifier::OID,
        false,
        &SubjectKeyIdentifier(OctetString::new(id).expect("an octet string")),
    )
}

/// The number `n` of a revocation list.
pub(crate) fn list_number(n: u8) -> Extension {
    extension(
        CrlNumber::OID,
        false,
        &CrlNumber(Uint::new(&[n]).expect("a list number")),
    )
}

/// The authority key identifier `id` of a revocation list.
pub(crate) fn names_key(id: &[u8]) -> Extension {
    extension(
        AuthorityKeyIdentifier::OID,
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(id).expect("an octet string")),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )
}

/// The entry revoking `serial` a minute ago, with `extensions`.
pub(crate) fn revoked_entry(serial: u32, extensions: Option<Vec<Extension>>) -> RevokedCert {
    RevokedCert {
        serial_number: SerialNumber::from(serial),
        revocation_date: Time::try_from(SystemTime::now() - Duration::from_secs(60))
            .expect("a list time"),
        crl_entry_extensions: extensions,
    }
}

/// One revocation list as a test states it.
pub(crate) struct StatedList {
    pub issuer: Name,
    pub this_update: SystemTime,
    pub next_update: Option<SystemTime>,
    pub revoked: Vec<RevokedCert>,
    pub extensions: Vec<Extension>,
}

impl StatedList {
    /// List `number` of `issuer`, whose key is named `key_id`, issued a
    /// minute ago with an hour of evidence left, revoking `serials`.
    pub(crate) fn new(issuer: &str, key_id: &[u8], number: u8, serials: &[u32]) -> Self {
        let now = SystemTime::now();
        Self {
            issuer: name(issuer),
            this_update: now - Duration::from_secs(60),
            next_update: Some(now + Duration::from_secs(3600)),
            revoked: serials
                .iter()
                .map(|serial| revoked_entry(*serial, None))
                .collect(),
            extensions: vec![list_number(number), names_key(key_id)],
        }
    }

    /// The fields the issuer signs.
    pub(crate) fn tbs(&self) -> TbsCertList {
        let time = |at: SystemTime| Time::try_from(at).expect("a list time");
        TbsCertList {
            version: x509_cert::certificate::Version::V2,
            signature: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            issuer: self.issuer.clone(),
            this_update: time(self.this_update),
            next_update: self.next_update.map(time),
            revoked_certificates: (!self.revoked.is_empty()).then(|| self.revoked.clone()),
            crl_extensions: (!self.extensions.is_empty()).then(|| self.extensions.clone()),
        }
    }

    /// The list (DER) signed with `key`.
    pub(crate) fn signed(&self, key: &SigningKey) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let tbs = self.tbs();
        let signature: p256::ecdsa::DerSignature =
            key.sign(&tbs.to_der().expect("the signed fields"));
        CertificateList {
            signature_algorithm: tbs.signature.clone(),
            tbs_cert_list: tbs,
            signature: BitString::from_bytes(signature.as_bytes()).expect("a signature"),
        }
        .to_der()
        .expect("a DER list")
    }
}
