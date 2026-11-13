// SPDX-License-Identifier: AGPL-3.0-only
//! Certificates the tests build for themselves: any subject, issuer,
//! extension set and validity, signed with ECDSA P-256 keys derived from a
//! seed. Nothing here follows an issuance policy; a test states exactly the
//! certificate it wants, a wrong one included.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use der::Encode;
use der::asn1::{ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use p256::ecdsa::SigningKey;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
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
