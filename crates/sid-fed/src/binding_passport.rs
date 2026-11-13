// SPDX-License-Identifier: AGPL-3.0-only
//! The Binding Passport as a recipient reads it: the end-entity certificate
//! of one authorized signer of a Binding, its BindingId as the subject.
//!
//! The extended key usage and the four SID extensions are read under one
//! explicit [`PassportProfile`]; production has no allocation until the
//! structured.id enterprise number is assigned, so it accepts no passport,
//! and a development passport is refused under any other profile.
//!
//! A Corporate Binding's subject also names its source organization
//! (`O=<OrgId>`), so it lies inside the name constraints of that
//! organization's authority; a Personal Binding's does not.
//!
//! Encodings (all extensions non-critical):
//! - `sid.binding.recipient_org`: `OCTET STRING (SIZE (16))`, the registered
//!   OrgId's UUID octets; a domain is never part of it;
//! - `sid.merkle_root`: `OCTET STRING (SIZE (32))`;
//! - `sid.instance_id`: `UTF8String`;
//! - `sid.assurance_level`: `ENUMERATED` of [`AssuranceLevel`].
//!
//! Only the passport's content is read here. Its path, validity and status
//! are the path verifier's.

use std::str::FromStr;

use der::asn1::{ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;

use crate::allocation::ContextAllocation;

/// The identifiers a passport is written and read under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassportProfile {
    /// Extended key usage `id-sid-binding-passport`.
    pub key_usage: ObjectIdentifier,
    pub recipient_org: ObjectIdentifier,
    pub merkle_root: ObjectIdentifier,
    pub instance_id: ObjectIdentifier,
    pub assurance_level: ObjectIdentifier,
}

/// The temporary allocation of development installations, under the
/// enterprise number reserved for documentation (RFC 5612).
pub const DEVELOPMENT_PASSPORT: PassportProfile = PassportProfile {
    key_usage: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.1"),
    recipient_org: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.2"),
    merkle_root: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.3"),
    instance_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.4"),
    assurance_level: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2.5"),
};

/// The registered structured.id allocation: none until the enterprise number
/// is assigned, so production accepts no passport.
pub const SID_PASSPORT: Option<PassportProfile> = None;

impl PassportProfile {
    /// The profile of `allocation`; production refuses without its
    /// registered allocation, and never takes the development one.
    pub fn of(allocation: ContextAllocation) -> Result<Self, PassportError> {
        match allocation {
            ContextAllocation::Development => Ok(DEVELOPMENT_PASSPORT),
            ContextAllocation::Production => SID_PASSPORT
                .filter(|p| !p.shares_identifiers_with(&DEVELOPMENT_PASSPORT))
                .ok_or(PassportError::NoAllocation),
        }
    }

    fn identifiers(&self) -> [ObjectIdentifier; 5] {
        [
            self.key_usage,
            self.recipient_org,
            self.merkle_root,
            self.instance_id,
            self.assurance_level,
        ]
    }

    fn shares_identifiers_with(&self, other: &Self) -> bool {
        self.identifiers()
            .iter()
            .any(|oid| other.identifiers().contains(oid))
    }
}

/// The Profile's highest assurance level, as `sid.assurance_level` carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, der::Enumerated)]
#[repr(u32)]
pub enum AssuranceLevel {
    /// Self-asserted.
    Loa0 = 0,
    /// Basic verification (confirmation link, one-time code).
    Loa1 = 1,
    /// Remote verification with a document.
    Loa2 = 2,
    /// Face-to-face or hardware-attested verification.
    Loa3 = 3,
    /// Government-issued, cryptographically verified.
    Loa4 = 4,
}

/// What one passport states about its Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passport {
    pub binding_id: uuid::Uuid,
    /// The source organization of a Corporate Binding, written into the
    /// subject; none for a Personal Binding.
    pub source_org: Option<uuid::Uuid>,
    /// The registered OrgId of the recipient organization: a domain change
    /// leaves it, and so the certificate, unchanged.
    pub recipient_org: uuid::Uuid,
    /// The Profile's Merkle root, the same in all its Bindings' passports.
    pub merkle_root: [u8; 32],
    /// The issuing instance.
    pub instance_id: String,
    pub assurance_level: AssuranceLevel,
}

/// Why a passport was not read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PassportError {
    /// Production has no registered allocation yet.
    #[error("no registered Binding Passport identifier allocation")]
    NoAllocation,
    /// The instance identifier is empty.
    #[error("the instance identifier is empty")]
    InstanceId,
    /// The certificate carries identifiers of the development allocation
    /// while read under another one.
    #[error("a development Binding Passport is not accepted under this allocation")]
    DevelopmentPassport,
    /// The certificate does not name the passport's extended key usage.
    #[error("the certificate is not certified for Binding Passport use")]
    NotPassport,
    /// The subject is not exactly `CN=<BindingId>,OU=Pairwise Binding`,
    /// followed by `O=<OrgId>` for a Corporate Binding.
    #[error("the subject is not a Binding Passport subject")]
    Subject,
    /// A passport extension is absent.
    #[error("passport extension {0} is absent")]
    Missing(ObjectIdentifier),
    /// A passport extension appears more than once (RFC 5280 §4.2).
    #[error("passport extension {0} appears more than once")]
    Duplicate(ObjectIdentifier),
    /// A passport extension is marked critical, which this profile never does.
    #[error("passport extension {0} is marked critical")]
    Critical(ObjectIdentifier),
    /// A passport extension's value is not its encoding.
    #[error("passport extension {0} is malformed")]
    Malformed(ObjectIdentifier),
    /// Encoding failed.
    #[error("passport encoding: {0}")]
    Encoding(String),
}

const ORGANIZATIONAL_UNIT: &str = "Pairwise Binding";

impl Passport {
    /// The passport `certificate` states under `profile`.
    pub fn read(
        profile: &PassportProfile,
        certificate: &Certificate,
    ) -> Result<Self, PassportError> {
        let tbs = certificate.tbs_certificate();
        let extensions: &[Extension] = tbs.extensions().map_or(&[], Vec::as_slice);
        if *profile != DEVELOPMENT_PASSPORT {
            let development = DEVELOPMENT_PASSPORT.identifiers();
            let carries_development = extensions.iter().any(|e| {
                development.contains(&e.extn_id)
                    || (e.extn_id == ExtendedKeyUsage::OID
                        && ExtendedKeyUsage::from_der(e.extn_value.as_bytes())
                            .is_ok_and(|eku| eku.0.iter().any(|oid| development.contains(oid))))
            });
            if carries_development {
                return Err(PassportError::DevelopmentPassport);
            }
        }
        let eku = ExtendedKeyUsage::from_der(
            single(extensions, ExtendedKeyUsage::OID)?
                .ok_or(PassportError::NotPassport)?
                .extn_value
                .as_bytes(),
        )
        .map_err(|_| PassportError::Malformed(ExtendedKeyUsage::OID))?;
        if !eku.0.contains(&profile.key_usage) {
            return Err(PassportError::NotPassport);
        }
        let value = |oid| -> Result<&[u8], PassportError> {
            let e = single(extensions, oid)?.ok_or(PassportError::Missing(oid))?;
            if e.critical {
                return Err(PassportError::Critical(oid));
            }
            Ok(e.extn_value.as_bytes())
        };
        let recipient_org = OctetString::from_der(value(profile.recipient_org)?)
            .ok()
            .and_then(|o| uuid::Uuid::from_slice(o.as_bytes()).ok())
            .ok_or(PassportError::Malformed(profile.recipient_org))?;
        let merkle_root = OctetString::from_der(value(profile.merkle_root)?)
            .ok()
            .and_then(|o| <[u8; 32]>::try_from(o.as_bytes()).ok())
            .ok_or(PassportError::Malformed(profile.merkle_root))?;
        let instance_id = String::from_der(value(profile.instance_id)?)
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(PassportError::Malformed(profile.instance_id))?;
        let assurance_level = AssuranceLevel::from_der(value(profile.assurance_level)?)
            .map_err(|_| PassportError::Malformed(profile.assurance_level))?;
        let (binding_id, source_org) = binding_subject(tbs.subject())?;
        Ok(Self {
            binding_id,
            source_org,
            recipient_org,
            merkle_root,
            instance_id,
            assurance_level,
        })
    }

    /// The four SID extensions of this passport under `profile`, as a
    /// certificate carries them, in the order recipient, root, instance,
    /// assurance.
    pub fn extensions(&self, profile: &PassportProfile) -> Result<Vec<Extension>, PassportError> {
        if self.instance_id.is_empty() {
            return Err(PassportError::InstanceId);
        }
        let encoding = |e: der::Error| PassportError::Encoding(e.to_string());
        let recipient = OctetString::new(self.recipient_org.as_bytes().to_vec())
            .map_err(encoding)?
            .to_der()
            .map_err(encoding)?;
        let root = OctetString::new(self.merkle_root.to_vec())
            .map_err(encoding)?
            .to_der()
            .map_err(encoding)?;
        let instance = self.instance_id.to_der().map_err(encoding)?;
        let assurance = self.assurance_level.to_der().map_err(encoding)?;
        [
            (profile.recipient_org, recipient),
            (profile.merkle_root, root),
            (profile.instance_id, instance),
            (profile.assurance_level, assurance),
        ]
        .into_iter()
        .map(|(extn_id, value)| {
            Ok(Extension {
                extn_id,
                critical: false,
                extn_value: OctetString::new(value).map_err(encoding)?,
            })
        })
        .collect()
    }

    /// The subject this passport is certified under.
    pub fn subject(&self) -> Result<Name, PassportError> {
        subject(self.binding_id, self.source_org)
    }
}

/// `CN=<BindingId>,OU=Pairwise Binding`, then `O=<OrgId>` for a Corporate
/// Binding (RFC 4514 order: the organization is the first RDN, inside its
/// authority's `O=<OrgId>` subtree), the UUIDs in their hyphenated lowercase
/// form.
fn subject(binding_id: uuid::Uuid, source_org: Option<uuid::Uuid>) -> Result<Name, PassportError> {
    let base = format!("CN={binding_id},OU={ORGANIZATIONAL_UNIT}");
    let text = match source_org {
        Some(org) => format!("{base},O={org}"),
        None => base,
    };
    Name::from_str(&text).map_err(|e| PassportError::Encoding(e.to_string()))
}

/// The BindingId and source organization of a subject that is exactly what
/// [`subject`] writes.
fn binding_subject(name: &Name) -> Result<(uuid::Uuid, Option<uuid::Uuid>), PassportError> {
    let text = name.to_string();
    let (id, rest) = text
        .strip_prefix("CN=")
        .and_then(|rest| rest.split_once(&format!(",OU={ORGANIZATIONAL_UNIT}")))
        .ok_or(PassportError::Subject)?;
    let id = uuid::Uuid::parse_str(id).map_err(|_| PassportError::Subject)?;
    let org = match rest {
        "" => None,
        rest => Some(
            rest.strip_prefix(",O=")
                .and_then(|org| uuid::Uuid::parse_str(org).ok())
                .ok_or(PassportError::Subject)?,
        ),
    };
    // Only the canonical spelling is a passport subject: one BindingId has
    // exactly one subject name.
    if subject(id, org)? != *name {
        return Err(PassportError::Subject);
    }
    Ok((id, org))
}

fn single(
    extensions: &[Extension],
    oid: ObjectIdentifier,
) -> Result<Option<&Extension>, PassportError> {
    let mut found = extensions.iter().filter(|e| e.extn_id == oid);
    let first = found.next();
    if found.next().is_some() {
        return Err(PassportError::Duplicate(oid));
    }
    Ok(first)
}

#[cfg(test)]
mod tests;
