// SPDX-License-Identifier: AGPL-3.0-only
//! The certificate of an enrolled site: who it is and where it may be
//! entered.
//!
//! In plain words: when an installation joins the federation, the platform
//! gives its site a certificate. It names the organization and the site, and
//! lists the exact web addresses that site is entered at. Another
//! installation that is asked to send people there checks this certificate
//! first, so a genuine site cannot claim a neighbour's address, even one on
//! the same host name.
//!
//! This module reads the certificate's CONTENT under that profile. It
//! verifies no signature and no path: what it returns means something only
//! for a certificate whose path to an admitted platform intermediate was
//! verified, and whose issuer was found to issue participants.

use std::str::FromStr;

use der::asn1::Ia5String;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::name::Name;

use crate::purpose::{PurposeError, PurposeProfile};

/// Why a certificate is not a site's participant certificate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParticipantError {
    /// The subject is not exactly `CN=<SiteId>,O=<OrgId>`.
    #[error("the subject is not a site of an organization")]
    Subject,
    /// The basic constraints are absent, not critical, or those of an
    /// authority.
    #[error("the certificate is not a critical end entity")]
    Constraints,
    /// The key usage is absent, not critical, or more than signing.
    #[error("the key usage is not signing alone")]
    KeyUsage,
    /// The extended key usage is not the participant purpose alone.
    #[error("the certificate is not for the participant purpose")]
    Purpose,
    /// The purpose could not be read under this allocation.
    #[error(transparent)]
    Allocation(#[from] PurposeError),
    /// The entry mounts are absent, repeated, of another name form, or not
    /// in the registered spelling.
    #[error("the certificate does not name the site's entry mounts")]
    Mounts,
    /// The expected name could not be encoded.
    #[error("participant name encoding: {0}")]
    Encoding(String),
}

/// One address a site is entered at: an HTTPS origin and path, in the one
/// spelling it is registered, signed and compared in.
///
/// Two spellings of one address are two different mounts here, on purpose:
/// comparison is exact, so only the registered spelling ever matches and no
/// alternate encoding reaches another site's address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mount(String);

impl Mount {
    /// `text` as a mount: an `https` URL with a host, in the spelling a URL
    /// parser writes back (lowercase host, no default port, no dot segments),
    /// without user information, query or fragment, without a wildcard and
    /// without a trailing slash.
    pub fn parse(text: &str) -> Option<Self> {
        let url = url::Url::parse(text).ok()?;
        let plain = url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && !text.contains('*')
            && !text.ends_with('/');
        // A bare origin is written back with a root path; a mount has none.
        let written = url.as_str();
        let canonical = written == text || written.strip_suffix('/') == Some(text);
        (plain && canonical).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The address of `route` (an absolute path) at this mount.
    pub fn at(&self, route: &str) -> String {
        format!("{}{route}", self.0)
    }
}

impl std::fmt::Display for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a participant certificate states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// The registered organization.
    pub organization: uuid::Uuid,
    /// The registered site of that organization.
    pub site: uuid::Uuid,
    /// The addresses this site may be entered at.
    pub mounts: Vec<Mount>,
}

impl Participant {
    /// Whether this site may be entered at `mount`: only at exactly one of
    /// the addresses its certificate lists. The same host with another port
    /// or path, or a path that merely begins the same, is another address.
    pub fn admits(&self, mount: &Mount) -> bool {
        self.mounts.contains(mount)
    }
}

/// The subject of site `site` of `organization`.
pub fn participant_subject(
    organization: uuid::Uuid,
    site: uuid::Uuid,
) -> Result<Name, ParticipantError> {
    Name::from_str(&format!("CN={site},O={organization}"))
        .map_err(|e| ParticipantError::Encoding(e.to_string()))
}

/// What `certificate` states as a participant under `profile`: its subject
/// is exactly `CN=<SiteId>,O=<OrgId>`; it is a critical end entity (RFC 5280
/// §4.2.1.9) whose critical key usage is `digitalSignature` alone
/// (§4.2.1.3); its extended key usage is the participant purpose and nothing
/// else (§4.2.1.12); and its subject alternative name lists only URIs
/// (§4.2.1.6), each a [`Mount`], at least one and none twice.
pub fn read_participant(
    profile: &PurposeProfile,
    certificate: &Certificate,
) -> Result<Participant, ParticipantError> {
    let tbs = certificate.tbs_certificate();
    let (organization, site) = site_of(tbs.subject())?;

    let end_entity = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|_| ParticipantError::Constraints)?
        .is_some_and(|(critical, c)| critical && !c.ca && c.path_len_constraint.is_none());
    if !end_entity {
        return Err(ParticipantError::Constraints);
    }
    let signs_only = tbs
        .get_extension::<KeyUsage>()
        .map_err(|_| ParticipantError::KeyUsage)?
        .is_some_and(|(critical, usage)| critical && usage.0 == KeyUsages::DigitalSignature);
    if !signs_only {
        return Err(ParticipantError::KeyUsage);
    }
    if !profile.is_participant(certificate)? {
        return Err(ParticipantError::Purpose);
    }

    let (_, names) = tbs
        .get_extension::<SubjectAltName>()
        .map_err(|_| ParticipantError::Mounts)?
        .ok_or(ParticipantError::Mounts)?;
    let mut mounts = Vec::with_capacity(names.0.len());
    for name in &names.0 {
        let GeneralName::UniformResourceIdentifier(uri) = name else {
            return Err(ParticipantError::Mounts);
        };
        let mount = Mount::parse(uri.as_str()).ok_or(ParticipantError::Mounts)?;
        if mounts.contains(&mount) {
            return Err(ParticipantError::Mounts);
        }
        mounts.push(mount);
    }
    if mounts.is_empty() {
        return Err(ParticipantError::Mounts);
    }
    Ok(Participant {
        organization,
        site,
        mounts,
    })
}

/// The subject alternative name listing `mounts`, as issuance writes it.
pub fn mounts_name(mounts: &[Mount]) -> Result<SubjectAltName, ParticipantError> {
    mounts
        .iter()
        .map(|mount| {
            Ia5String::new(mount.as_str())
                .map(GeneralName::UniformResourceIdentifier)
                .map_err(|e| ParticipantError::Encoding(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(SubjectAltName)
}

/// The label a site's key is published under, before the verified domain.
pub const KEY_RECORD_LABEL: &str = "_sid-fed";

/// The version tag of a key record.
const KEY_RECORD_VERSION: &str = "v=sid1";

/// The DNS name the site's key is published at under the verified domain
/// `domain`.
pub fn key_record_name(domain: &str) -> String {
    format!("{KEY_RECORD_LABEL}.{domain}")
}

/// The TXT value publishing the site's public key `public_key` (DER
/// `SubjectPublicKeyInfo`): `v=sid1; pubkey=<base64>`.
pub fn key_record(public_key: &[u8]) -> String {
    use base64::Engine;
    format!(
        "{KEY_RECORD_VERSION}; pubkey={}",
        base64::engine::general_purpose::STANDARD.encode(public_key)
    )
}

/// The public key a TXT value publishes; none when it is not exactly what
/// [`key_record`] writes. Whoever enrolls the site compares this key with
/// the one it is asked to certify: a record under a domain shows that the
/// domain's owner chose that key, and nothing more.
pub fn key_of_record(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let encoded = value
        .strip_prefix(KEY_RECORD_VERSION)?
        .strip_prefix("; pubkey=")?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    (!key.is_empty() && key_record(&key) == value).then_some(key)
}

/// The organization and site of a subject that is exactly what
/// [`participant_subject`] writes.
fn site_of(name: &Name) -> Result<(uuid::Uuid, uuid::Uuid), ParticipantError> {
    let text = name.to_string();
    let (site, organization) = text
        .strip_prefix("CN=")
        .and_then(|rest| rest.split_once(",O="))
        .ok_or(ParticipantError::Subject)?;
    let site = uuid::Uuid::parse_str(site).map_err(|_| ParticipantError::Subject)?;
    let organization =
        uuid::Uuid::parse_str(organization).map_err(|_| ParticipantError::Subject)?;
    // Only the canonical spelling is a participant subject: a name with
    // another attribute, order or identifier spelling is not one.
    if participant_subject(organization, site)? != *name {
        return Err(ParticipantError::Subject);
    }
    Ok((organization, site))
}

#[cfg(test)]
mod tests;
