// SPDX-License-Identifier: AGPL-3.0-only
use der::oid::AssociatedOid;
use x509_cert::ext::Extension;

use super::*;
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{Stated, authority, extension, key, purposes, read, signs};

const ORGANIZATION: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e";
const SITE: &str = "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9f";
const MOUNT: &str = "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef";

fn end_entity() -> Extension {
    extension(
        BasicConstraints::OID,
        true,
        &BasicConstraints {
            ca: false,
            path_len_constraint: None,
        },
    )
}

fn participant_purpose() -> Extension {
    purposes(&[DEVELOPMENT_PURPOSES.federation_participant])
}

fn entered_at(mounts: &[&str]) -> Extension {
    let names = mounts
        .iter()
        .map(|mount| GeneralName::UniformResourceIdentifier(Ia5String::new(mount).unwrap()))
        .collect();
    extension(SubjectAltName::OID, false, &SubjectAltName(names))
}

fn subject() -> String {
    format!("CN={SITE},O={ORGANIZATION}")
}

/// The certificate of `subject` with `extensions`, read under the
/// development profile.
fn stated(subject: &str, extensions: Vec<Extension>) -> Result<Participant, ParticipantError> {
    let certificate = read(&Stated::new(subject, extensions).self_signed(&key(1)));
    read_participant(&DEVELOPMENT_PURPOSES, &certificate)
}

fn well_formed() -> Vec<Extension> {
    vec![
        end_entity(),
        signs(),
        participant_purpose(),
        entered_at(&[MOUNT]),
    ]
}

/// The well-formed extensions with the one at `position` replaced by
/// `replacement`, or dropped when there is none.
fn with(position: usize, replacement: Option<Extension>) -> Vec<Extension> {
    let mut extensions = well_formed();
    match replacement {
        Some(extension) => extensions[position] = extension,
        None => {
            extensions.remove(position);
        }
    }
    extensions
}

// A certificate in the profile states its organization, its site and its
// entry mounts, and what issuance writes for them is what is read back. Bug
// prevented: an issuer and a verifier disagreeing on the subject or on the
// form the mounts are carried in.
#[test]
fn a_participant_states_its_site_and_mounts() {
    let other = "https://sid.example.com:8443";
    let read = stated(&subject(), with(3, Some(entered_at(&[MOUNT, other])))).unwrap();
    let (organization, site) = (
        uuid::Uuid::parse_str(ORGANIZATION).unwrap(),
        uuid::Uuid::parse_str(SITE).unwrap(),
    );
    assert_eq!(read.organization, organization);
    assert_eq!(read.site, site);
    assert_eq!(
        read.mounts,
        [Mount::parse(MOUNT).unwrap(), Mount::parse(other).unwrap()]
    );
    assert_eq!(
        participant_subject(organization, site).unwrap().to_string(),
        subject()
    );
    let written = extension(
        SubjectAltName::OID,
        false,
        &mounts_name(&read.mounts).unwrap(),
    );
    assert_eq!(stated(&subject(), with(3, Some(written))), Ok(read));
}

// A site is entered only at an address its certificate lists, compared
// exactly. Its neighbour on the same host, the same host on another port, a
// path that begins the same, a longer path under its own and its bare host
// are all other addresses. Bug prevented: a genuine site of a shared host
// claiming another site's address because the host names match.
#[test]
fn a_site_is_entered_only_at_its_own_mounts() {
    let site = stated(&subject(), well_formed()).unwrap();
    assert!(site.admits(&Mount::parse(MOUNT).unwrap()));
    for elsewhere in [
        "https://hosted.sid.example.com/i/fedcba9876543210fedcba9876543210",
        "https://hosted.sid.example.com:8443/i/0123456789abcdef0123456789abcdef",
        "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef0",
        "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef/x",
        "https://hosted.sid.example.com/i",
        "https://hosted.sid.example.com",
        "https://other.sid.example.com/i/0123456789abcdef0123456789abcdef",
    ] {
        let mount = Mount::parse(elsewhere).expect(elsewhere);
        assert!(!site.admits(&mount), "{elsewhere}");
    }
    assert_eq!(
        Mount::parse(MOUNT).unwrap().at("/auth/federation/callback"),
        format!("{MOUNT}/auth/federation/callback")
    );
}

// A mount has one spelling. Another scheme, user information, a query, a
// fragment, a wildcard, a trailing slash, an upper-case host, a written
// default port, dot segments and a relative reference are not mounts. Bug
// prevented: a second spelling of an address that compares unequal to the
// registered one yet is routed to the same or to another site.
#[test]
fn a_mount_has_one_spelling() {
    for mount in [
        MOUNT,
        "https://sid.example.com",
        "https://sid.example.com:8443",
        "https://sid.example.com:8443/tenant",
    ] {
        assert_eq!(
            Mount::parse(mount).map(|m| m.to_string()).as_deref(),
            Some(mount)
        );
    }
    for refused in [
        "http://sid.example.com",
        "https://user@sid.example.com",
        "https://user:secret@sid.example.com",
        "https://sid.example.com?x=1",
        "https://sid.example.com/i#part",
        "https://*.sid.example.com",
        "https://sid.example.com/*",
        "https://sid.example.com/",
        "https://sid.example.com/i/",
        "https://SID.example.com",
        "https://sid.example.com:443",
        "https://sid.example.com/a/../i",
        "https://sid.example.com/./i",
        "//sid.example.com/i",
        "/i",
        "sid.example.com",
        "",
    ] {
        assert_eq!(Mount::parse(refused), None, "{refused}");
    }
}

// The subject is exactly the site and the organization, each once, in that
// order and in canonical spelling. Bug prevented: a Binding Passport's
// subject, an organization authority's, or an ambiguous name read as a site.
#[test]
fn only_the_canonical_subject_is_a_site() {
    let upper = ORGANIZATION.to_uppercase();
    for refused in [
        format!("O={ORGANIZATION}"),
        format!("CN={SITE}"),
        format!("O={ORGANIZATION},CN={SITE}"),
        format!("CN={SITE},OU=Pairwise Binding,O={ORGANIZATION}"),
        format!("CN={SITE},O={ORGANIZATION},O={ORGANIZATION}"),
        format!("CN={SITE},O={ORGANIZATION},C=US"),
        format!("CN={SITE},O={upper}"),
        format!("CN=site,O={ORGANIZATION}"),
        format!("CN={SITE},O=Example"),
    ] {
        assert_eq!(
            stated(&refused, well_formed()),
            Err(ParticipantError::Subject),
            "{refused}"
        );
    }
}

// Each part of the profile is required as written: a critical end entity, a
// critical key usage of signing alone, the participant purpose alone, and
// mounts as URIs. Bug prevented: an authority, a TLS or client certificate,
// a certificate that may also sign certificates, one without any stated
// address or with a host name in place of an address, accepted as a site's
// enrollment.
#[test]
fn every_part_of_the_profile_is_required() {
    use x509_cert::ext::pkix::KeyUsages::{DigitalSignature, KeyCertSign, KeyEncipherment};
    let usage = |critical: bool, usages| extension(KeyUsage::OID, critical, &KeyUsage(usages));
    let not_critical = extension(
        BasicConstraints::OID,
        false,
        &BasicConstraints {
            ca: false,
            path_len_constraint: None,
        },
    );
    let server_auth = der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    let host = extension(
        SubjectAltName::OID,
        false,
        &SubjectAltName(vec![GeneralName::DnsName(
            Ia5String::new("hosted.sid.example.com").unwrap(),
        )]),
    );
    let mixed = extension(
        SubjectAltName::OID,
        false,
        &SubjectAltName(vec![
            GeneralName::UniformResourceIdentifier(Ia5String::new(MOUNT).unwrap()),
            GeneralName::DnsName(Ia5String::new("hosted.sid.example.com").unwrap()),
        ]),
    );
    let cases = [
        (with(0, None), ParticipantError::Constraints),
        (with(0, Some(not_critical)), ParticipantError::Constraints),
        (
            with(0, Some(authority(None))),
            ParticipantError::Constraints,
        ),
        (
            with(0, Some(authority(Some(0)))),
            ParticipantError::Constraints,
        ),
        (with(1, None), ParticipantError::KeyUsage),
        (
            with(1, Some(usage(false, DigitalSignature.into()))),
            ParticipantError::KeyUsage,
        ),
        (
            with(1, Some(usage(true, DigitalSignature | KeyCertSign))),
            ParticipantError::KeyUsage,
        ),
        (
            with(1, Some(usage(true, DigitalSignature | KeyEncipherment))),
            ParticipantError::KeyUsage,
        ),
        (with(2, None), ParticipantError::Purpose),
        (
            with(2, Some(purposes(&[server_auth]))),
            ParticipantError::Purpose,
        ),
        (
            with(
                2,
                Some(purposes(&[
                    DEVELOPMENT_PURPOSES.federation_participant,
                    server_auth,
                ])),
            ),
            ParticipantError::Purpose,
        ),
        (
            with(2, Some(purposes(&[DEVELOPMENT_PURPOSES.organization_ca]))),
            ParticipantError::Purpose,
        ),
        (with(3, None), ParticipantError::Mounts),
        (with(3, Some(entered_at(&[]))), ParticipantError::Mounts),
        (with(3, Some(host)), ParticipantError::Mounts),
        (with(3, Some(mixed)), ParticipantError::Mounts),
        (
            with(3, Some(entered_at(&[MOUNT, MOUNT]))),
            ParticipantError::Mounts,
        ),
        (
            with(3, Some(entered_at(&["https://hosted.sid.example.com/"]))),
            ParticipantError::Mounts,
        ),
        (
            with(3, Some(entered_at(&["https://*.sid.example.com"]))),
            ParticipantError::Mounts,
        ),
    ];
    for (position, (extensions, refusal)) in cases.into_iter().enumerate() {
        assert_eq!(
            stated(&subject(), extensions),
            Err(refusal),
            "case {position}"
        );
    }
}

// The key a site publishes is read back from exactly the record written
// for it, at the name under its verified domain. A record of another
// version, with spacing, padding, a token in place of a key or nothing
// after the tag publishes no key. Bug prevented: an enrollment certifying
// a key the domain's record does not state.
#[test]
fn a_key_record_publishes_exactly_its_key() {
    let key = vec![0x30, 0x59, 1, 2, 3, 4, 5];
    let record = key_record(&key);
    assert_eq!(record, "v=sid1; pubkey=MFkBAgMEBQ==");
    assert_eq!(key_of_record(&record), Some(key));
    assert_eq!(
        key_record_name("login.sid.example.com"),
        "_sid-fed.login.sid.example.com"
    );
    for refused in [
        "v=sid2; pubkey=MFkBAgMEBQ==",
        " v=sid1; pubkey=MFkBAgMEBQ==",
        "v=sid1;pubkey=MFkBAgMEBQ==",
        "v=sid1; pubkey=MFkBAgMEBQ== ",
        "v=sid1; pubkey=MFkBAgMEBQ",
        "v=sid1; pubkey=",
        "v=sid1; token=abc123",
        "v=sid1",
        "",
    ] {
        assert_eq!(key_of_record(refused), None, "{refused:?}");
    }
}

// A development participant is refused under any other allocation. Bug
// prevented: a development enrollment accepted by an installation that is
// not a development one.
#[test]
fn a_development_participant_stays_in_development() {
    let registered = PurposeProfile {
        federation_participant: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.6"),
        ..DEVELOPMENT_PURPOSES
    };
    let certificate = read(&Stated::new(&subject(), well_formed()).self_signed(&key(1)));
    assert_eq!(
        read_participant(&registered, &certificate),
        Err(ParticipantError::Allocation(
            PurposeError::DevelopmentPurpose
        ))
    );
}
