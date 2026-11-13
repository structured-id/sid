// SPDX-License-Identifier: AGPL-3.0-only
use std::time::{Duration, SystemTime};

use uuid::Uuid;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::time::Validity;

use super::*;
use crate::binding_passport::{AssuranceLevel, DEVELOPMENT_PASSPORT};
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{
    Stated, authority, current, key, name, permits, purposes, read as decoded, signs,
    signs_certificates, valid,
};

const ROOT: u8 = 1;
const INTERMEDIATE: u8 = 2;
const ORGANIZATION: u8 = 3;
const HOLDER: u8 = 4;

const ROOT_NAME: &str = "CN=SID Root";
const INTERMEDIATE_NAME: &str = "CN=SID Platform Intermediate";

const DAY: Duration = Duration::from_secs(86_400);
const HOUR: Duration = Duration::from_secs(3_600);

fn source() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0a0a)
}

fn recipient() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0b0b)
}

fn root() -> Vec<u8> {
    Stated::new(ROOT_NAME, vec![authority(None), signs_certificates()]).self_signed(&key(ROOT))
}

/// The platform intermediate under the Root, with `path_len` and `validity`.
fn intermediate(path_len: Option<u8>, validity: Validity) -> Vec<u8> {
    Stated {
        subject: name(INTERMEDIATE_NAME),
        serial: 2,
        validity,
        extensions: vec![
            authority(path_len),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
        ],
    }
    .signed(&key(INTERMEDIATE), &name(ROOT_NAME), &key(ROOT))
}

/// The extensions of an authority scoped exactly to `organization`.
fn scoped(organization: Uuid) -> Vec<Extension> {
    vec![
        authority(Some(0)),
        signs_certificates(),
        purposes(&[DEVELOPMENT_PURPOSES.organization_ca]),
        permits(&[&format!("O={organization}")], true),
    ]
}

/// The authority of `organization` under the platform intermediate.
fn organization_ca(organization: Uuid, extensions: Vec<Extension>, validity: Validity) -> Vec<u8> {
    Stated {
        subject: name(&format!("O={organization}")),
        serial: 3,
        validity,
        extensions,
    }
    .signed(
        &key(ORGANIZATION),
        &name(INTERMEDIATE_NAME),
        &key(INTERMEDIATE),
    )
}

fn stated(source_org: Option<Uuid>) -> Passport {
    Passport {
        binding_id: Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_8d9e),
        source_org,
        recipient_org: recipient(),
        merkle_root: [7; 32],
        instance_id: "instance.sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa2,
    }
}

/// The certificate of `passport`, signed by `issuer_key` under `issuer`.
fn issued(passport: &Passport, validity: Validity, issuer: &Name, issuer_key: u8) -> Vec<u8> {
    let mut extensions = vec![signs(), purposes(&[DEVELOPMENT_PASSPORT.key_usage])];
    extensions.extend(passport.extensions(&DEVELOPMENT_PASSPORT).unwrap());
    Stated {
        subject: passport.subject().unwrap(),
        serial: 9,
        validity,
        extensions,
    }
    .signed(&key(HOLDER), issuer, &key(issuer_key))
}

/// A Corporate passport of the source organization, under its authority.
fn corporate(validity: Validity) -> Vec<u8> {
    issued(
        &stated(Some(source())),
        validity,
        &name(&format!("O={}", source())),
        ORGANIZATION,
    )
}

fn owned(certificates: &[&[u8]]) -> Vec<Vec<u8>> {
    certificates.iter().map(|der| der.to_vec()).collect()
}

fn accept(
    certificate: &[u8],
    chain: &[&[u8]],
    anchors: &[&[u8]],
    at: SystemTime,
) -> Result<AcceptedPassport, PathError> {
    accept_passport(
        &Classical,
        &DEVELOPMENT_PASSPORT,
        &DEVELOPMENT_PURPOSES,
        certificate,
        &owned(chain),
        &owned(anchors),
        recipient(),
        at,
    )
}

fn not_after_of(der: &[u8]) -> SystemTime {
    decoded(der)
        .tbs_certificate()
        .validity()
        .not_after
        .to_system_time()
}

// A Corporate passport under its organization's scoped authority is accepted
// over the complete path to the platform intermediate, whatever the holder
// presents above it, and reads back to what was issued. The acceptance holds
// until the first end of validity on the path and not past it. Bug
// prevented: a recipient that reads a certificate without following its
// signatures, or reuses the result after a certificate it rests on ended.
#[test]
fn a_corporate_passport_is_accepted_to_its_platform_intermediate() {
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), current());
    let passport = corporate(valid(DAY, HOUR));
    let now = SystemTime::now();

    let root = root();
    let chains: [&[&[u8]]; 3] = [
        &[&authority],
        &[&authority, &anchor],
        &[&authority, &anchor, &root],
    ];
    for chain in chains {
        let accepted = accept(&passport, chain, &[&anchor], now).unwrap();
        assert_eq!(accepted.passport, stated(Some(source())));
        assert_eq!(accepted.issued(), Issued::CorporatePassport);
        assert_eq!(accepted.path.anchor, anchor);
        assert_eq!(accepted.path.issuers, vec![authority.clone()]);
        assert_eq!(accepted.until, not_after_of(&passport));
        assert!(accepted.until < not_after_of(&anchor));
    }
}

// The trust point is what the caller installs, and it is a platform
// intermediate. Bug prevented: a path that ends at whatever certificate the
// holder brought, or at an organization's own authority.
#[test]
fn the_trust_point_is_what_the_caller_installs() {
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), current());
    let passport = corporate(current());
    let now = SystemTime::now();

    assert_eq!(
        accept(&passport, &[&authority], &[], now),
        Err(PathError::NoAnchor)
    );
    // The organization's authority as the anchor: the signatures hold, and
    // it is not a platform intermediate.
    assert!(matches!(
        accept(&passport, &[], &[&authority], now),
        Err(PathError::Purpose(_))
    ));
    // Another intermediate, of another key, under the same name.
    let other = Stated::new(
        INTERMEDIATE_NAME,
        vec![
            crate::test_certificates::authority(Some(1)),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
        ],
    )
    .signed(&key(9), &name(ROOT_NAME), &key(ROOT));
    assert!(matches!(
        accept(&passport, &[&authority], &[&other], now),
        Err(PathError::Rejected(_))
    ));
    // One admitted anchor among several is enough.
    assert!(accept(&passport, &[&authority], &[&other, &anchor], now).is_ok());
}

// Only an organization's authority issues Corporate passports and only the
// platform intermediate Personal ones. Bug prevented: an authority with
// genuine signatures issuing what it has no business issuing.
#[test]
fn each_passport_has_its_issuer_role() {
    let anchor = intermediate(Some(1), current());
    let now = SystemTime::now();

    // A Personal passport the intermediate issued.
    let personal = issued(
        &stated(None),
        current(),
        &name(INTERMEDIATE_NAME),
        INTERMEDIATE,
    );
    let accepted = accept(&personal, &[], &[&anchor], now).unwrap();
    assert_eq!(accepted.issued(), Issued::PersonalPassport);
    assert!(accepted.path.issuers.is_empty());

    // A Corporate passport the intermediate issued directly.
    let direct = issued(
        &stated(Some(source())),
        current(),
        &name(INTERMEDIATE_NAME),
        INTERMEDIATE,
    );
    assert!(matches!(
        accept(&direct, &[], &[&anchor], now),
        Err(PathError::Purpose(_))
    ));

    // A Corporate passport under an authority naming no organization purpose.
    let mut unmarked = scoped(source());
    unmarked.retain(|e| {
        use der::oid::AssociatedOid;
        e.extn_id != x509_cert::ext::pkix::ExtendedKeyUsage::OID
    });
    let authority = organization_ca(source(), unmarked, current());
    assert!(matches!(
        accept(&corporate(current()), &[&authority], &[&anchor], now),
        Err(PathError::Purpose(_))
    ));

    // A Personal passport under an organization's authority: it names no
    // source organization, so it is outside that authority's names.
    let authority = organization_ca(source(), scoped(source()), current());
    let under_organization = issued(
        &stated(None),
        current(),
        &name(&format!("O={}", source())),
        ORGANIZATION,
    );
    assert!(accept(&under_organization, &[&authority], &[&anchor], now).is_err());
}

// A platform intermediate used as the trust point keeps its own validity.
// Bug prevented: an expired intermediate anchoring passports, since RFC 5280
// path processing does not apply an anchor's validity.
#[test]
fn an_expired_trust_point_anchors_nothing() {
    let long = valid(DAY, 10 * DAY);
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), long);
    let passport = corporate(long);
    let later = SystemTime::now() + 2 * DAY;

    assert!(accept(&passport, &[&authority], &[&anchor], SystemTime::now()).is_ok());
    assert_eq!(
        accept(&passport, &[&authority], &[&anchor], later),
        Err(PathError::Anchor("not valid at that time"))
    );
}

// The recipient extension scopes where the passport may be used. Bug
// prevented: a passport issued for one organization presented to another.
#[test]
fn another_recipient_refuses_the_passport() {
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), current());
    let refused = accept_passport(
        &Classical,
        &DEVELOPMENT_PASSPORT,
        &DEVELOPMENT_PURPOSES,
        &corporate(current()),
        &[authority],
        &[anchor],
        source(),
        SystemTime::now(),
    );
    assert_eq!(refused, Err(PathError::Recipient));
}

// A passport signed by a key that is not its issuer's, or past its validity,
// does not validate. Bug prevented: a certificate naming the right issuer
// accepted without that issuer's signature.
#[test]
fn a_forged_or_expired_passport_is_refused() {
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), current());
    let now = SystemTime::now();

    let forged = issued(
        &stated(Some(source())),
        current(),
        &name(&format!("O={}", source())),
        9,
    );
    assert!(matches!(
        accept(&forged, &[&authority], &[&anchor], now),
        Err(PathError::Rejected(_))
    ));

    let short = corporate(valid(DAY, HOUR));
    assert!(accept(&short, &[&authority], &[&anchor], now).is_ok());
    assert!(matches!(
        accept(&short, &[&authority], &[&anchor], now + 2 * HOUR),
        Err(PathError::Rejected(_))
    ));
}

// An organization's authority carries its organization's exact scope. Bug
// prevented: an authority with no name constraint, or another
// organization's, issuing a passport in the source organization's name;
// path processing applies a constraint it finds and does not require one.
#[test]
fn an_organization_ca_outside_the_source_scope_is_refused() {
    let anchor = intermediate(Some(1), current());
    let now = SystemTime::now();

    let mut unconstrained = scoped(source());
    unconstrained.retain(|e| {
        use der::oid::AssociatedOid;
        e.extn_id != x509_cert::ext::pkix::constraints::name::NameConstraints::OID
    });
    let authority = organization_ca(source(), unconstrained, current());
    assert!(matches!(
        accept(&corporate(current()), &[&authority], &[&anchor], now),
        Err(PathError::Purpose(_))
    ));

    // Another organization's authority, correctly scoped to itself, issuing
    // in the source organization's name.
    let other = recipient();
    let authority = organization_ca(other, scoped(other), current());
    let passport = issued(
        &stated(Some(source())),
        current(),
        &name(&format!("O={other}")),
        ORGANIZATION,
    );
    assert_eq!(
        accept(&passport, &[&authority], &[&anchor], now),
        Err(PathError::NameConstraints)
    );
}

fn accept_ca(
    certificate: &[u8],
    chain: &[&[u8]],
    anchors: &[&[u8]],
    organization: Uuid,
) -> Result<ValidatedPath, PathError> {
    accept_organization_ca(
        &Classical,
        &DEVELOPMENT_PURPOSES,
        certificate,
        &owned(chain),
        &owned(anchors),
        organization,
        SystemTime::now(),
    )
}

// An organization's authority is accepted on the same path: to an admitted
// platform intermediate, the Root optional, with its purpose and exact
// scope, for its own organization only. Bug prevented: an authority
// installed for an organization it was not issued to.
#[test]
fn an_organization_ca_is_accepted_to_its_platform_intermediate() {
    let anchor = intermediate(Some(1), current());
    let authority = organization_ca(source(), scoped(source()), current());

    let root = root();
    let chains: [&[&[u8]]; 3] = [&[], &[&anchor], &[&anchor, &root]];
    for chain in chains {
        let path = accept_ca(&authority, chain, &[&anchor], source()).unwrap();
        assert_eq!(path.anchor, anchor);
        assert!(path.issuers.is_empty());
    }
    assert!(matches!(
        accept_ca(&authority, &[], &[&anchor], recipient()),
        Err(PathError::Purpose(_))
    ));
}

// An organization's authority issues further, so the path lengths above it
// leave room for it, and its own key usage signs certificates. Bug
// prevented: an authority imported as an issuer although path processing,
// which counts and checks only what is above the target, accepted it.
#[test]
fn an_organization_ca_must_be_usable_as_an_issuer() {
    let authority = organization_ca(source(), scoped(source()), current());
    let tight = intermediate(Some(0), current());
    assert!(matches!(
        accept_ca(&authority, &[], &[&tight], source()),
        Err(PathError::Target(_))
    ));

    let anchor = intermediate(Some(1), current());
    let mut mute = scoped(source());
    mute.retain(|e| {
        use der::oid::AssociatedOid;
        e.extn_id != x509_cert::ext::pkix::KeyUsage::OID
    });
    mute.push(signs());
    let authority = organization_ca(source(), mute, current());
    assert_eq!(
        accept_ca(&authority, &[], &[&anchor], source()),
        Err(PathError::Target(
            "an authority not allowed to sign certificates"
        ))
    );
}
