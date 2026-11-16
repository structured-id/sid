// SPDX-License-Identifier: AGPL-3.0-only
use std::time::{Duration, SystemTime};

use der::oid::AssociatedOid;
use p256::ecdsa::SigningKey;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};

use super::*;
use crate::participant::{mounts_name, participant_subject};
use crate::passport_path::Classical;
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{
    Stated, authority, current, extension, key, name, purposes, signs, signs_certificates,
};

const ROOT: u8 = 1;
const INTERMEDIATE: u8 = 2;
const SITE: u8 = 5;
const NEIGHBOUR: u8 = 6;

const ROOT_NAME: &str = "CN=SID Root";
const INTERMEDIATE_NAME: &str = "CN=SID Platform Intermediate";

const MOUNT: &str = "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef";
const NEIGHBOUR_MOUNT: &str = "https://hosted.sid.example.com/i/fedcba9876543210fedcba9876543210";

fn organization() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0b0b)
}

fn site() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0c0c)
}

fn source(n: u128) -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_a000 + n)
}

fn intermediate() -> Vec<u8> {
    Stated {
        subject: name(INTERMEDIATE_NAME),
        serial: 2,
        validity: current(),
        extensions: vec![
            authority(Some(1)),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
        ],
    }
    .signed(&key(INTERMEDIATE), &name(ROOT_NAME), &key(ROOT))
}

fn participant_extensions(mounts: &[&str]) -> Vec<Extension> {
    let mounts: Vec<Mount> = mounts.iter().map(|m| Mount::parse(m).unwrap()).collect();
    vec![
        extension(
            BasicConstraints::OID,
            true,
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        ),
        signs(),
        purposes(&[DEVELOPMENT_PURPOSES.federation_participant]),
        extension(SubjectAltName::OID, false, &mounts_name(&mounts).unwrap()),
    ]
}

/// The participant certificate of site `site` of `organization`, with the
/// key of `seed`, entered at `mounts`.
fn enrolled(organization: Uuid, site: Uuid, seed: u8, mounts: &[&str]) -> Vec<u8> {
    Stated {
        subject: participant_subject(organization, site).unwrap(),
        serial: 11,
        validity: current(),
        extensions: participant_extensions(mounts),
    }
    .signed(&key(seed), &name(INTERMEDIATE_NAME), &key(INTERMEDIATE))
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// What the site states at [`MOUNT`]: other organizations' employees
/// admitted from sources 1 and 2, good for an hour around now.
fn stated() -> Admission {
    Admission {
        recipient_org: organization(),
        site: site(),
        mount: Mount::parse(MOUNT).unwrap(),
        revision: 7,
        allow_personal_profiles: false,
        allow_foreign_corporate_profiles: true,
        admitted_sources: vec![source(1), source(2)],
        not_before: now() - 3600,
        not_after: now() + 3600,
        certificate: enrolled(organization(), site(), SITE, &[MOUNT]),
        chain: vec![],
    }
}

/// `payload` under the signature of the key of `seed`.
fn signed_by(payload: &[u8], seed: u8) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let key: SigningKey = key(seed);
    sealed(payload, |input| {
        let signature: p256::ecdsa::Signature = key.sign(input);
        Ok::<_, std::convert::Infallible>(signature.to_bytes().into())
    })
    .unwrap()
}

fn verify(jws: &[u8]) -> Result<VerifiedAdmission, AdmissionError> {
    verify_admission(
        &Classical,
        &DEVELOPMENT_PURPOSES,
        jws,
        &[intermediate()],
        SystemTime::now(),
    )
}

// A site's statement is accepted as that site's own: what it states is what
// is read back, the site is the one its certificate enrolls, and exactly the
// named organizations are admitted. Bug prevented: a verifier reading a
// different admission than the site signed, or admitting an organization the
// statement does not name.
#[test]
fn a_sites_statement_is_accepted_as_its_own() {
    let admission = stated();
    let verified = verify(&signed_by(&admission.payload(), SITE)).unwrap();
    assert_eq!(verified.admission, admission);
    assert_eq!(
        verified.participant.participant.organization,
        organization()
    );
    assert_eq!(verified.participant.participant.site, site());
    assert!(verified.admission.admits_source(source(1)));
    assert!(verified.admission.admits_source(source(2)));
    assert!(!verified.admission.admits_source(source(3)));
    assert_eq!(Admission::read(&admission.payload()), Ok(admission));
}

// Removing an organization, an empty set and the switch turned off are each
// a different, unambiguous statement: the removed organization is no longer
// admitted, an empty set admits none, and with the switch off a listed
// organization is not admitted either. Bug prevented: an omitted source
// read as "unchanged", or a list outliving the switch that enables it.
#[test]
fn the_set_of_sources_is_complete() {
    let full = stated();
    let removed = Admission {
        admitted_sources: vec![source(2)],
        revision: 8,
        ..full.clone()
    };
    let none = Admission {
        admitted_sources: vec![],
        revision: 9,
        ..full.clone()
    };
    let off = Admission {
        allow_foreign_corporate_profiles: false,
        revision: 10,
        ..full.clone()
    };
    for (statement, admitted) in [
        (&full, [true, true]),
        (&removed, [false, true]),
        (&none, [false, false]),
        (&off, [false, false]),
    ] {
        let verified = verify(&signed_by(&statement.payload(), SITE)).unwrap();
        assert_eq!(
            [
                verified.admission.admits_source(source(1)),
                verified.admission.admits_source(source(2)),
            ],
            admitted,
            "revision {}",
            statement.revision
        );
    }
    assert_ne!(full.payload(), removed.payload());
    assert_ne!(none.payload(), off.payload());
}

// A genuine site cannot speak for an entry its certificate does not list:
// its neighbour's on the same host, the same host on another port, its bare
// host, or a path under its own. Nor for another site or organization. Bug
// prevented: a hosted site redirecting another site's arrivals to itself, or
// naming itself the entry of an organization it does not belong to.
#[test]
fn a_site_speaks_only_for_its_own_entries() {
    for elsewhere in [
        NEIGHBOUR_MOUNT,
        "https://hosted.sid.example.com:8443/i/0123456789abcdef0123456789abcdef",
        "https://hosted.sid.example.com",
        "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef/x",
    ] {
        let claimed = Admission {
            mount: Mount::parse(elsewhere).unwrap(),
            ..stated()
        };
        assert_eq!(
            verify(&signed_by(&claimed.payload(), SITE)),
            Err(AdmissionError::Scope("entry mounts")),
            "{elsewhere}"
        );
    }
    let other_site = Admission {
        site: Uuid::from_u128(1),
        ..stated()
    };
    assert_eq!(
        verify(&signed_by(&other_site.payload(), SITE)),
        Err(AdmissionError::Scope("site"))
    );
    let other_organization = Admission {
        recipient_org: source(1),
        ..stated()
    };
    assert_eq!(
        verify(&signed_by(&other_organization.payload(), SITE)),
        Err(AdmissionError::Scope("organization"))
    );

    // The neighbour's own certificate, which lists the neighbour's entry,
    // does speak for that entry, and only under the neighbour's key.
    let neighbour = Admission {
        site: Uuid::from_u128(2),
        mount: Mount::parse(NEIGHBOUR_MOUNT).unwrap(),
        certificate: enrolled(
            organization(),
            Uuid::from_u128(2),
            NEIGHBOUR,
            &[NEIGHBOUR_MOUNT],
        ),
        ..stated()
    };
    assert!(verify(&signed_by(&neighbour.payload(), NEIGHBOUR)).is_ok());
    assert_eq!(
        verify(&signed_by(&neighbour.payload(), SITE)),
        Err(AdmissionError::Envelope(PresentationError::Signature))
    );
}

// The statement is signed by the enrolled key, over the exact bytes, as this
// kind of statement, and within its time. Another key, altered bytes, a
// holder's sign-in proof envelope carrying the same bytes, and a statement
// before or after its time are refused. Bug prevented: an altered source
// set accepted under the original signature, a signature made for another
// purpose replayed as an admission, or an old statement accepted forever.
#[test]
fn only_the_signed_statement_in_its_time_is_accepted() {
    let admission = stated();
    let genuine = signed_by(&admission.payload(), SITE);
    assert_eq!(
        verify(&signed_by(&admission.payload(), NEIGHBOUR)),
        Err(AdmissionError::Envelope(PresentationError::Signature))
    );

    // The same signature over a statement that admits one more source.
    let widened = Admission {
        admitted_sources: vec![source(1), source(2), source(3)],
        ..admission.clone()
    };
    let mut altered: Value = serde_json::from_slice(&genuine).unwrap();
    altered["payload"] = json!(URL_SAFE_NO_PAD.encode(widened.payload()));
    assert_eq!(
        verify(&serde_json::to_vec(&altered).unwrap()),
        Err(AdmissionError::Envelope(PresentationError::Signature))
    );

    // The same bytes in the envelope of another kind of statement.
    let mut retyped: Value = serde_json::from_slice(&genuine).unwrap();
    retyped["signatures"][0]["protected"] = json!(
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": ES256,
                "typ": crate::presentation::PRESENTATION_TYP,
            }))
            .unwrap()
        )
    );
    assert_eq!(
        verify(&serde_json::to_vec(&retyped).unwrap()),
        Err(AdmissionError::Envelope(PresentationError::Envelope(
            "of another type"
        )))
    );
    assert!(matches!(
        Envelope::parse(&genuine),
        Err(PresentationError::Envelope("of another type"))
    ));

    for (not_before, not_after) in [(now() + 600, now() + 3600), (now() - 3600, now() - 600)] {
        let untimely = Admission {
            not_before,
            not_after,
            ..admission.clone()
        };
        assert_eq!(
            verify(&signed_by(&untimely.payload(), SITE)),
            Err(AdmissionError::Time)
        );
    }

    // A statement whose certificate no admitted intermediate signed.
    assert!(matches!(
        verify_admission(
            &Classical,
            &DEVELOPMENT_PURPOSES,
            &genuine,
            &[],
            SystemTime::now() + Duration::from_secs(1),
        ),
        Err(AdmissionError::Path(PathError::NoAnchor))
    ));
}

// The one spelling is the same in every build: its members stand in the
// order of their names, whatever map serde_json is built with. Bug
// prevented: the order followed serde_json's `preserve_order` feature,
// which another crate in a host's build can switch on, so a CE signer and
// a platform verifier built apart spelled one statement two ways and every
// genuine statement was refused as not in its one spelling. Run also with
// `--features serde_json/preserve_order`.
#[test]
fn the_spelling_does_not_follow_the_map_build() {
    let payload = String::from_utf8(stated().payload()).unwrap();
    let mut names = Vec::new();
    let mut rest = payload.as_str();
    while let Some(start) = rest.find("\":") {
        let before = &rest[..start];
        names.push(before[before.rfind('"').unwrap() + 1..].to_owned());
        rest = &rest[start + 2..];
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names.len(), 13, "{payload}");
    assert_eq!(names, sorted, "{payload}");
}

// A statement has one spelling and exactly its members. Sources out of
// order or repeated, an unknown member, another type, version or purpose,
// spacing, and a missing certificate are refused. Bug prevented: two
// documents with the same revision read as the same admission while stating
// different things, or a member the verifier cannot check riding along.
#[test]
fn a_statement_has_one_spelling() {
    let admission = stated();
    let document = || -> Value { serde_json::from_slice(&admission.payload()).unwrap() };
    let refused = |document: Value, why: &'static str| {
        assert_eq!(
            Admission::read(&serde_json::to_vec(&document).unwrap()),
            Err(AdmissionError::Statement(why)),
            "{why}"
        );
    };
    let (one, two) = (source(1).to_string(), source(2).to_string());

    let mut unordered = document();
    unordered["admitted_sources"] = json!([two, one]);
    refused(unordered, "with sources out of order or repeated");
    let mut repeated = document();
    repeated["admitted_sources"] = json!([one, one]);
    refused(repeated, "with sources out of order or repeated");
    let mut upper = document();
    upper["admitted_sources"] = json!([one.to_uppercase()]);
    refused(upper, "with a source that is not an organization");
    let mut extra = document();
    extra["roles"] = json!(["admin"]);
    refused(extra, "not exactly the version 1 members");
    let mut missing = document();
    missing.as_object_mut().unwrap().remove("not_after");
    refused(missing, "not exactly the version 1 members");
    for (member, value, why) in [
        ("type", json!("SIDBindingPresentation"), "of another type"),
        ("version", json!(2), "of another version"),
        ("purpose", json!("authentication"), "for another purpose"),
        (
            "mount",
            json!("https://hosted.sid.example.com/"),
            "without an entry mount",
        ),
        ("revision", json!(-1), "without an exact integer revision"),
        (
            "revision",
            json!(1u64 << 53),
            "without an exact integer revision",
        ),
        (
            "allow_personal_profiles",
            json!("false"),
            "without its admission switches",
        ),
        ("not_before", json!(1.5), "without exact integer times"),
        ("x5c", json!([]), "without a site certificate"),
    ] {
        let mut changed = document();
        changed[member] = value;
        refused(changed, why);
    }
    let mut inverted = document();
    inverted["not_before"] = json!(admission.not_after + 1);
    refused(inverted, "with an empty time");

    // The same statement with spacing is not that statement.
    let spaced = serde_json::to_vec_pretty(&document()).unwrap();
    assert_eq!(
        Admission::read(&spaced),
        Err(AdmissionError::Statement("not in its one spelling"))
    );
    let too_many: Vec<Uuid> = (0..=MAX_SOURCES as u128).map(source).collect();
    let crowded = Admission {
        admitted_sources: too_many,
        ..admission.clone()
    };
    assert_eq!(
        Admission::read(&crowded.payload()),
        Err(AdmissionError::Statement("without its admitted sources"))
    );
}
