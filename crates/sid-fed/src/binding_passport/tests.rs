// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_certificates::{Stated, extension, key, name, purposes, read, signs};

const PROFILE: PassportProfile = DEVELOPMENT_PASSPORT;

fn stated(source_org: Option<uuid::Uuid>) -> Passport {
    Passport {
        binding_id: uuid::Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_8d9e),
        source_org,
        recipient_org: uuid::Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0b0b),
        merkle_root: [7; 32],
        instance_id: "instance.sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa2,
    }
}

/// The extensions of `passport` as a certificate carries them, after `edit`.
fn extensions(passport: &Passport, edit: impl FnOnce(&mut Vec<Extension>)) -> Vec<Extension> {
    let mut all = vec![signs(), purposes(&[PROFILE.key_usage])];
    all.extend(passport.extensions(&PROFILE).unwrap());
    edit(&mut all);
    all
}

/// The certificate of `subject` with `extensions`, issued by some authority.
fn certified(subject: &Name, extensions: Vec<Extension>) -> Certificate {
    let stated = Stated {
        subject: subject.clone(),
        serial: 9,
        validity: crate::test_certificates::current(),
        extensions,
    };
    read(&stated.signed(&key(2), &name("CN=Authority"), &key(1)))
}

fn passport_of(passport: &Passport) -> Certificate {
    certified(&passport.subject().unwrap(), extensions(passport, |_| {}))
}

// What is written is what is read: a Personal passport names no source
// organization, a Corporate one names it in its subject, and both keep their
// BindingId, recipient, root, instance and assurance. Bug prevented: a
// reader and a writer of the format drifting apart, or the source
// organization of a Corporate passport being lost or invented.
#[test]
fn a_passport_reads_back_as_stated() {
    let source = uuid::Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0a0a);
    for passport in [stated(None), stated(Some(source))] {
        let read = Passport::read(&PROFILE, &passport_of(&passport)).unwrap();
        assert_eq!(read, passport);
    }
    assert_eq!(
        stated(Some(source)).subject().unwrap().to_string(),
        format!(
            "CN={},OU=Pairwise Binding,O={source}",
            stated(None).binding_id
        )
    );
}

// A certificate is a passport only when its extended key usage names the
// passport purpose. Bug prevented: any certificate of the same authority
// (a TLS one, an authority's own) taken as somebody's passport.
#[test]
fn only_a_certificate_certified_as_a_passport_is_one() {
    let passport = stated(None);
    let subject = passport.subject().unwrap();
    let without = extensions(&passport, |all| {
        all.retain(|e| e.extn_id != ExtendedKeyUsage::OID)
    });
    assert_eq!(
        Passport::read(&PROFILE, &certified(&subject, without)),
        Err(PassportError::NotPassport)
    );
    let other_purpose = extensions(&passport, |all| {
        all.retain(|e| e.extn_id != ExtendedKeyUsage::OID);
        all.push(purposes(&[ObjectIdentifier::new_unwrap(
            "1.3.6.1.5.5.7.3.2",
        )]));
    });
    assert_eq!(
        Passport::read(&PROFILE, &certified(&subject, other_purpose)),
        Err(PassportError::NotPassport)
    );
}

// Each of the four extensions is required once, non-critical, in its exact
// encoding: a missing, repeated, critical or wrongly sized one refuses the
// passport and names the extension. Bug prevented: a recipient of 15 octets
// or a root of 31 read as some value, a second recipient extension ignored.
#[test]
fn each_extension_is_required_once_in_its_encoding() {
    let passport = stated(None);
    let subject = passport.subject().unwrap();
    let refused = |edit: &dyn Fn(&mut Vec<Extension>)| {
        Passport::read(
            &PROFILE,
            &certified(&subject, extensions(&passport, |all| edit(all))),
        )
        .unwrap_err()
    };
    for oid in [
        PROFILE.recipient_org,
        PROFILE.merkle_root,
        PROFILE.instance_id,
        PROFILE.assurance_level,
    ] {
        assert_eq!(
            refused(&|all| all.retain(|e| e.extn_id != oid)),
            PassportError::Missing(oid)
        );
        assert_eq!(
            refused(&|all| {
                let again = all.iter().find(|e| e.extn_id == oid).unwrap().clone();
                all.push(again);
            }),
            PassportError::Duplicate(oid)
        );
        assert_eq!(
            refused(&|all| all.iter_mut().find(|e| e.extn_id == oid).unwrap().critical = true),
            PassportError::Critical(oid)
        );
    }
    let replaced = |oid: ObjectIdentifier, value: Extension| {
        refused(&|all| {
            all.retain(|e| e.extn_id != oid);
            all.push(value.clone());
        })
    };
    let octets = |len: usize| OctetString::new(vec![1u8; len]).unwrap();
    assert_eq!(
        replaced(
            PROFILE.recipient_org,
            extension(PROFILE.recipient_org, false, &octets(15))
        ),
        PassportError::Malformed(PROFILE.recipient_org)
    );
    assert_eq!(
        replaced(
            PROFILE.merkle_root,
            extension(PROFILE.merkle_root, false, &octets(31))
        ),
        PassportError::Malformed(PROFILE.merkle_root)
    );
    assert_eq!(
        replaced(
            PROFILE.instance_id,
            extension(PROFILE.instance_id, false, &String::new())
        ),
        PassportError::Malformed(PROFILE.instance_id)
    );
    assert_eq!(
        replaced(
            PROFILE.assurance_level,
            extension(PROFILE.assurance_level, false, &octets(1))
        ),
        PassportError::Malformed(PROFILE.assurance_level)
    );
}

// One BindingId has exactly one subject: `CN=<id>,OU=Pairwise Binding`,
// then `O=<org>` for a Corporate Binding, in that spelling only. Bug
// prevented: a second certificate for the same Binding under a differently
// spelled name, or an organization read from a name that is not the form.
#[test]
fn only_the_canonical_subject_is_a_binding() {
    let passport = stated(None);
    let id = passport.binding_id;
    for wrong in [
        format!("CN={id}"),
        format!("CN={id},OU=Other Unit"),
        format!("CN={},OU=Pairwise Binding", id.simple()),
        format!("CN={},OU=Pairwise Binding", id.to_string().to_uppercase()),
        "CN=not-a-uuid,OU=Pairwise Binding".to_owned(),
        format!("CN={id},OU=Pairwise Binding,O=acme.example"),
        format!("CN={id},OU=Pairwise Binding,C=NL"),
        format!("OU=Pairwise Binding,CN={id}"),
    ] {
        let certificate = certified(&name(&wrong), extensions(&passport, |_| {}));
        assert_eq!(
            Passport::read(&PROFILE, &certificate),
            Err(PassportError::Subject),
            "{wrong}"
        );
    }
}

// Production has no allocation, and a profile other than the development
// one refuses a certificate carrying development identifiers, in an
// extension or in its key usage. An empty instance is not written. Bug
// prevented: a development passport accepted by an installation that is not
// a development one.
#[test]
fn a_development_passport_stays_in_development() {
    assert_eq!(
        PassportProfile::of(ContextAllocation::Development),
        Ok(DEVELOPMENT_PASSPORT)
    );
    assert_eq!(
        PassportProfile::of(ContextAllocation::Production),
        Err(PassportError::NoAllocation)
    );
    let oid = |last: u32| ObjectIdentifier::new_unwrap(&format!("1.3.6.1.4.1.99999.2.{last}"));
    let registered = PassportProfile {
        key_usage: oid(1),
        recipient_org: oid(2),
        merkle_root: oid(3),
        instance_id: oid(4),
        assurance_level: oid(5),
    };
    let passport = stated(None);
    assert_eq!(
        Passport::read(&registered, &passport_of(&passport)),
        Err(PassportError::DevelopmentPassport)
    );
    // Its own identifiers with the development key usage beside them.
    let mut mixed = vec![
        signs(),
        purposes(&[registered.key_usage, PROFILE.key_usage]),
    ];
    mixed.extend(passport.extensions(&registered).unwrap());
    assert_eq!(
        Passport::read(&registered, &certified(&passport.subject().unwrap(), mixed)),
        Err(PassportError::DevelopmentPassport)
    );
    let unnamed = Passport {
        instance_id: String::new(),
        ..passport
    };
    assert_eq!(unnamed.extensions(&PROFILE), Err(PassportError::InstanceId));
}
