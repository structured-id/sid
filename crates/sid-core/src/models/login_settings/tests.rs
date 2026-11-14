// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn settings(personal: bool, corporate: bool, sources: Vec<OrgId>) -> LoginSettings {
    LoginSettings {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        admitted_sources: AdmittedSources::try_from(sources).unwrap(),
        revision: 1,
    }
}

// Nothing is admitted until an administrator turns an admission on, and
// incoming federated sign-in is the OR of the two, with no third value.
// Bug prevented: a fresh installation admitting external identities, or
// one admission implying the other.
#[test]
fn federated_sign_in_is_the_or_of_two_independent_admissions() {
    let unset = LoginSettings::default();
    assert!(!unset.allow_personal_profiles && !unset.allow_foreign_corporate_profiles);
    assert!(unset.admitted_sources.as_slice().is_empty());
    assert_eq!(unset.revision, 0);
    for (personal, corporate) in [(false, false), (true, false), (false, true), (true, true)] {
        assert_eq!(
            settings(personal, corporate, Vec::new()).admits_federated_sign_in(),
            personal || corporate
        );
    }
}

// A Corporate Profile of another organization is admitted only when the kind
// is on and its organization is named. Bug prevented: the kind switch alone
// admitting every organization, or a named organization admitted with the
// kind off; the Personal switch deciding either way.
#[test]
fn a_corporate_profile_is_admitted_from_a_named_organization_only() {
    let (admitted, other) = (OrgId::generate(), OrgId::generate());
    for personal in [false, true] {
        let named = settings(personal, true, vec![admitted]);
        assert!(named.admits_corporate_of(admitted));
        assert!(!named.admits_corporate_of(other));
        // The kind is on and nobody is named: nobody is admitted.
        assert!(!settings(personal, true, Vec::new()).admits_corporate_of(admitted));
        // Named, with the kind off.
        assert!(!settings(personal, false, vec![admitted]).admits_corporate_of(admitted));
    }
}

// The origin is decided by the organization the accepted passport names and
// by nothing else, and each kind is admitted by its own setting. Bug
// prevented: the recipient's own Corporate Profile treated as an outside
// one (and refused by a closed switch), a Corporate Profile admitted by the
// Personal switch, or a Personal Profile admitted because an organization
// is named.
#[test]
fn an_origin_is_admitted_by_its_own_setting_only() {
    let (recipient, admitted, other) = (OrgId::generate(), OrgId::generate(), OrgId::generate());
    assert_eq!(Origin::of(None, recipient), Some(Origin::Personal));
    assert_eq!(Origin::of(Some(recipient), recipient), None);
    assert_eq!(
        Origin::of(Some(admitted), recipient),
        Some(Origin::Corporate(admitted))
    );

    let personal_only = settings(true, false, vec![admitted]);
    assert!(personal_only.admits(Origin::Personal));
    assert!(!personal_only.admits(Origin::Corporate(admitted)));

    let corporate_only = settings(false, true, vec![admitted]);
    assert!(!corporate_only.admits(Origin::Personal));
    assert!(corporate_only.admits(Origin::Corporate(admitted)));
    assert!(!corporate_only.admits(Origin::Corporate(other)));

    let nobody_named = settings(true, true, Vec::new());
    assert!(nobody_named.admits(Origin::Personal));
    assert!(!nobody_named.admits(Origin::Corporate(admitted)));
}

// The set has one form whatever order and repeats it was given in, so two
// equal sets compare and encode alike. Bug prevented: a compare-and-replace
// or a signed copy that differs by the order an administrator typed.
#[test]
fn the_set_is_sorted_and_counts_a_repeat_once() {
    let (a, b) = (OrgId::generate(), OrgId::generate());
    let one = AdmittedSources::try_from(vec![b, a, b]).unwrap();
    let other = AdmittedSources::try_from(vec![a, b]).unwrap();
    assert_eq!(one, other);
    assert_eq!(one.as_slice().len(), 2);
    assert!(one.as_slice().is_sorted());
    assert_eq!(AdmittedSources::from_bytes(&one.to_bytes()).unwrap(), one);
    assert_eq!(one.to_bytes().len(), 32);
}

// Bug prevented: an unbounded settings record, or stored bytes read as ids
// they are not.
#[test]
fn the_set_is_bounded_and_its_stored_form_is_checked() {
    let many: Vec<OrgId> = (0..=MAX_ADMITTED_SOURCES)
        .map(|_| OrgId::generate())
        .collect();
    assert_eq!(AdmittedSources::try_from(many), Err(TooManySources));
    assert_eq!(
        AdmittedSources::from_bytes(&[0u8; 17]),
        Err(MalformedSources)
    );
    // Sixteen zero bytes are the nil UUID, which is no organization id.
    assert_eq!(
        AdmittedSources::from_bytes(&[0u8; 16]),
        Err(MalformedSources)
    );
    assert_eq!(
        AdmittedSources::from_bytes(&[]).unwrap(),
        AdmittedSources::default()
    );
}
