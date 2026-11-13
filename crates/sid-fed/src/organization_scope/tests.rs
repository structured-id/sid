// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_certificates::{
    Stated, authority, extension, key, name, permits, read, signs_certificates,
};
use der::oid::AssociatedOid;

const ORGANIZATION: uuid::Uuid = uuid::Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0a0a);
const OTHER: uuid::Uuid = uuid::Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0c0c);

fn subject(organization: uuid::Uuid) -> String {
    format!("O={organization}")
}

/// An authority named `subject` with the name constraints `constraints`.
fn scoped(subject: &str, constraints: Option<x509_cert::ext::Extension>) -> Certificate {
    let mut extensions = vec![authority(Some(0)), signs_certificates()];
    extensions.extend(constraints);
    read(&Stated::new(subject, extensions).signed(&key(2), &name("CN=Intermediate"), &key(1)))
}

// An organization's authority is one whose subject is the organization and
// whose critical name constraint permits exactly the organization's subtree.
// Bug prevented: passports of organization A accepted under an authority
// named for B, or under one whose constraint was left out, made advisory,
// broadened to a second subtree or paired with an exclusion.
#[test]
fn only_an_exactly_scoped_authority_is_the_organizations() {
    let own = subject(ORGANIZATION);
    let exact = scoped(&own, Some(permits(&[&own], true)));
    assert_eq!(check_organization_scope(&exact, ORGANIZATION), Ok(()));
    // The same certificate is not another organization's.
    assert_eq!(
        check_organization_scope(&exact, OTHER),
        Err(ScopeError::Subject)
    );

    let named_otherwise = scoped(&format!("CN=Authority,{own}"), Some(permits(&[&own], true)));
    assert_eq!(
        check_organization_scope(&named_otherwise, ORGANIZATION),
        Err(ScopeError::Subject)
    );

    for (constraints, why) in [
        (None, "no constraint"),
        (Some(permits(&[&own], false)), "not critical"),
        (
            Some(permits(&[&subject(OTHER)], true)),
            "another organization's subtree",
        ),
        (
            Some(permits(&[&own, &subject(OTHER)], true)),
            "a second subtree",
        ),
        (
            Some(permits(&[&format!("OU=Unit,{own}")], true)),
            "a narrower subtree is not the organization's",
        ),
        (
            Some(extension(
                NameConstraints::OID,
                true,
                &NameConstraints {
                    permitted_subtrees: Some(vec![GeneralSubtree {
                        base: GeneralName::DirectoryName(name(&own)),
                        minimum: 0,
                        maximum: None,
                    }]),
                    excluded_subtrees: Some(vec![GeneralSubtree {
                        base: GeneralName::DirectoryName(name(&format!("OU=Unit,{own}"))),
                        minimum: 0,
                        maximum: None,
                    }]),
                },
            )),
            "an exclusion",
        ),
    ] {
        assert_eq!(
            check_organization_scope(&scoped(&own, constraints), ORGANIZATION),
            Err(ScopeError::Constraints),
            "{why}"
        );
    }
}
