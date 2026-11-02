// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// Stored names read back as the value written, and nothing else is accepted.
#[test]
fn stored_names_roundtrip() {
    for t in [
        OrgType::Family,
        OrgType::Community,
        OrgType::Commercial,
        OrgType::Government,
    ] {
        assert_eq!(t.as_str().parse::<OrgType>().unwrap(), t);
    }
    for s in [
        OrgStatus::PendingDns,
        OrgStatus::PendingClaim,
        OrgStatus::ActiveTrial,
        OrgStatus::Active,
        OrgStatus::Suspended,
        OrgStatus::Deprovisioning,
        OrgStatus::Deleted,
    ] {
        assert_eq!(s.as_str().parse::<OrgStatus>().unwrap(), s);
    }
    assert!("ce".parse::<OrgType>().is_err());
    assert!("".parse::<OrgStatus>().is_err());
}

/// A CE installation's organization is an active Community with the
/// instance domain as its canonical domain.
#[test]
fn implicit_community_is_active() {
    let org = Organization::implicit_community("id.sid.example.com");
    assert_eq!(org.org_type, OrgType::Community);
    assert_eq!(org.status, OrgStatus::Active);
    assert_eq!(org.canonical_domain, "id.sid.example.com");
}
