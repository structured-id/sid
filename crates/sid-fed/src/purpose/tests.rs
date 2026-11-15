// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_certificates::{Stated, authority, key, purposes, read};

fn holding(usages: Vec<x509_cert::ext::Extension>) -> Certificate {
    let mut extensions = vec![authority(None)];
    extensions.extend(usages);
    read(&Stated::new("CN=Authority", extensions).self_signed(&key(1)))
}

// The issuance transitions are exactly five: the platform intermediate
// issues organization authorities, Personal passports and the participant
// certificates of enrolled sites; an organization's authority issues its
// Corporate passports and an agent candidate authority. Bug prevented: a
// verifier accepting a certificate from an authority whose role does not
// issue it (an organization's authority minting a Personal passport or
// enrolling a site into the platform, an intermediate minting a Corporate
// passport, a chain of organization authorities).
#[test]
fn only_the_stated_transitions_are_issued() {
    use IssuerRole::{AgentMemberIssuer, OrganizationCa, PlatformIntermediate};
    let issued = [
        Issued::Ca(PlatformIntermediate),
        Issued::Ca(OrganizationCa),
        Issued::Ca(AgentMemberIssuer),
        Issued::PersonalPassport,
        Issued::CorporatePassport,
        Issued::FederationParticipant,
    ];
    let allowed = [
        (PlatformIntermediate, Issued::Ca(OrganizationCa)),
        (PlatformIntermediate, Issued::PersonalPassport),
        (PlatformIntermediate, Issued::FederationParticipant),
        (OrganizationCa, Issued::CorporatePassport),
        (OrganizationCa, Issued::Ca(AgentMemberIssuer)),
    ];
    for role in [PlatformIntermediate, OrganizationCa, AgentMemberIssuer] {
        for what in issued {
            assert_eq!(
                role.may_issue(what),
                allowed.contains(&(role, what)),
                "{role:?} -> {what:?}"
            );
        }
    }
}

// A certificate's roles are the SID purposes its extended key usage names:
// none without that extension or with only foreign purposes, each named one
// otherwise, and a leaf purpose is no issuer role. Bug prevented: an
// authority without a SID purpose, or a leaf credential, read as an issuer.
#[test]
fn roles_are_the_purposes_the_certificate_names() {
    let profile = DEVELOPMENT_PURPOSES;
    let server_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    assert_eq!(profile.issuer_roles(&holding(vec![])), Ok(vec![]));
    assert_eq!(
        profile.issuer_roles(&holding(vec![purposes(&[server_auth])])),
        Ok(vec![])
    );
    assert_eq!(
        profile.issuer_roles(&holding(vec![purposes(&[
            profile.key_association,
            profile.agent_part
        ])])),
        Ok(vec![])
    );
    for (oid, role) in [
        (
            profile.platform_intermediate,
            IssuerRole::PlatformIntermediate,
        ),
        (profile.organization_ca, IssuerRole::OrganizationCa),
        (profile.agent_member_issuer, IssuerRole::AgentMemberIssuer),
    ] {
        let certificate = holding(vec![purposes(&[server_auth, oid])]);
        assert_eq!(profile.issuer_roles(&certificate), Ok(vec![role]));
        // The usage written for a role is the one read back as it.
        assert_eq!(profile.issuer_usage(role).0, vec![oid]);
    }
    let both = holding(vec![purposes(&[
        profile.platform_intermediate,
        profile.organization_ca,
    ])]);
    assert_eq!(
        profile.issuer_roles(&both),
        Ok(vec![
            IssuerRole::PlatformIntermediate,
            IssuerRole::OrganizationCa
        ])
    );
    assert_eq!(profile.may_issue(&both, Issued::PersonalPassport), Ok(true));
    assert_eq!(
        profile.may_issue(&both, Issued::Ca(IssuerRole::PlatformIntermediate)),
        Ok(false)
    );
}

// A participant certificate names the participant purpose and nothing else.
// No usage at all, a server or client purpose, a Binding or issuer purpose,
// or the participant purpose with another beside it is not one, and the
// participant purpose is no issuer role. Bug prevented: a TLS certificate,
// an organization's authority or a passport standing in for a site's
// enrollment, or an enrolled site read as an issuer.
#[test]
fn a_participant_names_that_purpose_alone() {
    let profile = DEVELOPMENT_PURPOSES;
    let server_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    let client_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
    let enrolled = holding(vec![purposes(&[profile.federation_participant])]);
    assert_eq!(profile.is_participant(&enrolled), Ok(true));
    assert_eq!(profile.issuer_roles(&enrolled), Ok(vec![]));
    assert_eq!(
        profile.participant_usage().0,
        vec![profile.federation_participant]
    );
    for other in [
        vec![],
        vec![purposes(&[server_auth])],
        vec![purposes(&[client_auth])],
        vec![purposes(&[profile.organization_ca])],
        vec![purposes(&[profile.key_association])],
        vec![purposes(&[profile.federation_participant, server_auth])],
        vec![purposes(&[
            profile.federation_participant,
            profile.organization_ca,
        ])],
    ] {
        assert_eq!(profile.is_participant(&holding(other)), Ok(false));
    }
}

// Two extended key usage extensions are refused (RFC 5280 §4.2: an extension
// appears once), as is one that does not decode. Bug prevented: reading the
// first of two and ignoring a second that names another role.
#[test]
fn a_repeated_or_undecodable_usage_is_malformed() {
    let profile = DEVELOPMENT_PURPOSES;
    let twice = holding(vec![
        purposes(&[profile.organization_ca]),
        purposes(&[profile.platform_intermediate]),
    ]);
    assert_eq!(profile.issuer_roles(&twice), Err(PurposeError::Malformed));
    let garbage = holding(vec![crate::test_certificates::extension(
        ExtendedKeyUsage::OID,
        false,
        &der::asn1::OctetString::new(vec![1, 2, 3]).unwrap(),
    )]);
    assert_eq!(profile.issuer_roles(&garbage), Err(PurposeError::Malformed));
}

// Production has no allocation, so it yields no profile; and a profile other
// than the development one refuses a certificate that carries a development
// purpose instead of reading it as nothing. Bug prevented: a development
// authority accepted, or silently ignored, by an installation that is not a
// development one.
#[test]
fn development_purposes_stay_in_development() {
    assert_eq!(
        PurposeProfile::of(ContextAllocation::Development),
        Ok(DEVELOPMENT_PURPOSES)
    );
    assert_eq!(
        PurposeProfile::of(ContextAllocation::Production),
        Err(PurposeError::NoAllocation)
    );
    let registered = PurposeProfile {
        platform_intermediate: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1"),
        organization_ca: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.2"),
        agent_member_issuer: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.3"),
        key_association: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.4"),
        agent_part: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.5"),
        federation_participant: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.6"),
    };
    // The participant purpose stays in its allocation like every other.
    let enrolled = holding(vec![purposes(&[
        DEVELOPMENT_PURPOSES.federation_participant
    ])]);
    assert_eq!(
        registered.is_participant(&enrolled),
        Err(PurposeError::DevelopmentPurpose)
    );
    assert_eq!(DEVELOPMENT_PURPOSES.is_participant(&enrolled), Ok(true));
    let development = holding(vec![purposes(&[DEVELOPMENT_PURPOSES.organization_ca])]);
    assert_eq!(
        registered.issuer_roles(&development),
        Err(PurposeError::DevelopmentPurpose)
    );
    let own = holding(vec![purposes(&[registered.organization_ca])]);
    assert_eq!(
        registered.issuer_roles(&own),
        Ok(vec![IssuerRole::OrganizationCa])
    );
    // The development profile reads the other allocation's purpose as none.
    assert_eq!(DEVELOPMENT_PURPOSES.issuer_roles(&own), Ok(vec![]));
}
