// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::InviteConfig;

fn policy(mode: EnrollmentMode, domains: &[&str]) -> EnrollmentPolicy {
    EnrollmentPolicy {
        mode,
        invite: InviteConfig {
            default_max_uses: 1,
            default_expiry_hours: 72,
        },
        allowed_domains: domains.iter().map(|d| (*d).to_string()).collect(),
        track_source: true,
    }
}

/// Unset pins nothing; a mode's name pins it; anything else stops the start
/// instead of leaving registration open by accident.
#[test]
fn test_pinned_mode_setting() {
    assert_eq!(
        pinned_mode_setting(Err(std::env::VarError::NotPresent)).unwrap(),
        None
    );
    assert_eq!(
        pinned_mode_setting(Ok("admin_only".into())).unwrap(),
        Some(EnrollmentMode::AdminOnly)
    );
    assert!(pinned_mode_setting(Ok("closed".into())).is_err());
    assert!(pinned_mode_setting(Ok(String::new())).is_err());
    assert!(
        pinned_mode_setting(Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::new()
        )))
        .is_err()
    );
}

/// A pinned mode cannot be changed through the API; the other fields can,
/// so long as the mode stays the pinned one.
#[test]
fn test_validated_refuses_changing_pinned_mode() {
    assert_eq!(
        validated(
            policy(EnrollmentMode::Open, &[]),
            Some(EnrollmentMode::AdminOnly)
        ),
        Err(Refusal::Pinned(EnrollmentMode::AdminOnly))
    );
    let mut same = policy(EnrollmentMode::AdminOnly, &[]);
    same.track_source = false;
    assert_eq!(
        validated(same.clone(), Some(EnrollmentMode::AdminOnly)),
        Ok(same)
    );
}

/// Domains are stored as registration compares them; a domain-restricted
/// policy without a usable domain, or with something that is no domain name,
/// is refused rather than stored as a policy that admits no one.
#[test]
fn test_validated_normalizes_and_checks_domains() {
    assert_eq!(
        validated(
            policy(
                EnrollmentMode::DomainRestricted,
                &[" Acme.Example ", "acme.example", "xn--bcher-kva.example"]
            ),
            None
        )
        .unwrap()
        .allowed_domains,
        vec!["acme.example", "xn--bcher-kva.example"]
    );
    assert_eq!(
        validated(policy(EnrollmentMode::DomainRestricted, &[]), None),
        Err(Refusal::NoDomain)
    );
    for bad in [
        "",
        "acme..example",
        "-acme.example",
        "acme.example-",
        "a b.example",
        "@acme.example",
    ] {
        assert!(
            matches!(
                validated(policy(EnrollmentMode::DomainRestricted, &[bad]), None),
                Err(Refusal::BadDomain(_))
            ),
            "{bad:?} accepted"
        );
    }
    // Other modes need no domain.
    assert!(validated(policy(EnrollmentMode::InviteOnly, &[]), None).is_ok());
}
