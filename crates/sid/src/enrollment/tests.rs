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

/// A pinned mode cannot be changed through the API; the other fields can,
/// so long as the request carries the pinned mode.
#[test]
fn test_validated_refuses_changing_pinned_mode() {
    assert_eq!(
        validated(
            policy(EnrollmentMode::Open, &[]),
            Some(EnrollmentMode::AdminOnly),
            EnrollmentMode::Open,
        ),
        Err(Refusal::Pinned(EnrollmentMode::AdminOnly))
    );
}

/// Regression: an update of other fields under a pin wrote the pinned mode
/// into the store, so removing the pin left the installation in it. The
/// stored mode is kept, and the domain check applies to the mode stored.
#[test]
fn test_validated_keeps_the_stored_mode_under_a_pin() {
    let mut request = policy(EnrollmentMode::AdminOnly, &[]);
    request.track_source = false;
    let stored = validated(
        request,
        Some(EnrollmentMode::AdminOnly),
        EnrollmentMode::Open,
    )
    .unwrap();
    assert_eq!(stored.mode, EnrollmentMode::Open);
    assert!(!stored.track_source);
    assert_eq!(
        validated(
            policy(EnrollmentMode::AdminOnly, &[]),
            Some(EnrollmentMode::AdminOnly),
            EnrollmentMode::DomainRestricted,
        ),
        Err(Refusal::NoDomain)
    );
}

/// Regression: a pinned domain-restricted mode over a stored open one took
/// a policy without domains, though the mode in force then admitted no one.
/// And a default use limit no invite can store was accepted.
#[test]
fn test_validated_checks_the_pinned_mode_and_use_range() {
    assert_eq!(
        validated(
            policy(EnrollmentMode::DomainRestricted, &[]),
            Some(EnrollmentMode::DomainRestricted),
            EnrollmentMode::Open,
        ),
        Err(Refusal::NoDomain)
    );
    let mut wide = policy(EnrollmentMode::Open, &[]);
    wide.invite.default_max_uses = MAX_INVITE_USES + 1;
    assert_eq!(
        validated(wide.clone(), None, EnrollmentMode::Open),
        Err(Refusal::TooManyUses)
    );
    wide.invite.default_max_uses = MAX_INVITE_USES;
    assert!(validated(wide, None, EnrollmentMode::Open).is_ok());
}

/// Regression: a default expiry beyond what a time can hold panicked when an
/// invite was created. It is refused when stored, and computed without a
/// panic; 0 hours is no expiry.
#[test]
fn test_default_expiry_is_bounded() {
    let now = chrono::Utc::now();
    assert_eq!(default_expiry(now, 0), Some(None));
    assert_eq!(
        default_expiry(now, 2),
        Some(Some(now + chrono::TimeDelta::hours(2)))
    );
    assert_eq!(default_expiry(now, u32::MAX), None);

    let mut far = policy(EnrollmentMode::Open, &[]);
    far.invite.default_expiry_hours = u32::MAX;
    assert_eq!(
        validated(far, None, EnrollmentMode::Open),
        Err(Refusal::ExpiryTooFar)
    );
}

/// Domains are stored as registration compares them; a domain-restricted
/// policy without a usable domain, or with something that is no domain name,
/// is refused rather than stored as a policy that admits no one.
#[test]
fn test_validated_normalizes_and_checks_domains() {
    let open = EnrollmentMode::Open;
    assert_eq!(
        validated(
            policy(
                EnrollmentMode::DomainRestricted,
                &[" Acme.Example ", "acme.example", "xn--bcher-kva.example"]
            ),
            None,
            open,
        )
        .unwrap()
        .allowed_domains,
        vec!["acme.example", "xn--bcher-kva.example"]
    );
    assert_eq!(
        validated(policy(EnrollmentMode::DomainRestricted, &[]), None, open),
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
                validated(policy(EnrollmentMode::DomainRestricted, &[bad]), None, open),
                Err(Refusal::BadDomain(_))
            ),
            "{bad:?} accepted"
        );
    }
    // Other modes need no domain.
    assert!(validated(policy(EnrollmentMode::InviteOnly, &[]), None, open).is_ok());
}

/// An unspecified or unknown mode and a missing invite configuration are
/// refused, never read as a default; a stored policy reads back unchanged.
#[test]
fn test_policy_from_proto_refuses_defaults() {
    let stored = policy(EnrollmentMode::InviteOnly, &["acme.example"]);
    assert_eq!(policy_from_proto(policy_to_proto(&stored)).unwrap(), stored);
    let mut unspecified = policy_to_proto(&stored);
    unspecified.mode = 0;
    assert!(matches!(
        policy_from_proto(unspecified),
        Err(EnrollmentError::MissingField("policy.mode"))
    ));
    let mut unknown = policy_to_proto(&stored);
    unknown.mode = 99;
    assert!(matches!(
        policy_from_proto(unknown),
        Err(EnrollmentError::InvalidField {
            field: "policy.mode",
            ..
        })
    ));
    let mut no_invite = policy_to_proto(&stored);
    no_invite.invite = None;
    assert!(matches!(
        policy_from_proto(no_invite),
        Err(EnrollmentError::MissingField("policy.invite"))
    ));
}

/// Page tokens are offsets this engine issued: empty is the first page,
/// anything negative, past BIGINT or not a number is refused; a full page
/// has a next token unless it would leave BIGINT.
#[test]
fn test_paging() {
    assert_eq!(page_offset("").unwrap(), 0);
    assert_eq!(page_offset("50").unwrap(), 50);
    for bad in ["-1", "x", "9223372036854775808"] {
        assert!(
            matches!(
                page_offset(bad),
                Err(EnrollmentError::InvalidField {
                    field: "page_token",
                    ..
                })
            ),
            "{bad:?} accepted"
        );
    }
    assert_eq!(page_limit(0), DEFAULT_PAGE_SIZE);
    assert_eq!(page_limit(10_000), MAX_PAGE_SIZE);
    assert_eq!(next_page(0, 50, 50), "50");
    assert_eq!(next_page(0, 50, 49), "");
    assert_eq!(next_page(i64::MAX as u64, 50, 50), "");
}

/// An undefined status filter is refused, never read as "any status"; a
/// blank search is no search.
#[test]
fn test_invite_filter() {
    let filter = invite_filter(v1::InviteStatus::Revoked as i32, "  ").unwrap();
    assert_eq!(filter.status, Some(InviteStatus::Revoked));
    assert_eq!(filter.search, None);
    assert!(matches!(
        invite_filter(99, ""),
        Err(EnrollmentError::InvalidField {
            field: "status",
            ..
        })
    ));
}

/// An expiry must be a valid time in the future.
#[test]
fn test_invite_expiry() {
    assert_eq!(invite_expiry(None).unwrap(), None);
    let past = prost_types::Timestamp {
        seconds: 1,
        nanos: 0,
    };
    let bad_nanos = prost_types::Timestamp {
        seconds: i64::from(u32::MAX),
        nanos: -1,
    };
    for ts in [past, bad_nanos] {
        assert!(matches!(
            invite_expiry(Some(ts)),
            Err(EnrollmentError::InvalidField {
                field: "expires_at",
                ..
            })
        ));
    }
}

/// A machine user creator is reported in its own field, never as a Profile.
#[test]
fn test_invite_to_proto_names_its_creator() {
    use v1::invite::CreatedBy;
    let machine = MachineUserId::generate();
    let invite = Invite {
        id: InviteId::generate(),
        code: generate_invite_code(),
        created_by: InviteCreator::MachineUser(machine),
        created_by_name: "ci".into(),
        metadata: Default::default(),
        max_uses: 0,
        use_count: 0,
        expires_at: None,
        active: true,
        created_at: chrono::Utc::now(),
    };
    assert!(matches!(
        invite_to_proto(&invite).created_by,
        Some(CreatedBy::CreatedByMachineUserId(_))
    ));
    assert_eq!(
        invite_to_proto(&invite).status,
        v1::InviteStatus::Active as i32
    );
}
