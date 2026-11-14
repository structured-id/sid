// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

const NOW: i64 = 1_800_000_000;

fn offline(missing: bool, max_stale: Option<u64>) -> StatusRequirement {
    StatusRequirement::Offline(OfflineLimits { missing, max_stale })
}

/// A list within its time is fresh evidence under every requirement, and
/// the answer holds to the list's end.
#[test]
fn a_list_in_its_time_is_fresh_under_every_requirement() {
    for requirement in [
        StatusRequirement::Fresh,
        offline(false, Some(0)),
        offline(true, None),
    ] {
        assert_eq!(
            requirement.weigh(Some(NOW + 60), NOW),
            Some((StatusEvidence::Fresh, Some(NOW + 60)))
        );
        // The list's last second is still its time.
        assert_eq!(
            requirement.weigh(Some(NOW), NOW),
            Some((StatusEvidence::Fresh, Some(NOW)))
        );
    }
}

/// The strict requirement decides nothing without a list in its time. Bug
/// prevented: an absent or expired list read as "not withdrawn".
#[test]
fn the_strict_requirement_needs_a_list_in_its_time() {
    assert_eq!(StatusRequirement::Fresh.weigh(None, NOW), None);
    assert_eq!(StatusRequirement::Fresh.weigh(Some(NOW - 1), NOW), None);
}

/// The offline requirement admits exactly the absences it names: a list
/// never held only when it permits a missing one, an expired list only
/// within its limit, and it never calls either of them fresh. Bug
/// prevented: an offline mode that admits more than it says, or reports
/// unknown status as good.
#[test]
fn the_offline_requirement_admits_only_what_it_names() {
    assert_eq!(
        offline(true, Some(0)).weigh(None, NOW),
        Some((StatusEvidence::Unknown, None))
    );
    assert_eq!(offline(false, None).weigh(None, NOW), None);

    // Expired a minute ago.
    let expired = Some(NOW - 60);
    assert_eq!(
        offline(false, None).weigh(expired, NOW),
        Some((StatusEvidence::Stale, None))
    );
    assert_eq!(
        offline(false, Some(60)).weigh(expired, NOW),
        Some((StatusEvidence::Stale, Some(NOW)))
    );
    assert_eq!(offline(true, Some(59)).weigh(expired, NOW), None);
    assert_eq!(offline(true, Some(0)).weigh(expired, NOW), None);
    // A limit past the end of time is no limit.
    assert_eq!(
        offline(false, Some(u64::MAX)).weigh(expired, NOW),
        Some((StatusEvidence::Stale, None))
    );
}

/// The default asks the passport's issuer for a list in its time and takes
/// the authorities above it on what is held.
#[test]
fn the_default_is_strict_about_the_passports_issuer() {
    let policy = StatusPolicy::default();
    assert_eq!(policy.issuer, StatusRequirement::Fresh);
    assert_eq!(
        policy.authorities,
        StatusRequirement::Offline(OfflineLimits::ANY)
    );
}

/// Different policies have different tags. Bug prevented: a path accepted
/// under an offline policy answered from the cache after the installation
/// turned strict.
#[test]
fn a_tag_tells_policies_apart() {
    let policies = [
        StatusPolicy::default(),
        StatusPolicy {
            issuer: StatusRequirement::Fresh,
            authorities: StatusRequirement::Fresh,
        },
        StatusPolicy {
            issuer: offline(true, None),
            authorities: StatusRequirement::Fresh,
        },
        StatusPolicy {
            issuer: offline(false, None),
            authorities: StatusRequirement::Fresh,
        },
        StatusPolicy {
            issuer: offline(false, Some(0)),
            authorities: StatusRequirement::Fresh,
        },
        StatusPolicy {
            issuer: offline(false, Some(1)),
            authorities: StatusRequirement::Fresh,
        },
    ];
    for (i, a) in policies.iter().enumerate() {
        for b in &policies[i + 1..] {
            assert_ne!(a.tag(), b.tag(), "{a:?} {b:?}");
        }
        assert_eq!(a.tag(), a.tag());
        // A store keeps a policy as its tag: it reads back as itself.
        assert_eq!(StatusPolicy::from_tag(&a.tag()), Some(*a));
    }
}

/// Bytes no policy encodes read as no policy. Bug prevented: a damaged
/// stored value silently read as a more permissive policy.
#[test]
fn bytes_that_encode_no_policy_are_refused() {
    let valid = StatusPolicy::default().tag();
    assert_eq!(StatusPolicy::from_tag(&valid[..19]), None);
    assert_eq!(StatusPolicy::from_tag(&[]), None);
    let damaged = |edit: fn(&mut [u8; 20])| {
        let mut tag = valid;
        edit(&mut tag);
        StatusPolicy::from_tag(&tag)
    };
    // An unknown kind, an unknown limit flag, a strict requirement carrying
    // limits, and a limit stated without its flag.
    assert_eq!(damaged(|tag| tag[0] = 3), None);
    assert_eq!(damaged(|tag| tag[11] = 2), None);
    assert_eq!(damaged(|tag| tag[9] = 1), None);
    assert_eq!(damaged(|tag| tag[19] = 1), None);
}
