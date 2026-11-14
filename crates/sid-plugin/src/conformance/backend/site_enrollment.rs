// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's enrollment as a site of the federation.
//!
//! Needs a backend that never held an enrollment (an isolated schema or a
//! fresh database): the scenarios start from none held.

use super::test_audit;
use sid_core::models::{LoginSettings, SiteEnrollment};
use sid_plugin::storage::StorageBackend;

/// An enrollment whose certificate is `seed` repeated, under `above`
/// certificates.
fn enrolled(seed: u8, above: usize) -> SiteEnrollment {
    SiteEnrollment {
        certificate: vec![seed; 600],
        chain: (0..above)
            .map(|level| {
                let mut above = vec![seed.wrapping_add(1); 500 + level];
                above[0] = u8::try_from(level).unwrap();
                above
            })
            .collect(),
    }
}

/// None held reads as none. An enrollment reads back exactly as held, with
/// its chain whole and in order and an empty chain as empty, and a renewal
/// replaces the record whole: the earlier chain does not carry over. Bug
/// prevented: a renewed certificate served under the chain of the one it
/// replaced.
pub async fn test_site_enrollment_held_and_renewed(backend: &dyn StorageBackend) {
    let mut held = None;
    assert_eq!(backend.site_enrollment().await.unwrap(), held);
    for written in [enrolled(1, 2), enrolled(2, 0), enrolled(3, 1)] {
        assert!(
            backend
                .set_site_enrollment(&written, held.as_ref(), test_audit())
                .await
                .unwrap()
        );
        held = Some(written);
        assert_eq!(backend.site_enrollment().await.unwrap(), held);
    }
}

/// A write replaces only the enrollment its writer read: with none held, or
/// another one held, it writes nothing. Of two renewals started from the
/// same read, and of several first imports, exactly one is held and each
/// other is refused without an error. Bug prevented: a slower import of an
/// older certificate overwriting the renewal that landed first.
pub async fn test_site_enrollment_replaces_only_what_was_read(backend: &dyn StorageBackend) {
    assert!(
        !backend
            .set_site_enrollment(&enrolled(2, 1), Some(&enrolled(1, 1)), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.site_enrollment().await.unwrap(), None);

    let attempts = [enrolled(1, 1), enrolled(2, 1), enrolled(3, 1)];
    let outcomes = futures::future::join_all(
        attempts
            .iter()
            .map(|written| backend.set_site_enrollment(written, None, test_audit())),
    )
    .await;
    let landed: Vec<bool> = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("a refused first write is not a failure"))
        .collect();
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    let first = attempts[landed.iter().position(|l| *l).unwrap()].clone();
    assert_eq!(
        backend.site_enrollment().await.unwrap(),
        Some(first.clone())
    );

    for stale in [None, Some(enrolled(9, 1))] {
        assert!(
            !backend
                .set_site_enrollment(&enrolled(4, 1), stale.as_ref(), test_audit())
                .await
                .unwrap(),
            "{stale:?}"
        );
    }
    let (one, other) = (enrolled(5, 1), enrolled(6, 2));
    let (a, b) = tokio::join!(
        backend.set_site_enrollment(&one, Some(&first), test_audit()),
        backend.set_site_enrollment(&other, Some(&first), test_audit()),
    );
    let landed = [a.unwrap(), b.unwrap()];
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    assert_eq!(
        backend.site_enrollment().await.unwrap(),
        Some(if landed[0] { one } else { other })
    );
}

/// An enrollment outside its bounds is refused and nothing is held; and
/// holding or renewing an enrollment changes neither the login settings nor
/// the login policy epoch. Bug prevented: an empty value kept as the site's
/// identity, or a renewed certificate ending every sign-in in progress as
/// if the installation had changed whom it admits.
pub async fn test_site_enrollment_is_bounded_and_apart(backend: &dyn StorageBackend) {
    let empty = SiteEnrollment {
        certificate: Vec::new(),
        chain: Vec::new(),
    };
    for refused in [
        empty,
        enrolled(1, sid_core::models::site_enrollment::MAX_CHAIN + 1),
    ] {
        assert!(matches!(
            backend
                .set_site_enrollment(&refused, None, test_audit())
                .await,
            Err(sid_core::Error::Validation(_))
        ));
    }
    assert_eq!(backend.site_enrollment().await.unwrap(), None);

    let settings = LoginSettings {
        allow_foreign_corporate_profiles: true,
        ..LoginSettings::default()
    };
    assert!(
        backend
            .set_login_settings(&settings, None, test_audit())
            .await
            .unwrap()
    );
    let epoch = backend.export_login_policy_epoch().await.unwrap();
    assert!(
        backend
            .set_site_enrollment(&enrolled(1, 1), None, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .set_site_enrollment(&enrolled(2, 1), Some(&enrolled(1, 1)), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.login_settings().await.unwrap(), Some(settings));
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), epoch);
}
