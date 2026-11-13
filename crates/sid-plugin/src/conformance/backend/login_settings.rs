// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's stored login settings.
//!
//! Needs a backend whose settings and policies were never set (an isolated
//! schema or a fresh database): the scenarios start from the unset state.

use super::test_audit;
use sid_core::models::{EnrollmentMode, EnrollmentPolicy, InviteConfig, LoginSettings, ModeWrite};
use sid_plugin::storage::StorageBackend;

const NEITHER: LoginSettings = LoginSettings {
    allow_personal_profiles: false,
    allow_foreign_corporate_profiles: false,
};

const PERSONAL_ONLY: LoginSettings = LoginSettings {
    allow_personal_profiles: true,
    allow_foreign_corporate_profiles: false,
};

const CORPORATE_ONLY: LoginSettings = LoginSettings {
    allow_personal_profiles: false,
    allow_foreign_corporate_profiles: true,
};

const BOTH: LoginSettings = LoginSettings {
    allow_personal_profiles: true,
    allow_foreign_corporate_profiles: true,
};

/// Unset reads as none (the defaults then apply, decided by the caller); each
/// of the four combinations reads back as written, and a write replaces the
/// stored record whole: one admission never carries over into the other.
pub async fn test_login_settings_stored_and_replaced(backend: &dyn StorageBackend) {
    let mut stored = None;
    assert_eq!(backend.login_settings().await.unwrap(), stored);
    for written in [PERSONAL_ONLY, CORPORATE_ONLY, BOTH, NEITHER] {
        assert!(
            backend
                .set_login_settings(&written, stored.as_ref(), test_audit())
                .await
                .unwrap()
        );
        stored = Some(written);
        assert_eq!(backend.login_settings().await.unwrap(), stored);
    }
}

/// A write replaces exactly the settings its caller read: against any other
/// stored state it writes nothing and leaves the epoch where it was, so a
/// change of one admission decided on a stale read never overwrites a change
/// of the other. Two writers starting from the same read end with one of
/// them refused.
pub async fn test_login_settings_replace_only_what_was_read(backend: &dyn StorageBackend) {
    // Nothing stored: a write expecting stored settings is refused.
    assert!(
        !backend
            .set_login_settings(&BOTH, Some(&NEITHER), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.login_settings().await.unwrap(), None);
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);

    assert!(
        backend
            .set_login_settings(&PERSONAL_ONLY, None, test_audit())
            .await
            .unwrap()
    );
    let epoch = backend.export_login_policy_epoch().await.unwrap();

    // Stale reads: never set, and settings that are not the stored ones.
    for stale in [None, Some(&CORPORATE_ONLY), Some(&NEITHER)] {
        assert!(
            !backend
                .set_login_settings(&BOTH, stale, test_audit())
                .await
                .unwrap(),
            "{stale:?}"
        );
    }
    assert_eq!(backend.login_settings().await.unwrap(), Some(PERSONAL_ONLY));
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), epoch);

    // Two administrators read the same settings and each turns on another
    // admission: one write lands, the other is told to read again.
    let (first, second) = tokio::join!(
        backend.set_login_settings(&BOTH, Some(&PERSONAL_ONLY), test_audit()),
        backend.set_login_settings(&NEITHER, Some(&PERSONAL_ONLY), test_audit()),
    );
    // The one that did not land is refused, never failed: its caller reads
    // again and decides again.
    let landed = [first.unwrap(), second.unwrap()];
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    let stored = backend.login_settings().await.unwrap();
    assert_eq!(stored, Some(if landed[0] { BOTH } else { NEITHER }));
}

/// The very first change races too: of several administrators changing the
/// settings of an installation that has none, one write lands and each other
/// is refused, without an error, however the store makes its first record.
pub async fn test_first_login_settings_write_races_without_failing(backend: &dyn StorageBackend) {
    let attempts = [PERSONAL_ONLY, CORPORATE_ONLY, BOTH, NEITHER];
    let outcomes = futures::future::join_all(
        attempts
            .iter()
            .map(|written| backend.set_login_settings(written, None, test_audit())),
    )
    .await;
    let landed: Vec<bool> = outcomes
        .into_iter()
        .map(|outcome| outcome.expect("a refused first write is not a failure"))
        .collect();
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    let winner = attempts[landed.iter().position(|l| *l).unwrap()];
    assert_eq!(backend.login_settings().await.unwrap(), Some(winner));
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), Some(1));
}

/// Moved settings are stored as they were and advance no epoch (the epoch
/// moves as a record of its own); the same settings imported again are a
/// repeat, other ones conflict and change nothing.
pub async fn test_login_settings_import_keeps_the_epoch(backend: &dyn StorageBackend) {
    assert!(
        backend
            .import_login_settings(&CORPORATE_ONLY, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(CORPORATE_ONLY)
    );
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);

    assert!(
        !backend
            .import_login_settings(&CORPORATE_ONLY, test_audit())
            .await
            .unwrap()
    );
    assert!(matches!(
        backend.import_login_settings(&BOTH, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(CORPORATE_ONLY)
    );
}

/// Every change of the login settings advances the installation's login
/// policy epoch, the first one starting it, so a sign-in decided under the
/// earlier settings no longer commits. Writing the same values again is a
/// change of its own: the epoch never stands still across a write.
pub async fn test_login_settings_advance_the_login_policy_epoch(backend: &dyn StorageBackend) {
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);
    let (mut stored, mut last) = (None, 0);
    for written in [PERSONAL_ONLY, CORPORATE_ONLY, CORPORATE_ONLY] {
        assert!(
            backend
                .set_login_settings(&written, stored.as_ref(), test_audit())
                .await
                .unwrap()
        );
        stored = Some(written);
        let epoch = backend
            .export_login_policy_epoch()
            .await
            .unwrap()
            .expect("a login settings write starts the epoch");
        assert!(epoch > last, "epoch {epoch} after {last}");
        last = epoch;
    }
}

/// Login settings and the enrollment policy are records of their own: saving
/// either leaves the other exactly as stored, in both orders, and an
/// enrollment policy stored before any login settings does not make them
/// read as set.
pub async fn test_login_settings_and_enrollment_policy_are_independent(
    backend: &dyn StorageBackend,
) {
    let enrollment = |mode| EnrollmentPolicy {
        mode,
        invite: InviteConfig {
            default_max_uses: 3,
            default_expiry_hours: 48,
        },
        allowed_domains: Vec::new(),
        track_source: true,
    };
    let invite_only = enrollment(EnrollmentMode::InviteOnly);
    backend
        .set_enrollment_policy(&invite_only, ModeWrite::Replace, test_audit())
        .await
        .unwrap();
    assert_eq!(backend.login_settings().await.unwrap(), None);

    assert!(
        backend
            .set_login_settings(&CORPORATE_ONLY, None, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.enrollment_policy().await.unwrap(),
        Some(invite_only)
    );

    let admin_only = enrollment(EnrollmentMode::AdminOnly);
    backend
        .set_enrollment_policy(&admin_only, ModeWrite::Replace, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(CORPORATE_ONLY)
    );

    assert!(
        backend
            .set_login_settings(&PERSONAL_ONLY, Some(&CORPORATE_ONLY), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.enrollment_policy().await.unwrap(), Some(admin_only));
    assert_eq!(backend.login_settings().await.unwrap(), Some(PERSONAL_ONLY));
}
