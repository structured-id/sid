// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's stored login settings.
//!
//! Needs a backend whose settings and policies were never set (an isolated
//! schema or a fresh database): the scenarios start from the unset state.

use super::test_audit;
use sid_core::models::{
    AdmittedSources, EnrollmentMode, EnrollmentPolicy, InviteConfig, LoginSettings, ModeWrite,
    OrgId,
};
use sid_plugin::storage::StorageBackend;

/// The two admissions with no source organization named.
fn kinds(personal: bool, corporate: bool) -> LoginSettings {
    LoginSettings {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        ..LoginSettings::default()
    }
}

fn neither() -> LoginSettings {
    kinds(false, false)
}

fn personal_only() -> LoginSettings {
    kinds(true, false)
}

fn corporate_only() -> LoginSettings {
    kinds(false, true)
}

fn both() -> LoginSettings {
    kinds(true, true)
}

/// Unset reads as none (the defaults then apply, decided by the caller); each
/// of the four combinations reads back as written, and a write replaces the
/// stored record whole: one admission never carries over into the other.
pub async fn test_login_settings_stored_and_replaced(backend: &dyn StorageBackend) {
    let mut stored = None;
    assert_eq!(backend.login_settings().await.unwrap(), stored);
    for written in [personal_only(), corporate_only(), both(), neither()] {
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

/// The admitted source organizations and the revision read back exactly as
/// written: the set whole and in id order, an empty set as empty, never as
/// the one stored before. A write expecting the same switches with another
/// set or revision is a stale read like any other. Bug prevented: a set that
/// survives its own removal, an organization lost or added by the stored
/// form, a change decided on an older set overwriting a newer one.
pub async fn test_login_settings_keep_admitted_sources(backend: &dyn StorageBackend) {
    let sources = |ids: Vec<OrgId>| AdmittedSources::try_from(ids).unwrap();
    let (a, b, c) = (OrgId::generate(), OrgId::generate(), OrgId::generate());
    let with = |ids: Vec<OrgId>, revision: u64| LoginSettings {
        admitted_sources: sources(ids),
        revision,
        ..corporate_only()
    };

    let first = with(vec![c, a, b], 1);
    assert!(
        backend
            .set_login_settings(&first, None, test_audit())
            .await
            .unwrap()
    );
    let read = backend.login_settings().await.unwrap().unwrap();
    assert_eq!(read, first);
    assert_eq!(read.admitted_sources.as_slice().len(), 3);
    assert!(read.admitted_sources.as_slice().is_sorted());
    assert_eq!(read.revision, 1);

    // The same switches read with another set, or at another revision, are
    // not what is stored: nothing is written.
    for stale in [with(vec![a, b], 1), with(vec![c, a, b], 2)] {
        assert!(
            !backend
                .set_login_settings(&with(Vec::new(), 2), Some(&stale), test_audit())
                .await
                .unwrap(),
            "{stale:?}"
        );
    }
    assert_eq!(backend.login_settings().await.unwrap(), Some(first.clone()));

    // One organization is removed, then all of them.
    let second = with(vec![a, c], 2);
    assert!(
        backend
            .set_login_settings(&second, Some(&first), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(second.clone())
    );
    let third = with(Vec::new(), 3);
    assert!(
        backend
            .set_login_settings(&third, Some(&second), test_audit())
            .await
            .unwrap()
    );
    let read = backend.login_settings().await.unwrap().unwrap();
    assert!(read.admitted_sources.as_slice().is_empty());
    assert_eq!(read, third);
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
            .set_login_settings(&both(), Some(&neither()), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.login_settings().await.unwrap(), None);
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);

    assert!(
        backend
            .set_login_settings(&personal_only(), None, test_audit())
            .await
            .unwrap()
    );
    let epoch = backend.export_login_policy_epoch().await.unwrap();

    // Stale reads: never set, and settings that are not the stored ones.
    for stale in [None, Some(corporate_only()), Some(neither())] {
        assert!(
            !backend
                .set_login_settings(&both(), stale.as_ref(), test_audit())
                .await
                .unwrap(),
            "{stale:?}"
        );
    }
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(personal_only())
    );
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), epoch);

    // Two administrators read the same settings and each turns on another
    // admission: one write lands, the other is told to read again.
    let (read, one, other) = (personal_only(), both(), neither());
    let (first, second) = tokio::join!(
        backend.set_login_settings(&one, Some(&read), test_audit()),
        backend.set_login_settings(&other, Some(&read), test_audit()),
    );
    // The one that did not land is refused, never failed: its caller reads
    // again and decides again.
    let landed = [first.unwrap(), second.unwrap()];
    assert_eq!(landed.iter().filter(|l| **l).count(), 1, "{landed:?}");
    let stored = backend.login_settings().await.unwrap();
    assert_eq!(stored, Some(if landed[0] { one } else { other }));
}

/// The very first change races too: of several administrators changing the
/// settings of an installation that has none, one write lands and each other
/// is refused, without an error, however the store makes its first record.
pub async fn test_first_login_settings_write_races_without_failing(backend: &dyn StorageBackend) {
    let attempts = [personal_only(), corporate_only(), both(), neither()];
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
    let winner = attempts[landed.iter().position(|l| *l).unwrap()].clone();
    assert_eq!(backend.login_settings().await.unwrap(), Some(winner));
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), Some(1));
}

/// Moved settings are stored as they were, with their source organizations
/// and revision, and advance no epoch (the epoch moves as a record of its
/// own); the same settings imported again are a repeat, other ones conflict
/// and change nothing.
pub async fn test_login_settings_import_keeps_the_epoch(backend: &dyn StorageBackend) {
    let moved = LoginSettings {
        admitted_sources: AdmittedSources::try_from(vec![OrgId::generate()]).unwrap(),
        revision: 7,
        ..corporate_only()
    };
    assert!(
        backend
            .import_login_settings(&moved, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.login_settings().await.unwrap(), Some(moved.clone()));
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);

    assert!(
        !backend
            .import_login_settings(&moved, test_audit())
            .await
            .unwrap()
    );
    // The same switches without the source organization are other settings.
    for other in [both(), corporate_only()] {
        assert!(matches!(
            backend.import_login_settings(&other, test_audit()).await,
            Err(sid_core::Error::Conflict(_))
        ));
    }
    assert_eq!(backend.login_settings().await.unwrap(), Some(moved));
}

/// Every change of the login settings advances the installation's login
/// policy epoch, the first one starting it, so a sign-in decided under the
/// earlier settings no longer commits. Writing the same values again is a
/// change of its own: the epoch never stands still across a write.
pub async fn test_login_settings_advance_the_login_policy_epoch(backend: &dyn StorageBackend) {
    assert_eq!(backend.export_login_policy_epoch().await.unwrap(), None);
    let (mut stored, mut last) = (None, 0);
    for written in [personal_only(), corporate_only(), corporate_only()] {
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
            .set_login_settings(&corporate_only(), None, test_audit())
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
        Some(corporate_only())
    );

    assert!(
        backend
            .set_login_settings(&personal_only(), Some(&corporate_only()), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(backend.enrollment_policy().await.unwrap(), Some(admin_only));
    assert_eq!(
        backend.login_settings().await.unwrap(),
        Some(personal_only())
    );
}
