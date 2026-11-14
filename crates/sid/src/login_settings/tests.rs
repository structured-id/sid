// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::test_support::{administrator, operation, storage, stored_profile};

fn offline(missing: bool, max_stale_seconds: Option<u64>) -> wire::StatusRequirement {
    wire::StatusRequirement {
        offline: Some(wire::OfflineStatusLimits {
            missing,
            max_stale_seconds,
        }),
    }
}

/// An installation that was never configured reads the default policy: a
/// list within its time from the passport's issuer, the authorities above
/// on what is held. A change replaces the policy whole, is the next
/// revision of the settings, leaves the admissions as they were, and reads
/// back as given. Bug prevented: a policy change that silently admits an
/// identity kind, or a relaxed policy read back as the strict one.
#[tokio::test]
async fn the_status_policy_is_read_and_replaced_whole() {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let admin = administrator(stored_profile(storage.as_ref(), "admin").await);
    let settings = LoginSettingsAdmin::new(storage.clone());

    let unset = settings.settings(&admin).await.unwrap();
    assert_eq!(
        unset.status_policy,
        Some(wire::StatusPolicy {
            issuer: Some(wire::StatusRequirement { offline: None }),
            authorities: Some(offline(true, None)),
        })
    );
    assert_eq!(unset.revision, 0);

    let relaxed = wire::StatusPolicy {
        issuer: Some(offline(false, Some(86_400))),
        authorities: Some(wire::StatusRequirement { offline: None }),
    };
    let changed = settings
        .update(
            &admin,
            operation(storage.as_ref(), "policy-1").await,
            UpdateLoginSettingsRequest {
                status_policy: Some(relaxed),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(changed.status_policy, Some(relaxed));
    assert_eq!(changed.revision, 1);
    assert!(!changed.allow_personal_profiles);
    assert!(!changed.allow_foreign_corporate_profiles);
    assert_eq!(settings.settings(&admin).await.unwrap(), changed);
    assert_eq!(
        in_force(storage.as_ref()).await.unwrap().status_policy,
        StatusPolicy {
            issuer: StatusRequirement::Offline(OfflineLimits {
                missing: false,
                max_stale: Some(86_400),
            }),
            authorities: StatusRequirement::Fresh,
        }
    );

    // Another setting changed without naming the policy keeps it.
    let kept = settings
        .update(
            &admin,
            operation(storage.as_ref(), "kinds-1").await,
            UpdateLoginSettingsRequest {
                allow_personal_profiles: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(kept.status_policy, Some(relaxed));
    assert_eq!(kept.revision, 2);
}

/// A change names both requirements: one left out is refused, never read
/// as the strict one or as the stored one, and nothing is written.
#[tokio::test]
async fn a_policy_change_names_both_requirements() {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let admin = administrator(stored_profile(storage.as_ref(), "admin").await);
    let settings = LoginSettingsAdmin::new(storage.clone());
    for half in [
        wire::StatusPolicy {
            issuer: Some(offline(true, None)),
            authorities: None,
        },
        wire::StatusPolicy {
            issuer: None,
            authorities: Some(offline(true, None)),
        },
    ] {
        let refused = settings
            .update(
                &admin,
                operation(storage.as_ref(), "policy-half").await,
                UpdateLoginSettingsRequest {
                    status_policy: Some(half),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            refused,
            Err(LoginSettingsError::InvalidField {
                field: "status_policy",
                ..
            })
        ));
    }
    assert_eq!(storage.login_settings().await.unwrap(), None);
}
