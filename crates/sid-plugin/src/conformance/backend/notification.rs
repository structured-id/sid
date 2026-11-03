// SPDX-License-Identifier: AGPL-3.0-only
//! A profile's notification preferences: absent until saved, and a save
//! replaces what was there.

use sid_core::models::notification::{NotificationCategory, NotificationPreferences};
use sid_plugin::storage::StorageBackend;

use super::{create_test_profile, test_audit};

/// Nothing is stored before the first save; the saved preferences read back.
pub async fn test_notification_preferences_round_trip(backend: &dyn StorageBackend) {
    let profile = create_test_profile("notify");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_notification_preferences(profile.id)
            .await
            .unwrap()
            .is_none()
    );

    let saved = NotificationPreferences::defaults(profile.id);
    backend
        .save_notification_preferences(&saved, test_audit())
        .await
        .unwrap();
    let loaded = backend
        .get_notification_preferences(profile.id)
        .await
        .unwrap()
        .expect("saved preferences read back");
    assert_eq!(loaded.profile_id, profile.id);
    assert_eq!(loaded.categories.len(), saved.categories.len());
    assert!(
        loaded
            .categories
            .iter()
            .any(|c| c.category == NotificationCategory::SecurityAlerts)
    );
}

/// A second save replaces the first: a category switched off stays off.
pub async fn test_notification_preferences_replace(backend: &dyn StorageBackend) {
    let profile = create_test_profile("notify");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let saved = NotificationPreferences::defaults(profile.id);
    backend
        .save_notification_preferences(&saved, test_audit())
        .await
        .unwrap();

    let mut changed = saved.clone();
    changed
        .categories
        .iter_mut()
        .find(|c| c.category == NotificationCategory::LoginNotifications)
        .expect("the defaults name login notifications")
        .enabled = false;
    changed.updated_at = chrono::Utc::now();
    backend
        .save_notification_preferences(&changed, test_audit())
        .await
        .unwrap();

    let loaded = backend
        .get_notification_preferences(profile.id)
        .await
        .unwrap()
        .unwrap();
    let login = loaded
        .categories
        .iter()
        .find(|c| c.category == NotificationCategory::LoginNotifications)
        .unwrap();
    assert!(!login.enabled, "the replacing save did not apply");
}
