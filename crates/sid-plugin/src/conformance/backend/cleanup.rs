// SPDX-License-Identifier: AGPL-3.0-only
//! Cleanup operations: each removes what is expired or dismissed and nothing
//! that is still live. Other writers share the store, so counts are checked
//! as lower bounds and live records by name.

use std::future::Future;
use std::pin::Pin;

use chrono::{Duration, Utc};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

/// Ages one IP's reputation entry past a window: the harness reaches past
/// the trait, which offers no way to write an entry's update time.
pub type AgeEntry = dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// Dismissing an outbound DLQ entry removes it alone.
pub async fn test_delete_outbound_dlq_entry(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AttributeMapping, GroupPushConfig, OutboundAuthConfig, OutboundDlqEntry,
        OutboundEntityType, OutboundSyncConfig, ScimOutboundTarget, ScimOutboundTargetId,
    };

    backend.ensure_system_project(test_audit()).await.unwrap();
    let now = Utc::now();
    let target = ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: format!("dlq-{}", Uuid::now_v7().simple()),
        project_id: sid_core::models::ProjectId::system(),
        display_name: "Downstream".into(),
        endpoint_url: "https://scim.sid.example.com/v2".into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "sealed-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig::default(),
        sync_config: OutboundSyncConfig::default(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    backend
        .create_scim_outbound_target(&target, test_audit())
        .await
        .unwrap();
    let entry = || OutboundDlqEntry {
        id: Uuid::now_v7(),
        target_id: target.id,
        event_type: "sid.user.created.v1".into(),
        payload: serde_json::json!({}),
        sid_entity_id: Uuid::now_v7(),
        entity_type: OutboundEntityType::User,
        error: "503".into(),
        attempts: 5,
        first_attempt: now,
        last_attempt: now,
    };
    let (dismissed, kept) = (entry(), entry());
    for e in [&dismissed, &kept] {
        backend
            .create_outbound_dlq_entry(e, test_audit())
            .await
            .unwrap();
    }

    backend
        .delete_outbound_dlq_entry(dismissed.id, test_audit())
        .await
        .unwrap();
    let left: Vec<_> = backend
        .list_outbound_dlq_entries(target.id)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(left, vec![kept.id]);
}

/// Expired device authorization requests are removed; a live one stays.
pub async fn test_cleanup_expired_device_auth_codes(backend: &dyn StorageBackend) {
    use sid_core::models::{DeviceAuthorizationCode, ProjectId};

    backend.ensure_system_project(test_audit()).await.unwrap();
    let resource = super::application::grant_resource(backend).await;
    let request = |expires_at| {
        let tag = Uuid::now_v7().simple().to_string();
        let mut code = DeviceAuthorizationCode::new(
            "test-client".to_string(),
            Uuid::now_v7().as_bytes().to_vec(),
            tag[tag.len() - 8..].to_uppercase(),
            None,
            resource,
            ProjectId::system(),
        );
        code.expires_at = expires_at;
        code
    };
    let expired = request(Utc::now() - Duration::minutes(5));
    let live = request(Utc::now() + Duration::minutes(10));
    for c in [&expired, &live] {
        backend
            .create_device_auth_code(c, test_audit())
            .await
            .unwrap();
    }

    let removed = backend
        .cleanup_expired_device_auth_codes(test_audit())
        .await
        .unwrap();
    assert!(removed >= 1, "{removed}");
    assert!(
        backend
            .get_device_auth_by_user_code(&expired.user_code)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .get_device_auth_by_user_code(&live.user_code)
            .await
            .unwrap()
            .is_some(),
        "a live request was removed"
    );
}

/// Expired magic links are removed; a live one stays.
pub async fn test_delete_expired_magic_link_sessions(backend: &dyn StorageBackend) {
    use sid_core::models::magic_link::MagicLinkSession;

    let link = |expires_at| {
        let id = Uuid::now_v7();
        MagicLinkSession {
            id,
            email: format!("ml-{}@sid.example.com", id.simple()),
            token_hash: format!("hash_{id}"),
            consumed: false,
            created_at: Utc::now() - Duration::hours(2),
            expires_at,
        }
    };
    let expired = link(Utc::now() - Duration::minutes(5));
    let live = link(Utc::now() + Duration::minutes(10));
    for l in [&expired, &live] {
        backend
            .create_magic_link_session(l, test_audit())
            .await
            .unwrap();
    }

    let removed = backend
        .delete_expired_magic_link_sessions(test_audit())
        .await
        .unwrap();
    assert!(removed >= 1, "{removed}");
    assert!(
        backend
            .get_magic_link_session(expired.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .get_magic_link_session(live.id)
            .await
            .unwrap()
            .is_some(),
        "a live link was removed"
    );
}

/// Expired password reset sessions are removed; a live one stays.
pub async fn test_delete_expired_reset_sessions(backend: &dyn StorageBackend) {
    use sid_core::models::PasswordResetSession;

    let profile = create_test_profile("reset_cleanup");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut expired =
        PasswordResetSession::new(profile.id, "r@sid.example.com".into(), "h1".into());
    expired.expires_at = Utc::now() - Duration::minutes(5);
    let live = PasswordResetSession::new(profile.id, "r@sid.example.com".into(), "h2".into());
    for r in [&expired, &live] {
        backend.create_reset_session(r, test_audit()).await.unwrap();
    }

    let removed = backend
        .delete_expired_reset_sessions(test_audit())
        .await
        .unwrap();
    assert!(removed >= 1, "{removed}");
    assert!(
        backend
            .get_reset_session(expired.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend.get_reset_session(live.id).await.unwrap().is_some(),
        "a live reset session was removed"
    );
}

/// A unique address of the documentation prefix (RFC 3849).
fn test_ip() -> String {
    std::net::Ipv6Addr::from(
        (0x2001_0db8_u128 << 96) | (Uuid::new_v4().as_u128() & ((1_u128 << 96) - 1)),
    )
    .to_string()
}

/// Decay halves the counters of entries not updated within the window and
/// removes those left at zero; an entry updated within it is untouched. A
/// window that cannot be expressed is an error and changes nothing.
pub async fn test_decay_ip_reputation(backend: &dyn StorageBackend, age: &AgeEntry) {
    let record = |ip: String, failed: u32, ok: u32| async move {
        for _ in 0..failed {
            backend
                .record_ip_reputation_event(&ip, false)
                .await
                .unwrap();
        }
        for _ in 0..ok {
            backend.record_ip_reputation_event(&ip, true).await.unwrap();
        }
    };
    let (stale, single, fresh) = (test_ip(), test_ip(), test_ip());
    record(stale.clone(), 4, 2).await;
    record(single.clone(), 1, 0).await;
    record(fresh.clone(), 3, 0).await;
    age(stale.clone()).await;
    age(single.clone()).await;

    assert!(
        backend
            .decay_ip_reputation(std::time::Duration::MAX)
            .await
            .is_err(),
        "a window beyond any date was accepted"
    );
    let score = |ip: String| async move { backend.get_ip_reputation_score(&ip).await.unwrap() };
    assert!(
        (score(stale.clone()).await.unwrap() - 4.0 / 7.0).abs() < 1e-6,
        "a refused decay changed an entry"
    );

    let removed = backend
        .decay_ip_reputation(std::time::Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(removed >= 1, "{removed}");
    let halved = score(stale).await.expect("the stale entry stays");
    assert!(
        (halved - 2.0 / 4.0).abs() < 1e-6,
        "stale entry score {halved}"
    );
    assert!(
        score(single).await.is_none(),
        "an entry left at zero was kept"
    );
    let untouched = score(fresh).await.unwrap();
    assert!(
        (untouched - 3.0 / 4.0).abs() < 1e-6,
        "a fresh entry decayed: {untouched}"
    );
}
