// SPDX-License-Identifier: AGPL-3.0-only
//! Upstream providers and the identities linked through them: created once,
//! a provider updated only over the revision it was read at, a login counted
//! in place.

use sid_core::models::{UpstreamIdentity, UpstreamLogin, UpstreamProtocol, UpstreamProvider};
use sid_keys::EncryptedField;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

fn provider() -> UpstreamProvider {
    let secret = EncryptedField {
        ciphertext: vec![7; 32],
        nonce: [3; 12],
        key_version: 1,
        context: "upstream:test".into(),
    };
    UpstreamProvider::new(
        format!("idp-{}", Uuid::now_v7().simple()),
        UpstreamProtocol::Oidc,
        "client",
        secret,
    )
}

fn login(email: &str) -> UpstreamLogin {
    UpstreamLogin {
        email: Some(email.into()),
        name: None,
        picture: None,
        at: chrono::Utc::now(),
    }
}

/// A second create never replaces a provider; a stale copy never re-enables
/// a provider disabled since, and an update never recreates a deleted one.
pub async fn test_upstream_provider_write_contract(backend: &dyn StorageBackend) {
    let created = provider();
    backend
        .create_upstream_provider(&created, test_audit())
        .await
        .unwrap();
    let mut replacement = created.clone();
    replacement.client_id = "attacker".into();
    let err = backend
        .create_upstream_provider(&replacement, test_audit())
        .await
        .expect_err("a second create must not replace the provider");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    let stored = backend
        .get_upstream_provider(created.id)
        .await
        .unwrap()
        .expect("provider stored");
    assert_eq!(stored.client_id, "client");
    assert_eq!(
        stored.client_secret.to_bytes(),
        created.client_secret.to_bytes()
    );
    assert_eq!(stored.scopes, created.scopes);
    assert_eq!(stored.revision, 0);

    let stale = stored.clone();
    let mut disable = stored;
    disable.enabled = false;
    assert!(
        backend
            .update_upstream_provider(&disable, test_audit())
            .await
            .unwrap()
    );
    let mut stale_edit = stale;
    stale_edit.display_order = 9;
    assert!(
        !backend
            .update_upstream_provider(&stale_edit, test_audit())
            .await
            .unwrap(),
        "an update over a stale revision must not apply"
    );
    let current = backend
        .get_upstream_provider(created.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!current.enabled, "a stale copy re-enabled the provider");
    assert_eq!(current.revision, 1);

    backend
        .delete_upstream_provider(created.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .update_upstream_provider(&current, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .get_upstream_provider(created.id)
            .await
            .unwrap()
            .is_none(),
        "an update recreated a deleted provider"
    );
}

/// An upstream subject is linked to one profile: linking it again, to this
/// profile or another, is `Conflict` and the first link stays.
pub async fn test_upstream_identity_never_relinked(backend: &dyn StorageBackend) {
    let idp = provider();
    backend
        .create_upstream_provider(&idp, test_audit())
        .await
        .unwrap();
    let owner = create_test_profile("upstream_owner");
    let other = create_test_profile("upstream_other");
    backend.create_profile(&owner, test_audit()).await.unwrap();
    backend.create_profile(&other, test_audit()).await.unwrap();

    let subject = format!("sub-{}", Uuid::now_v7().simple());
    let link = UpstreamIdentity::new(owner.id, idp.id, &subject);
    backend
        .create_upstream_identity(&link, test_audit())
        .await
        .unwrap();

    let takeover = UpstreamIdentity::new(other.id, idp.id, &subject);
    let err = backend
        .create_upstream_identity(&takeover, test_audit())
        .await
        .expect_err("a subject is linked to one profile");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    let mut replayed = link.clone();
    replayed.profile_id = other.id;
    let err = backend
        .create_upstream_identity(&replayed, test_audit())
        .await
        .expect_err("a second create must not relink");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    let stored = backend
        .get_upstream_identity_by_provider_subject(idp.id, &subject)
        .await
        .unwrap()
        .expect("link stored");
    assert_eq!(stored.profile_id, owner.id);
}

/// Concurrent logins through one link are all counted; a removed link
/// records none.
pub async fn test_record_upstream_login_counts_every_login(backend: &dyn StorageBackend) {
    let idp = provider();
    backend
        .create_upstream_provider(&idp, test_audit())
        .await
        .unwrap();
    let owner = create_test_profile("upstream_login");
    backend.create_profile(&owner, test_audit()).await.unwrap();
    let link = UpstreamIdentity::new(owner.id, idp.id, format!("sub-{}", Uuid::now_v7()));
    backend
        .create_upstream_identity(&link, test_audit())
        .await
        .unwrap();

    let (first, second, third) = (
        login("a@sid.example.com"),
        login("b@sid.example.com"),
        login("c@sid.example.com"),
    );
    let (a, b, c) = tokio::join!(
        backend.record_upstream_login(link.id, &first, test_audit()),
        backend.record_upstream_login(link.id, &second, test_audit()),
        backend.record_upstream_login(link.id, &third, test_audit()),
    );
    assert!(a.unwrap() && b.unwrap() && c.unwrap());
    let stored = backend
        .get_upstream_identity_by_provider_subject(idp.id, &link.upstream_subject)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.login_count, 3, "a concurrent login was lost");
    assert!(stored.last_login_at.is_some());
    assert!(stored.upstream_email.is_some());

    backend
        .delete_upstream_identity(link.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .record_upstream_login(link.id, &login("d@sid.example.com"), test_audit())
            .await
            .unwrap()
    );
}

/// The login screen lists enabled providers only; identities list per
/// profile across providers.
pub async fn test_enabled_providers_and_identities_by_profile(backend: &dyn StorageBackend) {
    let enabled = provider();
    let mut disabled = provider();
    disabled.enabled = false;
    for p in [&enabled, &disabled] {
        backend
            .create_upstream_provider(p, test_audit())
            .await
            .unwrap();
    }
    let listed: Vec<_> = backend
        .list_enabled_upstream_providers()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert!(
        listed.contains(&enabled.id),
        "an enabled provider is missing"
    );
    assert!(
        !listed.contains(&disabled.id),
        "a disabled provider was listed"
    );

    let profile = create_test_profile("upstream_links");
    let other = create_test_profile("upstream_other");
    for p in [&profile, &other] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    let a = UpstreamIdentity::new(profile.id, enabled.id, format!("sub-{}", Uuid::now_v7()));
    let b = UpstreamIdentity::new(profile.id, disabled.id, format!("sub-{}", Uuid::now_v7()));
    let foreign = UpstreamIdentity::new(other.id, enabled.id, format!("sub-{}", Uuid::now_v7()));
    for i in [&a, &b, &foreign] {
        backend
            .create_upstream_identity(i, test_audit())
            .await
            .unwrap();
    }
    let mut ids: Vec<_> = backend
        .list_upstream_identities_by_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.id)
        .collect();
    ids.sort_by_key(|id| id.0);
    let mut expected = vec![a.id, b.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(ids, expected);
}
