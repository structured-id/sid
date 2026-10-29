// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{AuditEntry, Role, RoleAssignmentPrincipal};
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

async fn stored(storage: &SqliteBackend, roles: &[&str]) -> Profile {
    let mut profile = Profile::new(Some(format!("u{}", uuid::Uuid::now_v7().simple())));
    profile.roles = roles.iter().map(|r| r.to_string()).collect();
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile
}

async fn administer(storage: &SqliteBackend, assignment: RoleAssignment) {
    match storage
        .create_role(
            &Role::installation_administrator(),
            AuditEntry::system("test", "role").into(),
        )
        .await
    {
        Ok(()) | Err(sid_core::Error::Conflict(_)) => {}
        Err(e) => panic!("store the administrator role: {e}"),
    }
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "assignment").into())
        .await
        .unwrap();
}

fn installation_wide(profile: ProfileId) -> RoleAssignment {
    RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(profile),
        Role::installation_administrator().id,
    )
    .on_installation()
}

/// Regression: a token's administrator role was read from a label on the
/// Profile, which a profile update, an import or a directory could write.
/// A stored `admin` label now gives no administrator role; the installation
/// administrator assignment gives it, and the Profile's other labels stay.
#[tokio::test]
async fn the_administrator_role_comes_from_the_assignment_only() {
    let storage = storage().await;
    let labelled = stored(&storage, &["editor", ADMIN_ROLE_CLAIM]).await;
    assert_eq!(
        account_roles(&storage, &labelled).await.unwrap(),
        vec!["editor".to_string()]
    );

    let administrator = stored(&storage, &["editor"]).await;
    administer(&storage, installation_wide(administrator.id)).await;
    assert_eq!(
        account_roles(&storage, &administrator).await.unwrap(),
        vec!["editor".to_string(), ADMIN_ROLE_CLAIM.to_string()]
    );
}

/// The administrator role on one resource, or an expired assignment across
/// the installation, makes no installation administrator.
#[tokio::test]
async fn only_a_live_installation_wide_assignment_counts() {
    let storage = storage().await;
    let scoped = stored(&storage, &[]).await;
    administer(
        &storage,
        RoleAssignment::new(
            RoleAssignmentPrincipal::Profile(scoped.id),
            Role::installation_administrator().id,
        )
        .on_resource(sid_core::models::ResourceId::generate()),
    )
    .await;
    assert!(!administers_installation(&storage, scoped.id).await.unwrap());

    let expired = stored(&storage, &[]).await;
    administer(
        &storage,
        installation_wide(expired.id)
            .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1)),
    )
    .await;
    assert!(
        !administers_installation(&storage, expired.id)
            .await
            .unwrap()
    );
}
