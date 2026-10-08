use super::*;
use crate::test_mock::MockStorage;
use sid_core::models::{
    AUTHZ_CHECK, PERMISSION_CHECKER_ROLE, SCIM_ACTIONS, SCIM_PROVISIONER_ROLE,
    TOKEN_INSPECTOR_ROLE, TOKEN_INTROSPECT,
};

fn stored_with_key(roles: &[Role], key: &str) -> usize {
    roles.iter().filter(|r| r.key == key).count()
}

/// The role is created once: a second start reads the stored one back.
#[tokio::test]
async fn the_token_inspector_role_is_provisioned_once() {
    let storage = MockStorage::new();
    let first = ensure_token_inspector_role(&storage).await.unwrap();
    assert_eq!(first.project_id, ProjectId::system());
    assert!(first.has_permission(TOKEN_INTROSPECT));

    let again = ensure_token_inspector_role(&storage).await.unwrap();
    assert_eq!(again.id, first.id);
    let roles = storage.list_roles(ProjectId::system()).await.unwrap();
    assert_eq!(stored_with_key(&roles, TOKEN_INSPECTOR_ROLE), 1);
}

/// The SCIM provisioner role is created once, beside the inspector, and
/// grants every SCIM action and nothing else.
#[tokio::test]
async fn the_scim_provisioner_role_is_provisioned_once() {
    let storage = MockStorage::new();
    ensure_token_inspector_role(&storage).await.unwrap();
    let first = ensure_scim_provisioner_role(&storage).await.unwrap();
    assert_eq!(first.project_id, ProjectId::system());
    assert_eq!(first.permissions, SCIM_ACTIONS.map(String::from).to_vec());

    let again = ensure_scim_provisioner_role(&storage).await.unwrap();
    assert_eq!(again.id, first.id);
    let roles = storage.list_roles(ProjectId::system()).await.unwrap();
    assert_eq!(stored_with_key(&roles, SCIM_PROVISIONER_ROLE), 1);
    assert_eq!(stored_with_key(&roles, TOKEN_INSPECTOR_ROLE), 1);
}

/// The permission checker role is created once, beside the inspector, and
/// grants the permission query alone.
#[tokio::test]
async fn the_permission_checker_role_is_provisioned_once() {
    let storage = MockStorage::new();
    ensure_token_inspector_role(&storage).await.unwrap();
    let first = ensure_permission_checker_role(&storage).await.unwrap();
    assert_eq!(first.project_id, ProjectId::system());
    assert_eq!(first.permissions, vec![AUTHZ_CHECK.to_string()]);

    let again = ensure_permission_checker_role(&storage).await.unwrap();
    assert_eq!(again.id, first.id);
    let roles = storage.list_roles(ProjectId::system()).await.unwrap();
    assert_eq!(stored_with_key(&roles, PERMISSION_CHECKER_ROLE), 1);
    assert_eq!(stored_with_key(&roles, TOKEN_INSPECTOR_ROLE), 1);
}
