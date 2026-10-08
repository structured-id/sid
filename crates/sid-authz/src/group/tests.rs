// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_mock::MockStorage;

async fn setup() -> (GroupService<MockStorage>, Arc<MockStorage>, ProjectId) {
    let storage = Arc::new(MockStorage::new());
    let service = GroupService::new(storage.clone());
    let project_id = ProjectId::new();
    (service, storage, project_id)
}

#[tokio::test]
async fn test_create_group() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "engineering", Some("Engineers".into()))
        .await
        .unwrap();

    assert_eq!(group.name, "engineering");
    assert_eq!(group.description.as_deref(), Some("Engineers"));
    assert_eq!(group.project_id, project_id);
    assert!(group.parent_group_id.is_none());
}

#[tokio::test]
async fn test_add_member() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "team", None)
        .await
        .unwrap();
    let profile_id = ProfileId::generate();

    let member = service.add_member(group.id, profile_id).await.unwrap();
    assert_eq!(member.group_id, group.id);
    assert_eq!(member.profile_id, profile_id);
}

#[tokio::test]
async fn test_add_member_duplicate() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "team", None)
        .await
        .unwrap();
    let profile_id = ProfileId::generate();

    service.add_member(group.id, profile_id).await.unwrap();
    let result = service.add_member(group.id, profile_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_add_member_group_not_found() {
    let (service, _, _) = setup().await;
    let result = service
        .add_member(GroupId::new(), ProfileId::generate())
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_member() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "team", None)
        .await
        .unwrap();
    let profile_id = ProfileId::generate();

    service.add_member(group.id, profile_id).await.unwrap();
    assert!(service.is_member(group.id, profile_id).await.unwrap());

    service.remove_member(group.id, profile_id).await.unwrap();
    assert!(!service.is_member(group.id, profile_id).await.unwrap());
}

#[tokio::test]
async fn test_is_member() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "team", None)
        .await
        .unwrap();
    let profile_id = ProfileId::generate();

    assert!(!service.is_member(group.id, profile_id).await.unwrap());
    service.add_member(group.id, profile_id).await.unwrap();
    assert!(service.is_member(group.id, profile_id).await.unwrap());
}

#[tokio::test]
async fn test_list_members() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "team", None)
        .await
        .unwrap();

    let p1 = ProfileId::generate();
    let p2 = ProfileId::generate();
    service.add_member(group.id, p1).await.unwrap();
    service.add_member(group.id, p2).await.unwrap();

    let members = service.list_members(group.id).await.unwrap();
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn test_list_groups_for_profile() {
    let (service, _, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let g1 = service
        .create_group(project_id, "team-a", None)
        .await
        .unwrap();
    let g2 = service
        .create_group(project_id, "team-b", None)
        .await
        .unwrap();

    service.add_member(g1.id, profile_id).await.unwrap();
    service.add_member(g2.id, profile_id).await.unwrap();

    let groups = service.list_groups_for_profile(profile_id).await.unwrap();
    assert_eq!(groups.len(), 2);
}

#[tokio::test]
async fn test_list_groups_in_project() {
    let (service, _, project_id) = setup().await;

    service.create_group(project_id, "a", None).await.unwrap();
    service.create_group(project_id, "b", None).await.unwrap();

    let groups = service.list_groups_in_project(project_id).await.unwrap();
    assert_eq!(groups.len(), 2);
}

#[tokio::test]
async fn test_delete_group() {
    let (service, _, project_id) = setup().await;
    let group = service
        .create_group(project_id, "temp", None)
        .await
        .unwrap();

    service.delete_group(group.id).await.unwrap();

    let groups = service.list_groups_in_project(project_id).await.unwrap();
    assert!(groups.is_empty());
}
