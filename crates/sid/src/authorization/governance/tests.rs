use std::sync::Arc;

use super::*;
use crate::test_support::{administrator, operation, storage, stored_profile};
use sid_core::models::{INSTALLATION_SCOPE, ProjectId};
use sid_plugin::storage::StorageBackend;

/// Each request state answers as its own wire value.
#[test]
fn test_status_to_proto() {
    for (domain, wire) in [
        (DomainStatus::Pending, AccessRequestStatus::Pending),
        (DomainStatus::Approved, AccessRequestStatus::Approved),
        (DomainStatus::Denied, AccessRequestStatus::Denied),
        (DomainStatus::Expired, AccessRequestStatus::Expired),
        (DomainStatus::Cancelled, AccessRequestStatus::Cancelled),
    ] {
        assert_eq!(status_to_proto(domain), wire as i32);
    }
}

/// A store with a role `reviewer` in the system project, its installation
/// administrator and a member who requests roles.
struct Fixture {
    storage: Arc<sid_storage::sqlite::SqliteBackend>,
    authorization: Authorization,
    admin: InstallationAdministrator,
    member: ProfileId,
}

async fn fixture() -> Fixture {
    let storage = storage().await;
    let admin_id = stored_profile(storage.as_ref(), "governance_admin").await;
    storage
        .create_role(
            &Role::installation_administrator(),
            AuditEntry::system("test", "role").into(),
        )
        .await
        .unwrap();
    let mut held = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(admin_id),
        Role::installation_administrator().id,
    );
    held.scope = Some(INSTALLATION_SCOPE.into());
    storage
        .create_role_assignment(&held, AuditEntry::system("test", "admin").into())
        .await
        .unwrap();
    storage
        .create_role(
            &Role::new(ProjectId::SYSTEM, "reviewer", "Reviewer"),
            AuditEntry::system("test", "role").into(),
        )
        .await
        .unwrap();
    let member = stored_profile(storage.as_ref(), "governance_member").await;
    Fixture {
        authorization: Authorization::new(storage.clone(), sid_authz::cedar::CedarService::new()),
        admin: InstallationAdministrator {
            caller: administrator(admin_id),
        },
        storage,
        member,
    }
}

fn ask(member: ProfileId) -> AccessRequestMessage {
    AccessRequestMessage {
        requester_profile_id: Some(member.into()),
        project_id: Some(ProjectId::SYSTEM.into()),
        requested_role: "reviewer".into(),
        justification: "audits".into(),
        requested_duration: None,
    }
}

/// A request's lost response is retried: the retry answers with the request
/// it made and no second request is pending.
#[tokio::test]
async fn test_access_request_retry_answers_with_its_request() {
    let f = fixture().await;
    let caller = f.admin.caller().clone();
    let first = f
        .authorization
        .request_access(
            &caller,
            operation(f.storage.as_ref(), "op-ask").await,
            ask(f.member),
        )
        .await
        .unwrap();
    let retry = f
        .authorization
        .request_access(
            &caller,
            operation(f.storage.as_ref(), "op-ask").await,
            ask(f.member),
        )
        .await
        .unwrap();

    assert_eq!(retry, first);
    assert_eq!(
        f.storage
            .list_pending_access_requests()
            .await
            .unwrap()
            .len(),
        1,
        "the retry made another request"
    );
}

/// A request is approved, then the approval's lost response is retried: the
/// retry answers as the approval did, not as a request already decided, and
/// grants the role once.
#[tokio::test]
async fn test_decision_retry_answers_as_the_decision() {
    let f = fixture().await;
    let caller = f.admin.caller().clone();
    let request = f
        .authorization
        .request_access(
            &caller,
            operation(f.storage.as_ref(), "op-req").await,
            ask(f.member),
        )
        .await
        .unwrap();
    let approve = || DecideRequestRequest {
        request_id: request.request_id.clone(),
        approved: true,
        reason: String::new(),
    };

    let first = f
        .authorization
        .decide_request(
            &f.admin,
            operation(f.storage.as_ref(), "op-yes").await,
            approve(),
        )
        .await
        .unwrap();
    let retry = f
        .authorization
        .decide_request(
            &f.admin,
            operation(f.storage.as_ref(), "op-yes").await,
            approve(),
        )
        .await
        .expect("the retry answers as the approval did");

    assert_eq!(retry, first);
    assert_eq!(
        f.storage
            .list_role_assignments_for_profile(f.member)
            .await
            .unwrap()
            .len(),
        1,
        "the retry granted the role again"
    );
}

/// A temporary role is granted, its response is lost and the retry comes
/// after its expiry: the retry answers with the assignment the grant made,
/// not as an expiry no longer in the future.
#[tokio::test]
async fn test_temporary_role_retry_after_its_expiry_answers_the_grant() {
    let f = fixture().await;
    let until = chrono::Utc::now() + chrono::Duration::milliseconds(300);
    let grant = || GrantTemporaryRoleRequest {
        profile_id: Some(f.member.into()),
        project_id: Some(ProjectId::SYSTEM.into()),
        role: "reviewer".into(),
        justification: "incident review".into(),
        expires_at: Some(to_timestamp(until)),
    };
    let first = f
        .authorization
        .grant_temporary_role(
            &f.admin,
            operation(f.storage.as_ref(), "op-short").await,
            grant(),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let retry = f
        .authorization
        .grant_temporary_role(
            &f.admin,
            operation(f.storage.as_ref(), "op-short").await,
            grant(),
        )
        .await
        .expect("the retry answers with the grant it made");
    assert_eq!(retry, first);
}

/// A temporary role's grant is retried after its response was lost: the
/// retry answers with the assignment it made and grants no second one.
#[tokio::test]
async fn test_temporary_role_retry_grants_once() {
    let f = fixture().await;
    // A retry sends the request it sent before.
    let until = chrono::Utc::now() + chrono::Duration::hours(4);
    let grant = || GrantTemporaryRoleRequest {
        profile_id: Some(f.member.into()),
        project_id: Some(ProjectId::SYSTEM.into()),
        role: "reviewer".into(),
        justification: "incident review".into(),
        expires_at: Some(to_timestamp(until)),
    };

    let first = f
        .authorization
        .grant_temporary_role(
            &f.admin,
            operation(f.storage.as_ref(), "op-temp").await,
            grant(),
        )
        .await
        .unwrap();
    let retry = f
        .authorization
        .grant_temporary_role(
            &f.admin,
            operation(f.storage.as_ref(), "op-temp").await,
            grant(),
        )
        .await
        .unwrap();

    assert_eq!(retry, first);
    assert_eq!(
        f.storage
            .list_role_assignments_for_profile(f.member)
            .await
            .unwrap()
            .len(),
        1,
        "the retry granted another assignment"
    );
}
