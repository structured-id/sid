// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of MachineUserService: machine users, their credentials and
//! their impersonation grants are instance administration. Without this,
//! anyone could mint a service account, issue it a secret and grant it the
//! right to act as any user.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token};
use sid_core::models::{MachineOwner, MachineUser, MachineUserId, Profile, ProfileId, ProjectId};
use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

/// `msg` with `token` as its bearer, or without credentials.
/// `msg` as one new command, of `token`'s when given (a method that promises
/// a safe retry takes an operation key).
fn req<T>(msg: T, token: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    common::name_new_command(req.metadata_mut());
    req
}

/// A stored machine user every RPC can name.
fn existing() -> MachineUser {
    MachineUser::new(
        ProjectId::SYSTEM,
        "mu_existing",
        "existing",
        MachineOwner::System,
    )
}

/// The status code each of the 14 RPCs answers for `token`, in declaration
/// order; `None` when the call succeeds.
async fn codes(svc: &TestServices, id: MachineUserId, token: Option<&str>) -> Vec<Option<Code>> {
    let m = &svc.machine_user;
    let project = Some(ProjectId::SYSTEM.into());
    let id = Some(id.into());
    vec![
        m.create_machine_user(req(
            CreateMachineUserRequest {
                project_id: project.clone(),
                display_name: "rogue".to_string(),
                ..Default::default()
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.get_machine_user(req(
            GetMachineUserRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.update_machine_user(req(
            UpdateMachineUserRequest {
                machine_user_id: id.clone(),
                display_name: "renamed".to_string(),
                ..Default::default()
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.list_machine_users(req(
            ListMachineUsersRequest {
                project_id: project.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.suspend_machine_user(req(
            SuspendMachineUserRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.reactivate_machine_user(req(
            ReactivateMachineUserRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.add_machine_credential(req(
            AddMachineCredentialRequest {
                machine_user_id: id.clone(),
                credential_type: MachineCredentialType::ClientSecret.into(),
                ..Default::default()
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.list_machine_credentials(req(
            ListMachineCredentialsRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.rotate_machine_credential(req(
            RotateMachineCredentialRequest {
                machine_user_id: id.clone(),
                kid: "kid_missing".to_string(),
                ..Default::default()
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.revoke_machine_credential(req(
            RevokeMachineCredentialRequest {
                machine_user_id: id.clone(),
                kid: "kid_missing".to_string(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.grant_impersonation(req(
            GrantImpersonationRequest {
                machine_user_id: id.clone(),
                target_type: ImpersonationTargetType::User.into(),
                target: ProfileId::generate().to_string(),
                allowed_scopes: vec!["*".to_string()],
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.list_impersonation_grants(req(
            ListImpersonationGrantsRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.revoke_impersonation(req(
            RevokeImpersonationRequest {
                machine_user_id: id.clone(),
                target_type: "user".to_string(),
                target: ProfileId::generate().to_string(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        m.delete_machine_user(req(
            DeleteMachineUserRequest {
                machine_user_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
    ]
}

/// Regression:without a token no RPC acts, and the stored machine
/// user is left as it was.
#[tokio::test]
async fn test_machine_user_rpcs_require_a_token() {
    let mu = existing();
    let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
    let got = codes(&svc, mu.id, None).await;
    assert_eq!(got.len(), 14);
    for (i, code) in got.into_iter().enumerate() {
        assert_eq!(code, Some(Code::Unauthenticated), "rpc #{i}");
    }
    let stored = svc
        .storage
        .get_machine_user(mu.id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(stored.display_name, mu.display_name);
    assert_eq!(stored.status, mu.status);
}

/// Regression:a signed-in user without the administrator role cannot
/// create a machine user, issue it credentials or grant it impersonation.
#[tokio::test]
async fn test_machine_user_rpcs_refuse_a_non_admin() {
    let mu = existing();
    let user = Profile::new(Some("mallory"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(user.clone())
            .with_machine_user(mu.clone()),
    );
    let token = issue_token(&svc.jwt, &user, &["openid".to_string()]);
    let got = codes(&svc, mu.id, Some(&token)).await;
    for (i, code) in got.into_iter().enumerate() {
        assert_eq!(code, Some(Code::PermissionDenied), "rpc #{i}");
    }
    assert!(svc.mock_storage.machine_user_audits().is_empty());
}

/// A machine user created by an administrator records that administrator as
/// the actor, not a placeholder.
#[tokio::test]
async fn test_machine_user_creation_records_the_administrator() {
    let svc = TestServices::new(MockStorage::new());
    let admin = ProfileId::generate();
    let token = issue_admin_token(&svc.jwt, admin);
    svc.machine_user
        .create_machine_user(req(
            CreateMachineUserRequest {
                project_id: Some(ProjectId::SYSTEM.into()),
                display_name: "billing".to_string(),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .expect("admin creates");
    let audits = svc.mock_storage.machine_user_audits();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].actor_id, admin.to_string());
}

/// A machine user an administrator creates belongs to the installation's
/// organization: the administrator acts for it. It is never system-owned,
/// which only the installation's own provisioning establishes.
#[tokio::test]
async fn test_an_administrators_machine_user_belongs_to_the_organization() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let created = svc
        .machine_user
        .create_machine_user(req(
            CreateMachineUserRequest {
                project_id: Some(ProjectId::SYSTEM.into()),
                display_name: "billing".to_string(),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .unwrap()
        .into_inner()
        .machine_user
        .unwrap();
    assert_eq!(
        created.owner.and_then(|o| o.owner),
        Some(machine_user_owner::Owner::Organization(
            common::test_org().into()
        ))
    );
}

/// An unknown machine user is MACHINE_USER_NOT_FOUND naming it in
/// ResourceInfo, not a generic not-found text.
#[tokio::test]
async fn test_unknown_machine_user_is_machine_user_not_found() {
    use tonic_types::StatusExt;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let id = existing().id;
    let err = svc
        .machine_user
        .get_machine_user(req(
            GetMachineUserRequest {
                machine_user_id: Some(id.into()),
            },
            Some(&token),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(
        details.error_info().unwrap().reason,
        "MACHINE_USER_NOT_FOUND"
    );
    assert_eq!(
        details.resource_info().unwrap().resource_name,
        id.to_string()
    );
}

/// A deleted machine user cannot be suspended: INVALID_STATE whose
/// PreconditionFailure names the state and the machine user.
#[tokio::test]
async fn test_suspending_a_deleted_machine_user_is_invalid_state() {
    use sid_core::models::MachineUserStatus;
    use tonic_types::StatusExt;
    let mut mu = existing();
    mu.status = MachineUserStatus::Deleted;
    let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .machine_user
        .suspend_machine_user(req(
            SuspendMachineUserRequest {
                machine_user_id: Some(mu.id.into()),
            },
            Some(&token),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "MACHINE_USER_STATE");
    assert_eq!(violation.subject, mu.id.to_string());
    assert_eq!(violation.description, "deleted");
}

/// A suspension of a machine user already suspended changes nothing and is
/// still its command's outcome: retried after a reactivation it answers as
/// it did and does not suspend the machine user again. The same holds for a
/// reactivation of an active one retried after a suspension.
#[tokio::test]
async fn test_a_state_change_already_in_effect_is_recorded_for_its_retry() {
    use sid_core::models::MachineUserStatus;
    let mut mu = existing();
    mu.status = MachineUserStatus::Suspended;
    let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let keyed = |key: &str| {
        let mut r = Request::new(Some(mu.id.into()));
        r.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        common::name_command(r.metadata_mut(), key);
        r
    };
    let suspend = |key: &str| {
        let r = keyed(key);
        let (meta, ext, id) = r.into_parts();
        Request::from_parts(
            meta,
            ext,
            SuspendMachineUserRequest {
                machine_user_id: id,
            },
        )
    };
    let reactivate = |key: &str| {
        let r = keyed(key);
        let (meta, ext, id) = r.into_parts();
        Request::from_parts(
            meta,
            ext,
            ReactivateMachineUserRequest {
                machine_user_id: id,
            },
        )
    };
    let status = || async {
        svc.storage
            .get_machine_user(mu.id)
            .await
            .unwrap()
            .unwrap()
            .status
    };
    let m = &svc.machine_user;

    m.suspend_machine_user(suspend("k-suspended"))
        .await
        .unwrap();
    m.reactivate_machine_user(reactivate("k-reactivate"))
        .await
        .unwrap();
    m.suspend_machine_user(suspend("k-suspended"))
        .await
        .unwrap();
    assert_eq!(status().await, MachineUserStatus::Active, "suspended again");

    m.reactivate_machine_user(reactivate("k-active"))
        .await
        .unwrap();
    m.suspend_machine_user(suspend("k-suspend")).await.unwrap();
    m.reactivate_machine_user(reactivate("k-active"))
        .await
        .unwrap();
    assert_eq!(
        status().await,
        MachineUserStatus::Suspended,
        "reactivated again"
    );
}

/// A rotated-out secret works only for its grace period: the rotation gives
/// it an end 72 hours away, instead of leaving it valid for ever.
#[tokio::test]
async fn test_a_rotated_credential_has_a_grace_end() {
    let mu = existing();
    let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let added = svc
        .machine_user
        .add_machine_credential(req(
            AddMachineCredentialRequest {
                machine_user_id: Some(mu.id.into()),
                credential_type: MachineCredentialType::ClientSecret as i32,
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .unwrap()
        .into_inner();
    let kid = added.credential.unwrap().kid;
    let before = chrono::Utc::now();
    let rotated = svc
        .machine_user
        .rotate_machine_credential(req(
            RotateMachineCredentialRequest {
                machine_user_id: Some(mu.id.into()),
                kid: kid.clone(),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .unwrap()
        .into_inner();
    let old = rotated.old_credential.unwrap();
    assert_eq!(old.status, MachineCredentialStatus::GracePeriod as i32);
    let end = old.expires_at.expect("a grace end").seconds;
    let grace = chrono::Duration::hours(72);
    assert!(end >= (before + grace).timestamp() - 1, "{end}");
    assert!(end <= (chrono::Utc::now() + grace).timestamp() + 1, "{end}");
    let stored = svc
        .storage
        .get_machine_credential_by_kid(&kid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.expires_at.unwrap().timestamp(), end);
}

/// Revoking a credential, suspending the machine user or deleting it stops
/// the tokens already issued at every replica and at every resource: the
/// credentials they were issued for are revoked in the shared cache.
#[tokio::test]
async fn test_revocation_reaches_issued_tokens() {
    let token_ids = |kid: &str| ("jti-unrelated".to_string(), kid.to_string());
    for action in ["revoke", "suspend", "delete"] {
        let mu = existing();
        let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
        let token = issue_admin_token(&svc.jwt, ProfileId::generate());
        let mut kids = Vec::new();
        for _ in 0..2 {
            let added = svc
                .machine_user
                .add_machine_credential(req(
                    AddMachineCredentialRequest {
                        machine_user_id: Some(mu.id.into()),
                        credential_type: MachineCredentialType::ClientSecret as i32,
                        ..Default::default()
                    },
                    Some(&token),
                ))
                .await
                .unwrap()
                .into_inner();
            kids.push(added.credential.unwrap().kid);
        }
        let id = Some(mu.id.into());
        match action {
            "revoke" => {
                svc.machine_user
                    .revoke_machine_credential(req(
                        RevokeMachineCredentialRequest {
                            machine_user_id: id,
                            kid: kids[0].clone(),
                        },
                        Some(&token),
                    ))
                    .await
                    .unwrap();
            }
            "suspend" => {
                svc.machine_user
                    .suspend_machine_user(req(
                        SuspendMachineUserRequest {
                            machine_user_id: id,
                        },
                        Some(&token),
                    ))
                    .await
                    .unwrap();
            }
            _ => {
                svc.machine_user
                    .delete_machine_user(req(
                        DeleteMachineUserRequest {
                            machine_user_id: id,
                        },
                        Some(&token),
                    ))
                    .await
                    .unwrap();
            }
        }
        for (n, kid) in kids.iter().enumerate() {
            let (jti, sid) = token_ids(kid);
            let revoked = svc.revocation_cache.is_revoked(&jti, &sid).await.unwrap();
            // A single credential's revocation leaves the other working.
            let expected = action != "revoke" || n == 0;
            assert_eq!(revoked, expected, "{action}: credential {n}");
        }
    }
}

/// Rotating a credential the machine user does not hold is
/// CREDENTIAL_NOT_FOUND naming the kid.
#[tokio::test]
async fn test_rotating_an_unknown_kid_is_credential_not_found() {
    use tonic_types::StatusExt;
    let mu = existing();
    let svc = TestServices::new(MockStorage::new().with_machine_user(mu.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .machine_user
        .rotate_machine_credential(req(
            RotateMachineCredentialRequest {
                machine_user_id: Some(mu.id.into()),
                kid: "kid_missing".to_string(),
                ..Default::default()
            },
            Some(&token),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "CREDENTIAL_NOT_FOUND");
    assert_eq!(
        details.resource_info().unwrap().resource_name,
        "kid_missing"
    );
}
