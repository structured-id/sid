// SPDX-License-Identifier: AGPL-3.0-only
//! Durable operation results: a keyed ordinary mutation retried after its
//! response was lost returns the original outcome and executes once.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token};
use sid_core::models::ProfileId;
use sid_infra::grpc_error::extract_error_info;
use sid_proto::sid::v1::project_service_server::ProjectService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn keyed<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    if let Some(key) = key {
        common::name_command(req.metadata_mut(), key);
    }
    req
}

fn create(name: &str) -> CreateProjectRequest {
    CreateProjectRequest {
        name: name.to_string(),
        ..Default::default()
    }
}

async fn projects_named(svc: &TestServices, token: &str, name: &str) -> usize {
    svc.project
        .list_projects(keyed(ListProjectsRequest::default(), token, None))
        .await
        .unwrap()
        .into_inner()
        .projects
        .iter()
        .filter(|p| p.name == name)
        .count()
}

/// The response of CreateProject is lost after the commit; the caller
/// retries with the same key and gets the same project, and only one exists.
#[tokio::test]
async fn test_create_project_retry_returns_original_outcome() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    let first = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-1")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-1")))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry.id, first.id);
    assert_eq!(projects_named(&svc, &token, "billing").await, 1);
}

/// A new command needs a new key: the same key with other inputs is refused
/// and changes nothing.
#[tokio::test]
async fn test_create_project_key_reused_for_other_inputs_conflicts() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    svc.project
        .create_project(keyed(create("billing"), &token, Some("op-2")))
        .await
        .unwrap();

    let err = svc
        .project
        .create_project(keyed(create("payroll"), &token, Some("op-2")))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::AlreadyExists);
    assert_eq!(
        extract_error_info(&err).expect("ErrorInfo").0,
        "OPERATION_KEY_CONFLICT"
    );
    assert_eq!(projects_named(&svc, &token, "payroll").await, 0);
}

/// Without a key the method cannot promise a safe retry, so it refuses
/// before any effect.
#[tokio::test]
async fn test_create_project_without_key_is_refused() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .project
        .create_project(keyed(create("billing"), &token, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(projects_named(&svc, &token, "billing").await, 0);
}

/// `msg` from the bearer of `token` named by `key` under `period`.
fn in_period<T>(msg: T, token: &str, key: &str, period: u64) -> Request<T> {
    let mut req = keyed(msg, token, None);
    sid_infra::authn::operation::insert_context(
        req.metadata_mut(),
        &sid_core::models::OperationContext::new(
            sid_core::models::OperationKey::parse(key).unwrap(),
            sid_core::models::OperationPeriod::new(period),
        ),
    );
    req
}

/// A period the store issues after the test's own, far in the future so the
/// test can retire everything before it.
async fn later_period(svc: &TestServices) -> sid_core::models::IssuedOperationPeriod {
    let later = chrono::DateTime::<chrono::Utc>::MAX_UTC - chrono::Duration::days(1);
    svc.storage
        .current_operation_period(later, chrono::Duration::hours(1))
        .await
        .unwrap()
}

/// The same key under another period is not a retry of the command: it is
/// refused as a conflict and creates nothing.
#[tokio::test]
async fn test_same_key_under_another_period_conflicts() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    svc.project
        .create_project(keyed(create("billing"), &token, Some("op-p")))
        .await
        .unwrap();
    let other = later_period(&svc).await.period.get();
    let err = svc
        .project
        .create_project(in_period(create("billing"), &token, "op-p", other))
        .await
        .unwrap_err();
    assert_eq!(
        extract_error_info(&err).expect("ErrorInfo").0,
        "OPERATION_KEY_CONFLICT"
    );
    assert_eq!(projects_named(&svc, &token, "billing").await, 1);
}

/// A command named with a retired period is refused as expired and creates
/// nothing, never executed as a new command; one with a period the server
/// never issued is refused as malformed.
#[tokio::test]
async fn test_retired_or_unissued_period_is_refused_before_effects() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let issued = later_period(&svc).await;
    svc.storage
        .retire_operation_periods(issued.accepted_until + chrono::Duration::seconds(1))
        .await
        .unwrap();

    let expired = svc
        .project
        .create_project(in_period(
            create("billing"),
            &token,
            "op-r",
            issued.period.get(),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        extract_error_info(&expired).expect("ErrorInfo").0,
        "OPERATION_EXPIRED"
    );

    let unissued = svc
        .project
        .create_project(in_period(create("billing"), &token, "op-u", u64::MAX))
        .await
        .unwrap_err();
    assert_eq!(unissued.code(), Code::InvalidArgument);
    assert_eq!(projects_named(&svc, &token, "billing").await, 0);
}

/// A command named with a retired period is refused before any of its
/// effects, those before its commit included: adding an email principal
/// creates no contact for it.
#[tokio::test]
async fn test_retired_period_leaves_no_effect_before_the_commit() {
    let svc = TestServices::new(MockStorage::new());
    let profile = common::test_profile();
    svc.storage
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "setup").into(),
        )
        .await
        .unwrap();
    let token = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let issued = later_period(&svc).await;
    svc.storage
        .retire_operation_periods(issued.accepted_until + chrono::Duration::seconds(1))
        .await
        .unwrap();
    let before = svc
        .storage
        .list_profile_emails(profile.id)
        .await
        .unwrap()
        .len();

    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let err = svc
        .identity
        .add_principal(in_period(
            AddPrincipalRequest {
                profile_id: None,
                r#type: PrincipalType::Email.into(),
                value: "fresh@sid.example.com".into(),
            },
            &token,
            "op-email",
            issued.period.get(),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        extract_error_info(&err).expect("ErrorInfo").0,
        "OPERATION_EXPIRED"
    );
    assert_eq!(
        svc.storage
            .list_profile_emails(profile.id)
            .await
            .unwrap()
            .len(),
        before,
        "the refused command created a contact"
    );
}

fn rename(id: &Option<sid_ids_proto::ProjectId>, name: &str) -> UpdateProjectRequest {
    UpdateProjectRequest {
        id: id.clone(),
        name: Some(name.to_string()),
        ..Default::default()
    }
}

/// Edit A completes, a later edit B completes, then A's lost response is
/// retried: the retry answers with the project as A left it and does not
/// write A's name over B's (it applied A again).
#[tokio::test]
async fn test_update_project_retry_does_not_overwrite_a_later_edit() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-c")))
        .await
        .unwrap()
        .into_inner();

    let a = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, Some("op-a")))
        .await
        .unwrap()
        .into_inner();
    svc.project
        .update_project(keyed(rename(&project.id, "invoices"), &token, Some("op-b")))
        .await
        .unwrap();
    let retry = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, Some("op-a")))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, a);
    assert_eq!(retry.name, "ledger");
    assert_eq!(projects_named(&svc, &token, "invoices").await, 1);
    assert_eq!(projects_named(&svc, &token, "ledger").await, 0);
}

/// A deletion's lost response is retried: the retry answers as the deletion
/// did (it answered NOT_FOUND, the absence the deletion left).
#[tokio::test]
async fn test_delete_project_retry_answers_as_the_deletion() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("scratch"), &token, Some("op-e")))
        .await
        .unwrap()
        .into_inner();
    let delete = || DeleteProjectRequest {
        id: project.id.clone(),
    };

    svc.project
        .delete_project(keyed(delete(), &token, Some("op-f")))
        .await
        .unwrap();
    svc.project
        .delete_project(keyed(delete(), &token, Some("op-f")))
        .await
        .expect("the retry answers as the deletion");

    assert_eq!(projects_named(&svc, &token, "scratch").await, 0);
    // A new deletion under a new key finds nothing to delete.
    let err = svc
        .project
        .delete_project(keyed(delete(), &token, Some("op-g")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
}

/// A creation that issues a one-time secret, retried after its response was
/// lost, answers with the token it created and no value (SID keeps only its
/// hash) and creates no second token.
#[tokio::test]
async fn test_initial_access_token_retry_answers_without_its_value() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || CreateInitialAccessTokenRequest {
        project_id: Some(sid_core::models::ProjectId::SYSTEM.into()),
        max_clients: 1,
        ..Default::default()
    };

    let first = svc
        .project
        .create_initial_access_token(keyed(create(), &token, Some("op-iat")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_initial_access_token(keyed(create(), &token, Some("op-iat")))
        .await
        .unwrap()
        .into_inner();

    assert!(!first.token_value.is_empty());
    assert!(retry.token_value.is_empty());
    assert_eq!(retry.token, first.token);
    let listed = svc
        .project
        .list_initial_access_tokens(keyed(
            ListInitialAccessTokensRequest {
                project_id: Some(sid_core::models::ProjectId::SYSTEM.into()),
            },
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.tokens.len(), 1);
}

/// An application whose client gets a one-time secret, retried after its
/// response was lost, answers with the application it created and no secret,
/// and creates no second application.
#[tokio::test]
async fn test_create_application_retry_answers_without_its_secret() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || CreateApplicationRequest {
        project_id: Some(sid_core::models::ProjectId::SYSTEM.into()),
        name: "billing".to_string(),
        client: Some(ClientRoleSettings {
            // A web client (the unspecified type) gets a secret.
            redirect_uris: vec!["https://app.sid.example.com/cb".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let first = svc
        .project
        .create_application(keyed(create(), &token, Some("op-app")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .project
        .create_application(keyed(create(), &token, Some("op-app")))
        .await
        .unwrap()
        .into_inner();

    assert!(!first.client_secret.is_empty());
    assert!(retry.client_secret.is_empty());
    assert_eq!(retry.application, first.application);
    let listed = svc
        .project
        .list_applications(keyed(
            ListApplicationsRequest {
                project_id: Some(sid_core::models::ProjectId::SYSTEM.into()),
                ..Default::default()
            },
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed
            .applications
            .iter()
            .filter(|a| a.name == "billing")
            .count(),
        1
    );
}

/// A suspension completes, the profile is reactivated, then the suspension's
/// lost response is retried: the retry answers as the suspension did and
/// neither suspends the profile again nor ends its new access.
#[tokio::test]
async fn test_admin_suspension_retry_keeps_a_later_reactivation() {
    use sid_proto::sid::v1::admin_service_server::AdminService;
    let user = sid_core::models::Profile::new(Some("suspended_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(user.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let status = |s: sid_proto::sid::v1::ProfileStatus| AdminUpdateProfileRequest {
        profile_id: Some(user.id.into()),
        profile_status: s as i32,
        ..Default::default()
    };
    let stored = || async {
        svc.storage
            .get_profile(user.id)
            .await
            .unwrap()
            .unwrap()
            .status
    };

    let first = svc
        .admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Suspended),
            &token,
            Some("op-suspend"),
        ))
        .await
        .unwrap()
        .into_inner();
    svc.admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Active),
            &token,
            Some("op-activate"),
        ))
        .await
        .unwrap();
    let retry = svc
        .admin
        .admin_update_profile(keyed(
            status(sid_proto::sid::v1::ProfileStatus::Suspended),
            &token,
            Some("op-suspend"),
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, first);
    assert_eq!(
        stored().await,
        sid_core::models::ProfileStatus::Active,
        "the retry suspended the profile again"
    );
}

/// Revoking all sessions completes, the user signs in again, then the
/// revocation's lost response is retried: the retry answers with the count
/// it ended and leaves the new session alive.
#[tokio::test]
async fn test_revoke_all_sessions_retry_keeps_a_later_session() {
    use sid_proto::sid::v1::admin_service_server::AdminService;
    let user = sid_core::models::Profile::new(Some("revoke_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(user.clone()));
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let sign_in = || async {
        let session = sid_core::models::Session::new(
            user.id,
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        svc.storage
            .create_session(
                &session,
                sid_core::models::AuditEntry::system("test", "session").into(),
            )
            .await
            .unwrap();
        session.id
    };
    let revoke = || {
        keyed(
            RevokeAllSessionsRequest {
                profile_id: Some(user.id.into()),
            },
            &token,
            Some("op-revoke"),
        )
    };

    sign_in().await;
    sign_in().await;
    let first = svc
        .admin
        .revoke_all_sessions(revoke())
        .await
        .unwrap()
        .into_inner();
    let later = sign_in().await;
    let retry = svc
        .admin
        .revoke_all_sessions(revoke())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(first.revoked_count, 2);
    assert_eq!(retry, first);
    assert!(
        svc.storage.get_session(later).await.unwrap().is_some(),
        "the retry ended a session signed in after the revocation"
    );
}

/// An administrator's provisioning whose response was lost is retried: the
/// retry answers with the account it created, not with "username taken" by
/// that very account, and no second account exists.
#[tokio::test]
async fn test_create_profile_retry_answers_with_its_account() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || CreateProfileRequest {
        username: Some("provisioned_retry".to_string()),
        ..Default::default()
    };
    let before = svc.mock_storage.profile_count();

    let first = svc
        .identity
        .create_profile(keyed(create(), &token, Some("op-provision")))
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .identity
        .create_profile(keyed(create(), &token, Some("op-provision")))
        .await
        .expect("the retry answers with the account it created")
        .into_inner();

    assert_eq!(retry, first);
    assert_eq!(svc.mock_storage.profile_count(), before + 1);
}

/// A credential is renamed, renamed again, then the first rename's lost
/// response is retried: the retry answers as the first rename did and the
/// later label stays.
#[tokio::test]
async fn test_credential_rename_retry_keeps_a_later_label() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let profile = sid_core::models::Profile::new(Some("relabel_retry"));
    let cred = sid_core::models::Credential::new(
        profile.id,
        sid_core::models::CredentialType::Totp,
        vec![1],
        Some("old".into()),
    );
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_credential(cred.clone()),
    );
    let token = common::fresh_token(&svc, &profile).await;
    let rename = |label: &str, key: &str| {
        keyed(
            UpdateCredentialRequest {
                credential_id: Some(common::wire_credential_id(cred.id)),
                label: Some(label.to_string()),
            },
            &token,
            Some(key),
        )
    };

    let first = svc
        .identity
        .update_credential(rename("phone", "op-a"))
        .await
        .unwrap()
        .into_inner();
    svc.identity
        .update_credential(rename("laptop", "op-b"))
        .await
        .unwrap();
    let retry = svc
        .identity
        .update_credential(rename("phone", "op-a"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, first);
    let stored = svc.storage.get_credential(cred.id).await.unwrap().unwrap();
    assert_eq!(
        stored.label.as_deref(),
        Some("laptop"),
        "the retry wrote its label over a later rename"
    );
}

/// Regression guard: a contact's label edit answers with the contact as its
/// own commit left it. A primary move committed between the edit's read and
/// its write makes the email primary; the edit, which writes only the label,
/// answers primary (as it does on a retry), not the flag it read.
#[tokio::test]
async fn test_a_contact_edit_answers_with_what_its_commit_left() {
    use sid_proto::sid::v1::account_service_server::AccountService;
    let profile = sid_core::models::Profile::new(Some("contact_edit"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let token = common::fresh_token(&svc, &profile).await;
    let email = svc
        .account
        .add_email(keyed(
            AddEmailRequest {
                email: "second@sid.example.com".into(),
                ..Default::default()
            },
            &token,
            Some("op-email"),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!email.is_primary);
    let phone = svc
        .account
        .add_phone(keyed(
            AddPhoneRequest {
                e164: 380_501_234_567,
                ..Default::default()
            },
            &token,
            Some("op-phone"),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!phone.is_primary);

    svc.mock_storage.move_primary_before_next_contact_edit();
    let edited = svc
        .account
        .update_email(keyed(
            UpdateEmailRequest {
                email_id: email.id,
                label: Some(EmailLabel::Work as i32),
                ..Default::default()
            },
            &token,
            Some("op-email-label"),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(edited.is_primary, "the edit answered the flag it read");

    svc.mock_storage.move_primary_before_next_contact_edit();
    let edited = svc
        .account
        .update_phone(keyed(
            UpdatePhoneRequest {
                phone_id: phone.id,
                label: Some(PhoneLabel::Work as i32),
                ..Default::default()
            },
            &token,
            Some("op-phone-label"),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(edited.is_primary, "the edit answered the flag it read");
}

/// A device is trusted, then distrusted, then the trust's lost response is
/// retried: the retry answers as the trust did and the device stays
/// distrusted.
#[tokio::test]
async fn test_device_trust_retry_keeps_a_later_distrust() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let profile = sid_core::models::Profile::new(Some("trust_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let device = sid_core::models::Device::new(profile.id, sid_core::models::DeviceType::Desktop);
    svc.storage
        .create_device(
            &device,
            sid_core::models::AuditEntry::system("test", "device").into(),
        )
        .await
        .unwrap();
    let token = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let id: sid_ids_proto::DeviceId = device.id.into();

    let first = svc
        .identity
        .trust_device(keyed(
            TrustDeviceRequest {
                device_id: Some(id.clone()),
            },
            &token,
            Some("op-trust"),
        ))
        .await
        .unwrap()
        .into_inner();
    svc.identity
        .revoke_device_trust(keyed(
            RevokeDeviceTrustRequest {
                device_id: Some(id.clone()),
            },
            &token,
            Some("op-distrust"),
        ))
        .await
        .unwrap();
    let retry = svc
        .identity
        .trust_device(keyed(
            TrustDeviceRequest {
                device_id: Some(id),
            },
            &token,
            Some("op-trust"),
        ))
        .await
        .unwrap()
        .into_inner();

    assert!(first.trusted);
    assert_eq!(retry, first);
    assert!(
        !svc.storage
            .get_device(device.id)
            .await
            .unwrap()
            .unwrap()
            .trusted,
        "the retry trusted the device again"
    );
}

/// A handle is removed, then the removal's lost response is retried: the
/// retry answers as the removal did, not as a principal not found.
#[tokio::test]
async fn test_principal_removal_retry_answers_as_the_removal() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let profile = sid_core::models::Profile::new(Some("unbind_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let token = common::fresh_token(&svc, &profile).await;
    let added = svc
        .identity
        .add_principal(keyed(
            AddPrincipalRequest {
                profile_id: None,
                r#type: PrincipalType::Username as i32,
                value: "unbind_retry_handle".to_string(),
            },
            &token,
            Some("op-add"),
        ))
        .await
        .unwrap()
        .into_inner()
        .principal
        .unwrap();
    let remove = || {
        keyed(
            RemovePrincipalRequest {
                principal_id: added.id.clone(),
            },
            &token,
            Some("op-remove"),
        )
    };

    let first = svc
        .identity
        .remove_principal(remove())
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .identity
        .remove_principal(remove())
        .await
        .expect("the retry answers as the removal did")
        .into_inner();

    assert_eq!(retry, first);
}

/// The passkey prompt is dismissed and the response lost: the retry answers
/// with the same prompt state and counts one skip, not two.
#[tokio::test]
async fn test_passkey_prompt_dismissal_retry_counts_one_skip() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let profile = sid_core::models::Profile::new(Some("dismiss_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let token = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let dismiss = || {
        keyed(
            RecordPasskeyPromptDismissalRequest::default(),
            &token,
            Some("op-dismiss"),
        )
    };

    let first = svc
        .identity
        .record_passkey_prompt_dismissal(dismiss())
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .identity
        .record_passkey_prompt_dismissal(dismiss())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(first.state.as_ref().unwrap().skip_count, 1);
    assert_eq!(retry, first, "the retry counted a second skip");
}

/// A closure request's response is lost: the retry answers with the closure
/// it started and its grace period, not as a profile already closing.
#[tokio::test]
async fn test_closure_request_retry_answers_with_its_closure() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;
    let profile = sid_core::models::Profile::new(Some("closure_retry"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let token = common::issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let request = || {
        keyed(
            RequestClosureRequest {
                mode: ClosureMode::Voluntary as i32,
                ..Default::default()
            },
            &token,
            Some("op-close"),
        )
    };

    let first = svc
        .identity
        .request_closure(request())
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .identity
        .request_closure(request())
        .await
        .expect("the retry answers with the closure it started")
        .into_inner();

    assert_eq!(retry, first);
}

/// A machine user with one active client secret, stored for the tests below.
async fn machine_user_with_secret(
    svc: &TestServices,
    token: &str,
) -> (sid_core::models::MachineUserId, String) {
    use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
    let created = svc
        .machine_user
        .create_machine_user(keyed(
            CreateMachineUserRequest {
                project_id: Some(sid_core::models::ProjectId::SYSTEM.into()),
                display_name: "ci".into(),
                ..Default::default()
            },
            token,
            Some(&uuid::Uuid::new_v4().to_string()),
        ))
        .await
        .unwrap()
        .into_inner()
        .machine_user
        .unwrap();
    let id: sid_core::models::MachineUserId = sid_ids_proto::required(created.id.as_ref()).unwrap();
    let added = svc
        .machine_user
        .add_machine_credential(keyed(
            AddMachineCredentialRequest {
                machine_user_id: created.id.clone(),
                credential_type: MachineCredentialType::ClientSecret as i32,
                ..Default::default()
            },
            token,
            Some(&uuid::Uuid::new_v4().to_string()),
        ))
        .await
        .unwrap()
        .into_inner();
    (id, added.credential.unwrap().kid)
}

/// A rotation's response is lost and retried: the retry answers with the
/// credentials it left, the new secret empty since only its verifier is
/// kept, and rotates nothing again.
#[tokio::test]
async fn test_machine_credential_rotation_retry_rotates_once() {
    use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let (id, kid) = machine_user_with_secret(&svc, &token).await;
    let rotate = || {
        keyed(
            RotateMachineCredentialRequest {
                machine_user_id: Some(id.into()),
                kid: kid.clone(),
                ..Default::default()
            },
            &token,
            Some("op-rotate"),
        )
    };

    let first = svc
        .machine_user
        .rotate_machine_credential(rotate())
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .machine_user
        .rotate_machine_credential(rotate())
        .await
        .expect("the retry answers with the rotation it made")
        .into_inner();

    assert!(!first.client_secret.is_empty());
    assert!(
        retry.client_secret.is_empty(),
        "the retry disclosed the secret again"
    );
    assert_eq!(retry.new_credential, first.new_credential);
    assert_eq!(
        svc.storage
            .list_machine_credentials_by_user(id)
            .await
            .unwrap()
            .len(),
        2,
        "the retry added another credential"
    );
}

/// A machine user is suspended, reactivated, then the suspension's lost
/// response is retried: the retry answers as the suspension did and the
/// machine user stays active.
#[tokio::test]
async fn test_machine_user_suspension_retry_keeps_a_later_reactivation() {
    use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let (id, _) = machine_user_with_secret(&svc, &token).await;
    let suspend = || {
        keyed(
            SuspendMachineUserRequest {
                machine_user_id: Some(id.into()),
            },
            &token,
            Some("op-suspend-mu"),
        )
    };

    let first = svc
        .machine_user
        .suspend_machine_user(suspend())
        .await
        .unwrap()
        .into_inner();
    svc.machine_user
        .reactivate_machine_user(keyed(
            ReactivateMachineUserRequest {
                machine_user_id: Some(id.into()),
            },
            &token,
            Some("op-reactivate-mu"),
        ))
        .await
        .unwrap();
    let retry = svc
        .machine_user
        .suspend_machine_user(suspend())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, first);
    assert_eq!(
        svc.storage
            .get_machine_user(id)
            .await
            .unwrap()
            .unwrap()
            .status,
        sid_core::models::machine_user::MachineUserStatus::Active,
        "the retry suspended the machine user again"
    );
}

/// An allowlist entry is added, removed, then the addition's lost response
/// is retried: the retry answers with the allowlist the addition left and
/// the entry stays removed.
#[tokio::test]
async fn test_allowlist_addition_retry_keeps_a_later_removal() {
    use sid_proto::sid::v1::admin::security_service_server::SecurityService;
    use sid_proto::sid::v1::admin::{AddIpAllowlistEntryRequest, RemoveIpAllowlistEntryRequest};
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let add = || {
        keyed(
            AddIpAllowlistEntryRequest {
                cidr: "10.20.0.0/16".into(),
                description: "office".into(),
            },
            &token,
            Some("op-allow"),
        )
    };

    let first = svc
        .security
        .add_ip_allowlist_entry(add())
        .await
        .unwrap()
        .into_inner();
    svc.security
        .remove_ip_allowlist_entry(keyed(
            RemoveIpAllowlistEntryRequest {
                cidr: "10.20.0.0/16".into(),
            },
            &token,
            Some("op-disallow"),
        ))
        .await
        .unwrap();
    let retry = svc
        .security
        .add_ip_allowlist_entry(add())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(retry, first);
    assert!(
        svc.storage
            .list_ip_allowlist_entries()
            .await
            .unwrap()
            .is_empty(),
        "the retry added back a removed entry"
    );
}

/// An allowlist change answers with the allowlist its own commit left, as its
/// retry does, not with a read made after the commit: a failed read does not
/// report a committed change as failed.
#[tokio::test]
async fn test_an_allowlist_change_answers_with_what_it_committed() {
    use sid_proto::sid::v1::security_service_server::SecurityService;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    svc.mock_storage.fail_allowlist_reads();

    let added = svc
        .security
        .add_ip_allowlist_entry(keyed(
            AddIpAllowlistEntryRequest {
                cidr: "10.30.0.0/16".into(),
                description: "office".into(),
            },
            &token,
            Some("op-allow-office"),
        ))
        .await
        .expect("the committed addition is answered")
        .into_inner();
    assert_eq!(added.entries.len(), 1);
    assert_eq!(added.entries[0].cidr, "10.30.0.0/16");

    let removed = svc
        .security
        .remove_ip_allowlist_entry(keyed(
            RemoveIpAllowlistEntryRequest {
                cidr: "10.30.0.0/16".into(),
            },
            &token,
            Some("op-disallow-office"),
        ))
        .await
        .expect("the committed removal is answered")
        .into_inner();
    assert!(removed.entries.is_empty());
}

/// An upstream provider's creation is retried after its response was lost:
/// the retry answers with the provider it created, not "name taken" by that
/// very provider, and one provider exists.
#[tokio::test]
async fn test_upstream_provider_creation_retry_answers_with_its_provider() {
    use sid_proto::sid::v1::upstream_service_server::UpstreamService;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let create = || {
        keyed(
            CreateUpstreamProviderRequest {
                name: "Corporate IdP".into(),
                protocol: UpstreamProtocol::Oidc as i32,
                client_id: "sid".into(),
                client_secret: "upstream-secret".into(),
                discovery_url: "https://idp.sid.example.com".into(),
                ..Default::default()
            },
            &token,
            Some("op-upstream"),
        )
    };

    let first = svc
        .upstream
        .create_upstream_provider(create())
        .await
        .unwrap()
        .into_inner();
    let retry = svc
        .upstream
        .create_upstream_provider(create())
        .await
        .expect("the retry answers with the provider it created")
        .into_inner();

    assert_eq!(retry, first);
    assert_eq!(
        svc.mock_storage.upstream_creations().len(),
        1,
        "the retry created another provider"
    );
}

/// An edit without a key cannot promise a safe retry and changes nothing.
#[tokio::test]
async fn test_update_project_without_key_is_refused() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let project = svc
        .project
        .create_project(keyed(create("billing"), &token, Some("op-d")))
        .await
        .unwrap()
        .into_inner();
    let err = svc
        .project
        .update_project(keyed(rename(&project.id, "ledger"), &token, None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(projects_named(&svc, &token, "billing").await, 1);
}

/// Keys belong to the caller: another administrator's command under the
/// same key is its own command.
#[tokio::test]
async fn test_operation_keys_are_per_caller() {
    let svc = TestServices::new(MockStorage::new());
    let alice = issue_admin_token(&svc.jwt, ProfileId::generate());
    let bob = issue_admin_token(&svc.jwt, ProfileId::generate());
    let a = svc
        .project
        .create_project(keyed(create("billing"), &alice, Some("op-3")))
        .await
        .unwrap()
        .into_inner();
    let b = svc
        .project
        .create_project(keyed(create("billing"), &bob, Some("op-3")))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(a.id, b.id);
    assert_eq!(projects_named(&svc, &alice, "billing").await, 2);
}
