// SPDX-License-Identifier: AGPL-3.0-only
//! The login settings an administrator reads and changes through
//! RealmService: which incoming external identities the organization admits.
//! The two admissions are independent, off until set, and the settings this
//! build does not serve are neither reported nor accepted.

mod common;

use common::mock_storage::MockStorage;
use common::{issue_admin_token, issue_token, test_jwt, test_key_manager, test_revocation};
use sid_core::models::{Profile, ProfileId};
use sid_infra::grpc_error::extract_error_info;
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::realm_service_server::RealmService;
use sid_proto::sid::v1::admin::{
    GetLoginSettingsRequest, LoginSettings, RequiredAction, UpdateLoginSettingsRequest,
};
use sid_server::grpc::realm_service::RealmServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn services() -> (RealmServiceImpl, Arc<MockStorage>) {
    let storage = Arc::new(MockStorage::new());
    let svc = RealmServiceImpl::new(
        storage.clone(),
        test_jwt(),
        test_revocation(),
        test_key_manager(),
    );
    (svc, storage)
}

/// `msg` from the bearer of `token`; with `key`, named as that command.
fn from<T>(msg: T, token: &str, key: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    match key {
        Some(key) => common::name_command(req.metadata_mut(), key),
        None => common::name_new_command(req.metadata_mut()),
    }
    req
}

fn admin_token() -> String {
    issue_admin_token(&test_jwt(), ProfileId::generate())
}

async fn read(svc: &RealmServiceImpl, token: &str) -> LoginSettings {
    svc.get_login_settings(from(GetLoginSettingsRequest {}, token, None))
        .await
        .unwrap()
        .into_inner()
}

fn admissions(personal: bool, corporate: bool) -> LoginSettings {
    LoginSettings {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        ..Default::default()
    }
}

// Nothing is admitted until an administrator says so, each admission is
// changed on its own and keeps the other, and all four combinations are
// reachable. A setting this build does not serve is absent in every answer,
// never a `false` that reads as stored. Bug prevented: one toggle resetting
// or implying the other, or a fresh installation admitting external
// identities.
#[tokio::test]
async fn each_admission_is_changed_on_its_own() {
    let (svc, storage) = services();
    let token = admin_token();
    assert_eq!(read(&svc, &token).await, admissions(false, false));
    assert_eq!(storage.login_settings().await.unwrap(), None);

    let change = |personal: Option<bool>, corporate: Option<bool>| UpdateLoginSettingsRequest {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        ..Default::default()
    };
    for (personal, corporate, expected) in [
        (None, Some(true), admissions(false, true)),
        (Some(true), None, admissions(true, true)),
        (None, Some(false), admissions(true, false)),
        (Some(false), None, admissions(false, false)),
        // Nothing named: nothing changes.
        (None, None, admissions(false, false)),
    ] {
        let answered = svc
            .update_login_settings(from(change(personal, corporate), &token, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answered, expected);
        assert_eq!(answered.self_registration, None);
        assert_eq!(read(&svc, &token).await, expected);
    }
}

// A change naming a setting this build does not serve is refused whole:
// the admission sent with it is not applied either. Bug prevented: a page
// saving every toggle at once and silently losing, or half-applying, the
// ones the server ignores.
#[tokio::test]
async fn an_unserved_setting_is_refused_and_changes_nothing() {
    let (svc, storage) = services();
    let token = admin_token();
    let with_admission = |unserved: UpdateLoginSettingsRequest| UpdateLoginSettingsRequest {
        allow_personal_profiles: Some(true),
        ..unserved
    };
    for unserved in [
        UpdateLoginSettingsRequest {
            self_registration: Some(true),
            ..Default::default()
        },
        UpdateLoginSettingsRequest {
            identity_first_login: Some(false),
            ..Default::default()
        },
        UpdateLoginSettingsRequest {
            default_roles: vec!["member".into()],
            ..Default::default()
        },
        UpdateLoginSettingsRequest {
            required_actions: vec![RequiredAction::VerifyEmail as i32],
            ..Default::default()
        },
    ] {
        let refused = svc
            .update_login_settings(from(with_admission(unserved), &token, None))
            .await
            .expect_err("an unserved setting was accepted");
        assert_eq!(refused.code(), Code::Unimplemented, "{refused:?}");
        assert_eq!(
            extract_error_info(&refused).expect("ErrorInfo").0,
            "FEATURE_NOT_AVAILABLE"
        );
    }
    assert_eq!(storage.login_settings().await.unwrap(), None);
}

// Only an administrator reads or changes the admissions: no token, an
// invalid one and a signed-in user without the role are refused, and
// nothing is stored. Bug prevented: any signed-in user opening the
// organization to external identities.
#[tokio::test]
async fn only_an_administrator_reads_or_changes_them() {
    let (svc, storage) = services();
    let open = || UpdateLoginSettingsRequest {
        allow_personal_profiles: Some(true),
        allow_foreign_corporate_profiles: Some(true),
        ..Default::default()
    };

    let unsigned = svc
        .update_login_settings(Request::new(open()))
        .await
        .expect_err("no token");
    assert_eq!(unsigned.code(), Code::Unauthenticated);
    let forged = svc
        .update_login_settings(from(open(), "x", None))
        .await
        .expect_err("invalid token");
    assert_eq!(forged.code(), Code::Unauthenticated);

    let user = issue_token(
        &test_jwt(),
        &Profile::new(Some("mallory")),
        &["openid".to_string()],
    );
    let denied = svc
        .update_login_settings(from(open(), &user, None))
        .await
        .expect_err("not an administrator");
    assert_eq!(denied.code(), Code::PermissionDenied);
    let denied = svc
        .get_login_settings(from(GetLoginSettingsRequest {}, &user, None))
        .await
        .expect_err("not an administrator");
    assert_eq!(denied.code(), Code::PermissionDenied);

    assert_eq!(storage.login_settings().await.unwrap(), None);
}

// A change whose answer was lost is repeated under its key: it answers what
// it answered first and is not applied over a later change. The same key
// for another change is refused. Bug prevented: a retried "turn Personal
// on" silently undoing an administrator's later "turn it off".
#[tokio::test]
async fn a_repeated_change_answers_its_first_result() {
    let (svc, _) = services();
    let token = admin_token();
    let personal = |on: bool| UpdateLoginSettingsRequest {
        allow_personal_profiles: Some(on),
        ..Default::default()
    };
    let first = svc
        .update_login_settings(from(personal(true), &token, Some("turn-on")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first, admissions(true, false));

    svc.update_login_settings(from(personal(false), &token, Some("turn-off")))
        .await
        .unwrap();

    let repeated = svc
        .update_login_settings(from(personal(true), &token, Some("turn-on")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(repeated, first);
    assert_eq!(read(&svc, &token).await, admissions(false, false));

    let reused = svc
        .update_login_settings(from(personal(false), &token, Some("turn-on")))
        .await
        .expect_err("a key reused for another change");
    assert_eq!(reused.code(), Code::AlreadyExists);
    assert_eq!(
        extract_error_info(&reused).expect("ErrorInfo").0,
        "OPERATION_KEY_CONFLICT"
    );
}
