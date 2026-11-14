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
    AdmittedSourceOrganizations, GetLoginSettingsRequest, LoginSettings, RequiredAction,
    UpdateLoginSettingsRequest,
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

/// The two admissions as answered after `revision` changes of them, with no
/// source organization named.
fn admissions(personal: bool, corporate: bool, revision: u64) -> LoginSettings {
    LoginSettings {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        revision,
        ..Default::default()
    }
}

/// A change replacing the admitted source organizations with `sources`.
fn replace_sources(sources: &[sid_core::models::OrgId]) -> UpdateLoginSettingsRequest {
    UpdateLoginSettingsRequest {
        admitted_source_organizations: Some(AdmittedSourceOrganizations {
            organizations: sources.iter().map(|id| (*id).into()).collect(),
        }),
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
    assert_eq!(read(&svc, &token).await, admissions(false, false, 0));
    assert_eq!(storage.login_settings().await.unwrap(), None);

    let change = |personal: Option<bool>, corporate: Option<bool>| UpdateLoginSettingsRequest {
        allow_personal_profiles: personal,
        allow_foreign_corporate_profiles: corporate,
        ..Default::default()
    };
    for (personal, corporate, expected) in [
        (None, Some(true), admissions(false, true, 1)),
        (Some(true), None, admissions(true, true, 2)),
        (None, Some(false), admissions(true, false, 3)),
        (Some(false), None, admissions(false, false, 4)),
        // Nothing named: nothing changes, and the revision stays.
        (None, None, admissions(false, false, 4)),
        // A switch set to the value it has: the same.
        (Some(false), None, admissions(false, false, 4)),
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

// The admitted source organizations are read as stored and replaced whole:
// an organization left out is no longer admitted, a present empty list
// admits none, and a change that names no list keeps it. Each change of the
// list is one revision; the switches keep their values. Bug prevented: a
// list that only grows, a removal that needs the other organizations sent
// again and loses them, or a toggle change wiping the list.
#[tokio::test]
async fn the_admitted_source_organizations_are_replaced_whole() {
    use sid_core::models::OrgId;
    let (svc, storage) = services();
    let token = admin_token();
    let (a, b) = (OrgId::generate(), OrgId::generate());
    let (first, second) = if a < b { (a, b) } else { (b, a) };
    let listed = |answer: &LoginSettings| -> Vec<sid_ids_proto::OrgId> {
        answer.admitted_source_organizations.clone()
    };

    // Named in any order and twice: answered in id order, each once.
    let answered = svc
        .update_login_settings(from(
            replace_sources(&[second, first, second]),
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed(&answered), vec![first.into(), second.into()]);
    assert_eq!(answered.revision, 1);
    // Naming organizations turns no switch on.
    assert!(!answered.allow_foreign_corporate_profiles);

    // A switch change keeps the list.
    let answered = svc
        .update_login_settings(from(
            UpdateLoginSettingsRequest {
                allow_foreign_corporate_profiles: Some(true),
                ..Default::default()
            },
            &token,
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed(&answered), vec![first.into(), second.into()]);
    assert_eq!(answered.revision, 2);

    // One organization is left out: only it is no longer admitted.
    let answered = svc
        .update_login_settings(from(replace_sources(&[second]), &token, None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed(&answered), vec![second.into()]);
    assert_eq!(answered.revision, 3);
    let stored = storage.login_settings().await.unwrap().unwrap();
    assert!(stored.admits_corporate_of(second));
    assert!(!stored.admits_corporate_of(first));

    // The same list again changes nothing.
    let answered = svc
        .update_login_settings(from(replace_sources(&[second]), &token, None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(answered.revision, 3);

    // A present empty list admits nobody, with the switch still on.
    let answered = svc
        .update_login_settings(from(replace_sources(&[]), &token, None))
        .await
        .unwrap()
        .into_inner();
    assert!(listed(&answered).is_empty());
    assert!(answered.allow_foreign_corporate_profiles);
    assert_eq!(answered.revision, 4);
    assert_eq!(read(&svc, &token).await, answered);
}

// A list naming something that is no organization id, or more organizations
// than the settings hold, is refused before anything is changed, the switch
// sent with it included. Bug prevented: a half-applied change, or a stored
// list no reader can decode.
#[tokio::test]
async fn an_invalid_source_list_is_refused_and_changes_nothing() {
    use sid_core::models::{MAX_ADMITTED_SOURCES, OrgId};
    let (svc, storage) = services();
    let token = admin_token();
    let with_switch = |list: AdmittedSourceOrganizations| UpdateLoginSettingsRequest {
        allow_foreign_corporate_profiles: Some(true),
        admitted_source_organizations: Some(list),
        ..Default::default()
    };
    let malformed = AdmittedSourceOrganizations {
        organizations: vec![sid_ids_proto::OrgId { value: vec![7; 15] }],
    };
    let too_many = AdmittedSourceOrganizations {
        organizations: (0..=MAX_ADMITTED_SOURCES)
            .map(|_| OrgId::generate().into())
            .collect(),
    };
    for list in [malformed, too_many] {
        let refused = svc
            .update_login_settings(from(with_switch(list), &token, None))
            .await
            .expect_err("an invalid list was accepted");
        assert_eq!(refused.code(), Code::InvalidArgument, "{refused:?}");
    }
    assert_eq!(storage.login_settings().await.unwrap(), None);
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
    assert_eq!(first, admissions(true, false, 1));

    svc.update_login_settings(from(personal(false), &token, Some("turn-off")))
        .await
        .unwrap();

    let repeated = svc
        .update_login_settings(from(personal(true), &token, Some("turn-on")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(repeated, first);
    assert_eq!(read(&svc, &token).await, admissions(false, false, 2));

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
