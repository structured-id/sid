// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands meeting other writes in the store, on PostgreSQL (port
//! 54399) and SQLite: concurrent attempts of one command meet the winner's
//! effect (a unique value it took) before their operation key and still
//! answer with the winner's recorded result; a command's answer is the state
//! its own commit left, never one read before it.

mod common;

use std::sync::Arc;

use sid_core::models::{AuditEntry, AuthLevel, Profile};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::account_service_server::AccountService;
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::{
    AddEmailRequest, AddPhoneRequest, CreateUpstreamProviderRequest, UpstreamProtocol,
};
use sid_server::grpc::account_service::AccountServiceImpl;
use sid_server::grpc::upstream_service::UpstreamServiceImpl;
use tonic::Request;

struct Harness {
    storage: Arc<dyn StorageBackend>,
    account: Arc<AccountServiceImpl>,
    upstream: Arc<UpstreamServiceImpl>,
}

async fn harness(storage: Arc<dyn StorageBackend>) -> Harness {
    common::adopt_operation_period(storage.as_ref()).await;
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let auth = common::auth_service_over(storage.clone(), cache, None, None);
    Harness {
        account: Arc::new(AccountServiceImpl::new(
            storage.clone(),
            common::test_jwt(),
            common::test_revocation(),
        )),
        upstream: Arc::new(UpstreamServiceImpl::new(
            storage.clone(),
            common::test_key_manager(),
            common::test_jwt(),
            common::test_revocation(),
            auth,
        )),
        storage,
    }
}

async fn postgres() -> Harness {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    harness(Arc::new(backend)).await
}

async fn sqlite() -> Harness {
    harness(Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    ))
    .await
}

fn tag() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

fn call<T>(msg: T, token: &str, key: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_command(req.metadata_mut(), key);
    req
}

/// A stored Profile's session token.
async fn signed_in(h: &Harness) -> String {
    let profile = Profile::new(Some(format!("p{}", tag())));
    h.storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let session = common::authenticated_session(&profile, AuthLevel::Basic, 0);
    h.storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    common::issue_token_with_session(&common::test_jwt(), &profile, &["openid".into()], session).0
}

/// Regression guard: concurrent attempts of one email addition all answer
/// with the email the winner added, though the losers' inserts meet its
/// unique address first; one email exists.
async fn concurrent_email_additions_with_one_key_add_one(h: Harness) {
    let token = signed_in(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let account = h.account.clone();
        let request = call(
            AddEmailRequest {
                email: format!("a{}@sid.example.com", tag_of(&key)),
                ..Default::default()
            },
            &token,
            &key,
        );
        async move { account.add_email(request).await }
    });
    let answers: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("every attempt answers").into_inner())
        .collect();
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
}

/// Regression guard: the same for a phone addition and its unique number.
async fn concurrent_phone_additions_with_one_key_add_one(h: Harness) {
    let token = signed_in(&h).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let account = h.account.clone();
        let request = call(
            AddPhoneRequest {
                e164: 380_501_234_567,
                ..Default::default()
            },
            &token,
            &key,
        );
        async move { account.add_phone(request).await }
    });
    let answers: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("every attempt answers").into_inner())
        .collect();
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
}

/// Regression guard: concurrent attempts of one upstream provider creation
/// all answer with the provider the winner created, not "name taken" by it.
async fn concurrent_provider_creations_with_one_key_create_one(h: Harness) {
    let token = common::administrator_token(&common::test_jwt(), h.storage.as_ref()).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let upstream = h.upstream.clone();
        let request = call(
            CreateUpstreamProviderRequest {
                name: format!("IdP {}", tag_of(&key)),
                protocol: UpstreamProtocol::Oidc as i32,
                client_id: "sid".into(),
                client_secret: "upstream-secret".into(),
                discovery_url: "https://idp.sid.example.com".into(),
                ..Default::default()
            },
            &token,
            &key,
        );
        async move { upstream.create_upstream_provider(request).await }
    });
    let answers: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("every attempt answers").into_inner())
        .collect();
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
}

/// Regression guard: concurrent attempts of one credential rotation all
/// answer with the rotation the winner made, though the losers may read the
/// rotated credential already out of its active state.
async fn concurrent_rotations_with_one_key_rotate_once(h: Harness) {
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
    use sid_core::models::{MachineUser, ProjectId};
    use sid_proto::sid::v1::RotateMachineCredentialRequest;
    use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
    h.storage
        .ensure_system_project(AuditEntry::system("test", "machine").into())
        .await
        .unwrap();
    let machine = MachineUser::new(
        ProjectId::SYSTEM,
        format!("mu_{}", tag()),
        "Rotated",
        OwnerType::System,
        "system",
    );
    h.storage
        .create_machine_user(&machine, AuditEntry::system("test", "machine").into())
        .await
        .unwrap();
    let kid = format!("kid_{}", tag());
    h.storage
        .add_machine_credential(
            &MachineUserCredential::new(
                machine.id,
                &kid,
                MachineCredentialType::ClientSecret,
                "verifier",
            ),
            None,
            AuditEntry::system("test", "credential").into(),
        )
        .await
        .unwrap();
    let service = Arc::new(
        sid_server::grpc::machine_user_service::MachineUserServiceImpl::new(
            h.storage.clone(),
            common::test_jwt(),
            common::test_revocation(),
            common::test_org(),
        ),
    );
    let token = common::administrator_token(&common::test_jwt(), h.storage.as_ref()).await;
    let key = format!("k-{}", tag());
    let calls = (0..4).map(|_| {
        let service = service.clone();
        let request = call(
            RotateMachineCredentialRequest {
                machine_user_id: machine.id.to_string(),
                kid: kid.clone(),
                ..Default::default()
            },
            &token,
            &key,
        );
        async move { service.rotate_machine_credential(request).await }
    });
    let new_kids: std::collections::BTreeSet<String> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| {
            r.expect("every attempt answers")
                .into_inner()
                .new_credential
                .unwrap()
                .kid
        })
        .collect();
    assert_eq!(new_kids.len(), 1, "{new_kids:?}");
}

/// Regression guard: a publication answers with the config as its commit
/// published it, as a read of the config shows it afterwards.
async fn a_publication_answers_with_the_config_it_published(h: Harness) {
    use sid_proto::sid::v1::admin::branding_service_server::BrandingService;
    use sid_proto::sid::v1::admin::{
        CreateBrandingConfigRequest, GetBrandingConfigRequest, PublishBrandingConfigRequest,
    };
    h.storage
        .ensure_system_project(AuditEntry::system("test", "branding").into())
        .await
        .unwrap();
    let project = sid_core::models::ProjectId::SYSTEM.to_string();
    let token = common::administrator_token(&common::test_jwt(), h.storage.as_ref()).await;
    let branding = sid_server::grpc::branding_service::BrandingServiceImpl::new(
        h.storage.clone(),
        common::test_jwt(),
        common::test_revocation(),
    );
    let draft = branding
        .create_branding_config(call(
            CreateBrandingConfigRequest {
                project_id: project.clone(),
                ..Default::default()
            },
            &token,
            &format!("k-{}", tag()),
        ))
        .await
        .unwrap()
        .into_inner();
    let published = branding
        .publish_branding_config(call(
            PublishBrandingConfigRequest {
                project_id: project.clone(),
                config_id: draft.id.clone(),
            },
            &token,
            &format!("k-{}", tag()),
        ))
        .await
        .unwrap()
        .into_inner();
    let mut read = Request::new(GetBrandingConfigRequest {
        project_id: project,
        config_id: draft.id,
    });
    read.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let stored = branding
        .get_branding_config(read)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(published, stored);
}

/// The unique part of a key made as `k-{tag}`.
fn tag_of(key: &str) -> &str {
    key.trim_start_matches("k-")
}

macro_rules! on_both_engines {
    ($($scenario:ident),* $(,)?) => {
        mod pg {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::postgres().await).await;
                }
            )*
        }
        mod lite {
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario(super::sqlite().await).await;
                }
            )*
        }
    };
}

on_both_engines!(
    concurrent_email_additions_with_one_key_add_one,
    concurrent_phone_additions_with_one_key_add_one,
    concurrent_provider_creations_with_one_key_create_one,
    a_publication_answers_with_the_config_it_published,
    concurrent_rotations_with_one_key_rotate_once,
);
