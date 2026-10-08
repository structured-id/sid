// SPDX-License-Identifier: AGPL-3.0-only
//! Email login handles on PostgreSQL (port 54399) and SQLite: spellings that
//! share a resolution key are one handle, also when they arrive at once.
//! Exactly one account gets it, keeping its own spelling as the contact;
//! the other is refused and stores nothing.

mod common;

use std::sync::Arc;

use common::{issue_admin_token, test_jwt};
use sid_authn::account_closure::AccountClosureService;
use sid_authn::data_export::DataExportService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::models::{PrincipalType, ProfileId};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::{CreateProfileRequest, CreateProfileResponse};
use sid_server::feature_flags::FeatureFlagService;
use sid_server::grpc::identity_service::IdentityServiceImpl;
use tonic::{Code, Request, Response, Status};

async fn postgres() -> Arc<dyn StorageBackend> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    Arc::new(backend)
}

async fn sqlite() -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    )
}

struct Harness {
    identity: IdentityServiceImpl,
    storage: Arc<dyn StorageBackend>,
    token: String,
}

fn harness(storage: Arc<dyn StorageBackend>) -> Harness {
    let jwt = test_jwt();
    let revocation_cache = Arc::new(RevocationCache::new(
        std::time::Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ));
    let cascade = Arc::new(RevocationCascadeService::new(
        storage.clone(),
        revocation_cache.clone(),
    ));
    let identity = IdentityServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache,
        FeatureFlagService::disabled(),
        cascade.clone(),
        Arc::new(AccountClosureService::new(storage.clone(), cascade)),
        Arc::new(DataExportService::new(
            storage.clone(),
            "/tmp/sid-test-exports".to_string(),
        )),
    );
    Harness {
        identity,
        storage,
        token: issue_admin_token(&jwt, ProfileId::generate()),
    }
}

impl Harness {
    async fn create(&self, email: &str) -> Result<Response<CreateProfileResponse>, Status> {
        let mut request = Request::new(CreateProfileRequest {
            email: Some(email.to_string()),
            ..Default::default()
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        self.identity.create_profile(request).await
    }
}

/// Two equivalent spellings provisioned at the same moment: one account holds
/// the key with its own spelling as the contact, the other is refused.
async fn equivalent_spellings_race(storage: Arc<dyn StorageBackend>) {
    let h = harness(storage);
    for _ in 0..20 {
        let domain = format!("{}.sid.example.com", uuid::Uuid::now_v7().simple());
        let first = format!("Ann.Smith+a@{domain}");
        let second = format!("annsmith+b@{domain}");
        let (a, b) = tokio::join!(h.create(&first), h.create(&second));

        let (winner, loser) = match (a, b) {
            (Ok(_), Err(e)) => (&first, e),
            (Err(e), Ok(_)) => (&second, e),
            other => panic!("exactly one provisioning must succeed: {other:?}"),
        };
        assert_eq!(loser.code(), Code::AlreadyExists, "{loser:?}");

        let key = format!("annsmith@{domain}");
        let profile = h
            .storage
            .get_profile_by_principal(PrincipalType::Email, &key)
            .await
            .unwrap()
            .expect("the key finds the winner");
        let contacts = h.storage.list_profile_emails(profile.id).await.unwrap();
        let spellings: Vec<&str> = contacts.iter().map(|c| c.email.as_str()).collect();
        assert_eq!(spellings, [winner.as_str()]);
        let principal = h
            .storage
            .get_principal_by_value(PrincipalType::Email, &key)
            .await
            .unwrap()
            .expect("one principal");
        let claims = h
            .storage
            .get_principal_bindings(principal.id)
            .await
            .unwrap();
        assert_eq!(claims.len(), 1, "the loser left no claim on the handle");
    }
}

#[tokio::test]
async fn equivalent_spellings_race_on_postgres() {
    equivalent_spellings_race(postgres().await).await;
}

#[tokio::test]
async fn equivalent_spellings_race_on_sqlite() {
    equivalent_spellings_race(sqlite().await).await;
}
