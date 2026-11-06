// SPDX-License-Identifier: AGPL-3.0-only
//! A machine user's credential additions against real PostgreSQL (port
//! 54399), where concurrent attempts of one command race for the user's
//! last credential slot.

mod common;

use common::{issue_admin_token, test_jwt};
use sid_core::models::machine_user::MAX_ACTIVE_CREDENTIALS;
use sid_core::models::{
    AuditEntry, MachineOwner, MachineUser, MachineUserCredential, ProfileId, ProjectId,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::machine_user_service_server::MachineUserService;
use sid_proto::sid::v1::{AddMachineCredentialRequest, MachineCredentialType};
use sid_server::grpc::machine_user_service::MachineUserServiceImpl;
use std::sync::Arc;
use tonic::Request;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn pg_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Arc::new(backend)
}

/// Concurrent attempts of one credential addition that fills the machine
/// user's last slot: the store counts the limit before it sees the key, so
/// an attempt that lost the race answers with the credential the winner
/// added, not with QUOTA_EXCEEDED, and one credential is added.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_attempts_at_the_limit_add_one_credential() {
    let storage = pg_storage().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let mu = MachineUser::new(
        ProjectId::SYSTEM,
        format!("mu_{}", &suffix[..12]),
        "racing",
        MachineOwner::System,
    );
    storage
        .create_machine_user(&mu, AuditEntry::system("test.setup", "mu").into())
        .await
        .unwrap();
    for i in 1..MAX_ACTIVE_CREDENTIALS {
        let cred = MachineUserCredential::new(
            mu.id,
            format!("kid-{suffix}-{i}"),
            sid_core::models::machine_user::MachineCredentialType::PrivateKeyJwt,
            "pem",
        );
        storage
            .add_machine_credential(&cred, None, AuditEntry::system("test.setup", "cred").into())
            .await
            .unwrap();
    }
    let jwt = test_jwt();
    let svc = MachineUserServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        common::test_revocation(),
        common::test_org(),
    );
    let token = issue_admin_token(&jwt, ProfileId::generate());
    let add = || {
        let mut req = Request::new(AddMachineCredentialRequest {
            machine_user_id: Some(mu.id.into()),
            credential_type: MachineCredentialType::ClientSecret as i32,
            ..Default::default()
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        common::name_command(req.metadata_mut(), &format!("op-last-{suffix}"));
        req
    };

    let attempts =
        futures::future::join_all((0..8).map(|_| svc.add_machine_credential(add()))).await;
    let kids: std::collections::BTreeSet<String> = attempts
        .into_iter()
        .map(|a| {
            a.expect("every attempt answers")
                .into_inner()
                .credential
                .unwrap()
                .kid
        })
        .collect();
    assert_eq!(
        kids.len(),
        1,
        "the attempts answered with different credentials"
    );
    assert_eq!(
        storage
            .list_machine_credentials_by_user(mu.id)
            .await
            .unwrap()
            .len(),
        MAX_ACTIVE_CREDENTIALS
    );
}
