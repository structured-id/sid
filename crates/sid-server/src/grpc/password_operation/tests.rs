// SPDX-License-Identifier: AGPL-3.0-only
use std::sync::Arc;

use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::password_operation::{HistoryEvaluation, OperationPurpose as _};
use sid_core::models::{CredentialId, ProfileId, ResetSessionId};
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::CurveId;
use sid_storage::sqlite::SqliteBackend;

use super::{OperationPurpose, PasswordOperations};

pub(super) fn change() -> OperationPurpose {
    OperationPurpose::Change {
        profile_id: ProfileId::generate(),
        credential_id: CredentialId(uuid::Uuid::now_v7()),
        password: [5; 16],
    }
}

/// A key manager over its own master secret.
pub(super) fn manager(master: u8) -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([master; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "test")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

pub(super) async fn sqlite() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

/// The two authorities over one database and cache, as a standalone
/// installation runs them: the evaluator over its own store, sealing history
/// keys and its records with `history_keys`; the credential side sealing its
/// records with `field_keys`, holding no history key.
pub(super) fn split(
    storage: Arc<SqliteBackend>,
    installation: sid_core::models::OrgId,
    history_keys: Arc<dyn sid_keys::KeyManager>,
    field_keys: Arc<dyn sid_keys::KeyManager>,
) -> (PasswordOperations, Arc<HistoryEvaluation>) {
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let evaluation = Arc::new(HistoryEvaluation::new(
        Arc::new(storage.history_keys()),
        cache.clone(),
        history_keys,
    ));
    let ops = PasswordOperations::new(storage, cache, field_keys, installation, evaluation.clone());
    (ops, evaluation)
}

/// A ZKPP server that verifies no proof and accepts unproven passwords.
pub(super) fn zkpp_without_proofs() -> ZkppOpaqueServer {
    use sid_authn::opaque::{OpaqueRouter, PallasOpaque};
    use sid_authn::opaque_zkpp::ZkppConfig;
    use sid_plugin::crypto::OpaqueOperations;
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let providers = [(
        CurveId::Pallas,
        Box::new(PallasOpaque::new()) as Box<dyn OpaqueOperations>,
    )]
    .into();
    let router = OpaqueRouter::new(primary, providers, setup);
    ZkppOpaqueServer::new(
        &router,
        vec![],
        ZkppConfig {
            require_proof: false,
            policy_version: 1,
        },
    )
    .unwrap()
}

/// Every purpose names the method of its durable result: a registration, a
/// change and a reset are different commands under one operation key.
#[test]
fn every_purpose_names_its_method() {
    assert_eq!(change().method(), "change");
    assert_eq!(
        OperationPurpose::Reset {
            session: ResetSessionId(uuid::Uuid::now_v7()),
        }
        .method(),
        "reset"
    );
}
