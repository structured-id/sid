// SPDX-License-Identifier: AGPL-3.0-only
//! Retained unsupported history must never become an empty comparison window.
//! PostgreSQL migrates once; every scenario owns unique rows and never clears
//! shared tables. SQLite scenarios each own their in-memory database.

use chrono::{Duration, Utc};
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialType, HistoryCommit, HistoryEpoch,
    HistoryEpochId, HistoryEpochUse, HistoryEvidence, HistoryKsf, HistorySuite, MutationContext,
    NewHistoryEpoch, PasswordResetSession, Profile, ProfileId, ResetSessionStatus,
    RevocationReason, Session, SessionEnd, WrappedHistoryKey,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

enum Database {
    #[cfg(feature = "storage-pg")]
    Postgres(sid_storage::PostgresBackend),
    #[cfg(feature = "storage-sqlite")]
    Sqlite(sid_storage::sqlite::SqliteBackend),
}

enum Inventory {
    RetainedRows,
    #[cfg(feature = "storage-sqlite")]
    CredentialColumn,
}

impl Database {
    fn storage(&self) -> &dyn StorageBackend {
        match self {
            #[cfg(feature = "storage-pg")]
            Self::Postgres(db) => db,
            #[cfg(feature = "storage-sqlite")]
            Self::Sqlite(db) => db,
        }
    }

    async fn seed(&self, password: &Credential, inventory: Inventory) {
        #[cfg(feature = "storage-sqlite")]
        if let Inventory::CredentialColumn = inventory {
            let db = match self {
                Self::Sqlite(db) => db,
                #[cfg(feature = "storage-pg")]
                Self::Postgres(_) => panic!("old credential-column fixture is SQLite only"),
            };
            sqlx::query("ALTER TABLE credentials ADD COLUMN history_commitment BLOB")
                .execute(db.pool())
                .await
                .unwrap();
            sqlx::query("UPDATE credentials SET history_commitment = ? WHERE id = ?")
                .bind(vec![11u8; 32])
                .bind(password.id.0.to_string())
                .execute(db.pool())
                .await
                .unwrap();
            return;
        }
        #[cfg(not(feature = "storage-sqlite"))]
        let Inventory::RetainedRows = inventory;
        match self {
            #[cfg(feature = "storage-pg")]
            Self::Postgres(db) => {
                sqlx::query("INSERT INTO password_history_legacy (credential_id, owner_id, digest, salt, proof_verified, created_at) VALUES ($1,$2,$3,$4,true,$5)")
                    .bind(password.id.0).bind(password.profile_id).bind(vec![11u8; 32])
                    .bind(vec![12u8; 32]).bind(Utc::now()).execute(db.pool()).await.unwrap();
            }
            #[cfg(feature = "storage-sqlite")]
            Self::Sqlite(db) => {
                // Model a file adopted from the former implementation. Its
                // schema is private to this scenario, never a shared test DB.
                sqlx::query("CREATE TABLE password_history_legacy (credential_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, digest BLOB NOT NULL, salt BLOB NOT NULL, proof_verified INTEGER NOT NULL, created_at TEXT NOT NULL)")
                    .execute(db.pool()).await.unwrap();
                sqlx::query("INSERT INTO password_history_legacy VALUES (?,?,?,?,1,?)")
                    .bind(password.id.0.to_string())
                    .bind(password.profile_id)
                    .bind(vec![11u8; 32])
                    .bind(vec![12u8; 32])
                    .bind(Utc::now().to_rfc3339())
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
        }
    }

    async fn reconcile_fixture(&self, owner: ProfileId) {
        // This is test fixture cleanup, not a product conversion algorithm.
        // It models completion of an independently authorized reconciliation.
        match self {
            #[cfg(feature = "storage-pg")]
            Self::Postgres(db) => {
                sqlx::query("DELETE FROM password_history_legacy WHERE owner_id = $1")
                    .bind(owner)
                    .execute(db.pool())
                    .await
                    .unwrap();
            }
            #[cfg(feature = "storage-sqlite")]
            Self::Sqlite(db) => {
                let table: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = 'password_history_legacy')")
                    .fetch_one(db.pool()).await.unwrap();
                if table {
                    sqlx::query("DELETE FROM password_history_legacy WHERE owner_id = ?")
                        .bind(owner)
                        .execute(db.pool())
                        .await
                        .unwrap();
                } else {
                    sqlx::query(
                        "UPDATE credentials SET history_commitment = NULL WHERE profile_id = ?",
                    )
                    .bind(owner)
                    .execute(db.pool())
                    .await
                    .unwrap();
                }
            }
        }
    }
}

fn audit() -> MutationContext {
    AuditEntry::system("test", "history-inventory").into()
}

fn epoch(owner: ProfileId) -> NewHistoryEpoch {
    let id = HistoryEpochId::generate();
    NewHistoryEpoch {
        epoch: HistoryEpoch {
            id,
            owner,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [21; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [22; 32],
            status: HistoryEpochUse::Active,
            created_at: Utc::now(),
        },
        key: WrappedHistoryKey(
            sid_keys::EncryptedField {
                key_version: 1,
                nonce: [0; 12],
                context: format!("password-history-key:{}:{owner}", id.0),
                ciphertext: vec![23; 48],
            }
            .to_bytes(),
        ),
    }
}

async fn account(db: &dyn StorageBackend) -> Credential {
    let name = format!("history-inventory-{}", Uuid::now_v7());
    let profile = Profile::new(Some(&name));
    db.create_profile(&profile, audit()).await.unwrap();
    let password = Credential::new(
        profile.id,
        CredentialType::Opaque,
        b"original".to_vec(),
        None,
    );
    db.create_credential(&password, audit()).await.unwrap();
    password
}

fn refused<T: std::fmt::Debug>(result: sid_core::Result<T>) {
    assert!(
        matches!(result, Err(sid_core::Error::InvalidState(_))),
        "unsupported retained history must refuse, got {result:?}"
    );
}

async fn refuses_empty_window(db: Database, inventory: Inventory) {
    let storage = db.storage();
    let password = account(storage).await;
    let unaffected = account(storage).await;
    db.seed(&password, inventory).await;
    // The first read must not report revision zero, and preparation must not
    // create a fresh epoch over retained old-format constraints.
    refused(storage.get_password_history(password.profile_id).await);
    let new = epoch(password.profile_id);
    refused(storage.ensure_history_epoch(&new, audit()).await);
    assert!(
        storage
            .get_history_epoch_key(new.epoch.id)
            .await
            .unwrap()
            .is_none()
    );
    refused(storage.export_password_history(password.profile_id).await);
    assert_eq!(
        storage
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"original"
    );
    assert_eq!(
        storage
            .get_password_history(unaffected.profile_id)
            .await
            .unwrap()
            .revision,
        0
    );
    db.reconcile_fixture(password.profile_id).await;
    assert_eq!(
        storage
            .get_password_history(password.profile_id)
            .await
            .unwrap()
            .revision,
        0,
        "refused preparation must not leave a history row"
    );
}

async fn fences_prepared_mutations(db: Database, inventory: Inventory) {
    let storage = db.storage();
    let password = account(storage).await;
    let prepared = storage
        .ensure_history_epoch(&epoch(password.profile_id), audit())
        .await
        .unwrap();
    let before = storage
        .export_password_history(password.profile_id)
        .await
        .unwrap()
        .unwrap();
    let reset = PasswordResetSession::new(
        password.profile_id,
        "user@example.com".into(),
        "fixture".into(),
    );
    storage.create_reset_session(&reset, audit()).await.unwrap();
    assert!(
        storage
            .verify_reset_session(reset.id, audit())
            .await
            .unwrap()
    );
    let session = Session::new(
        password.profile_id,
        "127.0.0.1".into(),
        Utc::now() + Duration::hours(1),
    );
    storage.create_session(&session, audit()).await.unwrap();
    let commit = HistoryCommit {
        owner: password.profile_id,
        expected_revision: before.revision,
        new_epoch: None,
        entries: vec![(prepared.id, [31; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth: 1,
    };
    let mut replacement = password.clone();
    replacement.data = CredentialData::new(b"replacement".to_vec());
    replacement.policy_evidence = sid_core::models::PolicyEvidence::Verified {
        policy_version: 1,
        artifact: [1; 32],
    };
    // Inventory appears after Begin. Refusing reads alone cannot fence this
    // already prepared operation: the check must also be inside its commit.
    db.seed(&password, inventory).await;
    refused(
        storage
            .change_password(
                password.id,
                b"original",
                &replacement,
                Some(&commit),
                audit(),
            )
            .await,
    );
    let reset_credential = Credential::new(
        password.profile_id,
        CredentialType::Opaque,
        b"reset".to_vec(),
        None,
    );
    refused(
        storage
            .complete_password_reset(
                reset.id,
                &reset_credential,
                Some(&commit),
                &SessionEnd::new(RevocationReason::UserRequested, "system"),
                audit(),
            )
            .await,
    );
    // An authorized no-proof replacement may not erase the only retained
    // constraint either; permitted no-proof reset preserves retained history.
    refused(
        storage
            .complete_password_reset(
                reset.id,
                &reset_credential,
                None,
                &SessionEnd::new(RevocationReason::UserRequested, "system"),
                audit(),
            )
            .await,
    );
    assert_eq!(
        storage
            .get_credential(password.id)
            .await
            .unwrap()
            .unwrap()
            .data
            .expose(),
        b"original"
    );
    assert!(
        storage
            .get_credential(reset_credential.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        storage
            .get_reset_session(reset.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ResetSessionStatus::Verified
    );
    assert!(
        storage.get_session(session.id).await.unwrap().is_some(),
        "a refused reset must not revoke the existing login"
    );
    // After fixture reconciliation, exactly the original prepared revision
    // remains: refusal changed no credential, history, retention or reset state.
    db.reconcile_fixture(password.profile_id).await;
    assert_eq!(
        storage
            .export_password_history(password.profile_id)
            .await
            .unwrap(),
        Some(before)
    );
    assert!(
        storage
            .change_password(
                password.id,
                b"original",
                &replacement,
                Some(&commit),
                audit()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        storage
            .get_password_history(password.profile_id)
            .await
            .unwrap()
            .entries
            .len(),
        1
    );
    // Current-format history is a different case: an authorized no-proof
    // reset still works and preserves the exact trusted history archive.
    let trusted = storage
        .export_password_history(password.profile_id)
        .await
        .unwrap();
    assert!(
        storage
            .complete_password_reset(
                reset.id,
                &reset_credential,
                None,
                &SessionEnd::new(RevocationReason::UserRequested, "system"),
                audit(),
            )
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        storage
            .export_password_history(password.profile_id)
            .await
            .unwrap(),
        trusted,
        "no-proof reset must not append or evict trusted history"
    );
}

#[cfg(feature = "storage-pg")]
async fn postgres() -> Database {
    static READY: tokio::sync::OnceCell<sid_storage::PostgresBackend> =
        tokio::sync::OnceCell::const_new();
    let db = READY
        .get_or_init(|| async {
            let url = std::env::var("SID_STORAGE_TEST_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| {
                    "postgres://sid:sid_dev@localhost:54399/sid_storage_test".into()
                });
            let db = sid_storage::PostgresBackend::new(&url, None).await.unwrap();
            sid_storage::migrator::run_migrations(db.pool(), None)
                .await
                .unwrap();
            db
        })
        .await;
    Database::Postgres(db.clone())
}

#[cfg(feature = "storage-pg")]
#[tokio::test]
async fn postgres_legacy_inventory_is_not_an_empty_window() {
    refuses_empty_window(postgres().await, Inventory::RetainedRows).await;
}

#[cfg(feature = "storage-pg")]
#[tokio::test]
async fn postgres_legacy_inventory_fences_prepared_change_and_reset() {
    fences_prepared_mutations(postgres().await, Inventory::RetainedRows).await;
}

#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn sqlite_legacy_inventory_is_not_an_empty_window() {
    refuses_empty_window(
        Database::Sqlite(
            sid_storage::sqlite::SqliteBackend::new_in_memory()
                .await
                .unwrap(),
        ),
        Inventory::RetainedRows,
    )
    .await;
}

#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn sqlite_legacy_inventory_fences_prepared_change_and_reset() {
    fences_prepared_mutations(
        Database::Sqlite(
            sid_storage::sqlite::SqliteBackend::new_in_memory()
                .await
                .unwrap(),
        ),
        Inventory::RetainedRows,
    )
    .await;
}

#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn sqlite_old_credential_column_is_not_an_empty_window() {
    refuses_empty_window(
        Database::Sqlite(
            sid_storage::sqlite::SqliteBackend::new_in_memory()
                .await
                .unwrap(),
        ),
        Inventory::CredentialColumn,
    )
    .await;
}

#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn sqlite_old_credential_column_fences_prepared_change_and_reset() {
    // In particular, reset must check before deleting the credential row
    // that owns the adopted file's only copy of the retained constraint.
    fences_prepared_mutations(
        Database::Sqlite(
            sid_storage::sqlite::SqliteBackend::new_in_memory()
                .await
                .unwrap(),
        ),
        Inventory::CredentialColumn,
    )
    .await;
}
