// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the installed CLI path, including private output permissions.

use sid_core::models::*;
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use sid_storage::sqlite::SqliteBackend;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sid-migrate"))
        .args(args)
        .output()
        .unwrap()
}

fn ctx() -> MutationContext {
    AuditEntry::system("test", "cli").into()
}

/// A file-backed installation of `org` whose one profile has a nonempty
/// history under an evaluator key, written by an accepted password's commit.
struct Source {
    url: String,
    profile: ProfileId,
    epoch: NewKeyEpoch,
    history: Option<HistoryArchive>,
}

async fn source_with_history(dir: &std::path::Path, org: &Organization) -> Source {
    let path = dir.join("source.sqlite");
    let source = SqliteBackend::new(path.to_str().unwrap()).await.unwrap();
    source
        .insert_instance_organization(org, ctx())
        .await
        .unwrap();
    let profile = Profile::new(Some("cli-history-transfer"));
    source.create_profile(&profile, ctx()).await.unwrap();
    source
        .insert_key_version(
            &sid_keys::KeyVersionParams::new(1, vec![7; 16], "key-v1"),
            ctx(),
        )
        .await
        .unwrap();
    let id = HistoryEpochId::generate();
    let owner_domain = sid_authn::password_history::owner_domain(org.id.as_bytes(), profile.id);
    let epoch = NewKeyEpoch {
        epoch: KeyEpoch {
            id,
            owner_domain,
            suite: HistorySuite::PallasPoseidonV1,
            public_key: [3; 32],
            ksf: HistoryKsf::DEFAULT,
            ksf_salt: [4; 32],
            status: HistoryEpochUse::Active,
            created_at: chrono::DateTime::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap(),
        },
        key: WrappedHistoryKey(
            sid_keys::EncryptedField {
                key_version: 1,
                nonce: [0; 12],
                context: history_key_context(id, &owner_domain),
                ciphertext: vec![5; 48],
            }
            .to_bytes(),
        ),
    };
    source
        .history_keys()
        .create_first_epoch(
            &epoch,
            uuid::Uuid::now_v7(),
            AuditEntry::system("test", "cli"),
        )
        .await
        .unwrap();
    let password = Credential::new(profile.id, CredentialType::Totp, b"before".to_vec(), None);
    source.create_credential(&password, ctx()).await.unwrap();
    let mut changed = password.clone();
    changed.data = CredentialData::new(b"after".to_vec());
    let commit = HistoryCommit {
        owner: profile.id,
        expected_revision: 0,
        epochs: vec![epoch.epoch.descriptor()],
        entries: vec![(id, [9; 32])],
        evidence: HistoryEvidence {
            operation: uuid::Uuid::now_v7(),
            policy_version: 1,
        },
        depth: 3,
        max_age_days: 0,
    };
    assert!(
        source
            .change_password(password.id, b"before", &changed, Some(&commit), ctx())
            .await
            .unwrap()
    );
    let history = source.export_password_history(profile.id).await.unwrap();
    assert!(history.is_some());
    Source {
        url: format!("sqlite://{}", path.display()),
        profile: profile.id,
        epoch,
        history,
    }
}

/// A real file-backed source moves its nonempty history and the evaluator's
/// keys through JSON and the CLI; an existing output file is neither
/// overwritten nor made world-readable.
#[tokio::test]
async fn cli_moves_history_and_protects_the_export() {
    let dir = tempfile::tempdir().unwrap();
    let target_path = dir.path().join("target.sqlite");
    let output_path = dir.path().join("snapshot.json");
    let target_url = format!("sqlite://{}", target_path.display());
    // The target is an installation of the same authority, as a restore has it.
    let org = Organization::implicit_community("sid.example.com");
    let source = source_with_history(dir.path(), &org).await;
    let target = SqliteBackend::new(target_path.to_str().unwrap())
        .await
        .unwrap();
    target
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    drop(target);
    let output = output_path.to_str().unwrap();
    let exported = run(&["export", "--source", &source.url, "--output", output]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let bytes = std::fs::read(&output_path).unwrap();
    assert!(
        !run(&["export", "--source", &source.url, "--output", output])
            .status
            .success()
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), bytes);
    let imported = run(&["import", "--target", &target_url, "--input", output]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let target = SqliteBackend::new(target_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        target
            .export_password_history(source.profile)
            .await
            .unwrap(),
        source.history
    );
    assert_eq!(
        target
            .history_keys()
            .get_epoch_key(source.epoch.epoch.id)
            .await
            .unwrap(),
        Some(source.epoch.key)
    );
    let verified = run(&["verify", "--source", &source.url, "--target", &target_url]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// A split installation keeps the evaluator's keys in the evaluator's own
/// database: the CLI restores them there, creating its tables, and leaves the
/// credential service's database without them; verify reads them back.
#[tokio::test]
async fn cli_restores_history_keys_into_the_evaluators_own_database() {
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("snapshot.json");
    let org = Organization::implicit_community("sid.example.com");
    let source = source_with_history(dir.path(), &org).await;

    // Two schemas of the test database stand for the two databases.
    let suffix = uuid::Uuid::now_v7().simple();
    let storage_schema = format!("migrate_credentials_{suffix}");
    let keys_schema = format!("migrate_evaluator_{suffix}");
    let target = sid_storage::PostgresBackend::new(&database_url(), Some(storage_schema.clone()))
        .await
        .expect("PostgreSQL test database at 54399");
    sid_storage::migrator::run_migrations(target.pool(), Some(&storage_schema))
        .await
        .unwrap();
    target
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA \"{keys_schema}\""
    )))
    .execute(target.pool())
    .await
    .unwrap();
    let keys_url = format!(
        "{}?options=-c%20search_path%3D{keys_schema}",
        database_url()
    );
    let target_url = database_url();

    let output = output_path.to_str().unwrap();
    let exported = run(&["export", "--source", &source.url, "--output", output]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let imported = run(&[
        "import",
        "--target",
        &target_url,
        "--schema",
        &storage_schema,
        "--history-keys",
        &keys_url,
        "--input",
        output,
    ]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    assert_eq!(
        target
            .export_password_history(source.profile)
            .await
            .unwrap(),
        source.history
    );
    let keys = sid_storage::PgHistoryKeyStore::connect(&keys_url)
        .await
        .unwrap();
    assert_eq!(
        keys.get_epoch_key(source.epoch.epoch.id).await.unwrap(),
        Some(source.epoch.key)
    );
    let (in_credentials,): (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name LIKE 'history_key%')",
    )
    .bind(&storage_schema)
    .fetch_one(target.pool())
    .await
    .unwrap();
    assert!(
        !in_credentials,
        "the credential database holds no history key"
    );

    let verified = run(&[
        "verify",
        "--source",
        &source.url,
        "--target",
        &target_url,
        "--target-schema",
        &storage_schema,
        "--target-history-keys",
        &keys_url,
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );

    for schema in [&storage_schema, &keys_schema] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema}\" CASCADE"
        )))
        .execute(target.pool())
        .await
        .unwrap();
    }
}
