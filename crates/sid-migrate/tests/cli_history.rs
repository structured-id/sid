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

/// The evaluator's key version the source's history key is sealed under.
fn history_key_version() -> sid_keys::KeyVersionParams {
    sid_keys::KeyVersionParams::new(1, vec![7; 16], "history-v1")
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
        .history_keys()
        .insert_key_version(&history_key_version(), AuditEntry::system("test", "cli"))
        .await
        .unwrap();
    let id = HistoryEpochId::generate();
    let owner_domain = sid_authn::password_history::owner_domain(org.id.as_bytes(), profile.id);
    let epoch = NewKeyEpoch {
        epoch: KeyEpoch {
            id,
            owner_domain,
            suite: HistorySuite::PallasPoseidonV1,
            // A valid evaluator public key: the Pallas generator.
            public_key: {
                use group::{Curve, Group, GroupEncoding};
                pasta_curves::pallas::Point::generator()
                    .to_affine()
                    .to_bytes()
            },
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
/// A PostgreSQL schema has no meaning for a SQLite installation: asking for
/// one is refused before anything is read or written, never ignored.
#[tokio::test]
async fn cli_refuses_a_schema_for_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let org = Organization::implicit_community("sid.example.com");
    let source = source_with_history(dir.path(), &org).await;
    let output_path = dir.path().join("snapshot.json");
    let exported = run(&[
        "export",
        "--source",
        &source.url,
        "--schema",
        "tenant_a",
        "--output",
        output_path.to_str().unwrap(),
    ]);
    assert!(
        !exported.status.success(),
        "a schema for SQLite was accepted"
    );
    assert!(
        String::from_utf8_lossy(&exported.stderr).contains("schema"),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(!output_path.exists(), "nothing is written");
}

/// Every URL and option pair is checked before any input is read or any
/// database is reached: a wrong target (a schema for SQLite, a malformed
/// PostgreSQL schema, a history-key store that is not PostgreSQL) neither
/// waits on its input nor connects to (and
/// migrates) the source first. The input here does not exist and the
/// databases refuse connections, so a late check reports those instead.
#[tokio::test]
async fn cli_refuses_a_bad_target_before_any_io() {
    let dir = tempfile::tempdir().unwrap();
    let target = format!("sqlite://{}", dir.path().join("target.sqlite").display());
    let missing = dir.path().join("missing.json");
    let unreachable = "postgres://sid:sid_dev@127.0.0.1:1/sid";
    let sqlite_schema = "no PostgreSQL schema";
    let malformed_schema = "Schema name";
    let history_keys_url = "history key store is a PostgreSQL database";
    let runs = [
        (
            vec![
                "import",
                "--target",
                &target,
                "--schema",
                "tenant_a",
                "--input",
                missing.to_str().unwrap(),
            ],
            sqlite_schema,
        ),
        (
            vec![
                "migrate",
                "--source",
                unreachable,
                "--target",
                &target,
                "--target-schema",
                "tenant_a",
            ],
            sqlite_schema,
        ),
        (
            vec![
                "verify",
                "--source",
                unreachable,
                "--target",
                &target,
                "--target-schema",
                "tenant_a",
            ],
            sqlite_schema,
        ),
        (
            vec![
                "import",
                "--target",
                unreachable,
                "--schema",
                "tenant a",
                "--input",
                missing.to_str().unwrap(),
            ],
            malformed_schema,
        ),
        (
            vec![
                "migrate",
                "--source",
                unreachable,
                "--target",
                unreachable,
                "--target-schema",
                "tenant a",
            ],
            malformed_schema,
        ),
        (
            vec![
                "import",
                "--target",
                unreachable,
                "--history-keys",
                "sqlite:///tmp/keys.db",
                "--input",
                missing.to_str().unwrap(),
            ],
            history_keys_url,
        ),
        (
            vec![
                "migrate",
                "--source",
                unreachable,
                "--target",
                unreachable,
                "--target-history-keys",
                "sqlite:///tmp/keys.db",
            ],
            history_keys_url,
        ),
    ];
    for (args, refusal) in runs {
        let refused = run(&args);
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{args:?} was accepted");
        assert!(stderr.contains(refusal), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("failed to"),
            "{args:?} did I/O first: {stderr}"
        );
    }
    assert!(
        !dir.path().join("target.sqlite").exists(),
        "nothing created"
    );
}

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
    // The evaluator's key custody moved with its keys, to its database.
    assert_eq!(
        keys.list_key_versions().await.unwrap(),
        vec![history_key_version()]
    );
    assert!(target.list_key_versions().await.unwrap().is_empty());
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
