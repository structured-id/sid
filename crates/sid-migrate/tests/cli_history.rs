// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the installed CLI path, including private output permissions.

use sid_core::models::*;
use sid_plugin::storage::StorageBackend;
use sid_storage::sqlite::SqliteBackend;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sid-migrate"))
        .args(args)
        .output()
        .unwrap()
}

/// A real file-backed source moves its nonempty history through JSON and the
/// CLI; an existing output file is neither overwritten nor made world-readable.
#[tokio::test]
async fn cli_moves_history_and_protects_the_export() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.sqlite");
    let target_path = dir.path().join("target.sqlite");
    let output_path = dir.path().join("snapshot.json");
    let source_url = format!("sqlite://{}", source_path.display());
    let target_url = format!("sqlite://{}", target_path.display());
    let source = SqliteBackend::new(source_path.to_str().unwrap())
        .await
        .unwrap();
    let ctx = || AuditEntry::system("test", "cli").into();
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
    let epoch = NewHistoryEpoch {
        epoch: HistoryEpoch {
            id,
            owner: profile.id,
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
                context: format!("password-history-key:{}:{}", id.0, profile.id),
                ciphertext: vec![5; 48],
            }
            .to_bytes(),
        ),
    };
    source.ensure_history_epoch(&epoch, ctx()).await.unwrap();
    let before = source.export_password_history(profile.id).await.unwrap();
    let output = output_path.to_str().unwrap();
    let exported = run(&["export", "--source", &source_url, "--output", output]);
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
        !run(&["export", "--source", &source_url, "--output", output])
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
        target.export_password_history(profile.id).await.unwrap(),
        before
    );
    let verified = run(&["verify", "--source", &source_url, "--target", &target_url]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );
}
