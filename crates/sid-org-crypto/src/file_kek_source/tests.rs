// SPDX-License-Identifier: AGPL-3.0-only

use secrecy::ExposeSecret;

use super::*;

/// A mounted key directory holding `kek` and, when given, `kek_version`.
fn mounted(kek: &[u8], version: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(KEK_FILE), kek).unwrap();
    if let Some(version) = version {
        std::fs::write(dir.path().join(VERSION_FILE), version).unwrap();
    }
    dir
}

const HEX: &[u8] = b"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

// The KEK and its version are read from the mounted files: 32 raw bytes or
// 64 hex characters, a trailing newline ignored.
#[tokio::test]
async fn reads_the_mounted_kek_and_version() {
    let raw = mounted(&[0xAB; 32], Some("7\n"));
    let source = FileKekSource::new(raw.path());
    assert_eq!(source.current_version().await.unwrap(), 7);
    assert_eq!(
        source.fetch_kek(7).await.unwrap().expose_secret(),
        &[0xAB; 32]
    );
    assert_eq!(source.kind(), "file");

    let hex = mounted(&[HEX, b"\n"].concat(), None);
    let source = FileKekSource::new(hex.path());
    assert_eq!(
        source.current_version().await.unwrap(),
        1,
        "version 1 by default"
    );
    let kek = source.fetch_kek(1).await.unwrap();
    assert_eq!(kek.expose_secret()[0], 0x01);
    assert_eq!(kek.expose_secret()[31], 0x20);
}

// Another version than the mounted one is refused: an older wrap needs its
// own KEK, which this mount does not hold.
#[tokio::test]
async fn another_version_is_refused() {
    let dir = mounted(&[0; 32], Some("2"));
    assert!(matches!(
        FileKekSource::new(dir.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::KekVersionMismatch { have: 2, need: 1 }
    ));
}

// A missing mount, a KEK of the wrong length, 64 characters that are not hex
// and a version that is not a number are refused, never read as a default.
#[tokio::test]
async fn unusable_mounts_are_refused() {
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        FileKekSource::new(empty.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
    let short = mounted(b"too short", None);
    assert!(matches!(
        FileKekSource::new(short.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::InvalidKekLength(9)
    ));
    let not_hex = mounted(&[b'z'; 64], None);
    assert!(matches!(
        FileKekSource::new(not_hex.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::InvalidKekLength(64)
    ));
    let bad_version = mounted(&[0; 32], Some("one"));
    assert!(matches!(
        FileKekSource::new(bad_version.path())
            .current_version()
            .await
            .unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
}

// Every fetch reads the mount again: a rotated KEK is seen without a restart.
#[tokio::test]
async fn a_rotated_mount_is_read_again() {
    let dir = mounted(&[1; 32], Some("1"));
    let source = FileKekSource::new(dir.path());
    assert_eq!(source.fetch_kek(1).await.unwrap().expose_secret(), &[1; 32]);
    std::fs::write(dir.path().join(KEK_FILE), [2; 32]).unwrap();
    std::fs::write(dir.path().join(VERSION_FILE), "2").unwrap();
    assert_eq!(source.current_version().await.unwrap(), 2);
    assert_eq!(source.fetch_kek(2).await.unwrap().expose_secret(), &[2; 32]);
}
