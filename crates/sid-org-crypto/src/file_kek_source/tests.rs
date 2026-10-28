// SPDX-License-Identifier: AGPL-3.0-only

use secrecy::ExposeSecret;

use super::*;

/// A mounted key directory: `selector` as `kek_version` when given, and each
/// `(n, bytes)` as `kek.<n>`.
fn mounted(selector: Option<&str>, versions: &[(u32, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if let Some(selector) = selector {
        std::fs::write(dir.path().join(VERSION_FILE), selector).unwrap();
    }
    for (n, bytes) in versions {
        std::fs::write(dir.path().join(format!("kek.{n}")), bytes).unwrap();
    }
    dir
}

const HEX: &[u8] = b"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

// A version's KEK is read from its own file, 32 raw bytes or 64 hex
// characters with a trailing newline ignored; the selector names the
// current version.
#[tokio::test]
async fn reads_the_mounted_versions() {
    let dir = mounted(
        Some("7\n"),
        &[(7, &[0xAB; 32]), (2, &[HEX, b"\n"].concat())],
    );
    let source = FileKekSource::new(dir.path());
    assert_eq!(source.current_version().await.unwrap(), 7);
    assert_eq!(
        source.fetch_kek(7).await.unwrap().expose_secret(),
        &[0xAB; 32]
    );
    let old = source.fetch_kek(2).await.unwrap();
    assert_eq!(old.expose_secret()[0], 0x01);
    assert_eq!(old.expose_secret()[31], 0x20);
    assert_eq!(source.kind(), "file");
}

// A raw KEK written with a trailing newline is the 32 bytes before it; a raw
// KEK whose own last byte is whitespace keeps it.
#[tokio::test]
async fn a_raw_kek_with_a_trailing_newline_is_read() {
    let mut with_newline = vec![0xCD; 32];
    with_newline.push(b'\n');
    let mut ends_in_space = [0x11; 32];
    ends_in_space[31] = b' ';
    let dir = mounted(Some("1"), &[(1, &with_newline), (2, &ends_in_space)]);
    let source = FileKekSource::new(dir.path());
    assert_eq!(
        source.fetch_kek(1).await.unwrap().expose_secret(),
        &[0xCD; 32]
    );
    assert_eq!(
        source.fetch_kek(2).await.unwrap().expose_secret(),
        &ends_in_space
    );
}

// Without the selector there is no current version: refused, never taken
// as version 1.
#[tokio::test]
async fn a_missing_selector_is_refused() {
    let dir = mounted(None, &[(1, &[0; 32])]);
    assert!(matches!(
        FileKekSource::new(dir.path())
            .current_version()
            .await
            .unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
}

// A version without its own file is refused even with an unversioned `kek`
// beside it: bytes of an unproven version are never returned as that
// version, so nothing is wrapped under a version they do not belong to.
#[tokio::test]
async fn a_version_without_its_file_is_refused() {
    let dir = mounted(Some("1"), &[]);
    std::fs::write(dir.path().join("kek"), [9; 32]).unwrap();
    let source = FileKekSource::new(dir.path());
    assert!(matches!(
        source.fetch_kek(1).await.unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
    let retained = mounted(Some("3"), &[(1, &[1; 32]), (3, &[3; 32])]);
    assert!(matches!(
        FileKekSource::new(retained.path())
            .fetch_kek(2)
            .await
            .unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
}

// A KEK of the wrong length, 64 characters that are not hex and a selector
// that is not a number are refused.
#[tokio::test]
async fn malformed_mounts_are_refused() {
    let short = mounted(Some("1"), &[(1, b"too short")]);
    assert!(matches!(
        FileKekSource::new(short.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::InvalidKekLength(9)
    ));
    let not_hex = mounted(Some("1"), &[(1, &[b'z'; 64])]);
    assert!(matches!(
        FileKekSource::new(not_hex.path())
            .fetch_kek(1)
            .await
            .unwrap_err(),
        OrgCryptoError::InvalidKekLength(64)
    ));
    let bad_selector = mounted(Some("one"), &[(1, &[0; 32])]);
    assert!(matches!(
        FileKekSource::new(bad_selector.path())
            .current_version()
            .await
            .unwrap_err(),
        OrgCryptoError::KekUnavailable(_)
    ));
}

// A rotation adds the next version's file and then moves the selector: the
// old version stays readable, the new one is current without a restart.
#[tokio::test]
async fn a_rotation_keeps_the_old_version() {
    let dir = mounted(Some("1"), &[(1, &[1; 32])]);
    let source = FileKekSource::new(dir.path());
    assert_eq!(source.current_version().await.unwrap(), 1);
    std::fs::write(dir.path().join("kek.2"), [2; 32]).unwrap();
    std::fs::write(dir.path().join(VERSION_FILE), "2").unwrap();
    assert_eq!(source.current_version().await.unwrap(), 2);
    assert_eq!(source.fetch_kek(2).await.unwrap().expose_secret(), &[2; 32]);
    assert_eq!(source.fetch_kek(1).await.unwrap().expose_secret(), &[1; 32]);
}
