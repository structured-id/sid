// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use secrecy::ExposeSecret;

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("sid-field-keys-{}", uuid::Uuid::now_v7().simple()))
        .join(name)
}

/// A missing master file is created once; later starts read the same secret.
#[test]
fn master_is_created_once_and_reused() {
    let path = temp_path("master.key");
    let first = load_or_create_master(&path).unwrap();
    let second = load_or_create_master(&path).unwrap();
    assert_eq!(first.expose_secret(), second.expose_secret());
    assert_ne!(first.expose_secret(), &[0u8; 32]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "master key must be owner-only, got {mode:o}"
        );
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A master file of the wrong length is refused rather than padded or cut.
#[test]
fn master_of_wrong_length_is_refused() {
    let path = temp_path("short.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, [7u8; 31]).unwrap();
    let err = load_or_create_master(&path).unwrap_err();
    assert!(matches!(err, FieldKeyError::Length(_)), "{err:?}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
