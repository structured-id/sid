// SPDX-License-Identifier: AGPL-3.0-only

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use secrecy::SecretString;

use super::*;

/// A new pair: the private key the host loads signs an assertion the
/// published JWK Set verifies, under the kid the set names.
#[test]
fn a_new_pair_signs_what_its_jwks_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = (dir.path().join("key.pem"), dir.path().join("jwks.json"));
    let kid = generate(&private, &public).unwrap();

    let pem = SecretString::from(std::fs::read_to_string(&private).unwrap());
    let key = ClientKey::ed25519_from_pem(&pem).unwrap();
    assert_eq!(key.kid(), Some(kid.as_str()));
    let assertion = key
        .sign("client-1", "https://sid.example.com/token")
        .unwrap();

    let jwks: JwkSet = serde_json::from_slice(&std::fs::read(&public).unwrap()).unwrap();
    let jwk = jwks.find(&kid).expect("the set names the key");
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["https://sid.example.com/token"]);
    decode::<serde_json::Value>(
        &assertion,
        &DecodingKey::from_jwk(jwk).unwrap(),
        &validation,
    )
    .unwrap();
}

/// The private key is readable by its owner only.
#[cfg(unix)]
#[test]
fn the_private_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("key.pem");
    generate(&private, &dir.path().join("jwks.json")).unwrap();
    let mode = std::fs::metadata(&private).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// An existing key is never replaced: that would lock the client out of
/// what its installation registered.
#[test]
fn an_existing_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = (dir.path().join("key.pem"), dir.path().join("jwks.json"));
    std::fs::write(&private, "registered").unwrap();
    assert!(generate(&private, &public).is_err());
    assert_eq!(std::fs::read_to_string(&private).unwrap(), "registered");
}

/// A taken public path is refused before any private key is written, so no
/// key is left without its set.
#[test]
fn a_taken_public_path_writes_no_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = (dir.path().join("key.pem"), dir.path().join("jwks.json"));
    std::fs::write(&public, "{}").unwrap();
    assert!(generate(&private, &public).is_err());
    assert!(!private.exists());
}

/// A public set that cannot be written takes back the private key this call
/// wrote, so the same command succeeds once the cause is fixed; a dangling
/// link at the public path is a taken path too.
#[test]
fn an_unwritable_public_set_leaves_no_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("key.pem");
    let missing = dir.path().join("absent").join("jwks.json");
    assert!(generate(&private, &missing).is_err());
    assert!(!private.exists(), "the private key was taken back");

    std::fs::create_dir(dir.path().join("absent")).unwrap();
    generate(&private, &missing).unwrap();

    #[cfg(unix)]
    {
        let other = dir.path().join("other.pem");
        let dangling = dir.path().join("dangling.json");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(generate(&other, &dangling).is_err());
        assert!(!other.exists());
    }
}

/// A writer that fails as a full disk or an exhausted quota does.
struct Full;

impl std::io::Write for Full {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("no space left on device"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A file whose contents could not be written is removed, not left empty or
/// truncated: once the storage is fixed the same command runs again instead
/// of refusing its own leftover.
#[test]
fn a_file_that_could_not_be_written_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    std::fs::File::create(&path).unwrap();
    assert!(fill(&path, Full, b"contents").is_err());
    assert!(!path.exists(), "a partial file was left behind");
}

/// The command takes exactly the two paths.
#[test]
fn keygen_wants_two_paths() {
    for args in [
        vec![],
        vec!["key.pem".to_owned()],
        vec!["a".into(), "b".into(), "c".into()],
    ] {
        let err = keygen(&args).unwrap_err();
        assert!(err.to_string().starts_with("usage:"), "{args:?}: {err}");
    }
}
