use super::*;
use sid_crypto::RustCryptoPrimitives;

fn key(byte: u8) -> ArchiveKey {
    ArchiveKey::from_bytes(&[byte; 32]).unwrap()
}

// A sealed snapshot opens under its key into the same snapshot, and its
// manifest is readable without the key; the snapshot itself is not stored
// in the clear.
#[test]
fn a_sealed_snapshot_opens_under_its_key() {
    let crypto = RustCryptoPrimitives::new();
    let mut snapshot = Snapshot::new("sqlite");
    snapshot.metadata.installation_org = None;
    snapshot.history_write_cutoff = Some(chrono::Utc::now());
    let sealed = seal(&snapshot, &key(1), &crypto).unwrap();

    let manifest = manifest(&sealed).unwrap();
    assert_eq!(manifest.snapshot_id, snapshot.metadata.snapshot_id);
    assert_eq!(manifest.format, FORMAT_VERSION);
    let payload = snapshot.to_json().unwrap();
    assert!(
        !sealed
            .windows(b"history_write_cutoff".len())
            .any(|w| w == b"history_write_cutoff"),
        "the snapshot is stored encrypted"
    );

    let opened = open(&sealed, &key(1), &crypto).unwrap();
    assert_eq!(opened.to_json().unwrap(), payload);
}

// Another key, a changed manifest or a changed ciphertext opens nothing.
#[test]
fn a_changed_archive_or_another_key_opens_nothing() {
    let crypto = RustCryptoPrimitives::new();
    let sealed = seal(&Snapshot::new("sqlite"), &key(1), &crypto).unwrap();

    assert!(matches!(
        open(&sealed, &key(2), &crypto),
        Err(SnapshotError::Archive(_))
    ));

    let mut body = sealed.clone();
    let last = body.len() - 1;
    body[last] ^= 1;
    assert!(matches!(
        open(&body, &key(1), &crypto),
        Err(SnapshotError::Archive(_))
    ));

    // A manifest byte flipped: the manifest is authenticated with the
    // contents.
    let mut header = sealed.clone();
    let position = header
        .windows(6)
        .position(|w| w == b"sqlite")
        .expect("the manifest names its source");
    header[position] = b'S';
    assert!(open(&header, &key(1), &crypto).is_err());
}

// Bytes that are not an archive, a truncated archive and a key of another
// length are refused.
#[test]
fn what_is_not_an_archive_is_refused() {
    let crypto = RustCryptoPrimitives::new();
    assert!(matches!(
        manifest(b"{\"metadata\":{}}"),
        Err(SnapshotError::Archive(_))
    ));
    let sealed = seal(&Snapshot::new("sqlite"), &key(1), &crypto).unwrap();
    assert!(manifest(&sealed[..10]).is_err());
    assert!(open(&sealed[..sealed.len() / 2], &key(1), &crypto).is_err());
    assert!(ArchiveKey::from_bytes(&[0; 16]).is_err());
}
