use super::*;

#[test]
fn test_sanitize_url_postgres() {
    let url = "postgres://user:secret@host:5432/db";
    let sanitized = sanitize_url(url);
    assert!(sanitized.contains("***"));
    assert!(!sanitized.contains("secret"));
    assert!(sanitized.contains("user"));
    assert!(sanitized.contains("host:5432"));
}

#[test]
fn test_sanitize_url_sqlite() {
    let url = "sqlite:///var/lib/sid/auth.db";
    let sanitized = sanitize_url(url);
    assert_eq!(sanitized, url);
}

#[test]
fn test_snapshot_empty_count() {
    let snapshot = Snapshot::new("test", "test://");
    assert_eq!(snapshot.count_entities(), 0);
}

#[test]
fn test_snapshot_metadata_version() {
    let snapshot = Snapshot::new("postgresql", "postgres://localhost/sid");
    // Version 4 carries the history evaluator's sealed keys apart from the
    // history, besides the sealed setup required by OPAQUE files.
    assert_eq!(snapshot.metadata.version, 4);
    assert_eq!(snapshot.metadata.source_backend, "postgresql");
}
