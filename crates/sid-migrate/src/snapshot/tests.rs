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
    // Version 6 names a session's and refresh token's account `owner`.
    assert_eq!(snapshot.metadata.version, SNAPSHOT_VERSION);
    assert_eq!(snapshot.metadata.source_backend, "postgresql");
}

// A snapshot of an older format is refused for its version, before its body
// is read: a version-5 session names its account `profile_id`, which this
// format no longer reads, and the operator must learn to export again.
#[test]
fn test_older_format_is_refused_by_version() {
    let mut value = serde_json::to_value(Snapshot::new("sqlite", "sqlite://a.db")).unwrap();
    value["metadata"]["version"] = 5.into();
    value["sessions"] = serde_json::json!([{ "id": "x", "profile_id": "y" }]);
    let err = Snapshot::parse(&value.to_string()).unwrap_err().to_string();
    assert!(err.contains("format version 5"), "{err}");
}

#[test]
fn test_current_format_parses() {
    let json = serde_json::to_string(&Snapshot::new("sqlite", "sqlite://a.db")).unwrap();
    let parsed = Snapshot::parse(&json).unwrap();
    assert_eq!(parsed.metadata.version, SNAPSHOT_VERSION);
}
