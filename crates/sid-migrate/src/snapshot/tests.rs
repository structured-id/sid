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
    assert_eq!(snapshot.metadata.version, 5);
    assert_eq!(snapshot.metadata.source_backend, "postgresql");
}

// A session exported in a snapshot names its Profile as `profile_id` and is
// read back with the same Profile and session.
#[test]
fn test_session_round_trips_with_its_profile() {
    let profile = sid_core::models::ProfileId::generate();
    let session = Session::new(
        profile,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let mut snapshot = Snapshot::new("sqlite", "sqlite://a.db");
    snapshot.sessions.push(session.clone());

    let json = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        json["sessions"][0]["profile_id"],
        serde_json::json!(profile.to_string())
    );
    let read: Snapshot = serde_json::from_value(json).unwrap();
    assert_eq!(read.sessions[0].id, session.id);
    assert_eq!(read.sessions[0].profile_id, profile);
}
