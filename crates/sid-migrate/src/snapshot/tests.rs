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
    assert_eq!(snapshot.metadata.version, FORMAT_VERSION);
    assert_eq!(snapshot.metadata.source_backend, "postgresql");
}

// A snapshot written by this build is read back; one of an earlier format,
// whose contents this format does not have (operation period state), is
// refused by its version, not by a missing field deep in its body.
#[test]
fn test_only_this_format_is_read() {
    let snapshot = Snapshot::new("sqlite", "sqlite://a.db");
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(Snapshot::parse(&json).is_ok());

    let mut earlier = serde_json::to_value(&snapshot).unwrap();
    earlier["metadata"]["version"] = serde_json::json!(5);
    earlier.as_object_mut().unwrap().remove("operation_periods");
    let refused = Snapshot::parse(&earlier.to_string()).unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("unsupported snapshot format 5"),
        "{refused}"
    );
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
