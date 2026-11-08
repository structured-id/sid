use super::*;

#[test]
fn test_snapshot_empty_count() {
    let snapshot = Snapshot::new("test");
    assert_eq!(snapshot.count_entities(), 0);
}

#[test]
fn test_snapshot_metadata_version() {
    let snapshot = Snapshot::new("postgresql");
    assert_eq!(snapshot.metadata.version, FORMAT_VERSION);
    assert_eq!(snapshot.metadata.source_backend, "postgresql");
    assert_eq!(snapshot.metadata.snapshot_id.get_version_num(), 7);
}

// A snapshot written by this build is read back; one of an earlier format,
// whose contents this format does not have (the issuer registry), is
// refused by its version, not by a missing field deep in its body.
#[test]
fn test_only_this_format_is_read() {
    let snapshot = Snapshot::new("sqlite");
    let json = snapshot.to_json().unwrap();
    assert!(Snapshot::parse(&json).is_ok());

    let mut earlier = serde_json::to_value(&snapshot).unwrap();
    earlier["metadata"]["version"] = serde_json::json!(7);
    earlier.as_object_mut().unwrap().remove("oidc_issuers");
    let refused = Snapshot::parse(earlier.to_string().as_bytes()).unwrap_err();
    assert!(matches!(refused, SnapshotError::Format(7)), "{refused}");
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
    let mut snapshot = Snapshot::new("sqlite");
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
