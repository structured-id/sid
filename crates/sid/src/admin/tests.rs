use super::*;

/// A metadata entry carries its JSON value as a protobuf value, nested
/// objects and arrays included.
#[test]
fn test_metadata_to_proto_carries_the_value() {
    let profile = ProfileId::generate();
    let entry = metadata_to_proto(ProfileMetadata::new(
        profile,
        "team",
        serde_json::json!({"name": "platform", "tags": ["a", "b"], "size": 3, "lead": null}),
    ));
    assert_eq!(entry.profile_id, Some(profile.into()));
    assert_eq!(entry.key, "team");
    assert!(entry.updated_at.is_some());
    let back = value_to_json(entry.value.expect("value"));
    assert_eq!(back["name"], "platform");
    assert_eq!(back["tags"][1], "b");
    assert_eq!(back["size"], 3.0);
    assert!(back["lead"].is_null());
}

/// The roles reserved to role assignment are refused on the roles field.
#[test]
fn test_invalid_names_its_field() {
    match invalid("roles", "reserved") {
        AdminError::InvalidField { field, reason } => {
            assert_eq!(field, "roles");
            assert_eq!(reason, "reserved");
        }
        other => panic!("{other:?}"),
    }
}
