use super::*;

/// Each entry names an earlier consumer and its receiver; blanks and spaces
/// around entries are ignored.
#[test]
fn test_receivers_parse() {
    let parsed = parse_receivers(" notify-events=sid-notify , scim=sid-scim-outbound,").unwrap();
    assert_eq!(
        parsed,
        [
            (
                "notify-events".to_string(),
                WorkRecipient::new("sid-notify").unwrap()
            ),
            (
                "scim".to_string(),
                WorkRecipient::new("sid-scim-outbound").unwrap()
            ),
        ]
    );
    assert!(parse_receivers("").unwrap().is_empty());
}

/// An entry without a receiver, without a consumer name, or naming an
/// invalid receiver is a configuration error, never a skipped consumer.
#[test]
fn test_malformed_receivers_are_refused() {
    for malformed in ["notify", "=sid-notify", "notify=", "notify=Not A Receiver"] {
        assert!(
            matches!(parse_receivers(malformed), Err(TopologyError::Config(_))),
            "{malformed:?}"
        );
    }
}

/// The archive subject stays under the root and apart from every family of
/// the identity topology.
#[test]
fn test_archive_is_apart_from_the_identity_families() {
    let t = Topology::default();
    let archive = archive_subject(&t);
    assert_eq!(archive, "sid.archive.>");
    for family in ["sid.events.identity.>", "sid.work.identity.>"] {
        assert_ne!(archive.split('.').nth(1), family.split('.').nth(1));
    }
    assert_eq!(t.earlier_stream(), "SID_EVENTS");
}
