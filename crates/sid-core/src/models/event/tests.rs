use super::*;

#[test]
fn test_event_creation() {
    let event = Event::new("sid-identity.test", event_types::USER_CREATED);
    assert_eq!(event.specversion, "1.0");
    assert_eq!(event.source, "sid-identity.test");
    assert_eq!(event.event_type, "sid.user.created.v1");
    assert!(event.subject.is_none());
    assert_eq!(event.datacontenttype, "application/json");
}

#[test]
fn test_event_builder() {
    let event = Event::new("test", event_types::SESSION_CREATED)
        .with_subject("session/sess_123")
        .with_data(serde_json::json!({"ip": "1.2.3.4"}))
        .with_sequence(42);

    assert_eq!(event.subject.as_deref(), Some("session/sess_123"));
    assert_eq!(event.data["ip"], "1.2.3.4");
    assert_eq!(event.sequence, 42);
}

#[test]
fn test_event_serde_roundtrip() {
    let event = Event::new("test-src", event_types::USER_DEACTIVATED)
        .with_subject("profile/prof_abc")
        .with_data(serde_json::json!({"reason": "admin_action"}));

    let json = serde_json::to_string(&event).unwrap();
    let deserialized: Event = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.event_type, "sid.user.deactivated.v1");
    assert_eq!(deserialized.source, "test-src");
    assert_eq!(deserialized.data["reason"], "admin_action");
}

#[test]
fn test_event_type_field_renamed() {
    let event = Event::new("src", "test.type.v1");
    let json = serde_json::to_string(&event).unwrap();
    // JSON should have "type" not "event_type"
    assert!(json.contains("\"type\":\"test.type.v1\""));
    assert!(!json.contains("\"event_type\""));
}

// ── Relay (transactional outbox) ──

/// The relay work carries the whole event and is identified by it: the same
/// event is owed once, another event is owed separately.
#[test]
fn test_relay_work_is_the_event() {
    let event = Event::new("src", event_types::USER_CREATED).with_subject("profile/p");
    let work = event.relay();
    assert_eq!(work.kind.as_str(), EVENT_RELAY_KIND);
    assert_eq!(work.max_attempts, EVENT_RELAY_ATTEMPTS);
    assert_eq!(work.id.0.to_string(), event.id);
    assert_eq!(event.relay().id, work.id);
    let back: Event = serde_json::from_slice(&work.payload).unwrap();
    assert_eq!(back.id, event.id);
    assert_eq!(back.subject.as_deref(), Some("profile/p"));
    assert_ne!(
        Event::new("src", event_types::USER_CREATED).relay().id,
        work.id
    );
}

/// An event from elsewhere whose id is not a UUID still has a stable relay id.
#[test]
fn test_relay_id_for_non_uuid_event_id_is_stable() {
    let mut event = Event::new("src", "test.v1");
    event.id = "ce-id-001".into();
    assert_eq!(event.relay().id, event.relay().id);
    let mut other = event.clone();
    other.id = "ce-id-002".into();
    assert_ne!(event.relay().id, other.relay().id);
}

// ── Validation tests ──

#[test]
fn test_validate_valid_event() {
    let event = Event::new("src", "test.v1");
    assert!(event.validate().is_ok());
}

#[test]
fn test_validate_missing_specversion() {
    let mut event = Event::new("src", "test.v1");
    event.specversion = String::new();
    assert_eq!(
        event.validate().unwrap_err(),
        EventValidationError::MissingSpecVersion
    );
}

#[test]
fn test_validate_wrong_specversion() {
    let mut event = Event::new("src", "test.v1");
    event.specversion = "0.3".to_string();
    assert_eq!(
        event.validate().unwrap_err(),
        EventValidationError::UnsupportedSpecVersion("0.3".into())
    );
}

#[test]
fn test_validate_missing_id() {
    let mut event = Event::new("src", "test.v1");
    event.id = String::new();
    assert_eq!(
        event.validate().unwrap_err(),
        EventValidationError::MissingId
    );
}

#[test]
fn test_validate_missing_source() {
    let event = Event::new("", "test.v1");
    assert_eq!(
        event.validate().unwrap_err(),
        EventValidationError::MissingSource
    );
}

#[test]
fn test_validate_missing_type() {
    let event = Event::new("src", "");
    assert_eq!(
        event.validate().unwrap_err(),
        EventValidationError::MissingType
    );
}

// ── TryFrom<serde_json::Value> tests ──

#[test]
fn test_try_from_json_valid() {
    let json = serde_json::json!({
        "specversion": "1.0",
        "id": "test-id-001",
        "source": "sid-identity.test",
        "type": "sid.user.created.v1",
        "time": "2026-03-15T12:00:00Z",
        "datacontenttype": "application/json",
        "data": {"profile_id": "abc123"},
        "sequence": 5
    });
    let event = Event::try_from(json).unwrap();
    assert_eq!(event.id, "test-id-001");
    assert_eq!(event.source, "sid-identity.test");
    assert_eq!(event.event_type, "sid.user.created.v1");
    assert_eq!(event.sequence, 5);
    assert_eq!(event.data["profile_id"], "abc123");
}

#[test]
fn test_try_from_json_missing_required() {
    let json = serde_json::json!({
        "specversion": "1.0",
        "id": "test-id",
        // missing source and type
    });
    let err = Event::try_from(json).unwrap_err();
    assert!(matches!(err, EventValidationError::InvalidStructure(_)));
}

#[test]
fn test_try_from_json_wrong_specversion() {
    let json = serde_json::json!({
        "specversion": "2.0",
        "id": "test-id",
        "source": "src",
        "type": "test.v1",
        "time": "2026-03-15T12:00:00Z"
    });
    let err = Event::try_from(json).unwrap_err();
    assert_eq!(
        err,
        EventValidationError::UnsupportedSpecVersion("2.0".into())
    );
}

#[test]
fn test_try_from_json_not_an_object() {
    let json = serde_json::json!("just a string");
    let err = Event::try_from(json).unwrap_err();
    assert!(matches!(err, EventValidationError::InvalidStructure(_)));
}

// ── cloudevents-sdk interop tests ──

#[test]
fn test_to_cloudevents_sdk() {
    let sid_event = Event::new("sid-identity.test", event_types::USER_CREATED)
        .with_subject("profile/prof_123")
        .with_data(serde_json::json!({"name": "Alice"}))
        .with_sequence(42);

    let ce: cloudevents::Event = (&sid_event).into();

    use cloudevents::event::AttributesReader;
    assert_eq!(ce.id(), sid_event.id);
    assert_eq!(ce.source().to_string(), "sid-identity.test");
    assert_eq!(ce.ty(), "sid.user.created.v1");
    assert_eq!(ce.subject().unwrap(), "profile/prof_123");
    assert_eq!(ce.specversion(), cloudevents::event::SpecVersion::V10);

    // Check sequence extension
    let seq = ce.extension(EXT_SEQUENCE).unwrap();
    assert_eq!(*seq, cloudevents::event::ExtensionValue::Integer(42));
}

#[test]
fn test_from_cloudevents_sdk() {
    let ce = cloudevents::EventBuilderV10::new()
        .id("ce-id-001")
        .source("external-system.example.com")
        .ty("external.event.v1")
        .subject("resource/123")
        .time(Utc::now())
        .data("application/json", serde_json::json!({"key": "value"}))
        .extension(EXT_SEQUENCE, 99i64)
        .build()
        .unwrap();

    let sid_event = Event::try_from(ce).unwrap();
    assert_eq!(sid_event.id, "ce-id-001");
    assert_eq!(sid_event.source, "external-system.example.com");
    assert_eq!(sid_event.event_type, "external.event.v1");
    assert_eq!(sid_event.subject.as_deref(), Some("resource/123"));
    assert_eq!(sid_event.specversion, "1.0");
    assert_eq!(sid_event.sequence, 99);
    assert_eq!(sid_event.data["key"], "value");
}

#[test]
fn test_roundtrip_sid_to_ce_to_sid() {
    let original = Event::new("sid-identity.test", event_types::SESSION_CREATED)
        .with_subject("session/sess_abc")
        .with_data(serde_json::json!({"ip": "10.0.0.1"}))
        .with_sequence(7);

    let ce: cloudevents::Event = (&original).into();
    let roundtripped = Event::try_from(ce).unwrap();

    assert_eq!(roundtripped.id, original.id);
    assert_eq!(roundtripped.source, original.source);
    assert_eq!(roundtripped.event_type, original.event_type);
    assert_eq!(roundtripped.subject, original.subject);
    assert_eq!(roundtripped.sequence, original.sequence);
    assert_eq!(roundtripped.data["ip"], "10.0.0.1");
}

// ── Filter tests (unchanged) ──

#[test]
fn test_filter_matches_exact() {
    let filter = EventFilter {
        event_types: vec![event_types::USER_CREATED.to_string()],
        ..Default::default()
    };
    let event = Event::new("src", event_types::USER_CREATED);
    assert!(filter.matches(&event));

    let other = Event::new("src", event_types::USER_DELETED);
    assert!(!filter.matches(&other));
}

#[test]
fn test_filter_matches_wildcard() {
    let filter = EventFilter {
        event_types: vec!["sid.user.*".to_string()],
        ..Default::default()
    };

    assert!(filter.matches(&Event::new("src", event_types::USER_CREATED)));
    assert!(filter.matches(&Event::new("src", event_types::USER_LOCKED)));
    assert!(!filter.matches(&Event::new("src", event_types::SESSION_CREATED)));
}

#[test]
fn test_filter_matches_nats_wildcard() {
    let filter = EventFilter {
        event_types: vec!["sid.security.>".to_string()],
        ..Default::default()
    };

    assert!(filter.matches(&Event::new("src", event_types::SECURITY_BRUTE_FORCE)));
    assert!(!filter.matches(&Event::new("src", event_types::USER_CREATED)));
}

#[test]
fn test_filter_empty_matches_all() {
    let filter = EventFilter::default();
    assert!(filter.matches(&Event::new("src", event_types::USER_CREATED)));
    assert!(filter.matches(&Event::new("src", event_types::CERT_ROTATED)));
}

#[test]
fn test_filter_multiple_types() {
    let filter = EventFilter {
        event_types: vec![
            event_types::USER_CREATED.to_string(),
            event_types::SESSION_CREATED.to_string(),
        ],
        ..Default::default()
    };

    assert!(filter.matches(&Event::new("src", event_types::USER_CREATED)));
    assert!(filter.matches(&Event::new("src", event_types::SESSION_CREATED)));
    assert!(!filter.matches(&Event::new("src", event_types::MFA_ENROLLED)));
}

#[test]
fn test_event_types_constants() {
    // Verify naming convention: sid.{category}.{action}.v1
    assert!(event_types::USER_CREATED.starts_with("sid."));
    assert!(event_types::USER_CREATED.ends_with(".v1"));
    assert!(event_types::SECURITY_BRUTE_FORCE.contains("security"));
    assert!(event_types::CERT_EXPIRING.contains("cert"));
}

#[test]
fn test_principal_contestation_event_types() {
    // All three follow the sid.principal.*.v1 naming convention.
    assert_eq!(
        event_types::PRINCIPAL_CONTESTED,
        "sid.principal.contested.v1"
    );
    assert_eq!(event_types::PRINCIPAL_LOST, "sid.principal.lost.v1");
    assert_eq!(
        event_types::PRINCIPAL_OWNERSHIP_SUPERSEDED,
        "sid.principal.ownership_superseded.v1"
    );

    // Naming convention: sid.{category}.{action}.v1
    for constant in [
        event_types::PRINCIPAL_CONTESTED,
        event_types::PRINCIPAL_LOST,
        event_types::PRINCIPAL_OWNERSHIP_SUPERSEDED,
    ] {
        assert!(
            constant.starts_with("sid."),
            "{constant} must start with sid."
        );
        assert!(constant.ends_with(".v1"), "{constant} must end with .v1");
        assert!(
            constant.contains("principal"),
            "{constant} must contain principal"
        );
    }
}
