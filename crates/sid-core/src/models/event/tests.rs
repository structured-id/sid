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
    assert_eq!(event.relay().id, work.id);
    let back: Event = serde_json::from_slice(&work.payload).unwrap();
    assert_eq!(back.id, event.id);
    assert_eq!(back.subject.as_deref(), Some("profile/p"));
    assert_ne!(
        Event::new("src", event_types::USER_CREATED).relay().id,
        work.id
    );
}

/// Two producers may reuse an event id: the relay is owed per `(source, id)`,
/// so one producer's event never stands in for the other's.
#[test]
fn test_relay_id_is_per_source_and_id() {
    let mut event = Event::new("src", "test.v1");
    event.id = "ce-id-001".into();
    assert_eq!(event.relay().id, event.relay().id);
    let mut other_id = event.clone();
    other_id.id = "ce-id-002".into();
    assert_ne!(event.relay().id, other_id.relay().id);
    let mut other_source = event.clone();
    other_source.source = "other".into();
    assert_ne!(event.relay().id, other_source.relay().id);
}

/// The parts of an identity are length-prefixed: moving a boundary between
/// source and id gives another identity, not the same bytes.
#[test]
fn test_identity_parts_cannot_be_shifted() {
    let mut a = Event::new("ab", "test.v1");
    a.id = "c".into();
    let mut b = a.clone();
    b.source = "a".into();
    b.id = "bc".into();
    assert_ne!(a.relay().id, b.relay().id);
    let recipient = WorkRecipient::new("r").unwrap();
    assert_ne!(a.delivery_id(&recipient), b.delivery_id(&recipient));
}

fn recipient(name: &str) -> WorkRecipient {
    WorkRecipient::new(name).unwrap()
}

/// A delivery is one event for one receiver: stable for the pair, distinct
/// per receiver and from the relay, and its payload names both.
#[test]
fn test_delivery_work_is_per_event_and_receiver() {
    let event = Event::new("src", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    let notify = recipient("sid-notify");
    let work = event.deliver(&notify);
    assert_eq!(work.kind.as_str(), EVENT_DELIVERY_KIND);
    assert_eq!(work.id, event.delivery_id(&notify));
    assert_eq!(event.deliver(&notify).id, work.id);
    assert_ne!(event.deliver(&recipient("other")).id, work.id);
    assert_ne!(event.relay().id, work.id);
    let back: EventDelivery = serde_json::from_slice(&work.payload).unwrap();
    assert_eq!(back.recipient, notify);
    assert_eq!(back.event.id, event.id);
}

/// A plan is one per fact whatever receivers it names, so the store keeps
/// the first written; it carries the event and the receivers it was given.
#[test]
fn test_fanout_plan_is_one_per_fact() {
    let event = Event::new("src", event_types::USER_CREATED);
    let first = event.fanout(&[recipient("sid-notify")]);
    let other = event.fanout(&[recipient("audit-sink")]);
    assert_eq!(first.kind.as_str(), EVENT_FANOUT_KIND);
    assert_eq!(first.id, other.id, "the plan id follows the receivers");
    assert_ne!(first.id, event.relay().id);
    assert_ne!(
        first.id,
        Event::new("src", event_types::USER_CREATED).fanout(&[]).id
    );
    let plan: EventFanout = serde_json::from_slice(&first.payload).unwrap();
    assert_eq!(plan.event.id, event.id);
    assert_eq!(plan.receivers, [recipient("sid-notify")]);
}

/// A receiver name is a transport address token; anything that could widen
/// or split an address is refused, including when read back.
#[test]
fn test_work_recipient_is_an_address_token() {
    for valid in ["sid-notify", "a", "scim_outbound-01", &"x".repeat(128)] {
        assert!(WorkRecipient::new(valid).is_ok(), "{valid}");
    }
    for invalid in ["", "a.b", "a*", "a>", "a b", "ä", &"x".repeat(129)] {
        assert!(WorkRecipient::new(invalid).is_err(), "{invalid:?}");
    }
    assert!(serde_json::from_str::<WorkRecipient>("\"a.b\"").is_err());
    let back: WorkRecipient = serde_json::from_str("\"sid-notify\"").unwrap();
    assert_eq!(back.as_str(), "sid-notify");
}

// ── Registry ──

/// Every catalogued type has exactly one route; the platform trial fact is
/// not an identity fact, the cleanup is addressed, an unknown type has none.
#[test]
fn test_registry_routes_each_type_once() {
    let all = [
        event_types::IDENTITY_FACTS,
        event_types::IDENTITY_ADDRESSED,
        event_types::PLATFORM_FACTS,
    ]
    .concat();
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len(), "a type is registered twice");
    assert_eq!(
        event_route(event_types::SESSION_REVOKED),
        Some(EventRoute::Fact(EventFamily::Identity))
    );
    assert_eq!(
        event_route(event_types::ORG_TRIAL_ACTIVATED),
        Some(EventRoute::Fact(EventFamily::Platform))
    );
    assert_eq!(
        event_route(event_types::PASSWORD_HISTORY_CLEANUP_SETTLED),
        Some(EventRoute::Addressed(EventFamily::Identity))
    );
    assert_eq!(event_route("sid.unknown.v1"), None);
    assert_eq!(event_route("sid.>"), None);
}

/// A required receiver takes the facts its patterns name, every fact when
/// it names none, and never a type that only shares a prefix.
#[test]
fn test_required_receiver_patterns() {
    let scim = RequiredReceiver {
        recipient: recipient("scim"),
        event_types: vec!["sid.scim.*".into()],
    };
    assert!(scim.requires(event_types::SCIM_USER_PROVISIONED));
    assert!(!scim.requires(event_types::SESSION_CREATED));
    assert!(!scim.requires("sid.scimx.user.v1"));
    let all = RequiredReceiver {
        recipient: recipient("notify"),
        event_types: Vec::new(),
    };
    assert!(all.requires(event_types::SESSION_CREATED));
}

/// `none` names no receiver only on its own: within a list it is refused,
/// not taken for a receiver named `none` that nothing would ever settle.
#[test]
fn test_none_is_not_a_receiver_in_a_list() {
    assert!(RequiredReceiver::parse_list(" none ").unwrap().is_empty());
    for mixed in ["none,sid-notify", "sid-notify, none", "none,none"] {
        assert!(RequiredReceiver::parse_list(mixed).is_err(), "{mixed}");
    }
    assert_eq!(
        RequiredReceiver::parse_list("sid-notify,audit-sink")
            .unwrap()
            .iter()
            .map(|r| r.recipient.to_string())
            .collect::<Vec<_>>(),
        ["sid-notify", "audit-sink"]
    );
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
