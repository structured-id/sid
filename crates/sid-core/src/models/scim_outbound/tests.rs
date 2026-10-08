use super::*;

#[test]
fn test_outbound_target_id_unique() {
    let id1 = ScimOutboundTargetId::new();
    let id2 = ScimOutboundTargetId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_outbound_auth_config_serde_bearer() {
    let auth = OutboundAuthConfig::Bearer {
        token_secret: "xoxb-test-token".into(),
    };
    let json = serde_json::to_string(&auth).unwrap();
    assert!(json.contains("\"type\":\"bearer\""));
    let parsed: OutboundAuthConfig = serde_json::from_str(&json).unwrap();
    match parsed {
        OutboundAuthConfig::Bearer { token_secret } => {
            assert_eq!(token_secret, "xoxb-test-token");
        }
        _ => panic!("expected Bearer"),
    }
}

#[test]
fn test_outbound_auth_config_serde_oauth2() {
    let auth = OutboundAuthConfig::OAuth2ClientCredentials {
        token_url: "https://oauth.example.com/token".into(),
        client_id: "client123".into(),
        client_secret: "secret456".into(),
    };
    let json = serde_json::to_string(&auth).unwrap();
    assert!(json.contains("\"type\":\"o_auth2_client_credentials\""));
    let parsed: OutboundAuthConfig = serde_json::from_str(&json).unwrap();
    match parsed {
        OutboundAuthConfig::OAuth2ClientCredentials { client_id, .. } => {
            assert_eq!(client_id, "client123");
        }
        _ => panic!("expected OAuth2ClientCredentials"),
    }
}

#[test]
fn test_mapping_source_serde() {
    let source = MappingSource::Path {
        path: "profile.login".into(),
    };
    let json = serde_json::to_string(&source).unwrap();
    assert!(json.contains("\"type\":\"path\""));

    let literal = MappingSource::Literal {
        value: serde_json::json!(true),
    };
    let json = serde_json::to_string(&literal).unwrap();
    assert!(json.contains("\"type\":\"literal\""));
}

#[test]
fn test_default_sync_config() {
    let config = OutboundSyncConfig::default();
    assert_eq!(config.max_retry_attempts, 5);
    assert_eq!(config.retry_backoff_base_secs, 1);
}

#[test]
fn test_outbound_entity_type_display() {
    assert_eq!(OutboundEntityType::User.to_string(), "user");
    assert_eq!(OutboundEntityType::Group.to_string(), "group");
}

/// The stored name reads back as the entity type; an unknown one is an
/// error, not a user.
#[test]
fn test_outbound_entity_type_parses_stored_names() {
    for t in [OutboundEntityType::User, OutboundEntityType::Group] {
        assert_eq!(t.to_string().parse::<OutboundEntityType>(), Ok(t));
    }
    assert!("device".parse::<OutboundEntityType>().is_err());
}

#[test]
fn test_group_push_config_default() {
    let config = GroupPushConfig::default();
    assert!(!config.enabled);
    assert!(config.mapping.is_empty());
}

#[test]
fn test_attribute_mapping_default() {
    let mapping = AttributeMapping::default();
    assert!(mapping.mappings.is_empty());
}

#[test]
fn test_dlq_entry_creation() {
    let entry = OutboundDlqEntry {
        id: Uuid::now_v7(),
        target_id: ScimOutboundTargetId::new(),
        event_type: "sid.scim.user_provisioned.v1".into(),
        payload: serde_json::json!({"userName": "alice"}),
        sid_entity_id: Uuid::now_v7(),
        entity_type: OutboundEntityType::User,
        error: "connection refused".into(),
        attempts: 3,
        first_attempt: Utc::now(),
        last_attempt: Utc::now(),
    };
    assert_eq!(entry.attempts, 3);
    assert_eq!(entry.entity_type, OutboundEntityType::User);
}
