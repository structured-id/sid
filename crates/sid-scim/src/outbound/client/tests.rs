use super::*;
use chrono::Utc;
use sid_core::models::{
    AttributeMapping, GroupPushConfig, OutboundSyncConfig, ProjectId, ScimOutboundTarget,
    ScimOutboundTargetId,
};

fn test_target() -> ScimOutboundTarget {
    ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: "test-app".into(),
        project_id: ProjectId::system(),
        display_name: "Test App".into(),
        endpoint_url: "https://scim.example.com/v2".into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "test-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig::default(),
        sync_config: OutboundSyncConfig {
            max_retry_attempts: 3,
            retry_backoff_base_secs: 1,
        },
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_client_construction() {
    let target = test_target();
    let client = ScimHttpClient::new(&target, Hold::unbounded());
    assert_eq!(client.endpoint_url, "https://scim.example.com/v2");
}

#[test]
fn test_client_strips_trailing_slash() {
    let mut target = test_target();
    target.endpoint_url = "https://scim.example.com/v2/".into();
    let client = ScimHttpClient::new(&target, Hold::unbounded());
    assert_eq!(client.endpoint_url, "https://scim.example.com/v2");
}

#[test]
fn test_scim_client_error_display() {
    let err = ScimClientError::Unreachable("connection refused".into());
    assert!(err.to_string().contains("connection refused"));

    let err = ScimClientError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(err.to_string().contains("429"));

    let err = ScimClientError::AuthFailed { status: 401 };
    assert!(err.to_string().contains("401"));
}

/// A delivery whose hold would end before a request does sends nothing:
/// another replica may already be writing the same resource. The endpoint
/// does not exist, so any request sent would fail as unreachable instead.
#[tokio::test]
async fn test_an_unheld_delivery_sends_no_request() {
    let (_deadline, hold) =
        tokio::sync::watch::channel(tokio::time::Instant::now() + REQUEST_SPAN / 2);
    let mut target = test_target();
    target.endpoint_url = "http://127.0.0.1:1/scim/v2".into();
    let client = ScimHttpClient::new(&target, Hold::until(hold));
    let refused = client.find_user("alice").await.unwrap_err();
    assert!(matches!(refused, ScimClientError::NotHeld), "{refused}");
}

/// A lookup proves absence only by a well-formed empty ListResponse; one
/// match gives its id, several are a conflict, and anything unreadable is
/// an error rather than "not found" (which would create the resource again).
#[test]
fn test_a_lookup_reads_only_a_list_response() {
    use serde_json::json;
    assert_eq!(
        single_match(Some(json!({"totalResults": 0}))).unwrap(),
        None
    );
    assert_eq!(
        single_match(Some(json!({"totalResults": 0, "Resources": []}))).unwrap(),
        None
    );
    assert_eq!(
        single_match(Some(
            json!({"totalResults": 1, "Resources": [{"id": "u1", "userName": "alice"}]})
        ))
        .unwrap(),
        Some("u1".to_string())
    );
    assert!(matches!(
        single_match(Some(
            json!({"totalResults": 2, "Resources": [{"id": "u1"}, {"id": "u2"}]})
        )),
        Err(ScimClientError::Conflict { .. })
    ));
    for unreadable in [
        None,
        Some(json!({})),
        Some(json!({"Resources": []})),
        Some(json!({"totalResults": 1})),
        Some(json!({"totalResults": 1, "Resources": "alice"})),
        Some(json!({"totalResults": 1, "Resources": [{"userName": "alice"}]})),
        Some(json!({"totalResults": 1, "Resources": []})),
        Some(json!({"totalResults": 0, "Resources": [{"id": "u1"}]})),
    ] {
        let refused = single_match(unreadable.clone()).unwrap_err();
        assert!(
            matches!(refused, ScimClientError::Malformed(_)) && refused.is_transient(),
            "{unreadable:?}: {refused}"
        );
    }
}

/// Which failures a later attempt may cure: never a rejection the target
/// will repeat.
#[test]
fn test_transient_failures() {
    assert!(ScimClientError::Unreachable("down".into()).is_transient());
    assert!(ScimClientError::NotHeld.is_transient());
    assert!(
        ScimClientError::RateLimited {
            retry_after_secs: 1
        }
        .is_transient()
    );
    assert!(
        ScimClientError::Rejected {
            status: 503,
            body: String::new()
        }
        .is_transient()
    );
    assert!(
        !ScimClientError::Rejected {
            status: 400,
            body: String::new()
        }
        .is_transient()
    );
    assert!(
        !ScimClientError::Conflict {
            body: String::new()
        }
        .is_transient()
    );
    assert!(!ScimClientError::AuthFailed { status: 401 }.is_transient());
}
