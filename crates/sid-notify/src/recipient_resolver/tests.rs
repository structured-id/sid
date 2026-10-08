use super::*;
use sid_core::models::event::Event;

#[test]
fn test_extract_profile_id_with_prefix() {
    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject("profile/550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(
        extract_profile_id(&event).as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
}

#[test]
fn test_extract_profile_id_without_prefix() {
    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject("550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(
        extract_profile_id(&event).as_deref(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
}

#[test]
fn test_extract_profile_id_missing() {
    let event = Event::new("sid-server", "sid.session.created.v1");
    assert_eq!(extract_profile_id(&event), None);
}

#[test]
fn test_build_recipient_prefers_resolved_over_event() {
    let event = Event::new("sid-server", "sid.session.created.v1").with_data(serde_json::json!({
        "email": "event@sid.example.com",
        "phone": "+1111111111"
    }));
    let r = build_recipient(
        "profile-1",
        Some("resolved@sid.example.com"),
        Some("+2222222222"),
        "en",
        &event,
    );
    assert_eq!(r.email.as_deref(), Some("resolved@sid.example.com"));
    assert_eq!(r.phone.as_deref(), Some("+2222222222"));
}

#[test]
fn test_build_recipient_falls_back_to_event_data() {
    let event = Event::new("sid-server", "sid.session.created.v1").with_data(serde_json::json!({
        "email": "fallback@sid.example.com"
    }));
    let r = build_recipient("profile-1", None, None, "en", &event);
    assert_eq!(r.email.as_deref(), Some("fallback@sid.example.com"));
    assert!(r.phone.is_none());
}

#[test]
fn test_build_recipient_from_event_data_with_locale() {
    let event = Event::new("sid-server", "sid.session.created.v1").with_data(serde_json::json!({
        "email": "alice@sid.example.com",
        "locale": "fr"
    }));
    let r = build_recipient_from_event_data("profile-1", &event);
    assert_eq!(r.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(r.locale, "fr");
}

#[test]
fn test_build_recipient_from_event_data_default_locale() {
    let event = Event::new("sid-server", "sid.session.created.v1");
    let r = build_recipient_from_event_data("profile-1", &event);
    assert_eq!(r.locale, "en");
    assert!(r.email.is_none());
}

#[tokio::test]
async fn test_resolver_without_identity_uses_event_data() {
    let resolver = RecipientResolver::without_identity();
    assert!(!resolver.has_identity_client());

    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject("profile/test-uuid")
        .with_data(serde_json::json!({
            "email": "alice@sid.example.com",
            "phone": "+380501234567"
        }));

    let r = resolver.resolve(&event).await.unwrap();
    assert_eq!(r.profile_id, "test-uuid");
    assert_eq!(r.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(r.phone.as_deref(), Some("+380501234567"));
}

/// Without an identity service no profile's addresses are known.
#[tokio::test]
async fn test_contact_without_identity_is_none() {
    let resolver = RecipientResolver::without_identity();
    assert_eq!(resolver.contact("any-profile").await, Ok(None));
}

#[tokio::test]
async fn test_resolver_cache_hit() {
    let resolver = RecipientResolver::without_identity();

    // Manually insert into cache.
    resolver
        .put_cache(
            "cached-profile".to_string(),
            CachedRecipient {
                email: Some("cached@sid.example.com".into()),
                phone: None,
                locale: "de".into(),
                cached_at: Utc::now(),
            },
        )
        .await;

    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject("profile/cached-profile")
        .with_data(serde_json::json!({
            "email": "event@sid.example.com"
        }));

    let r = resolver.resolve(&event).await.unwrap();
    // Cache should win over event data.
    assert_eq!(r.email.as_deref(), Some("cached@sid.example.com"));
    assert_eq!(r.locale, "de");
}

#[tokio::test]
async fn test_resolver_cache_expired() {
    let mut resolver = RecipientResolver::without_identity();
    resolver.cache_ttl = Duration::from_millis(1); // Expire immediately.

    resolver
        .put_cache(
            "expired-profile".to_string(),
            CachedRecipient {
                email: Some("old@sid.example.com".into()),
                phone: None,
                locale: "en".into(),
                cached_at: Utc::now() - chrono::Duration::seconds(10),
            },
        )
        .await;

    let event = Event::new("sid-server", "sid.session.created.v1")
        .with_subject("profile/expired-profile")
        .with_data(serde_json::json!({
            "email": "fresh@sid.example.com"
        }));

    let r = resolver.resolve(&event).await.unwrap();
    // Expired cache → fallback to event data.
    assert_eq!(r.email.as_deref(), Some("fresh@sid.example.com"));
}

#[tokio::test]
async fn test_resolver_invalidate() {
    let resolver = RecipientResolver::without_identity();

    resolver
        .put_cache(
            "to-invalidate".to_string(),
            CachedRecipient {
                email: Some("cached@sid.example.com".into()),
                phone: None,
                locale: "en".into(),
                cached_at: Utc::now(),
            },
        )
        .await;

    resolver.invalidate("to-invalidate").await;

    let result = resolver.get_cached("to-invalidate").await;
    assert!(result.is_none());
}
