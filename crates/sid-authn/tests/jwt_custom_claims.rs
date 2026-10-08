// SPDX-License-Identifier: AGPL-3.0-only
//! Custom claims from claim mappings never replace the registered claims of an
//! access token.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use sid_authn::jwt::JwtService;
use sid_core::models::{Profile, Session};

fn jwt() -> JwtService {
    JwtService::new(
        include_bytes!("fixtures/test_ed25519_private.pem"),
        include_bytes!("fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .expect("test keys")
}

/// Regression: a mapping targeting `sub`, `exp`, `aud`, `acr` or `pid` must not
/// change the subject, extend the lifetime or widen the audience of the token;
/// other custom claims are still added.
#[test]
fn custom_claims_cannot_override_registered_claims() {
    let jwt = jwt();
    let profile = Profile::new(Some("alice"));
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );
    let far_future = (Utc::now() + Duration::days(3650)).timestamp();
    let mut custom = HashMap::new();
    custom.insert("sub".to_string(), serde_json::json!("attacker"));
    custom.insert("pid".to_string(), serde_json::json!("attacker"));
    custom.insert("exp".to_string(), serde_json::json!(far_future));
    custom.insert(
        "aud".to_string(),
        serde_json::json!(["https://evil.example.com"]),
    );
    custom.insert("acr".to_string(), serde_json::json!("urn:sid:acr:critical"));
    custom.insert("department".to_string(), serde_json::json!("finance"));

    let sub = profile.id.to_string();
    let token = jwt
        .issue_access_token(
            &sub,
            Some(&sub),
            &profile,
            &session,
            &[],
            None,
            Some(&custom),
        )
        .unwrap();
    let claims = jwt.validate_access_token(&token).unwrap();

    assert_eq!(claims.sub, sub);
    assert_eq!(claims.pid.as_deref(), Some(sub.as_str()));
    assert!(claims.exp < far_future);
    assert_eq!(claims.aud, vec!["https://sid.example.com".to_string()]);
    assert_ne!(claims.acr, "urn:sid:acr:critical");

    let payload = token.split('.').nth(1).unwrap();
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(json["department"], "finance");
}
