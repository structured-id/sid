use super::*;
use uuid::Uuid;

#[test]
fn test_upstream_auth_state_serde_roundtrip() {
    let state = UpstreamAuthState {
        provider_id: UpstreamProviderId(Uuid::now_v7()),
        state_token: "abc123state".into(),
        redirect_uri: "https://sid.example.com/callback".into(),
        code_verifier: "pkce-verifier-xyz".into(),
        nonce: Some("nonce-456".into()),
    };

    let json = serde_json::to_string(&state).unwrap();
    let parsed: UpstreamAuthState = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.state_token, "abc123state");
    assert_eq!(parsed.redirect_uri, "https://sid.example.com/callback");
    assert_eq!(parsed.code_verifier, "pkce-verifier-xyz");
    assert_eq!(parsed.nonce.as_deref(), Some("nonce-456"));
    let pending = parsed.pending();
    assert_eq!(pending.redirect_uri, "https://sid.example.com/callback");
    assert_eq!(pending.code_verifier, "pkce-verifier-xyz");
    assert_eq!(pending.nonce, Some("nonce-456"));
}

// A plain OAuth2 sign-in has no nonce, only the verifier.
#[test]
fn test_upstream_auth_state_without_nonce() {
    let state = UpstreamAuthState {
        provider_id: UpstreamProviderId(Uuid::now_v7()),
        state_token: "state-only".into(),
        redirect_uri: "https://sid.example.com/cb".into(),
        code_verifier: "verifier".into(),
        nonce: None,
    };

    let json = serde_json::to_string(&state).unwrap();
    let parsed: UpstreamAuthState = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.state_token, "state-only");
    assert!(parsed.pending().nonce.is_none());
}
