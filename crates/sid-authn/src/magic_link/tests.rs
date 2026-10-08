// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn test_generate_token_length() {
    let token = generate_token();
    // 32 bytes → 43 chars in URL-safe base64 (no padding)
    assert_eq!(token.len(), 43);
}

#[test]
fn test_generate_token_unique() {
    let t1 = generate_token();
    let t2 = generate_token();
    assert_ne!(t1, t2);
}

#[test]
fn test_error_display() {
    let err = MagicLinkError::RateLimited { wait_seconds: 42 };
    assert!(err.to_string().contains("42"));

    let err = MagicLinkError::Internal("test".into());
    assert!(err.to_string().contains("test"));
}

#[test]
fn test_magic_link_session_model() {
    let session = MagicLinkSession::new("alice@sid.example.com", "hash".to_string());
    assert_eq!(session.email, "alice@sid.example.com");
    assert!(!session.consumed);
    assert!(!session.is_expired());
}
