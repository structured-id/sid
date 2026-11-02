// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for principal normalization (public API).

use sid_authn::normalize::{
    LoginPrincipalType, NormalizeError, USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH,
    normalize_principal,
};

// ── Email detection & normalization ────────────────────────────

#[test]
fn email_basic() {
    let r = normalize_principal("alice@sid.example.com").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Email);
    assert_eq!(r.normalized, "alice@sid.example.com");
}

#[test]
fn email_case_folding() {
    let r = normalize_principal("Alice@SID.Example.COM").unwrap();
    assert_eq!(r.normalized, "alice@sid.example.com");
}

#[test]
fn email_trim() {
    let r = normalize_principal("  alice@sid.example.com  ").unwrap();
    assert_eq!(r.normalized, "alice@sid.example.com");
}

#[test]
fn email_plus_tag_stripped() {
    let r = normalize_principal("alice+promo@sid.example.com").unwrap();
    assert_eq!(r.normalized, "alice@sid.example.com");
}

/// The key folds the spelling; the delivery address keeps it, and the key
/// names the policy revision it was derived under.
#[test]
fn email_delivery_keeps_the_spelling() {
    let r = normalize_principal(" Ann.Smith+work@Example.COM ").unwrap();
    assert_eq!(r.normalized, "annsmith@example.com");
    let email = r.email.as_ref().expect("an email handle");
    assert_eq!(email.delivery, "Ann.Smith+work@example.com");
    assert_eq!(
        r.key_revision(),
        Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION)
    );
    let username = normalize_principal("alice").unwrap();
    assert_eq!(username.email, None);
    assert_eq!(username.key_revision(), None);
}

#[test]
fn email_idna_domain() {
    let r = normalize_principal("user@münchen.de").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Email);
    assert!(r.normalized.contains("xn--"));
}

#[test]
fn email_dot_insensitivity() {
    let r = normalize_principal("a.l.i.c.e@gmail.com").unwrap();
    assert_eq!(r.normalized, "alice@gmail.com");
}

#[test]
fn email_dot_and_plus_combined() {
    let r = normalize_principal("a.li.ce+tag@example.com").unwrap();
    assert_eq!(r.normalized, "alice@example.com");
}

// ── Phone detection & normalization ────────────────────────────

#[test]
fn phone_basic() {
    let r = normalize_principal("+12125551234").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Phone);
    assert_eq!(r.normalized, "+12125551234");
}

#[test]
fn phone_strips_formatting() {
    let r = normalize_principal("+1 (212) 555-1234").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Phone);
    assert_eq!(r.normalized, "+12125551234");
}

#[test]
fn phone_trim() {
    let r = normalize_principal("  +380501234567  ").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Phone);
    assert_eq!(r.normalized, "+380501234567");
}

// ── Username detection & normalization ─────────────────────────

#[test]
fn username_basic() {
    let r = normalize_principal("alice").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Username);
    assert_eq!(r.normalized, "alice");
}

#[test]
fn username_case_folding() {
    let r = normalize_principal("Alice").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Username);
    assert_eq!(r.normalized, "alice");
}

#[test]
fn username_strips_invalid_chars() {
    let r = normalize_principal("alice_123").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Username);
    assert!(
        r.normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    );
}

// ── Username length validation ────────────────────────────────

#[test]
fn username_too_short_rejected() {
    let err = normalize_principal("ab").unwrap_err();
    assert!(matches!(err, NormalizeError::UsernameTooShort(2)));
}

#[test]
fn username_min_length_accepted() {
    let r = normalize_principal("abc").unwrap();
    assert_eq!(r.normalized, "abc");
    assert_eq!(r.normalized.len(), USERNAME_MIN_LENGTH);
}

#[test]
fn username_max_length_accepted() {
    let input = "a".repeat(USERNAME_MAX_LENGTH);
    let r = normalize_principal(&input).unwrap();
    assert_eq!(r.normalized.len(), USERNAME_MAX_LENGTH);
}

#[test]
fn username_too_long_rejected() {
    let input = "a".repeat(USERNAME_MAX_LENGTH + 1);
    let err = normalize_principal(&input).unwrap_err();
    assert!(matches!(err, NormalizeError::UsernameTooLong(_)));
}

// ── Empty / whitespace ────────────────────────────────────────

#[test]
fn empty_principal_rejected() {
    let err = normalize_principal("").unwrap_err();
    assert!(matches!(err, NormalizeError::Empty));
}

#[test]
fn whitespace_only_rejected() {
    let err = normalize_principal("   ").unwrap_err();
    assert!(matches!(err, NormalizeError::Empty));
}

// ── Anti-homoglyph ─────────────────────────────────────────────

/// A look-alike email is its own handle: equality never rewrites characters
/// into a confusable ASCII skeleton, which would let `аlice` sign in as
/// `alice`.
#[test]
fn homoglyph_cyrillic_a_in_email_is_another_handle() {
    let r = normalize_principal("аlice@sid.example.com").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Email);
    assert_eq!(r.normalized, "аlice@sid.example.com");
    assert_ne!(
        r.normalized,
        normalize_principal("alice@sid.example.com")
            .unwrap()
            .normalized
    );
}

/// Malformed email input is refused, not repaired into another address.
#[test]
fn invalid_email_rejected() {
    for input in [
        "a..b@sid.example.com",
        "a@",
        "a b@sid.example.com",
        "+@x.com",
    ] {
        assert!(
            matches!(normalize_principal(input), Err(NormalizeError::Email(_))),
            "{input:?}"
        );
    }
}

#[test]
fn homoglyph_cyrillic_a_in_username() {
    let r = normalize_principal("аlice").unwrap();
    assert_eq!(r.principal_type, LoginPrincipalType::Username);
    assert_eq!(r.normalized, "alice");
}

// ── LoginPrincipalType conversion ─────────────────────────────

#[test]
fn principal_type_conversion() {
    use sid_core::models::PrincipalType;

    assert_eq!(
        LoginPrincipalType::Email.to_principal_type(),
        PrincipalType::Email
    );
    assert_eq!(
        LoginPrincipalType::Phone.to_principal_type(),
        PrincipalType::Phone
    );
    assert_eq!(
        LoginPrincipalType::Username.to_principal_type(),
        PrincipalType::Username
    );
}

// ── NormalizedPrincipal struct ────────────────────────────────

#[test]
fn normalized_principal_clone_eq() {
    let a = normalize_principal("Test@sid.example.com").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}
