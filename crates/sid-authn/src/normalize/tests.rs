use super::*;
use crate::email::{EmailError, EmailPolicy};

// ── Email normalization ────────────────────────────────────

#[test]
fn test_email_basic() {
    let result = normalize_principal("Alice@Example.COM").unwrap();
    assert_eq!(result.principal_type, LoginPrincipalType::Email);
    assert_eq!(result.normalized, "alice@example.com");
}

#[test]
fn test_email_plus_tag_stripped() {
    let result = normalize_principal("user+tag@example.com").unwrap();
    assert_eq!(result.normalized, "user@example.com");
}

#[test]
fn test_email_unicode_domain_idna() {
    let result = normalize_principal("user@münchen.de").unwrap();
    assert_eq!(result.normalized, "user@xn--mnchen-3ya.de");
}

#[test]
fn test_email_nfc_normalization() {
    // é as combining e + acute vs precomposed é
    let combining = "caf\u{0065}\u{0301}@example.com"; // e + combining acute
    let precomposed = "caf\u{00e9}@example.com"; // precomposed é
    let r1 = normalize_principal(combining).unwrap();
    let r2 = normalize_principal(precomposed).unwrap();
    assert_eq!(r1.normalized, r2.normalized);
}

// ── Email namespace ────────────────────────────────────────

/// The global Personal namespace refuses what it does not admit (a
/// non-ASCII local part, a Unicode or `xn--` domain) instead of folding it
/// into another key, which the installation's namespace accepts.
#[test]
fn personal_namespace_refuses_non_ascii_and_idn_handles() {
    for refused in [
        "caf\u{00e9}@example.com",
        "user@münchen.de",
        "user@xn--mnchen-3ya.de",
    ] {
        let result = normalize_principal_in(refused, &EmailPolicy::GLOBAL_PERSONAL);
        assert!(
            matches!(
                result,
                Err(NormalizeError::Email(
                    EmailError::NonAscii | EmailError::InternationalizedDomain
                ))
            ),
            "{refused}: {result:?}"
        );
        assert!(normalize_principal(refused).is_ok(), "{refused}");
    }
}

/// An admitted handle gets the namespace's key and the namespace's
/// revision: a lookup under another namespace's revision does not route it.
#[test]
fn a_handle_carries_the_revision_of_its_namespace() {
    let personal = normalize_principal_in(
        "Alice.Smith+news@Example.com",
        &EmailPolicy::GLOBAL_PERSONAL,
    )
    .unwrap();
    assert_eq!(personal.principal_type, LoginPrincipalType::Email);
    assert_eq!(personal.normalized, "alicesmith@example.com");
    assert_eq!(
        personal.key_revision(),
        Some(EmailPolicy::GLOBAL_PERSONAL.revision)
    );
    let local = normalize_principal("Alice.Smith+news@Example.com").unwrap();
    assert_eq!(local.key_revision(), Some(EmailPolicy::LOCAL.revision));
    assert_eq!(
        local,
        normalize_principal_in("Alice.Smith+news@Example.com", &EmailPolicy::LOCAL).unwrap(),
        "the installation's namespace is the default"
    );
}

/// Phones and usernames are normalized alike whatever the email namespace.
#[test]
fn phones_and_usernames_ignore_the_email_namespace() {
    for input in ["+1 (212) 555-1234", "Alice_Smith", "Alice#Acme.Corp"] {
        assert_eq!(
            normalize_principal_in(input, &EmailPolicy::GLOBAL_PERSONAL).unwrap(),
            normalize_principal(input).unwrap(),
            "{input}"
        );
    }
}

// ── Phone normalization ────────────────────────────────────

#[test]
fn test_phone_basic() {
    let result = normalize_principal("+1 (212) 555-1234").unwrap();
    assert_eq!(result.principal_type, LoginPrincipalType::Phone);
    assert_eq!(result.normalized, "+12125551234");
}

#[test]
fn test_phone_too_short() {
    let result = normalize_principal("+123");
    assert!(matches!(result, Err(NormalizeError::InvalidPhone(_))));
}

#[test]
fn test_phone_strips_formatting() {
    let result = normalize_principal("+380-50-123-4567").unwrap();
    assert_eq!(result.normalized, "+380501234567");
}

// ── Username normalization ─────────────────────────────────

#[test]
fn test_username_basic() {
    let result = normalize_principal("Alice_Smith").unwrap();
    assert_eq!(result.principal_type, LoginPrincipalType::Username);
    assert_eq!(result.normalized, "alice_smith");
}

#[test]
fn test_username_too_short() {
    let result = normalize_principal("ab");
    assert!(matches!(result, Err(NormalizeError::UsernameTooShort(2))));
}

#[test]
fn test_username_special_chars_stripped() {
    let result = normalize_principal("alice.smith!").unwrap();
    assert_eq!(result.normalized, "alicesmith");
}

#[test]
fn test_username_federated() {
    let result = normalize_principal("Alice#Acme.Corp").unwrap();
    assert_eq!(result.principal_type, LoginPrincipalType::Username);
    assert_eq!(result.normalized, "alice#acme.corp");
}

#[test]
fn test_username_federated_short_login_part_allowed() {
    // Federated: org admin decides login part length, no min length check
    let result = normalize_principal("ab#acme.corp").unwrap();
    assert_eq!(result.normalized, "ab#acme.corp");

    let result = normalize_principal("a#acme.corp").unwrap();
    assert_eq!(result.normalized, "a#acme.corp");
}

#[test]
fn test_username_federated_empty_login_part_rejected() {
    let result = normalize_principal("#acme.corp");
    assert!(matches!(result, Err(NormalizeError::UsernameTooShort(0))));
}

#[test]
fn test_username_federated_idna_domain() {
    let result = normalize_principal("alice#münchen.de").unwrap();
    assert_eq!(result.normalized, "alice#xn--mnchen-3ya.de");
}

// ── Edge cases ─────────────────────────────────────────────

#[test]
fn test_empty_input() {
    let result = normalize_principal("");
    assert!(matches!(result, Err(NormalizeError::Empty)));
}

#[test]
fn test_whitespace_only() {
    let result = normalize_principal("   ");
    assert!(matches!(result, Err(NormalizeError::Empty)));
}

#[test]
fn test_leading_trailing_whitespace() {
    let result = normalize_principal("  alice@example.com  ").unwrap();
    assert_eq!(result.normalized, "alice@example.com");
}

// ── Confusable skeleton ────────────────────────────────────

#[test]
fn test_confusable_cyrillic_a() {
    // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
    let latin = confusable_skeleton("alice");
    let cyrillic = confusable_skeleton("\u{0430}lice");
    assert_eq!(latin, cyrillic);
}

// ── LoginPrincipalType → PrincipalType ─────────────────────

#[test]
fn test_login_principal_type_to_principal_type() {
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
