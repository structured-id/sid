use super::*;

// ── mask_email ──

#[test]
fn test_mask_email_standard() {
    assert_eq!(mask_email("alice@example.com"), "a***@example.com");
}

#[test]
fn test_mask_email_single_char_local() {
    assert_eq!(mask_email("a@example.com"), "a***@example.com");
}

#[test]
fn test_mask_email_long_local() {
    assert_eq!(
        mask_email("john.doe.smith@corp.example.com"),
        "j***@corp.example.com"
    );
}

#[test]
fn test_mask_email_unicode_local() {
    assert_eq!(mask_email("über@example.de"), "ü***@example.de");
}

#[test]
fn test_mask_email_no_at_sign() {
    assert_eq!(mask_email("notanemail"), "n***");
}

#[test]
fn test_mask_email_empty_local() {
    assert_eq!(mask_email("@example.com"), "***@example.com");
}

// ── mask_phone ──

#[test]
fn test_mask_phone_international() {
    assert_eq!(mask_phone("+380501234567"), "+38***4567");
}

#[test]
fn test_mask_phone_us() {
    assert_eq!(mask_phone("+12025551234"), "+12***1234");
}

#[test]
fn test_mask_phone_short() {
    assert_eq!(mask_phone("+123"), "***");
}

#[test]
fn test_mask_phone_with_spaces() {
    // Spaces stripped, digits + plus preserved.
    assert_eq!(mask_phone("+38 050 123 4567"), "+38***4567");
}

// ── mask_name ──

#[test]
fn test_mask_name_standard() {
    assert_eq!(mask_name("Alice"), "A***");
}

#[test]
fn test_mask_name_single_char() {
    assert_eq!(mask_name("A"), "A***");
}

#[test]
fn test_mask_name_unicode() {
    assert_eq!(mask_name("Ідентифікація"), "І***");
}

#[test]
fn test_mask_name_empty() {
    assert_eq!(mask_name(""), "");
}

// ── mask_claim_value (dispatch) ──

#[test]
fn test_mask_claim_value_email() {
    assert_eq!(
        mask_claim_value("email", "bob@sid.example.com"),
        "b***@sid.example.com"
    );
}

#[test]
fn test_mask_claim_value_phone() {
    assert_eq!(
        mask_claim_value("phone_number", "+491701234567"),
        "+49***4567"
    );
}

#[test]
fn test_mask_claim_value_display_name() {
    assert_eq!(mask_claim_value("display_name", "Bob"), "B***");
}

#[test]
fn test_mask_claim_value_preferred_username() {
    assert_eq!(mask_claim_value("preferred_username", "bobsmith"), "b***");
}

#[test]
fn test_mask_claim_value_unknown_claim() {
    assert_eq!(mask_claim_value("custom_field", "anything"), "***");
}

#[test]
fn test_mask_claim_value_empty() {
    assert_eq!(mask_claim_value("email", ""), "");
}

// ── resolve_claim_preview ──

#[test]
fn test_resolve_claim_preview_no_profile() {
    let result = resolve_claim_preview("email", None, &[]);
    assert_eq!(result, "");
}
