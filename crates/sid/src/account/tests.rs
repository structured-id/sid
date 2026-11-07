use super::*;

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

#[test]
fn test_claim_preview_no_profile() {
    assert_eq!(claim_preview("email", None, &[]), "");
}

fn phone(id: ProfilePhoneId, label: PhoneLabel) -> ProfilePhone {
    let now = chrono::Utc::now();
    ProfilePhone {
        id,
        profile_id: ProfileId::generate(),
        e164: 12025551234,
        extension: None,
        label,
        custom_label: None,
        is_primary: false,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn email(id: ProfileEmailId, label: EmailLabel) -> ProfileEmail {
    let now = chrono::Utc::now();
    ProfileEmail {
        id,
        profile_id: ProfileId::generate(),
        email: "test@sid.example.com".to_string(),
        label,
        custom_label: None,
        is_primary: false,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn test_phone_to_proto_all_fields() {
    let now = chrono::Utc::now();
    let mut p = phone(ProfilePhoneId::new(), PhoneLabel::Work);
    p.e164 = 380501234567;
    p.extension = Some(5678);
    p.custom_label = Some("Office main".to_string());
    p.is_primary = true;
    p.can_receive_sms = false;
    p.can_receive_fax = true;
    p.verified = true;
    p.verified_at = Some(now);
    let proto = phone_to_proto(&p).unwrap();
    let wire_id = sid_ids_proto::required(proto.id.as_ref()).unwrap();
    assert_eq!(wire_id.into_uuid(), p.id.0);
    assert_eq!(proto.e164, 380501234567);
    assert_eq!(proto.extension, Some(5678));
    assert_eq!(proto.label, v1::PhoneLabel::Work as i32);
    assert_eq!(proto.custom_label.as_deref(), Some("Office main"));
    assert!(proto.is_primary);
    assert!(!proto.can_receive_sms);
    assert!(proto.can_receive_fax);
    assert!(proto.can_receive_voice);
    assert!(proto.verified);
    assert!(proto.verified_at.is_some());
}

#[test]
fn test_email_to_proto_all_fields() {
    let now = chrono::Utc::now();
    let mut e = email(ProfileEmailId::new(), EmailLabel::Work);
    e.email = "alice@sid.example.com".to_string();
    e.custom_label = Some("Corporate".to_string());
    e.is_primary = true;
    e.verified = true;
    e.verified_at = Some(now);
    let proto = email_to_proto(&e).unwrap();
    let wire_id = sid_ids_proto::required(proto.id.as_ref()).unwrap();
    assert_eq!(wire_id.into_uuid(), e.id.0);
    assert_eq!(proto.email, "alice@sid.example.com");
    assert_eq!(proto.label, v1::EmailLabel::Work as i32);
    assert_eq!(proto.custom_label.as_deref(), Some("Corporate"));
    assert!(proto.is_primary);
    assert!(proto.verified);
    assert!(proto.verified_at.is_some());
}

/// A stored contact id that is not a valid identifier of its kind is
/// corruption: the answer is an internal error, never the value as stored.
#[test]
fn a_corrupt_stored_contact_id_is_never_sent() {
    assert!(matches!(
        email_to_proto(&email(
            ProfileEmailId(uuid::Uuid::nil()),
            EmailLabel::Personal
        )),
        Err(AccountError::Internal)
    ));
    assert!(matches!(
        phone_to_proto(&phone(
            ProfilePhoneId(uuid::Uuid::nil()),
            PhoneLabel::Mobile
        )),
        Err(AccountError::Internal)
    ));
}

/// Every label maps both ways; an unspecified request label is the default.
#[test]
fn test_labels_round_trip() {
    for label in [
        PhoneLabel::Mobile,
        PhoneLabel::Home,
        PhoneLabel::Work,
        PhoneLabel::Fax,
        PhoneLabel::Pager,
        PhoneLabel::Main,
        PhoneLabel::Other,
        PhoneLabel::Custom,
    ] {
        let proto = phone_to_proto(&phone(ProfilePhoneId::new(), label.clone())).unwrap();
        assert_eq!(phone_label(proto.label), label);
    }
    for label in [
        EmailLabel::Personal,
        EmailLabel::Work,
        EmailLabel::School,
        EmailLabel::Other,
        EmailLabel::Custom,
    ] {
        let proto = email_to_proto(&email(ProfileEmailId::new(), label.clone())).unwrap();
        assert_eq!(email_label(proto.label), label);
    }
    assert_eq!(phone_label(0), PhoneLabel::Mobile);
    assert_eq!(email_label(0), EmailLabel::Personal);
}
