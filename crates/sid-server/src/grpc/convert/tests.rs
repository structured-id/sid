use super::*;
use sid_core::models::ProfileId;

#[test]
fn test_phone_to_proto_all_fields() {
    use sid_core::models::profile_phone::{PhoneLabel, ProfilePhoneId};

    let now = chrono::Utc::now();
    let phone = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: ProfileId::generate(),
        e164: 380501234567,
        extension: Some(5678),
        label: PhoneLabel::Work,
        custom_label: Some("Office main".to_string()),
        is_primary: true,
        can_receive_sms: false,
        can_receive_fax: true,
        can_receive_voice: true,
        verified: true,
        verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };

    let proto = phone_to_proto(&phone).unwrap();
    let wire_id = sid_ids_proto::required(proto.id.as_ref()).unwrap();
    assert_eq!(wire_id.into_uuid(), phone.id.0);
    assert_eq!(proto.e164, 380501234567);
    assert_eq!(proto.extension, Some(5678));
    assert_eq!(proto.label, sid_proto::sid::v1::PhoneLabel::Work as i32);
    assert_eq!(proto.custom_label.as_deref(), Some("Office main"));
    assert!(proto.is_primary);
    assert!(!proto.can_receive_sms);
    assert!(proto.can_receive_fax);
    assert!(proto.can_receive_voice);
    assert!(proto.verified);
    assert!(proto.verified_at.is_some());
}

#[test]
fn test_phone_to_proto_minimal() {
    use sid_core::models::profile_phone::{PhoneLabel, ProfilePhoneId};

    let now = chrono::Utc::now();
    let phone = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: ProfileId::generate(),
        e164: 12025551234,
        extension: None,
        label: PhoneLabel::Mobile,
        custom_label: None,
        is_primary: false,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };

    let proto = phone_to_proto(&phone).unwrap();
    assert_eq!(proto.e164, 12025551234);
    assert_eq!(proto.extension, None);
    assert_eq!(proto.label, sid_proto::sid::v1::PhoneLabel::Mobile as i32);
    assert!(proto.custom_label.is_none());
    assert!(!proto.is_primary);
    assert!(!proto.verified);
    assert!(proto.verified_at.is_none());
}

#[test]
fn test_email_to_proto_all_fields() {
    use sid_core::models::profile_email::{EmailLabel, ProfileEmailId};

    let now = chrono::Utc::now();
    let email = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: ProfileId::generate(),
        email: "alice@sid.example.com".to_string(),
        label: EmailLabel::Work,
        custom_label: Some("Corporate".to_string()),
        is_primary: true,
        verified: true,
        verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };

    let proto = email_to_proto(&email).unwrap();
    let wire_id = sid_ids_proto::required(proto.id.as_ref()).unwrap();
    assert_eq!(wire_id.into_uuid(), email.id.0);
    assert_eq!(proto.email, "alice@sid.example.com");
    assert_eq!(proto.label, sid_proto::sid::v1::EmailLabel::Work as i32);
    assert_eq!(proto.custom_label.as_deref(), Some("Corporate"));
    assert!(proto.is_primary);
    assert!(proto.verified);
    assert!(proto.verified_at.is_some());
}

#[test]
fn test_email_to_proto_minimal() {
    use sid_core::models::profile_email::{EmailLabel, ProfileEmailId};

    let now = chrono::Utc::now();
    let email = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: ProfileId::generate(),
        email: "bob@sid.example.com".to_string(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: false,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };

    let proto = email_to_proto(&email).unwrap();
    assert_eq!(proto.email, "bob@sid.example.com");
    assert!(proto.custom_label.is_none());
    assert!(!proto.is_primary);
    assert!(!proto.verified);
    assert!(proto.verified_at.is_none());
}

/// A stored contact id that is not a valid identifier of its kind is
/// corruption: the answer is an internal error, never the value as stored.
#[test]
fn a_corrupt_stored_contact_id_is_never_sent() {
    use sid_core::models::profile_email::{EmailLabel, ProfileEmailId};
    use sid_core::models::profile_phone::{PhoneLabel, ProfilePhoneId};

    let now = chrono::Utc::now();
    let email = ProfileEmail {
        id: ProfileEmailId(uuid::Uuid::nil()),
        profile_id: ProfileId::generate(),
        email: "carol@sid.example.com".to_string(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: false,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };
    let refused = email_to_proto(&email).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Internal);

    let phone = ProfilePhone {
        id: ProfilePhoneId(uuid::Uuid::nil()),
        profile_id: ProfileId::generate(),
        e164: 12025551234,
        extension: None,
        label: PhoneLabel::Mobile,
        custom_label: None,
        is_primary: false,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };
    let refused = phone_to_proto(&phone).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Internal);
}

#[test]
fn test_phone_to_proto_all_labels() {
    use sid_core::models::profile_phone::{PhoneLabel, ProfilePhoneId};

    let now = chrono::Utc::now();
    let labels = [
        (PhoneLabel::Mobile, sid_proto::sid::v1::PhoneLabel::Mobile),
        (PhoneLabel::Home, sid_proto::sid::v1::PhoneLabel::Home),
        (PhoneLabel::Work, sid_proto::sid::v1::PhoneLabel::Work),
        (PhoneLabel::Fax, sid_proto::sid::v1::PhoneLabel::Fax),
        (PhoneLabel::Pager, sid_proto::sid::v1::PhoneLabel::Pager),
        (PhoneLabel::Main, sid_proto::sid::v1::PhoneLabel::Main),
        (PhoneLabel::Other, sid_proto::sid::v1::PhoneLabel::Other),
        (PhoneLabel::Custom, sid_proto::sid::v1::PhoneLabel::Custom),
    ];

    for (domain, proto_expected) in labels {
        let phone = ProfilePhone {
            id: ProfilePhoneId::new(),
            profile_id: ProfileId::generate(),
            e164: 1234567890,
            extension: None,
            label: domain,
            custom_label: None,
            is_primary: false,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };
        let proto = phone_to_proto(&phone).unwrap();
        assert_eq!(
            proto.label, proto_expected as i32,
            "label mismatch for {:?}",
            phone.label
        );
    }
}

#[test]
fn test_email_to_proto_all_labels() {
    use sid_core::models::profile_email::{EmailLabel, ProfileEmailId};

    let now = chrono::Utc::now();
    let labels = [
        (
            EmailLabel::Personal,
            sid_proto::sid::v1::EmailLabel::Personal,
        ),
        (EmailLabel::Work, sid_proto::sid::v1::EmailLabel::Work),
        (EmailLabel::School, sid_proto::sid::v1::EmailLabel::School),
        (EmailLabel::Other, sid_proto::sid::v1::EmailLabel::Other),
        (EmailLabel::Custom, sid_proto::sid::v1::EmailLabel::Custom),
    ];

    for (domain, proto_expected) in labels {
        let email = ProfileEmail {
            id: ProfileEmailId::new(),
            profile_id: ProfileId::generate(),
            email: "test@sid.example.com".to_string(),
            label: domain,
            custom_label: None,
            is_primary: false,
            verified: false,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };
        let proto = email_to_proto(&email).unwrap();
        assert_eq!(
            proto.label, proto_expected as i32,
            "label mismatch for {:?}",
            email.label
        );
    }
}
