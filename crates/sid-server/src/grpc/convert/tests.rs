use super::*;
use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;
use sid_authn::webauthn::{RegistrationResponse, WebAuthnServer};
use sid_proto::sid::v1::{AuthenticatorAttachment, AuthenticatorTransport, credential};

#[test]
fn test_profile_to_proto_basic_fields() {
    let mut profile = Profile::new(Some("basic_test"));
    profile.given_name = Some("Test".to_string());
    profile.family_name = Some("User".to_string());

    let proto = profile_to_proto(&profile);
    assert_eq!(proto.given_name.as_deref(), Some("Test"));
    assert_eq!(proto.family_name.as_deref(), Some("User"));
    // Phone/email now populated from profile_phones/profile_emails tables
    assert!(proto.phone.is_none());
    assert!(proto.email.is_none());
}

#[test]
fn test_profile_to_proto_phone_absent() {
    let profile = Profile::new(Some("no_phone"));
    let proto = profile_to_proto(&profile);
    assert!(proto.phone.is_none());
    assert!(!proto.phone_verified);
}

/// The record of a passkey registered by `key` through a real ceremony.
async fn passkey_record(key: &mut SoftAuthenticator) -> Vec<u8> {
    use secrecy::SecretBox;
    use sid_keys::{KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
    let keys = std::sync::Arc::new(
        SoftwareKeyManager::new(
            SecretBox::new(Box::new([3u8; 32])),
            vec![KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            std::sync::Arc::new(RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );
    let server = WebAuthnServer::new(
        "sid.example.com",
        &url::Url::parse("https://sid.example.com").unwrap(),
        std::sync::Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        keys,
    )
    .unwrap();
    let start = server
        .registration_start(sid_core::models::WebAuthnUserHandle([1; 16]), "alice", &[])
        .await
        .unwrap();
    let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
    server.registration_finish(&response).await.unwrap().data
}

fn webauthn_info(data: &[u8]) -> sid_proto::sid::v1::WebAuthnCredentialInfo {
    let credential::Info::WebauthnInfo(info) = extract_webauthn_info(data).unwrap();
    info
}

/// A synced platform passkey shows its transports, backup state, platform
/// attachment, `none` attestation and registration UV.
#[tokio::test]
async fn test_extract_webauthn_info_platform_authenticator() {
    let mut key = SoftAuthenticator::new("https://sid.example.com", "sid.example.com");
    let info = webauthn_info(&passkey_record(&mut key).await);
    assert_eq!(
        info.transports,
        vec![
            AuthenticatorTransport::Hybrid as i32,
            AuthenticatorTransport::Internal as i32
        ]
    );
    assert!(info.backup_eligible);
    assert!(info.backup_state);
    assert!(info.user_verified);
    assert_eq!(info.attestation_format, "none");
    assert_eq!(info.attachment, AuthenticatorAttachment::Platform as i32);
}

/// A device-bound security key over USB and NFC.
#[tokio::test]
async fn test_extract_webauthn_info_cross_platform() {
    let mut key = SoftAuthenticator::new("https://sid.example.com", "sid.example.com");
    key.behavior.transports = vec!["nfc", "usb"];
    key.behavior.backup_eligible = false;
    key.behavior.backed_up = false;
    key.behavior.attachment = "cross-platform";
    let info = webauthn_info(&passkey_record(&mut key).await);
    assert_eq!(
        info.transports,
        vec![
            AuthenticatorTransport::Usb as i32,
            AuthenticatorTransport::Nfc as i32
        ]
    );
    assert!(!info.backup_eligible);
    assert!(!info.backup_state);
    assert_eq!(
        info.attachment,
        AuthenticatorAttachment::CrossPlatform as i32
    );
}

/// Data that is not a passkey record is an error, never empty info.
#[test]
fn test_extract_webauthn_info_refuses_other_data() {
    assert!(extract_webauthn_info(&[]).is_err());
    assert!(extract_webauthn_info(b"not a record").is_err());
    assert!(extract_webauthn_info(br#"{"cred":{}}"#).is_err());
}

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

    let proto = phone_to_proto(&phone);
    assert_eq!(proto.id, phone.id.0.to_string());
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

    let proto = phone_to_proto(&phone);
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

    let proto = email_to_proto(&email);
    assert_eq!(proto.id, email.id.0.to_string());
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

    let proto = email_to_proto(&email);
    assert_eq!(proto.email, "bob@sid.example.com");
    assert!(proto.custom_label.is_none());
    assert!(!proto.is_primary);
    assert!(!proto.verified);
    assert!(proto.verified_at.is_none());
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
        let proto = phone_to_proto(&phone);
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
        let proto = email_to_proto(&email);
        assert_eq!(
            proto.label, proto_expected as i32,
            "label mismatch for {:?}",
            email.label
        );
    }
}
