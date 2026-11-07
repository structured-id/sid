use super::*;
use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;
use sid_authn::webauthn::{RegistrationResponse, WebAuthnServer};
use sid_core::models::{Credential, CredentialType, ProfileId};
use v1::{AuthenticatorAttachment, AuthenticatorTransport, credential};

/// A password credential names the OPAQUE configuration recorded with it,
/// whatever the deployment's current primary for new passwords is.
#[test]
fn test_credential_info_names_the_recorded_configuration() {
    use sid_plugin::crypto::CurveId;
    use v1::{OpaqueSuite, credential::Info};

    let suite = |curve: CurveId| {
        let mut c = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);
        c.opaque_curve = Some(curve as u8);
        match credential_info(&c).unwrap() {
            Some(Info::OpaqueInfo(info)) => info.suite(),
            _ => panic!("no OPAQUE info"),
        }
    };
    assert_eq!(suite(CurveId::Pallas), OpaqueSuite::PallasV1);
    assert_eq!(suite(CurveId::Ristretto255), OpaqueSuite::Ristretto255V1);
    assert_eq!(suite(CurveId::P256), OpaqueSuite::P256V1);
    assert_eq!(suite(CurveId::P384), OpaqueSuite::P384V1);
    assert_eq!(suite(CurveId::P521), OpaqueSuite::P521V1);
}

/// A password without a recorded configuration is an error, never the
/// current primary: the same record must not report or sign in with a
/// different configuration when the deployment's setting changes.
#[test]
fn test_credential_info_refuses_a_password_without_its_configuration() {
    let c = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);
    assert!(credential_info(&c).is_err());
    assert!(opaque_curve(&c).is_err());
}

/// A recorded curve the build does not know is an error, never a guess.
#[test]
fn test_credential_info_refuses_an_unknown_curve() {
    let mut c = Credential::new(ProfileId::generate(), CredentialType::Opaque, vec![1], None);
    c.opaque_curve = Some(200);
    assert!(credential_info(&c).is_err());
}

/// A type without type-specific info carries none.
#[test]
fn test_credential_info_is_absent_for_totp() {
    let c = Credential::new(ProfileId::generate(), CredentialType::Totp, vec![1], None);
    assert!(credential_info(&c).unwrap().is_none());
}

/// A credential's message never carries its secret material.
#[test]
fn test_credential_to_proto_carries_no_secret() {
    let mut c = Credential::new(
        ProfileId::generate(),
        CredentialType::Totp,
        vec![9; 32],
        Some("phone".into()),
    );
    c.id = sid_core::models::CredentialId(uuid::Uuid::now_v7());
    let proto = credential_to_proto(c).unwrap();
    assert!(proto.data.is_empty());
    assert_eq!(proto.label.as_deref(), Some("phone"));
    assert_eq!(proto.r#type, v1::CredentialType::Totp as i32);
}

#[test]
fn test_profile_to_proto_basic_fields() {
    let mut profile = Profile::new(Some("basic_test"));
    profile.given_name = Some("Test".to_string());
    profile.family_name = Some("User".to_string());

    let proto = profile_to_proto(&profile);
    assert_eq!(proto.given_name.as_deref(), Some("Test"));
    assert_eq!(proto.family_name.as_deref(), Some("User"));
    assert!(proto.phone.is_none());
    assert!(proto.email.is_none());
    assert!(!proto.phone_verified);
}

/// A federated subject is a federation association, not a handle its holder
/// manages: it is not listed.
#[test]
fn test_federated_subject_is_not_a_listed_principal() {
    let principal = sid_core::models::Principal::new(
        ProfileId::generate(),
        sid_core::models::PrincipalType::FederatedSubject,
        "issuer|subject",
    );
    assert!(principal_to_proto(&principal).unwrap().is_none());
}

/// The record of a passkey registered by `key` through a real ceremony.
async fn passkey_record(key: &mut SoftAuthenticator) -> Vec<u8> {
    use secrecy::SecretBox;
    use sid_crypto::RustCryptoPrimitives;
    use sid_keys::{KeyVersionParams, SoftwareKeyManager};
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
        std::sync::Arc::new(sid_plugin::InProcessCeremonyState::new()),
        keys,
    )
    .unwrap();
    let start = server
        .registration_start::<ProfileId>(
            sid_core::models::WebAuthnUserHandle([1; 16]),
            "alice",
            &[],
        )
        .await
        .unwrap();
    let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
    server.registration_finish(&response).await.unwrap().data
}

fn webauthn_info(data: &[u8]) -> v1::WebAuthnCredentialInfo {
    let credential::Info::WebauthnInfo(info) = extract_webauthn_info(data).unwrap() else {
        panic!("not passkey facts");
    };
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
