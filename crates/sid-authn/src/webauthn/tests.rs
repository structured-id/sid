use super::soft_authenticator::SoftAuthenticator;
use super::*;
use crate::test_support::key_manager;
use sid_core::models::{CredentialType, ProfileId};
use sid_plugin::cache::InMemoryCacheBackend;

const ORIGIN: &str = "https://sid.example.com";
const RP: &str = "sid.example.com";

fn server_on(cache: Arc<dyn CacheBackend>) -> WebAuthnServer {
    WebAuthnServer::new(RP, &Url::parse(ORIGIN).unwrap(), cache, key_manager())
        .expect("WebAuthn server creation should succeed")
}

fn server() -> WebAuthnServer {
    server_on(Arc::new(InMemoryCacheBackend::new()))
}

fn handle(byte: u8) -> WebAuthnUserHandle {
    WebAuthnUserHandle([byte; 16])
}

fn stored(profile: ProfileId, data: Vec<u8>) -> Credential {
    Credential::new(profile, CredentialType::WebAuthn, data, None)
}

/// A registered passkey: the server, the authenticator holding it and the
/// stored credential.
async fn registered(server: &WebAuthnServer) -> (SoftAuthenticator, Credential) {
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    let start = server
        .registration_start(handle(1), "alice", &[])
        .await
        .unwrap();
    let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
    let passkey = server.registration_finish(&response).await.unwrap();
    assert_eq!(passkey.user_handle, handle(1));
    (key, stored(ProfileId::generate(), passkey.data))
}

async fn sign_in(
    server: &WebAuthnServer,
    key: &mut SoftAuthenticator,
    passkeys: &[Credential],
) -> SidResult<VerifiedAssertion> {
    let start = server
        .authentication_start(AssertionPurpose::SignIn, passkeys)
        .await?;
    let response = AssertionResponse::parse(&key.assert(&start.options))?;
    server
        .authentication_finish(AssertionPurpose::SignIn, &response, passkeys)
        .await
}

async fn discoverable(
    server: &WebAuthnServer,
    key: &mut SoftAuthenticator,
    association: WebAuthnUserHandle,
    passkeys: &[Credential],
) -> SidResult<VerifiedAssertion> {
    let start = server.discoverable_authentication_start().await?;
    let response = DiscoverableAssertionResponse::parse(&key.assert(&start.options))?;
    server
        .discoverable_authentication_finish(&response, association, passkeys)
        .await
}

fn is_auth_failure(result: &SidResult<VerifiedAssertion>) -> bool {
    matches!(result, Err(SidError::AuthenticationFailed(_)))
}

/// Registration asks for a discoverable, user-verified credential with the
/// account's handle as `user.id`, and offers only ES256 and RS256: no
/// algorithm, post-quantum or other, is enabled by the library's inventory.
#[tokio::test]
async fn test_registration_options() {
    let server = server();
    let start = server
        .registration_start(handle(7), "alice", &[])
        .await
        .unwrap();
    let options: serde_json::Value = serde_json::from_slice(&start.options).unwrap();
    let pk = &options["publicKey"];
    assert_eq!(pk["rp"]["id"], RP);
    assert_eq!(
        pk["user"]["id"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16])
    );
    let selection = &pk["authenticatorSelection"];
    assert_eq!(selection["residentKey"], "required", "{selection}");
    assert_eq!(selection["userVerification"], "required", "{selection}");
    let algs: Vec<i64> = pk["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert_eq!(algs, [-7, -257]);
    assert_eq!(pk["challenge"], start.state_key);
}

/// A registered passkey signs in, is recorded with its new counter, and the
/// record keeps everything else byte for byte.
#[tokio::test]
async fn test_register_then_sign_in() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    let verified = sign_in(&server, &mut key, std::slice::from_ref(&passkey))
        .await
        .unwrap();
    assert_eq!(verified.credential, passkey.id);
    assert!(verified.user_verified);
    assert_eq!(verified.key_amr, "swk");
    let updated = verified.updated_data.expect("the counter advanced");
    assert_ne!(updated, passkey.data.expose());
    assert_eq!(updated.len(), passkey.data.expose().len());
    assert_eq!(
        passkey_credential_id(&updated).unwrap(),
        passkey_credential_id(passkey.data.expose()).unwrap()
    );
}

/// The stored record round-trips: the next sign-in verifies against the
/// record the previous one wrote.
#[tokio::test]
async fn test_updated_record_signs_in_again() {
    let server = server();
    let (mut key, mut passkey) = registered(&server).await;
    for _ in 0..3 {
        let verified = sign_in(&server, &mut key, std::slice::from_ref(&passkey))
            .await
            .unwrap();
        passkey.data = verified.updated_data.unwrap().into();
    }
}

/// A discoverable sign-in verifies when the credential carries the handle
/// the account's association holds, and is refused for another account's
/// handle even though the signature is valid.
#[tokio::test]
async fn test_discoverable_sign_in_checks_the_association() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    discoverable(&server, &mut key, handle(1), std::slice::from_ref(&passkey))
        .await
        .unwrap();
    assert!(is_auth_failure(
        &discoverable(&server, &mut key, handle(2), std::slice::from_ref(&passkey)).await
    ));
}

/// A returned user handle that is not the credential's is refused
/// (WebAuthn Level 3 §7.2 step 6).
#[tokio::test]
async fn test_wrong_user_handle_is_refused() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    key.behavior.user_handle = Some(vec![9; 16]);
    assert!(is_auth_failure(
        &discoverable(&server, &mut key, handle(1), std::slice::from_ref(&passkey)).await
    ));
    assert!(is_auth_failure(
        &sign_in(&server, &mut key, std::slice::from_ref(&passkey)).await
    ));
}

/// An assertion by a credential the account does not hold is refused.
#[tokio::test]
async fn test_unknown_credential_is_refused() {
    let server = server();
    let (mut key, _) = registered(&server).await;
    let (_, other) = registered(&server).await;
    assert!(is_auth_failure(
        &discoverable(&server, &mut key, handle(1), std::slice::from_ref(&other)).await
    ));
}

/// Each relying-party check refuses the assertion on its own: origin, RP ID,
/// signature, user presence, user verification, and a signature counter
/// that does not advance past a positive stored one.
#[tokio::test]
async fn test_each_assertion_check_refuses() {
    type Break = fn(&mut SoftAuthenticator);
    let breaks: [(&str, Break); 8] = [
        // Backed up but not eligible is invalid (WebAuthn Level 3 §6.1.3).
        ("backup flags", |k| {
            k.behavior.backup_eligible = false;
            k.behavior.backed_up = true;
        }),
        // Backup eligibility is fixed at creation (§7.2 step 19).
        ("backup eligibility", |k| {
            k.behavior.backup_eligible = false;
            k.behavior.backed_up = false;
        }),
        ("origin", |k| {
            k.behavior.origin = "https://evil.example.com".into()
        }),
        ("rp id", |k| k.behavior.rp_id = "evil.example.com".into()),
        ("signature", |k| k.behavior.corrupt_signature = true),
        ("user presence", |k| k.behavior.user_present = false),
        ("user verification", |k| k.behavior.user_verified = false),
        ("counter", |k| k.behavior.counter = Some(1)),
    ];
    for (what, break_it) in breaks {
        let server = server();
        let (mut key, mut passkey) = registered(&server).await;
        // Advance the stored counter past 1 first.
        key.behavior.counter = Some(5);
        passkey.data = sign_in(&server, &mut key, std::slice::from_ref(&passkey))
            .await
            .unwrap()
            .updated_data
            .unwrap()
            .into();
        key.behavior.counter = None;
        break_it(&mut key);
        assert!(
            is_auth_failure(&sign_in(&server, &mut key, std::slice::from_ref(&passkey)).await),
            "a broken {what} signed in"
        );
    }
}

/// An authenticator without a signature counter (always 0) keeps signing in:
/// a zero counter is not a clone signal.
#[tokio::test]
async fn test_zero_counter_authenticator_signs_in() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    key.behavior.counter = Some(0);
    for _ in 0..2 {
        sign_in(&server, &mut key, std::slice::from_ref(&passkey))
            .await
            .unwrap();
    }
}

/// A response is accepted once: replaying it finds no ceremony, and a state
/// of another purpose is not consumed as this one.
#[tokio::test]
async fn test_ceremony_is_single_use_and_bound_to_its_purpose() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    let passkeys = std::slice::from_ref(&passkey);
    let start = server
        .authentication_start(AssertionPurpose::StepUp, passkeys)
        .await
        .unwrap();
    let response = AssertionResponse::parse(&key.assert(&start.options)).unwrap();
    assert!(is_auth_failure(
        &server
            .authentication_finish(AssertionPurpose::SignIn, &response, passkeys)
            .await
    ));

    let start = server
        .authentication_start(AssertionPurpose::SignIn, passkeys)
        .await
        .unwrap();
    let response = AssertionResponse::parse(&key.assert(&start.options)).unwrap();
    server
        .authentication_finish(AssertionPurpose::SignIn, &response, passkeys)
        .await
        .unwrap();
    assert!(is_auth_failure(
        &server
            .authentication_finish(AssertionPurpose::SignIn, &response, passkeys)
            .await
    ));
}

/// A ceremony started on one replica finishes on another sharing the cache.
#[tokio::test]
async fn test_ceremony_finishes_on_another_replica() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let (a, b) = (server_on(cache.clone()), server_on(cache));
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    let start = a.registration_start(handle(1), "alice", &[]).await.unwrap();
    let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
    b.registration_finish(&response).await.unwrap();
}

/// A registration from another origin or for another RP is refused, and its
/// ceremony is spent.
#[tokio::test]
async fn test_registration_checks_origin_and_rp() {
    for wrong_origin in [true, false] {
        let server = server();
        let mut key = SoftAuthenticator::new(ORIGIN, RP);
        if wrong_origin {
            key.behavior.origin = "https://evil.example.com".into();
        } else {
            key.behavior.rp_id = "evil.example.com".into();
        }
        let start = server
            .registration_start(handle(1), "alice", &[])
            .await
            .unwrap();
        let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
        assert!(matches!(
            server.registration_finish(&response).await,
            Err(SidError::AuthenticationFailed(_))
        ));
    }
}

/// Responses are Level 3 JSON: one without `clientExtensionResults` is not
/// a WebAuthn response.
#[tokio::test]
async fn test_responses_parse_strictly() {
    let server = server();
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    let start = server
        .registration_start(handle(1), "alice", &[])
        .await
        .unwrap();
    let mut json: serde_json::Value =
        serde_json::from_slice(&key.register(&start.options)).unwrap();
    json.as_object_mut()
        .unwrap()
        .remove("clientExtensionResults");
    assert!(matches!(
        RegistrationResponse::parse(&serde_json::to_vec(&json).unwrap()),
        Err(SidError::Validation(_))
    ));
    assert!(matches!(
        AssertionResponse::parse(b"{}"),
        Err(SidError::Validation(_))
    ));
}

/// Existing passkeys are excluded from a new registration.
#[tokio::test]
async fn test_existing_passkeys_are_excluded() {
    let server = server();
    let (_, passkey) = registered(&server).await;
    let start = server
        .registration_start(handle(1), "alice", std::slice::from_ref(&passkey))
        .await
        .unwrap();
    let options: serde_json::Value = serde_json::from_slice(&start.options).unwrap();
    let excluded = options["publicKey"]["excludeCredentials"]
        .as_array()
        .unwrap();
    assert_eq!(excluded.len(), 1);
    assert_eq!(
        excluded[0]["id"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(passkey_credential_id(passkey.data.expose()).unwrap())
    );
}

/// An account without passkeys gets no assertion ceremony.
#[tokio::test]
async fn test_sign_in_needs_a_passkey() {
    assert!(matches!(
        server()
            .authentication_start(AssertionPurpose::SignIn, &[] as &[Credential])
            .await,
        Err(SidError::AuthenticationFailed(_))
    ));
}

/// A stored record that does not decode is a loud internal error, never a
/// skipped credential.
#[tokio::test]
async fn test_corrupt_record_fails_loudly() {
    let server = server();
    let (mut key, passkey) = registered(&server).await;
    let mut bytes = passkey.data.expose().to_vec();
    bytes.push(0);
    let corrupt = stored(passkey.profile_id, bytes);
    assert!(matches!(
        server
            .authentication_start(AssertionPurpose::SignIn, std::slice::from_ref(&corrupt))
            .await,
        Err(SidError::Internal(_))
    ));
    assert!(matches!(
        discoverable(&server, &mut key, handle(1), &[corrupt, passkey]).await,
        Err(SidError::Internal(_))
    ));
}

/// What a stored passkey shows: the soft authenticator's synced platform
/// passkey, `none` attestation, user verified at registration.
#[tokio::test]
async fn test_passkey_info() {
    let (_, passkey) = registered(&server()).await;
    let info = passkey_info(passkey.data.expose()).unwrap();
    assert_eq!(
        info,
        PasskeyInfo {
            transports: vec![PasskeyTransport::Hybrid, PasskeyTransport::Internal],
            backup_eligible: true,
            backed_up: true,
            attachment: PasskeyAttachment::Platform,
            attestation_format: "none",
            user_verified: true,
            key_amr: "swk",
        }
    );
}

/// `hwk` needs both a device-bound key and only roaming transports.
#[test]
fn test_key_method() {
    use structured_webauthn::response::AuthTransports;
    let transports = |names: &[&str]| -> AuthTransports {
        serde_json::from_value(serde_json::json!(names)).unwrap()
    };
    assert_eq!(method_of(transports(&["usb"]), Backup::NotEligible), "hwk");
    assert_eq!(
        method_of(transports(&["nfc", "usb"]), Backup::NotEligible),
        "hwk"
    );
    assert_eq!(method_of(transports(&["usb"]), Backup::Eligible), "swk");
    assert_eq!(
        method_of(transports(&["internal"]), Backup::NotEligible),
        "swk"
    );
    assert_eq!(
        method_of(transports(&["usb", "hybrid"]), Backup::NotEligible),
        "swk"
    );
    assert_eq!(method_of(transports(&[]), Backup::NotEligible), "swk");
}

/// The RP origin must be on the RP ID.
#[test]
fn test_origin_must_be_on_the_rp() {
    let new = |origin: &str| {
        WebAuthnServer::new(
            RP,
            &Url::parse(origin).unwrap(),
            Arc::new(InMemoryCacheBackend::new()),
            key_manager(),
        )
    };
    assert!(new("https://auth.sid.example.com").is_ok());
    assert!(new("https://example.com").is_err());
    assert!(new("https://notsid.example.com.evil").is_err());
}
