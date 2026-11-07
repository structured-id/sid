use std::sync::Arc;

use sid_authn::login_policy::{FixedLoginPolicy, LoginPolicySource};
use sid_core::models::{AuditEntry, Credential, CredentialData, CredentialFence, CredentialType};

use super::*;

async fn storage() -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    )
}

fn keys() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

fn sign_in(storage: Arc<dyn StorageBackend>) -> SignIn {
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
    let jwt = JwtService::new(
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .unwrap();
    SignIn::new(SignInParts {
        storage,
        jwt: Arc::new(jwt),
        revocation: Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache.clone(),
        )),
        issuer: "https://sid.example.com".to_string(),
        anomaly: Arc::new(AnomalyDetector::ce_default(ceremonies.clone())),
        ip_intelligence: Arc::new(IpIntelligenceAggregator::new(
            vec![],
            cache.clone(),
            std::time::Duration::from_secs(60),
        )),
        geoip: Arc::new(GeoIpChain::empty(cache)),
        captcha_gate: CaptchaGate::new(ceremonies, keys()),
        captcha_provider: Arc::new(sid_authn::captcha::SidPowProvider::new([0u8; 32], 4, 300)),
        opaque: opaque(),
        keys: keys(),
    })
}

fn opaque() -> Arc<OpaqueRouter> {
    use sid_plugin::crypto::OpaqueOperations;
    let primary = Box::new(sid_authn::opaque::PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: std::collections::HashMap<
        sid_plugin::crypto::CurveId,
        Box<dyn OpaqueOperations>,
    > = std::collections::HashMap::new();
    verifiers.insert(
        sid_plugin::crypto::CurveId::Pallas,
        Box::new(sid_authn::opaque::PallasOpaque::new()),
    );
    Arc::new(OpaqueRouter::new(primary, verifiers, setup))
}

async fn requirements() -> LoginRequirements {
    FixedLoginPolicy::of(&SecurityPolicy::ce_default())
        .requirements(None)
        .await
        .unwrap()
}

async fn stored_profile(storage: &dyn StorageBackend) -> Profile {
    let profile = Profile::new(Some("alice"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile
}

/// The lockout refuses an identity once its failed attempts reach the brute
/// force limit, and never one that failed nothing: the check runs before any
/// password work for known and unknown identities alike.
#[tokio::test]
async fn lockout_follows_failed_attempts() {
    let sign_in = sign_in(storage().await);
    sign_in.refuse_if_locked("alice").await.unwrap();
    for _ in 0..5 {
        sign_in.record_failed_login("alice", None).await.unwrap();
    }
    assert!(matches!(
        sign_in.refuse_if_locked("alice").await,
        Err(SignInError::Rules(SignInRefusal::TooManyAttempts(d))) if d == sign_in.anomaly().lockout_duration()
    ));
    sign_in.refuse_if_locked("bob").await.unwrap();
}

/// A full session lives for the policy's absolute lifetime, a day when the
/// policy sets none, and carries the sign-in scopes.
#[tokio::test]
async fn new_session_follows_policy_lifetime() {
    let mut sign_in = sign_in(storage().await);
    let profile = ProfileId::generate();
    let mut policy = SecurityPolicy::ce_default();
    policy.session.max_lifetime_hours = 0;
    sign_in.set_policy(policy.clone());
    assert_eq!(sign_in.session_lifetime(), Duration::hours(24));
    policy.session.max_lifetime_hours = 3;
    sign_in.set_policy(policy);
    assert_eq!(sign_in.session_lifetime(), Duration::hours(3));
    let session = sign_in.new_session(profile, None);
    assert_eq!(session.profile_id, profile);
    assert_eq!(session.scopes, ["openid", "profile", "email"]);
    let lifetime = session.expires_at - Utc::now();
    assert!(lifetime > Duration::minutes(179) && lifetime <= Duration::hours(3));
}

/// A native client gets the stored session's access token, expiring no
/// later than the session; nothing renews it without a proved key.
#[tokio::test]
async fn native_sign_in_stores_session_and_issues_token() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let profile = stored_profile(storage.as_ref()).await;
    let session = sign_in.new_session(profile.id, None);
    let signed_in = sign_in
        .sign_in(
            &profile,
            session,
            CeremonyClient::Native,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let stored = storage
        .get_session(signed_in.session_id)
        .await
        .unwrap()
        .expect("the session is stored");
    assert_eq!(stored.profile_id, profile.id);
    assert!(signed_in.expires_in > 0);
    assert!(matches!(
        signed_in.delivery,
        Delivery::Bearer { refresh: None, .. }
    ));
}

/// The browser sign-in page gets the IdP session cookie and no access
/// token; the stored session keeps only its secret's hash.
#[tokio::test]
async fn browser_sign_in_delivers_cookie() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let profile = stored_profile(storage.as_ref()).await;
    let session = sign_in.new_session(profile.id, None);
    let signed_in = sign_in
        .sign_in(
            &profile,
            session,
            CeremonyClient::Browser,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(!matches!(signed_in.delivery, Delivery::Bearer { .. }));
    let stored = storage
        .get_session(signed_in.session_id)
        .await
        .unwrap()
        .expect("the session is stored");
    assert!(stored.browser_secret_hash.is_some());
}

/// A sign-in whose proved credential changed before the session committed
/// commits nothing and is refused as fenced, so it is started again.
#[tokio::test]
async fn sign_in_with_changed_credential_is_fenced() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let profile = stored_profile(storage.as_ref()).await;
    let credential = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(b"first".to_vec()),
        None,
    );
    storage
        .create_credential(&credential, AuditEntry::system("test", "credential").into())
        .await
        .unwrap();
    let fence = CredentialFence {
        id: credential.id,
        data: CredentialData::new(b"first".to_vec()),
    };
    assert!(
        storage
            .replace_credential_data(
                credential.id,
                b"first",
                b"second",
                AuditEntry::system("test", "credential").into(),
            )
            .await
            .unwrap()
    );
    let session = sign_in.new_session(profile.id, None);
    let id = session.id;
    let refused = sign_in
        .sign_in(
            &profile,
            session,
            CeremonyClient::Native,
            None,
            Some(SignInProof::Credential(&fence)),
            None,
            None,
        )
        .await;
    assert!(matches!(refused, Err(SignInError::Fenced)));
    assert!(storage.get_session(id).await.unwrap().is_none());
}

/// A first factor the CE default requirements accept is admitted under
/// their fence, with nothing owed.
#[tokio::test]
async fn first_factor_admitted_under_default_requirements() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let profile = stored_profile(storage.as_ref()).await;
    let requirements = requirements().await;
    let amr = vec!["pwd".to_string()];
    let decision = sign_in
        .first_factor(
            profile.id,
            None,
            ("opaque", AuthLevel::Basic, &amr),
            AttemptContext::default(),
            &requirements,
        )
        .await
        .unwrap();
    assert!(matches!(decision, FirstFactor::Admitted(fence) if fence == requirements.fence));
}

/// A password sign-in of a principal nobody holds is started like any other
/// and refused at its finish like a wrong password, each refusal counted
/// against the principal until the lockout refuses the next start.
#[tokio::test]
async fn unknown_principal_password_sign_in_is_refused_and_counted() {
    let sign_in = sign_in(storage().await);
    for _ in 0..5 {
        let started = sign_in
            .password_start("nobody@example.com", &credential_request(), None)
            .await
            .unwrap();
        assert!(!started.credential_response.is_empty());
        assert!(matches!(
            sign_in
                .password_finish(&started.login_id, b"not a finalization", None)
                .await,
            Err(SignInError::Password(
                PasswordSignInError::AuthenticationFailed
            ))
        ));
    }
    assert!(matches!(
        sign_in
            .password_start("nobody@example.com", &credential_request(), None)
            .await,
        Err(SignInError::Rules(SignInRefusal::TooManyAttempts(_)))
    ));
}

/// A client's OPAQUE credential request (KE1) for some password.
fn credential_request() -> Vec<u8> {
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    sid_opaque_ke::ClientLogin::<sid_pake_core::pallas_opaque::PallasCipherSuite>::start(
        &mut rng,
        b"correct-horse-battery-staple",
    )
    .unwrap()
    .message
    .serialize()
    .to_vec()
}

/// A finish of a login that was never started is refused as expired.
#[tokio::test]
async fn unknown_login_finish_is_expired() {
    let sign_in = sign_in(storage().await);
    assert!(matches!(
        sign_in
            .password_finish(&OpaqueLoginId::generate(), b"finalization", None)
            .await,
        Err(SignInError::Password(PasswordSignInError::Expired))
    ));
}

/// An identifier that is no principal is refused as invalid, not answered
/// as an unknown account.
#[tokio::test]
async fn invalid_identifier_is_refused() {
    let sign_in = sign_in(storage().await);
    assert!(matches!(
        sign_in.resolve_profile("").await,
        Err(SignInError::InvalidIdentifier(_))
    ));
    assert!(
        sign_in
            .resolve_profile("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

/// A first factor that owes a second keeps the credential it proved for the
/// pending context: the completion finds it while it holds, a replaced one
/// is fenced, and a context without a kept proof has ended.
#[tokio::test]
async fn pending_context_keeps_first_factor_proof() {
    let storage = storage().await;
    let sign_in = sign_in(storage.clone());
    let profile = stored_profile(storage.as_ref()).await;
    let credential = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(b"first".to_vec()),
        None,
    );
    storage
        .create_credential(&credential, AuditEntry::system("test", "credential").into())
        .await
        .unwrap();
    let fence = CredentialFence {
        id: credential.id,
        data: CredentialData::new(b"first".to_vec()),
    };
    let signed = sign_in
        .complete_first_factor(
            &profile,
            LoginMethod::Password,
            None,
            None,
            CeremonyClient::Native,
            None,
            Some(&fence),
            FirstFactor::AwaitsSecondFactor {
                factors: vec![StepUpMethod::Totp],
                enrollable: Vec::new(),
                fence: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(signed.second_factors, [i32::from(StepUpMethod::Totp)]);
    let pending = storage
        .get_session(signed.signed_in.session_id)
        .await
        .unwrap()
        .expect("the pending context is stored");
    assert!(pending.awaits_second_factor());
    let kept = sign_in.first_factor_fence(&pending).await.unwrap().unwrap();
    assert_eq!(kept.id, credential.id);
    storage
        .replace_credential_data(
            credential.id,
            b"first",
            b"second",
            AuditEntry::system("test", "credential").into(),
        )
        .await
        .unwrap();
    assert!(matches!(
        sign_in.first_factor_fence(&pending).await,
        Err(SignInError::Fenced)
    ));
    let other = Session::new_awaiting_second_factor(
        profile.id,
        None,
        AuthLevel::Basic,
        vec!["pwd".to_string()],
    );
    assert!(matches!(
        sign_in.first_factor_fence(&other).await,
        Err(SignInError::SessionEnded)
    ));
}

/// A password sign-in records the password level and `pwd`; a passkey with
/// user verification reaches the multi-factor level when the policy lets a
/// passkey satisfy MFA, and one without stays at the basic level.
#[test]
fn login_method_assurance() {
    assert_eq!(LoginMethod::Password.auth_level(true), AuthLevel::Basic);
    assert_eq!(LoginMethod::Password.amr(), ["pwd"]);
    let verified = LoginMethod::Passkey {
        user_verified: true,
        key_amr: "hwk",
    };
    assert_eq!(verified.auth_level(true), AuthLevel::Standard);
    assert_eq!(verified.auth_level(false), AuthLevel::Basic);
    let unverified = LoginMethod::Passkey {
        user_verified: false,
        key_amr: "hwk",
    };
    assert_eq!(unverified.auth_level(true), AuthLevel::Basic);
}

/// An admitted sign-in's inputs name its principal assignment and revision,
/// so one relinked under a new revision is a different operation.
#[test]
fn admitted_inputs_follow_assignment_revision() {
    let profile = ProfileId::generate();
    let principal = sid_core::models::PrincipalId::new();
    let first = PrincipalAssignmentFence {
        profile,
        principal,
        revision: 1,
    };
    let second = PrincipalAssignmentFence {
        revision: 2,
        ..first
    };
    assert_ne!(admitted_inputs(first), admitted_inputs(second));
    assert_eq!(admitted_inputs(first), admitted_inputs(first));
}

/// A refusal of the rules converts into the sign-in's refusal unchanged.
#[test]
fn refusal_converts_into_rules_error() {
    assert!(matches!(
        SignInError::from(SignInRefusal::Refused),
        SignInError::Rules(SignInRefusal::Refused)
    ));
}
