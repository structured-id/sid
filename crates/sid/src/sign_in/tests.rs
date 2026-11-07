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
    })
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
