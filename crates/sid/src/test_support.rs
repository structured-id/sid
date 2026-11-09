//! What the engine's unit tests build an installation's parts from: a real
//! in-memory SQLite store, fixed keys and the sign-ins over them.

use std::sync::Arc;

use sid_core::models::{AuditEntry, Profile, ProfileId};
use sid_plugin::storage::StorageBackend;

use crate::sign_in::{SignIn, SignInParts};

pub(crate) async fn storage() -> Arc<sid_storage::sqlite::SqliteBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    )
}

pub(crate) fn keys() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

pub(crate) fn sign_in(storage: Arc<dyn StorageBackend>) -> SignIn {
    use sid_plugin::crypto::OpaqueOperations;
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
    let jwt = sid_authn::jwt::JwtService::new(
        include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
        include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .unwrap();
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
    SignIn::new(SignInParts {
        storage,
        jwt: Arc::new(jwt),
        revocation: Arc::new(sid_authn::revocation_cache::RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache.clone(),
        )),
        issuer: "https://sid.example.com".to_string(),
        anomaly: Arc::new(sid_authn::anomaly::AnomalyDetector::ce_default(
            ceremonies.clone(),
        )),
        ip_intelligence: Arc::new(sid_authn::ip_intelligence::IpIntelligenceAggregator::new(
            vec![],
            cache.clone(),
            std::time::Duration::from_secs(60),
        )),
        geoip: Arc::new(sid_authn::geoip::GeoIpChain::empty(cache)),
        captcha_gate: sid_authn::captcha::CaptchaGate::new(ceremonies, keys()),
        captcha_provider: Arc::new(sid_authn::captcha::SidPowProvider::new([0u8; 32], 4, 300)),
        opaque: Arc::new(sid_authn::opaque::OpaqueRouter::new(
            primary, verifiers, setup,
        )),
        keys: keys(),
    })
}

pub(crate) async fn stored_profile(storage: &dyn StorageBackend, username: &str) -> ProfileId {
    let profile = Profile::new(Some(username));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    profile.id
}

pub(crate) async fn stored_credential(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    credential_type: sid_core::models::CredentialType,
) -> sid_core::models::Credential {
    let credential = sid_core::models::Credential::new(
        profile_id,
        credential_type,
        sid_core::models::CredentialData::new(b"credential data".to_vec()),
        None,
    );
    storage
        .create_credential(&credential, AuditEntry::system("test", "credential").into())
        .await
        .unwrap();
    credential
}

/// An installation administrator signed in as `profile`.
pub(crate) fn administrator(profile: ProfileId) -> sid_authn::caller::Caller {
    let now = chrono::Utc::now().timestamp();
    sid_authn::caller::Caller::from_claims(&sid_authn::jwt::AccessTokenClaims {
        sub: profile.to_string(),
        pid: Some(profile.to_string()),
        iss: "https://sid.example.com".into(),
        aud: vec!["https://sid.example.com".into()],
        client_id: None,
        exp: now + 300,
        iat: now,
        auth_time: now,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: sid_authn::account_roles::ADMIN_ROLE_CLAIM.into(),
        sid: uuid::Uuid::now_v7().to_string(),
        amr: vec!["pwd".into()],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
    })
    .unwrap()
}

/// The operation context of a keyed call named `key`, under the store's
/// current period.
pub(crate) async fn operation(
    storage: &dyn StorageBackend,
    key: &str,
) -> sid_core::models::OperationContext {
    let period = storage
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;
    sid_core::models::OperationContext::new(
        sid_core::models::OperationKey::parse(key).unwrap(),
        period,
    )
}

pub(crate) fn fixed_policy() -> sid_authn::login_policy::FixedLoginPolicy {
    sid_authn::login_policy::FixedLoginPolicy::of(
        &sid_core::models::security_policy::SecurityPolicy::ce_default(),
    )
}
