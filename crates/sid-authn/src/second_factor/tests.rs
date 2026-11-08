// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use sid_core::models::{OperationContext, OperationKey, Profile, ProfileId};
use sid_plugin::{CeremonyStateStore, InProcessCeremonyState, StorageBackend};
use sid_storage::sqlite::SqliteBackend;

use super::*;
use crate::test_support::key_manager;

struct Fixture {
    store: SqliteBackend,
    keys: Arc<dyn KeyManager>,
    factors: FactorCeremonies<ProfileId>,
}

async fn fixture() -> Fixture {
    let ceremonies: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let keys = key_manager();
    Fixture {
        store: SqliteBackend::new_in_memory().await.unwrap(),
        factors: FactorCeremonies::new(
            "https://sid.example.com".into(),
            "profile",
            ceremonies,
            keys.clone(),
        ),
        keys,
    }
}

fn ctx() -> MutationContext {
    AuditEntry::system("test", "second_factor").into()
}

async fn account(f: &Fixture) -> ProfileId {
    let profile = Profile::new(Some("alice"));
    f.store.create_profile(&profile, ctx()).await.unwrap();
    profile.id
}

/// `owner` with an enrolled TOTP authenticator: its seed and recovery codes.
async fn enrolled(f: &Fixture, owner: ProfileId) -> (Vec<u8>, TotpEnrolled) {
    let started = f
        .factors
        .totp_enrollment_start(&f.store, owner, "alice".into())
        .await
        .unwrap();
    let secret = f.factors.take_totp_enrollment(owner).await.unwrap();
    assert_eq!(secret, started.shared_secret);
    let code = crate::generate_current_totp(&secret);
    let done = f
        .factors
        .enroll_totp(&f.store, f.keys.as_ref(), owner, &secret, &code)
        .await
        .unwrap();
    (secret, done)
}

/// The first TOTP authenticator is stored sealed (never the bare seed) and
/// comes with recovery codes; a second start is refused while it is active.
#[tokio::test]
async fn first_totp_is_sealed_and_comes_with_recovery_codes() {
    let f = fixture().await;
    let alice = account(&f).await;
    let (secret, done) = enrolled(&f, alice).await;
    assert_eq!(done.recovery_codes.len(), 10);
    let stored = f
        .store
        .get_credential(done.credential_id)
        .await
        .unwrap()
        .unwrap();
    assert!(crate::sealed_secret::is_sealed(stored.data.expose()));
    assert_ne!(stored.data.expose(), secret.as_slice());
    assert_eq!(codes_left(&f.store, alice).await.unwrap(), 10);
    assert!(matches!(
        f.factors
            .totp_enrollment_start(&f.store, alice, "alice".into())
            .await,
        Err(FactorError::AlreadyEnrolled)
    ));
}

/// Another account's pending enrollment is not this account's: it reads as
/// expired, and the owner's own one is still there.
#[tokio::test]
async fn another_accounts_enrollment_reads_as_expired() {
    let f = fixture().await;
    let alice = account(&f).await;
    let bob = ProfileId::generate();
    f.factors
        .totp_enrollment_start(&f.store, alice, "alice".into())
        .await
        .unwrap();
    assert!(matches!(
        f.factors.take_totp_enrollment(bob).await,
        Err(FactorError::Expired(_))
    ));
    assert!(f.factors.take_totp_enrollment(alice).await.is_ok());
}

/// A wrong code at the finish enrolls nothing.
#[tokio::test]
async fn a_wrong_code_enrolls_nothing() {
    let f = fixture().await;
    let alice = account(&f).await;
    f.factors
        .totp_enrollment_start(&f.store, alice, "alice".into())
        .await
        .unwrap();
    let secret = f.factors.take_totp_enrollment(alice).await.unwrap();
    let wrong = if crate::generate_current_totp(&secret) == "000000" {
        "111111"
    } else {
        "000000"
    };
    assert!(matches!(
        f.factors
            .enroll_totp(&f.store, f.keys.as_ref(), alice, &secret, wrong)
            .await,
        Err(FactorError::AuthenticationFailed)
    ));
    assert!(
        f.store
            .get_credentials_by_profile(alice, None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A TOTP code verifies once (RFC 6238 §5.2): the code the enrollment
/// spent is refused, the next step's code verifies, and then it too is spent.
#[tokio::test]
async fn a_totp_code_verifies_once() {
    let f = fixture().await;
    let alice = account(&f).await;
    let (secret, _) = enrolled(&f, alice).await;
    let spent = crate::generate_current_totp(&secret);
    assert!(matches!(
        f.factors
            .verify_totp(&f.store, f.keys.as_ref(), alice, &spent)
            .await,
        Err(FactorError::AuthenticationFailed)
    ));
    let next = crate::generate_next_totp(&secret);
    f.factors
        .verify_totp(&f.store, f.keys.as_ref(), alice, &next)
        .await
        .unwrap();
    assert!(matches!(
        f.factors
            .verify_totp(&f.store, f.keys.as_ref(), alice, &next)
            .await,
        Err(FactorError::AuthenticationFailed)
    ));
}

/// An account without TOTP has nothing to verify against.
#[tokio::test]
async fn verify_without_totp_is_not_enrolled() {
    let f = fixture().await;
    let alice = account(&f).await;
    assert!(matches!(
        f.factors
            .verify_totp(&f.store, f.keys.as_ref(), alice, "123456")
            .await,
        Err(FactorError::NotEnrolled(_))
    ));
}

/// A recovery code's spend removes exactly that code from the set as read,
/// and a code the set does not hold spends nothing.
#[tokio::test]
async fn a_recovery_spend_removes_its_code_from_the_set_as_read() {
    let f = fixture().await;
    let alice = account(&f).await;
    let (_, done) = enrolled(&f, alice).await;
    assert!(matches!(
        f.factors
            .recovery_spend(&f.store, alice, "NOT-A-CODE")
            .await,
        Err(FactorError::AuthenticationFailed)
    ));
    let (spend, remaining) = f
        .factors
        .recovery_spend(&f.store, alice, &done.recovery_codes[0])
        .await
        .unwrap();
    assert_eq!(remaining, 9);
    let set = f
        .store
        .get_credentials_by_profile(alice, Some(CredentialType::Recovery))
        .await
        .unwrap()
        .remove(0);
    assert_eq!(spend.spend.credential, set.id);
    assert_eq!(spend.spend.read, set.data.expose());
    let left: Vec<String> = serde_json::from_slice(&spend.spend.left).unwrap();
    let hash = crate::hash_code(&crate::normalize_code(&done.recovery_codes[0]));
    assert_eq!(left.len(), 9);
    assert!(!left.contains(&hash));
}

/// The operation `key` in the store's current period.
async fn operation(f: &Fixture, key: &str) -> OperationContext {
    let period = f
        .store
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;
    OperationContext::new(OperationKey::parse(key).unwrap(), period)
}

/// A regenerated set replaces the old one, and a retry of the same command
/// names the set it issued instead of issuing another.
#[tokio::test]
async fn regenerated_codes_replace_the_old_set_once_per_command() {
    use sid_proto::keyed::authn::auth_service::GenerateRecoveryCodes;
    let f = fixture().await;
    let alice = account(&f).await;
    let (_, done) = enrolled(&f, alice).await;
    let request = sid_proto::sid::v1::GenerateRecoveryCodesRequest::default();
    let context = operation(&f, "regen-1").await;
    let command = || {
        f.factors
            .command::<GenerateRecoveryCodes>(alice, context.clone(), &request)
    };
    let codes = f
        .factors
        .regenerate_recovery_codes(&f.store, &f.store, alice, command())
        .await
        .unwrap();
    assert_eq!(codes.len(), 10);
    assert!(matches!(
        f.factors
            .recovery_spend(&f.store, alice, &done.recovery_codes[0])
            .await,
        Err(FactorError::AuthenticationFailed)
    ));
    let set = f
        .store
        .get_credentials_by_profile(alice, Some(CredentialType::Recovery))
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.status.is_active())
        .unwrap();
    match f
        .factors
        .regenerate_recovery_codes(&f.store, &f.store, alice, command())
        .await
    {
        Err(FactorError::RecoveryCodesIssued(id)) => assert_eq!(id, set.id.0.as_bytes()),
        other => panic!("expected the issued set, got {:?}", other.map(|c| c.len())),
    }
}

fn requirements(mfa: sid_core::models::MfaEnforcement) -> LoginRequirements {
    LoginRequirements {
        min_acr: AuthLevel::Basic,
        required_amr: Default::default(),
        max_authentication_age: None,
        enforcement: sid_core::models::EnforcementMode::Hard,
        new_device: crate::anomaly::RuleReaction::StepUp,
        fence: None,
        mfa,
        passkey_satisfies_mfa: false,
        account_protection: AuthLevel::Basic,
    }
}

/// Factors offered to a password sign-in that owes one: an enrolled TOTP
/// authenticator and, behind the protection it establishes, recovery codes;
/// an account with no protection yet may enroll TOTP first, one with
/// protection may not.
#[tokio::test]
async fn offered_and_enrollable_factors_follow_the_accounts_protection() {
    use sid_core::models::MfaEnforcement;
    let f = fixture().await;
    let alice = account(&f).await;
    let now = chrono::Utc::now();
    let first = crate::login_policy::local_authentication(
        alice,
        AuthLevel::Basic,
        &["pwd".to_string()],
        now,
    );
    let required = requirements(MfaEnforcement::Required)
        .for_account(&f.store, alice)
        .await
        .unwrap();
    assert!(
        offered_factors(&f.store, alice, &required, &first, now)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        enrollable_factors(&f.store, alice, &required, &first, false, now)
            .await
            .unwrap(),
        vec![StepUpMethod::Totp]
    );

    enrolled(&f, alice).await;
    let optional = requirements(MfaEnforcement::Optional)
        .for_account(&f.store, alice)
        .await
        .unwrap();
    assert_eq!(optional.account_protection, AuthLevel::Standard);
    assert_eq!(
        offered_factors(&f.store, alice, &optional, &first, now)
            .await
            .unwrap(),
        vec![StepUpMethod::Totp, StepUpMethod::RecoveryCode]
    );
    assert!(
        enrollable_factors(&f.store, alice, &optional, &first, false, now)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Events about an account name it by the authority's account kind.
#[test]
fn events_name_the_account_by_its_kind() {
    let ceremonies: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let factors = FactorCeremonies::<ProfileId>::new(
        "https://sid.example.com".into(),
        "profile",
        ceremonies,
        key_manager(),
    );
    let id = ProfileId::generate();
    assert_eq!(factors.subject(id), format!("profile/{id}"));
}
