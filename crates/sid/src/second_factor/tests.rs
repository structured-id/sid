use std::sync::Arc;

use sid_core::models::{AuditEntry, Credential, CredentialData};
use sid_plugin::storage::StorageBackend;

use super::*;
use crate::test_support::{
    browser_only_sign_in, keys, sign_in, sign_in as sign_in_with_signer, storage, stored_profile,
};

fn second_factors(storage: Arc<dyn StorageBackend>) -> SecondFactors {
    let origin = url::Url::parse("https://sid.example.com").unwrap();
    let webauthn = WebAuthnServer::new("sid.example.com", &origin, storage.clone(), keys())
        .expect("WebAuthn relying party");
    SecondFactors::new(
        Arc::new(webauthn),
        "https://sid.example.com".to_string(),
        storage,
        keys(),
    )
}

/// A recovery code set holding the hashes of `codes`.
async fn stored_recovery_codes(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    codes: &[&str],
) {
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| sid_authn::hash_code(&sid_authn::normalize_code(code)))
        .collect();
    let set = Credential::new(
        profile_id,
        CredentialType::Recovery,
        CredentialData::new(serde_json::to_vec(&hashes).unwrap()),
        None,
    );
    storage
        .create_credential(&set, AuditEntry::system("test", "recovery").into())
        .await
        .unwrap();
}

/// A TOTP code is exactly six ASCII digits; anything else is a malformed
/// request, refused on its field rather than counted as a wrong code.
#[test]
fn totp_code_is_six_digits() {
    require_totp_code_format("123456").unwrap();
    for malformed in ["12345", "1234567", "12345a", "", "１２３４５６"] {
        assert!(matches!(
            require_totp_code_format(malformed),
            Err(SecondFactorError::InvalidField { field: "code", .. })
        ));
    }
}

/// The recovery codes `profile` has left.
async fn codes_left(storage: &dyn StorageBackend, profile: ProfileId) -> usize {
    let set = storage
        .get_credentials_by_profile(profile, Some(CredentialType::Recovery))
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.status.is_active())
        .unwrap();
    serde_json::from_slice::<Vec<String>>(set.data.expose())
        .unwrap()
        .len()
}

/// Regression: a recovery code is spent only by the commit of the effect it
/// pays for. An effect that fails (its session ended) spends nothing; of
/// two spends read from the same set, the second commits nothing once the
/// first did, so concurrent uses never spend a code without its effect;
/// a spent code then fails like a wrong one, and an account without a set
/// has none to spend. Before, the code was spent in its own commit, ahead
/// of an effect that could still fail.
#[tokio::test]
async fn recovery_code_is_spent_only_with_its_effect() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    assert!(matches!(
        factors.recovery_spend(&sign_in, alice, "AAAA-BBBB").await,
        Err(SecondFactorError::NotEnrolled("recovery code set"))
    ));
    stored_recovery_codes(storage.as_ref(), alice, &["AAAA-BBBB", "CCCC-DDDD"]).await;
    let session = sign_in.new_session(alice, None);
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    let record = |spend: FactorSpend, id: SessionId| {
        let factors = &factors;
        let sign_in = &sign_in;
        async move {
            factors
                .authenticate_session(
                    sign_in,
                    id,
                    spend.into_context(AuditEntry::system("test", "recovery").into()),
                    |active| active.add_amr("mca"),
                )
                .await
                .map_err(spent_concurrently)
        }
    };

    // An effect that cannot commit spends nothing.
    let (spend, _) = factors
        .recovery_spend(&sign_in, alice, "AAAA-BBBB")
        .await
        .unwrap();
    assert!(matches!(
        record(spend, SessionId::generate()).await,
        Err(SecondFactorError::SessionEnded)
    ));
    assert_eq!(codes_left(storage.as_ref(), alice).await, 2);

    // Two uses read the same set: the first spends with its effect, the
    // second commits nothing.
    let (first, remaining) = factors
        .recovery_spend(&sign_in, alice, "AAAA-BBBB")
        .await
        .unwrap();
    let (second, _) = factors
        .recovery_spend(&sign_in, alice, "CCCC-DDDD")
        .await
        .unwrap();
    assert_eq!(remaining, 1);
    record(first, session.id).await.unwrap();
    assert!(matches!(
        record(second, session.id).await,
        Err(SecondFactorError::ChangedConcurrently)
    ));
    assert_eq!(codes_left(storage.as_ref(), alice).await, 1);

    assert!(matches!(
        factors.recovery_spend(&sign_in, alice, "AAAA-BBBB").await,
        Err(SecondFactorError::AuthenticationFailed)
    ));
    assert!(matches!(
        factors.recovery_spend(&sign_in, alice, "EEEE-FFFF").await,
        Err(SecondFactorError::AuthenticationFailed)
    ));
}

/// The TOTP seed is stored sealed and opens to the enrolled secret; an
/// account without an active authenticator has none.
#[tokio::test]
async fn totp_seed_opens_sealed() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    assert!(
        factors
            .active_totp_seed(&sign_in, alice)
            .await
            .unwrap()
            .is_none()
    );
    let secret = sid_authn::generate_secret();
    let sealed = sid_authn::sealed_secret::seal(
        keys().as_ref(),
        &sid_authn::sealed_secret::totp_context(alice),
        &secret,
    )
    .await
    .unwrap();
    let totp = Credential::new(
        alice,
        CredentialType::Totp,
        CredentialData::new(sealed),
        None,
    );
    storage
        .create_credential(&totp, AuditEntry::system("test", "totp").into())
        .await
        .unwrap();
    let (found, opened) = factors
        .active_totp_seed(&sign_in, alice)
        .await
        .unwrap()
        .expect("the enrolled authenticator");
    assert_eq!(found.id, totp.id);
    assert_eq!(opened.secret.as_slice(), secret.as_slice());
}

/// The bug: on a host without a token signer, a TOTP step-up and a native
/// completion verified the code (spending its step) before being refused
/// for the delivery they need. Both are refused first now, and the same
/// code still completes what the host does serve.
#[tokio::test]
async fn an_unserved_totp_delivery_spends_no_code() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = browser_only_sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let secret = sid_authn::generate_secret();
    let sealed = sid_authn::sealed_secret::seal(
        keys().as_ref(),
        &sid_authn::sealed_secret::totp_context(alice),
        &secret,
    )
    .await
    .unwrap();
    let totp = Credential::new(
        alice,
        CredentialType::Totp,
        CredentialData::new(sealed),
        None,
    );
    storage
        .create_credential(&totp, AuditEntry::system("test", "totp").into())
        .await
        .unwrap();
    let session = sign_in.new_session(alice, None);
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    // A native sign-in owing its second factor, started where native
    // clients are served (another host on the same store).
    let profile = storage.get_profile(alice).await.unwrap().unwrap();
    let signer = sign_in_with_signer(storage.clone());
    let (started, _) = signer
        .sign_in_pending(
            &profile,
            Session::new_awaiting_second_factor(
                alice,
                None,
                sid_core::models::session::AuthLevel::Basic,
                vec!["pwd".to_string()],
            ),
            CeremonyClient::Native,
            None,
            None,
        )
        .await
        .unwrap();
    let pending = storage
        .get_session(started.session_id)
        .await
        .unwrap()
        .expect("the pending context");
    let code = sid_authn::generate_current_totp(&secret);
    let policy = sid_authn::login_policy::FixedLoginPolicy::of(
        &sid_core::models::security_policy::SecurityPolicy::ce_default(),
    );
    for caller in [
        FactorCaller::StepUp(session.clone()),
        FactorCaller::Pending(pending, CeremonyClient::Native),
    ] {
        let refused = factors
            .verify_totp(&sign_in, &policy, caller, None, None, &code)
            .await;
        let refusal = refused.err().map(|e| format!("{e:?}"));
        assert_eq!(
            refusal.as_deref(),
            Some("SignIn(BearerNotServed)"),
            "the refusal of an unserved delivery"
        );
    }
    let stored = storage
        .get_credential(totp.id)
        .await
        .unwrap()
        .expect("the authenticator");
    assert_eq!(
        stored.last_used_at, totp.last_used_at,
        "no TOTP step was spent"
    );
}

/// A finish with no enrollment of the caller's own started answers as
/// expired; a malformed code is refused before any enrollment is consumed.
#[tokio::test]
async fn totp_enrollment_finish_needs_a_started_enrollment() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let session = sign_in.new_session(alice, None);
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    let enroller = Enroller::Session(signed_in_as(alice, &session.id.to_string()));
    assert!(matches!(
        factors
            .totp_enrollment_finish(&sign_in, &enroller, "12x456")
            .await,
        Err(SecondFactorError::InvalidField { field: "code", .. })
    ));
    assert!(matches!(
        factors
            .totp_enrollment_finish(&sign_in, &enroller, "123456")
            .await,
        Err(SecondFactorError::Expired("TOTP enrollment"))
    ));
}

/// `profile` calling with a token of its session `sid`.
fn signed_in_as(profile: ProfileId, sid: &str) -> sid_authn::caller::Caller {
    let now = jiff::Timestamp::now().as_second();
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
        roles: String::new(),
        sid: sid.to_owned(),
        amr: vec!["pwd".into()],
        jti: uuid::Uuid::now_v7().to_string(),
        cnf: None,
        act: None,
        credential_kind: None,
    })
    .unwrap()
}

/// Regression: a finish refused for its caller's authority consumes nothing,
/// so the started enrollment completes once an authorized caller sends the
/// code. Before, the enrollment was taken first and lost with the refusal,
/// and a fresh sign-in had to start the setup again.
#[tokio::test]
async fn a_refused_finish_keeps_the_enrollment() {
    let backend = storage().await;
    let storage: Arc<dyn StorageBackend> = backend;
    let sign_in = sign_in(storage.clone());
    let factors = second_factors(storage.clone());
    let alice = stored_profile(storage.as_ref(), "alice").await;
    let session = sign_in.new_session(alice, None);
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    let enroller = Enroller::Session(signed_in_as(alice, &session.id.to_string()));
    let started = factors
        .totp_enrollment_start(&sign_in, &enroller)
        .await
        .unwrap();
    let code = sid_authn::generate_current_totp(&started.shared_secret);

    // A caller whose session is gone may not enroll.
    let refused = Enroller::Session(signed_in_as(alice, &SessionId::generate().to_string()));
    let answer = factors
        .totp_enrollment_finish(&sign_in, &refused, &code)
        .await;
    assert!(
        answer.is_err() && !matches!(answer, Err(SecondFactorError::Expired(_))),
        "{answer:?}"
    );

    let enrolled = factors
        .totp_enrollment_finish(&sign_in, &enroller, &code)
        .await
        .unwrap();
    assert_eq!(enrolled.recovery_codes.len(), 10);
}

/// A step-up's passkey ceremony is kept under its session and challenge, so
/// a completion on another session never consumes it.
#[test]
fn step_up_ceremony_is_bound_to_its_session() {
    assert_ne!(step_up_key("session-a", "c"), step_up_key("session-b", "c"));
    assert_ne!(
        step_up_key("session-a", "c1"),
        step_up_key("session-a", "c2")
    );
}
