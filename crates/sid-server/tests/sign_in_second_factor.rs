// SPDX-License-Identifier: AGPL-3.0-only
//! A sign-in whose login requirements need a second factor the account has
//! enrolled: the first factor gets a pending context, which authorizes
//! nothing but its completion, and the second factor completes it into a
//! session with a new credential. Before, the first factor was refused and
//! the second could never be given.

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::mock_storage::MockStorage;
use common::opaque_client::{bearer, register, start_login};
use common::{SIGN_IN_ORIGIN, TestServices};
use sid_authn::browser_session::BrowserCookie;
use sid_authn::login_policy::{LoginPolicySource, LoginPolicyUnavailable, LoginRequirements};
use sid_core::models::security_policy::EnforcementMode;
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialType, ProfileId, SessionId,
};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Response, Status};
use tonic_types::StatusExt;

const PRINCIPAL: &str = "second-factor@sid.example.com";
const PASSWORD: &[u8] = b"second-factor-password-2026";

/// The host policy, changed by the test; None stands for an unreadable store.
struct HostPolicy(Mutex<Option<LoginRequirements>>);

impl HostPolicy {
    fn set(&self, requirements: Option<LoginRequirements>) {
        *self.0.lock().unwrap() = requirements;
    }
}

#[async_trait]
impl LoginPolicySource for HostPolicy {
    async fn requirements(
        &self,
        _client_id: Option<&str>,
    ) -> Result<LoginRequirements, LoginPolicyUnavailable> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| LoginPolicyUnavailable("policy store down".to_string()))
    }
}

/// Requirements of a basic level with `amr`, hard enforcement.
fn requiring(amr: &[&str]) -> LoginRequirements {
    LoginRequirements {
        min_acr: AuthLevel::Basic,
        required_amr: amr
            .iter()
            .map(|m| (*m).to_string())
            .collect::<BTreeSet<_>>(),
        max_authentication_age: None,
        enforcement: EnforcementMode::Hard,
        new_device: sid_authn::anomaly::RuleReaction::StepUp,
        fence: None,
    }
}

/// Services under a policy requiring `otp`, with one registered account;
/// with `totp`, the account has an enrolled authenticator of that seed.
async fn services(totp: Option<&[u8]>) -> (TestServices, Arc<HostPolicy>, ProfileId) {
    let policy = Arc::new(HostPolicy(Mutex::new(Some(requiring(&[])))));
    let svc = TestServices::with_login_policy(MockStorage::new(), policy.clone());
    register(&svc, &svc, PRINCIPAL, PASSWORD).await;
    let profile = svc
        .storage
        .get_profile_by_email(PRINCIPAL)
        .await
        .unwrap()
        .unwrap()
        .id;
    if let Some(seed) = totp {
        let credential = Credential::new(
            profile,
            CredentialType::Totp,
            CredentialData::new(common::sealed_totp_seed(profile, seed).await),
            None,
        );
        svc.storage
            .create_credential(&credential, AuditEntry::system("test", "totp").into())
            .await
            .unwrap();
    }
    policy.set(Some(requiring(&["otp"])));
    (svc, policy, profile)
}

/// A native password sign-in.
async fn native_sign_in(svc: &TestServices) -> Result<Response<OpaqueLoginFinishResponse>, Status> {
    let finish = start_login(svc, PRINCIPAL, PASSWORD).await;
    svc.auth.opaque_login_finish(Request::new(finish)).await
}

/// VerifyTotp with `code`, presenting `token`.
async fn verify_with_token(
    svc: &TestServices,
    token: &str,
    code: String,
) -> Result<Response<MfaVerifyResponse>, Status> {
    let mut request = Request::new(VerifyTotpRequest { code });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    svc.auth.verify_totp(request).await
}

fn reason(status: &Status) -> Option<String> {
    status.get_details_error_info().map(|info| info.reason)
}

/// A password sign-in under an `otp` requirement, with TOTP enrolled, awaits
/// TOTP; the code completes it into a session of [pwd, otp] at Standard,
/// with a new token, and the pending context is gone.
#[tokio::test]
async fn a_password_sign_in_owing_otp_is_completed_by_totp() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, profile) = services(Some(&seed)).await;

    let first = native_sign_in(&svc).await.expect("pending context");
    let pending_token = bearer(&first);
    let body = first.into_inner();
    assert_eq!(body.second_factors, [StepUpMethod::Totp as i32]);
    assert_eq!(
        body.browser_csrf, None,
        "a native client gets no CSRF token"
    );
    let pending_id = SessionId::parse(&body.session_id).unwrap();
    let pending = svc.storage.get_session(pending_id).await.unwrap().unwrap();
    assert!(pending.awaits_second_factor());

    let completed = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .expect("TOTP completes the sign-in");
    let token = bearer(&completed);
    assert_ne!(token, pending_token);
    let claims = svc.jwt.validate_access_token(&token).unwrap();
    assert!(claims.amr.iter().any(|m| m == "pwd"), "{:?}", claims.amr);
    assert!(claims.amr.iter().any(|m| m == "otp"), "{:?}", claims.amr);
    let body = completed.into_inner();
    let session_id = SessionId::parse(body.session_id.as_deref().unwrap()).unwrap();
    assert_ne!(session_id, pending_id);
    let session = svc.storage.get_session(session_id).await.unwrap().unwrap();
    assert!(!session.is_provisional);
    assert_eq!(session.assurance_level, AuthLevel::Standard);
    assert_eq!(session.authenticated_at, pending.authenticated_at);
    assert!(svc.storage.get_session(pending_id).await.unwrap().is_none());
    assert_eq!(svc.mock_storage.sessions_of(profile), 1);
}

/// `message` arriving over a connection from `ip`.
fn from_ip<T>(ip: std::net::IpAddr, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(std::net::SocketAddr::new(ip, 40000)),
        });
    request
}

/// A password sign-in from `ip` on the device `user_agent` names.
async fn sign_in_from(
    svc: &TestServices,
    ip: &str,
    user_agent: &str,
) -> Result<Response<OpaqueLoginFinishResponse>, Status> {
    let finish = start_login(svc, PRINCIPAL, PASSWORD).await;
    let mut request = from_ip(ip.parse().unwrap(), finish);
    request
        .metadata_mut()
        .insert("user-agent", user_agent.parse().unwrap());
    svc.auth.opaque_login_finish(request).await
}

/// A new device from a new address, under a reaction asking a step-up, is
/// answered by the factor the account has enrolled: the first factor gets the
/// same pending context a requirement would give it. Before, it was refused
/// and the factor could never be given.
#[tokio::test]
async fn a_new_device_is_answered_by_the_enrolled_factor() {
    let seed = sid_authn::generate_secret();
    let (svc, policy, _) = services(Some(&seed)).await;
    policy.set(Some(requiring(&[])));
    sign_in_from(&svc, "198.51.100.23", "known-device")
        .await
        .expect("the first device signs in");

    let first = sign_in_from(&svc, "203.0.113.45", "another-device")
        .await
        .expect("pending context");
    let pending_token = bearer(&first);
    let body = first.into_inner();
    assert_eq!(body.second_factors, [StepUpMethod::Totp as i32]);
    let pending_id = SessionId::parse(&body.session_id).unwrap();
    let pending = svc.storage.get_session(pending_id).await.unwrap().unwrap();
    assert!(pending.awaits_second_factor());

    let completed = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .expect("TOTP answers the rule");
    let body = completed.into_inner();
    let session_id = SessionId::parse(body.session_id.as_deref().unwrap()).unwrap();
    let session = svc.storage.get_session(session_id).await.unwrap().unwrap();
    assert!(!session.is_provisional);
    assert_eq!(session.assurance_level, AuthLevel::Standard);
}

/// `message` carrying `token`.
fn with_token<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

/// With no factor ever enrolled there is nothing to challenge: the sign-in
/// gets no empty list of factors, it may enroll its first.
#[tokio::test]
async fn a_new_device_without_a_factor_enrolls_its_first() {
    let (svc, policy, _) = services(None).await;
    policy.set(Some(requiring(&[])));
    sign_in_from(&svc, "198.51.100.23", "known-device")
        .await
        .expect("the first device signs in");

    let body = sign_in_from(&svc, "203.0.113.45", "another-device")
        .await
        .expect("pending context")
        .into_inner();
    assert!(body.second_factors.is_empty());
    assert_eq!(body.enrollable_factors, [StepUpMethod::Totp as i32]);
}

/// A password-only account owing a factor enrolls its first from the pending
/// context, which elevates nothing by itself: the new factor then completes
/// the sign-in at Standard. The context reaches nothing else meanwhile.
#[tokio::test]
async fn a_sign_in_enrolls_its_first_factor_and_completes_with_it() {
    let (svc, _policy, profile) = services(None).await;
    let first = native_sign_in(&svc).await.expect("pending context");
    let token = bearer(&first);
    let pending_id = SessionId::parse(&first.into_inner().session_id).unwrap();
    assert_eq!(svc.mock_storage.sessions_of(profile), 1);

    let challenge = svc
        .auth
        .start_totp_enrollment(with_token(&token, StartTotpEnrollmentRequest {}))
        .await
        .expect("the first enrollment starts")
        .into_inner();
    let seed = sid_authn::base32_decode(&challenge.secret).unwrap();
    let finished = svc
        .auth
        .finish_totp_enrollment(with_token(
            &token,
            FinishTotpEnrollmentRequest {
                code: sid_authn::generate_current_totp(&seed),
            },
        ))
        .await
        .expect("the first enrollment commits")
        .into_inner();
    assert!(!finished.recovery_codes.is_empty());
    let pending = svc.storage.get_session(pending_id).await.unwrap().unwrap();
    assert!(pending.awaits_second_factor(), "enrolling elevates nothing");

    let completed = verify_with_token(&svc, &token, sid_authn::generate_next_totp(&seed))
        .await
        .expect("the new factor completes the sign-in")
        .into_inner();
    let session_id = SessionId::parse(completed.session_id.as_deref().unwrap()).unwrap();
    let session = svc.storage.get_session(session_id).await.unwrap().unwrap();
    assert!(!session.is_provisional);
    assert_eq!(session.assurance_level, AuthLevel::Standard);
    assert!(session.amr.iter().any(|m| m == "otp"), "{:?}", session.amr);
}

/// A pending context binds nothing to an account with established
/// protection: a factor it cannot give is not replaced by enrolling another.
#[tokio::test]
async fn a_protected_account_enrolls_nothing_from_a_pending_context() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, _) = services(Some(&seed)).await;
    let first = native_sign_in(&svc).await.expect("pending context");
    let token = bearer(&first);
    assert!(first.into_inner().enrollable_factors.is_empty());

    let refused = svc
        .auth
        .start_totp_enrollment(with_token(&token, StartTotpEnrollmentRequest {}))
        .await
        .expect_err("established protection stays");
    assert_eq!(reason(&refused).as_deref(), Some("MFA_REQUIRED"));
}

/// A sign-in begun with a password replaced since binds nothing, at the start
/// or at the finish of the ceremony: its proof no longer holds, and a seed of
/// its choosing would lock the owner out.
#[tokio::test]
async fn a_replaced_password_enrolls_nothing_from_its_older_sign_in() {
    let (svc, _policy, profile) = services(None).await;
    let replace_password = || async {
        let mut password = svc
            .storage
            .get_credentials_by_profile(profile, Some(CredentialType::Opaque))
            .await
            .unwrap()
            .remove(0);
        password.data = CredentialData::new(b"the password file of a later change".to_vec());
        svc.mock_storage.set_credential(&password);
    };

    let first = native_sign_in(&svc).await.expect("pending context");
    let token = bearer(&first);
    let challenge = svc
        .auth
        .start_totp_enrollment(with_token(&token, StartTotpEnrollmentRequest {}))
        .await
        .expect("the proof holds at the start")
        .into_inner();
    let seed = sid_authn::base32_decode(&challenge.secret).unwrap();
    replace_password().await;

    let refused = svc
        .auth
        .finish_totp_enrollment(with_token(
            &token,
            FinishTotpEnrollmentRequest {
                code: sid_authn::generate_current_totp(&seed),
            },
        ))
        .await
        .expect_err("the proof no longer holds at the finish");
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    svc.auth
        .start_totp_enrollment(with_token(&token, StartTotpEnrollmentRequest {}))
        .await
        .expect_err("nor at a new start");
    assert!(
        svc.storage
            .get_credentials_by_profile(profile, Some(CredentialType::Totp))
            .await
            .unwrap()
            .is_empty(),
        "nothing was bound"
    );
}

/// A passkey protects the account though this password sign-in cannot use
/// it: no enrollment is offered and the sign-in is refused for recovery.
#[tokio::test]
async fn a_lost_factor_is_no_first_enrollment() {
    let (svc, _policy, profile) = services(None).await;
    let passkey = Credential::new(
        profile,
        CredentialType::WebAuthn,
        CredentialData::new(b"a registered passkey".to_vec()),
        None,
    );
    svc.storage
        .create_credential(&passkey, AuditEntry::system("test", "passkey").into())
        .await
        .unwrap();

    let refused = native_sign_in(&svc).await.unwrap_err();
    assert_eq!(reason(&refused).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(svc.mock_storage.sessions_of(profile), 0);
}

/// A sign-in counts as successful evidence for later ones (the address's
/// reputation) only once its second factor completed it, never while it
/// waits. Before, a sign-in completed this way recorded none.
#[tokio::test]
async fn the_completed_sign_in_is_recorded_as_a_success() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, _) = services(Some(&seed)).await;
    let ip: std::net::IpAddr = "198.51.100.23".parse().unwrap();
    let finish = start_login(&svc, PRINCIPAL, PASSWORD).await;
    let first = svc
        .auth
        .opaque_login_finish(from_ip(ip, finish))
        .await
        .expect("pending context");
    let success = (ip.to_string(), true);
    assert!(!svc.mock_storage.ip_reputation_events().contains(&success));

    let mut verify = from_ip(
        ip,
        VerifyTotpRequest {
            code: sid_authn::generate_current_totp(&seed),
        },
    );
    verify.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", bearer(&first)).parse().unwrap(),
    );
    svc.auth.verify_totp(verify).await.expect("completed");

    assert!(svc.mock_storage.ip_reputation_events().contains(&success));
}

/// A password replaced after the first factor and before the second (a
/// reset of the account) leaves the sign-in nothing to complete: no session
/// is stored. Before, the completion committed without the password's fence
/// and the stale first factor signed in.
#[tokio::test]
async fn a_password_replaced_before_completion_signs_nobody_in() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, profile) = services(Some(&seed)).await;
    let pending_token = bearer(&native_sign_in(&svc).await.unwrap());

    let mut credential = svc
        .storage
        .get_credentials_by_profile(profile, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .remove(0);
    credential.data = sid_authn::sealed_secret::seal(
        common::test_key_manager().as_ref(),
        &sid_authn::sealed_secret::opaque_context(profile),
        b"the replacement password file",
    )
    .await
    .unwrap()
    .into();
    svc.mock_storage.set_credential(&credential);

    let refused = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    let sessions = svc.storage.list_sessions(&profile).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.awaits_second_factor()),
        "{sessions:?}"
    );
}

/// Wrong second-factor codes count against the account's sign-in budget:
/// past it the sign-in is locked out, the right code included, in every
/// pending context of the account. Before, a password holder could guess
/// codes without limit.
#[tokio::test]
async fn wrong_codes_lock_the_account_out() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, _) = services(Some(&seed)).await;
    let pending_token = bearer(&native_sign_in(&svc).await.unwrap());
    let right = sid_authn::generate_current_totp(&seed);
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };

    for _ in 0..5 {
        let refused = verify_with_token(&svc, &pending_token, wrong.to_string())
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
    }
    let locked = verify_with_token(&svc, &pending_token, right)
        .await
        .unwrap_err();
    assert_eq!(locked.code(), Code::ResourceExhausted, "{locked:?}");
}

/// The pending context authorizes no application grant and no account
/// operation, and completes once only.
#[tokio::test]
async fn a_pending_context_authorizes_nothing_else() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, _) = services(Some(&seed)).await;
    let pending_token = bearer(&native_sign_in(&svc).await.unwrap());

    let mut enroll = Request::new(StartTotpEnrollmentRequest {});
    enroll.metadata_mut().insert(
        "authorization",
        format!("Bearer {pending_token}").parse().unwrap(),
    );
    assert!(svc.auth.start_totp_enrollment(enroll).await.is_err());

    let mut authorize = Request::new(OAuth2AuthorizeRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        response_type: "code".to_string(),
        scope: Some("openid".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        issuer_handle: svc.issuer.handle.to_string(),
        ..Default::default()
    });
    authorize.metadata_mut().insert(
        "authorization",
        format!("Bearer {pending_token}").parse().unwrap(),
    );
    assert!(svc.auth.o_auth2_authorize(authorize).await.is_err());

    verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .unwrap();
    let again = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .expect_err("a completed context completes nothing again");
    assert_eq!(again.code(), Code::Unauthenticated, "{again:?}");
}

/// A requirement TOTP cannot meet is refused and stores no session, with no
/// factor enrolled or one enrolled.
#[tokio::test]
async fn a_sign_in_no_factor_completes_is_refused() {
    let (svc, policy, profile) = services(None).await;
    policy.set(Some(requiring(&["hwk"])));
    let refused = native_sign_in(&svc).await.unwrap_err();
    assert_eq!(reason(&refused).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(svc.mock_storage.sessions_of(profile), 0);

    let seed = sid_authn::generate_secret();
    let (svc, policy, profile) = services(Some(&seed)).await;
    policy.set(Some(requiring(&["hwk"])));
    let refused = native_sign_in(&svc).await.unwrap_err();
    assert_eq!(reason(&refused).as_deref(), Some("STEP_UP_REQUIRED"));
    assert_eq!(svc.mock_storage.sessions_of(profile), 0);
}

/// The requirements are read again at completion: a requirement TOTP no
/// longer meets asks to step up, an unreadable policy completes nothing.
#[tokio::test]
async fn completion_is_judged_by_the_policy_in_force() {
    let seed = sid_authn::generate_secret();
    let (svc, policy, _) = services(Some(&seed)).await;
    let pending_token = bearer(&native_sign_in(&svc).await.unwrap());

    policy.set(Some(requiring(&["otp", "hwk"])));
    let refused = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&refused).as_deref(), Some("STEP_UP_REQUIRED"));

    let seed = sid_authn::generate_secret();
    let (svc, policy, _) = services(Some(&seed)).await;
    let pending_token = bearer(&native_sign_in(&svc).await.unwrap());
    policy.set(None);
    let refused = verify_with_token(
        &svc,
        &pending_token,
        sid_authn::generate_current_totp(&seed),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
}

/// A VerifyTotp from the sign-in page carrying `cookie` and `csrf`.
fn browser_verify(code: String, cookie: &str, csrf: Option<&str>) -> Request<VerifyTotpRequest> {
    let mut request = Request::new(VerifyTotpRequest { code });
    let metadata = request.metadata_mut();
    metadata.insert("origin", SIGN_IN_ORIGIN.parse().unwrap());
    metadata.insert("cookie", cookie.parse().unwrap());
    if let Some(csrf) = csrf {
        metadata.insert("x-csrf-token", csrf.parse().unwrap());
    }
    request
}

/// The `name=value` of the cookie `response` sets.
fn cookie_of<T>(response: &Response<T>) -> String {
    response
        .metadata()
        .get("set-cookie")
        .expect("a cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// The sign-in page completes the pending context with its cookie and the
/// CSRF token it was given, and gets a new session cookie; without the
/// token, or from another origin, it completes nothing.
#[tokio::test]
async fn the_sign_in_page_completes_it_with_its_cookie_and_csrf() {
    let seed = sid_authn::generate_secret();
    let (svc, _policy, profile) = services(Some(&seed)).await;
    let finish = start_login(&svc, PRINCIPAL, PASSWORD).await;
    let first = common::opaque_client::finish_with_origins(&svc, finish, &[SIGN_IN_ORIGIN])
        .await
        .expect("pending context");
    let pending_cookie = cookie_of(&first);
    let body = first.into_inner();
    assert_eq!(body.second_factors, [StepUpMethod::Totp as i32]);
    let csrf = body
        .browser_csrf
        .expect("the CSRF token of the continuation");

    let code = sid_authn::generate_current_totp(&seed);
    let refused = svc
        .auth
        .verify_totp(browser_verify(code.clone(), &pending_cookie, None))
        .await
        .unwrap_err();
    assert_eq!(reason(&refused).as_deref(), Some("CSRF_TOKEN_INVALID"));
    let mut elsewhere = browser_verify(code.clone(), &pending_cookie, Some(&csrf));
    elsewhere
        .metadata_mut()
        .insert("origin", "https://evil.example.com".parse().unwrap());
    assert!(svc.auth.verify_totp(elsewhere).await.is_err());

    let completed = svc
        .auth
        .verify_totp(browser_verify(code, &pending_cookie, Some(&csrf)))
        .await
        .expect("completed with the cookie");
    assert!(completed.metadata().get("authorization").is_none());
    let session_cookie = cookie_of(&completed);
    assert_ne!(session_cookie, pending_cookie);
    let secret = BrowserCookie::default()
        .secret([session_cookie.as_str()])
        .unwrap();
    let session = svc
        .storage
        .get_session_by_browser_secret(&secret.hash())
        .await
        .unwrap()
        .expect("the new cookie names the session");
    assert!(!session.is_provisional);
    assert!(session.amr.iter().any(|m| m == "otp"));
    assert_eq!(svc.mock_storage.sessions_of(profile), 1);
}
