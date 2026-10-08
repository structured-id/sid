// SPDX-License-Identifier: AGPL-3.0-only
//! A sign-in asked for a CAPTCHA goes through once the challenge is solved:
//! the pass it earns answers that sign-in's retry once, from the same client,
//! and never lifts a lockout.

mod common;

use std::net::{IpAddr, SocketAddr};

use common::TestServices;
use common::mock_storage::MockStorage;
use sha2::{Digest, Sha256};
use sid_authn::anomaly::AnomalyDetector;
use sid_authn::captcha::{CaptchaProvider, SidPowProvider};
use sid_core::models::{AuditEntry, Principal, PrincipalType, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::transport::server::TcpConnectInfo;
use tonic::{Code, Request, Status};

const ADDRESS: &str = "holder@sid.example.com";

/// A request arriving over a connection from `ip`.
fn from<T>(ip: IpAddr, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(SocketAddr::new(ip, 40000)),
    });
    request
}

/// Services with one profile holding `ADDRESS`.
async fn services() -> (TestServices, Profile) {
    let holder = Profile::new(Some("holder"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_system_project()
            .with_profile(holder.clone()),
    );
    svc.storage
        .save_principal(
            &Principal::new(holder.id, PrincipalType::Email, ADDRESS),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
    (svc, holder)
}

/// Enough attempts from `ip` that its next sign-in needs a CAPTCHA.
async fn crowd(svc: &TestServices, ip: IpAddr) {
    let detector = AnomalyDetector::ce_default(svc.cache.clone());
    for _ in 0..10 {
        detector.record_ip_attempt(ip).await.unwrap();
    }
}

/// Sign in with a fresh one-time code from `ip`, carrying `pass` if given.
async fn sign_in(
    svc: &TestServices,
    ip: IpAddr,
    pass: Option<&str>,
) -> Result<VerifyOtpResponse, Status> {
    let (pending, code) = sid_authn::otp::OtpService::new(svc.cache.clone())
        .request_otp(ADDRESS)
        .await
        .unwrap();
    let mut request = from(
        ip,
        VerifyOtpRequest {
            code,
            session_id: Some(pending.session_id.to_string()),
        },
    );
    if let Some(pass) = pass {
        request
            .metadata_mut()
            .insert("captcha-pass", pass.parse().unwrap());
    }
    svc.auth.verify_otp(request).await.map(|r| r.into_inner())
}

/// The challenge identifier a refused sign-in carries: reason
/// CAPTCHA_REQUIRED and the challenge as a typed `CaptchaChallenge` detail,
/// never in the status message.
fn challenge_of(refusal: &Status) -> String {
    assert_eq!(refusal.code(), Code::FailedPrecondition, "{refusal:?}");
    let (reason, _, _) =
        sid_core::grpc_error::extract_error_info(refusal).expect("ErrorInfo detail");
    assert_eq!(reason, "CAPTCHA_REQUIRED", "{refusal:?}");
    assert!(
        !refusal.message().contains("challenge_id"),
        "the challenge travels as a detail, not in the message: {refusal:?}"
    );
    let rpc_status =
        <tonic_types::Status as prost::Message>::decode(refusal.details()).expect("status");
    let detail = rpc_status
        .details
        .iter()
        .find(|d| d.type_url == "type.googleapis.com/sid.v1.common.CaptchaChallenge")
        .unwrap_or_else(|| panic!("no CaptchaChallenge detail: {refusal:?}"));
    let challenge =
        <sid_proto::sid::v1::CaptchaChallenge as prost::Message>::decode(detail.value.as_slice())
            .expect("CaptchaChallenge");
    assert_eq!(challenge.kind, CaptchaKind::SidPow as i32);
    assert!(challenge.difficulty > 0);
    challenge.challenge_id
}

/// A nonce meeting the 4-bit proof of work of `challenge_id`.
fn solve(challenge_id: &str) -> String {
    let prefix = challenge_id.split(':').next().unwrap();
    (0u64..)
        .map(|n| n.to_string())
        .find(|nonce| Sha256::digest(format!("{prefix}{nonce}").as_bytes())[0] & 0xF0 == 0)
        .unwrap()
}

/// Solve the challenge `challenge_id` from `ip` and return the pass it earns.
async fn earn_pass(svc: &TestServices, ip: IpAddr, challenge_id: &str) -> Result<String, Status> {
    svc.auth
        .verify_captcha(from(
            ip,
            VerifyCaptchaRequest {
                challenge_id: challenge_id.to_owned(),
                token: solve(challenge_id),
            },
        ))
        .await
        .map(|r| r.into_inner().bypass_token)
}

/// Asked for a CAPTCHA, solve it and retry with the pass: the sign-in goes
/// through. No sign-in path used to accept the pass, so a user asked for a
/// CAPTCHA could never sign in.
#[tokio::test]
async fn solved_captcha_lets_the_sign_in_through() {
    let (svc, holder) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    crowd(&svc, ip).await;

    let challenge = challenge_of(&sign_in(&svc, ip, None).await.unwrap_err());
    let pass = earn_pass(&svc, ip, &challenge).await.unwrap();
    let signed_in = sign_in(&svc, ip, Some(&pass)).await.unwrap();

    assert!(signed_in.verified);
    let sessions = svc
        .storage
        .list_sessions_by_profile(holder.id)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
}

/// A pass answers one sign-in: the next one needs a new CAPTCHA.
#[tokio::test]
async fn pass_is_single_use() {
    let (svc, _) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    crowd(&svc, ip).await;

    let challenge = challenge_of(&sign_in(&svc, ip, None).await.unwrap_err());
    let pass = earn_pass(&svc, ip, &challenge).await.unwrap();
    sign_in(&svc, ip, Some(&pass)).await.unwrap();

    challenge_of(&sign_in(&svc, ip, Some(&pass)).await.unwrap_err());
}

/// A pass earned from one client does not answer a sign-in from another.
/// The old pass was bound to nothing and worked from anywhere.
#[tokio::test]
async fn pass_does_not_travel_to_another_client() {
    let (svc, _) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    let elsewhere: IpAddr = "203.0.113.9".parse().unwrap();
    crowd(&svc, ip).await;
    crowd(&svc, elsewhere).await;

    let challenge = challenge_of(&sign_in(&svc, ip, None).await.unwrap_err());
    let pass = earn_pass(&svc, ip, &challenge).await.unwrap();

    challenge_of(&sign_in(&svc, elsewhere, Some(&pass)).await.unwrap_err());
}

/// A solved CAPTCHA does not lift a lockout: the old pass skipped every
/// anomaly rule, the lockout included.
#[tokio::test]
async fn pass_does_not_lift_a_lockout() {
    let (svc, holder) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    crowd(&svc, ip).await;
    let challenge = challenge_of(&sign_in(&svc, ip, None).await.unwrap_err());
    let pass = earn_pass(&svc, ip, &challenge).await.unwrap();

    let detector = AnomalyDetector::ce_default(svc.cache.clone());
    for _ in 0..5 {
        detector
            .record_failed_attempt(&holder.id.to_string())
            .await
            .unwrap();
    }

    let refusal = sign_in(&svc, ip, Some(&pass)).await.unwrap_err();
    assert_eq!(refusal.code(), Code::ResourceExhausted, "{refusal:?}");
    // The lockout names its limit and how long it lasts at most.
    use tonic_types::StatusExt;
    let details = refusal.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "RATE_LIMIT_EXCEEDED");
    assert_eq!(
        details.quota_failure().unwrap().violations[0].subject,
        "sign_in_attempts"
    );
    assert_eq!(
        details.retry_info().unwrap().retry_delay,
        Some(std::time::Duration::from_secs(900))
    );
}

/// One solution earns one pass: the same solved challenge is refused the
/// second time, though the proof of work itself is still within its TTL.
#[tokio::test]
async fn solution_counts_once() {
    let (svc, _) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    crowd(&svc, ip).await;
    let challenge = challenge_of(&sign_in(&svc, ip, None).await.unwrap_err());

    earn_pass(&svc, ip, &challenge).await.unwrap();
    let refusal = earn_pass(&svc, ip, &challenge).await.unwrap_err();
    assert_spent_challenge(&refusal);
}

/// A challenge that earns no pass is a spent ceremony: the client asks for
/// a new one (INVALID_STATE), the solution is not malformed.
fn assert_spent_challenge(refusal: &Status) {
    use tonic_types::StatusExt;
    assert_eq!(refusal.code(), Code::FailedPrecondition, "{refusal:?}");
    let details = refusal.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "CEREMONY_STATE");
    assert_eq!(violation.subject, "CAPTCHA");
}

/// A challenge no sign-in was asked, even one validly signed by this
/// deployment, earns no pass.
#[tokio::test]
async fn unasked_challenge_earns_nothing() {
    let (svc, _) = services().await;
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    let challenge = SidPowProvider::new([0u8; 32], 4, 300).create_challenge();

    let refusal = earn_pass(&svc, ip, &challenge.challenge_id)
        .await
        .unwrap_err();
    assert_spent_challenge(&refusal);
}
