use std::net::{IpAddr, Ipv4Addr};

use sid_authn::captcha::CaptchaSubject;

use super::*;
use crate::test_support::{sign_in, storage};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

/// A nonce the test provider (difficulty 4) accepts for `challenge_id`.
async fn solution(sign_in: &SignIn, challenge_id: &str) -> String {
    for nonce in 0u32.. {
        let nonce = nonce.to_string();
        if sign_in
            .captcha_provider()
            .verify(challenge_id, &nonce, None)
            .await
            .is_ok()
        {
            return nonce;
        }
    }
    unreachable!("a difficulty-4 proof of work has a solution")
}

// A challenge a sign-in was asked, solved, earns one pass; the same solution
// a second time earns nothing.
#[tokio::test]
async fn a_solved_challenge_earns_one_pass() {
    let sign_in = sign_in(storage().await);
    let challenge = sign_in.captcha_provider().create_challenge();
    sign_in
        .captcha_gate()
        .asked(
            &challenge.challenge_id,
            &CaptchaSubject {
                account: "account".to_string(),
                client_ip: Some(CLIENT_IP),
            },
        )
        .await
        .unwrap();
    let nonce = solution(&sign_in, &challenge.challenge_id).await;

    let pass = sign_in
        .solve_captcha(&challenge.challenge_id, &nonce, Some(CLIENT_IP))
        .await
        .unwrap();
    assert!(!pass.is_empty());

    let again = sign_in
        .solve_captcha(&challenge.challenge_id, &nonce, Some(CLIENT_IP))
        .await;
    assert!(matches!(again, Err(CaptchaSolveError::Expired)));
}

// A valid solution of a challenge no sign-in was asked earns no pass.
#[tokio::test]
async fn a_challenge_nobody_was_asked_earns_nothing() {
    let sign_in = sign_in(storage().await);
    let challenge = sign_in.captcha_provider().create_challenge();
    let nonce = solution(&sign_in, &challenge.challenge_id).await;

    let refused = sign_in
        .solve_captcha(&challenge.challenge_id, &nonce, Some(CLIENT_IP))
        .await;

    assert!(matches!(refused, Err(CaptchaSolveError::Expired)));
}

// A challenge this installation did not sign is a rejected solution.
#[tokio::test]
async fn a_forged_challenge_is_rejected() {
    let sign_in = sign_in(storage().await);

    let refused = sign_in
        .solve_captcha("forged:4:9999999999:00", "0", Some(CLIENT_IP))
        .await;

    assert!(matches!(refused, Err(CaptchaSolveError::Rejected)));
}
