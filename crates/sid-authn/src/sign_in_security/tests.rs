// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn accepted(assurance_level: AuthLevel, amr: &[&str]) -> SessionAuthentication {
    SessionAuthentication {
        assurance_level,
        elevation: None,
        authenticated_at: chrono::Utc::now(),
        amr: amr.iter().map(|m| (*m).to_owned()).collect(),
    }
}

/// An issuer's accepted second factor is the stronger sign-in an anomaly rule
/// asks for: asking again would never end.
#[test]
fn accepted_evidence_at_the_multi_factor_level_answers_a_step_up() {
    for level in [
        AuthLevel::Standard,
        AuthLevel::Elevated,
        AuthLevel::Critical,
    ] {
        let evidence = accepted(level, &["pwd", "otp"]);
        assert!(AttemptAuthentication::Accepted(&evidence).answers_step_up());
    }
}

/// Evidence of one factor answers nothing, whatever methods it names: the
/// level is what the issuer attests.
#[test]
fn accepted_evidence_below_it_does_not() {
    let evidence = accepted(AuthLevel::Basic, &["pwd", "mfa"]);
    assert!(!AttemptAuthentication::Accepted(&evidence).answers_step_up());
}

/// A local sign-in answers a step-up with the second factor it then owes, not
/// with what it claims at the password.
#[test]
fn a_local_sign_in_does_not_answer_a_step_up() {
    let amr = vec!["pwd".to_owned()];
    let local = AttemptAuthentication::Local {
        method: "opaque",
        assurance: AuthLevel::Standard,
        amr: &amr,
    };
    assert!(!local.answers_step_up());
}
