// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use tonic::Code;

use super::*;
use crate::grpc_error::{extract_error_info, extract_retry_delay};

fn reason(status: &tonic::Status) -> String {
    extract_error_info(status).expect("ErrorInfo is set").0
}

/// One answer for every failed credential: the code and reason say nothing
/// about the cause.
#[test]
fn authentication_failed_is_one_answer() {
    let status = authentication_failed();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(reason(&status), "AUTHENTICATION_FAILED");
}

/// An expired ceremony asks the client to start it again.
#[test]
fn expired_ceremony_is_invalid_state() {
    let status = ceremony_expired("sign-in");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(reason(&status), "INVALID_STATE");
    assert!(status.message().contains("sign-in"), "{}", status.message());
}

/// A lockout names when to retry.
#[test]
fn lockout_carries_retry_info() {
    let status = too_many_attempts(Duration::from_secs(900));
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(reason(&status), "RATE_LIMIT_EXCEEDED");
    assert_eq!(extract_retry_delay(&status), Some(Duration::from_secs(900)));
}

/// Unreadable anomaly state refuses the sign-in for a short retry, never
/// lets it through uncounted.
#[test]
fn unreadable_anomaly_state_is_unavailable() {
    let status = anomaly_unavailable("cache down");
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(reason(&status), "DEPENDENCY_UNAVAILABLE");
    assert_eq!(extract_retry_delay(&status), Some(Duration::from_secs(5)));
    assert!(!status.message().contains("cache down"));
}

/// Each engine outcome is answered as its refusal.
#[test]
fn engine_errors_map_to_their_refusals() {
    let failed = PasswordSignInError::AuthenticationFailed.into_status();
    assert_eq!(reason(&failed), "AUTHENTICATION_FAILED");
    let expired = PasswordSignInError::Expired.into_status();
    assert_eq!(reason(&expired), "INVALID_STATE");
    let migrate = PasswordSignInError::MigrationRequired.into_status();
    assert_eq!(migrate.code(), Code::FailedPrecondition);
    assert_eq!(reason(&migrate), "LEGACY_MIGRATION_REQUIRED");
    let storage =
        PasswordSignInError::Storage(sid_core::Error::Storage("down".into())).into_status();
    assert_ne!(reason(&storage), "AUTHENTICATION_FAILED");
    let state = PasswordSignInError::State(ChallengeStoreError::Encoding(
        serde_json::from_str::<u8>("x").unwrap_err(),
    ))
    .into_status();
    assert_ne!(reason(&state), "AUTHENTICATION_FAILED");
}
