// SPDX-License-Identifier: AGPL-3.0-only
//! Each caller refusal keeps the status the services have always answered
//! with. How a request's bearer reaches the verifier is tested end to end in
//! `tests/caller_verifier.rs`.

use tonic::Code;

use super::*;
use crate::grpc_error::extract_error_info;

#[test]
fn refusals_keep_their_status() {
    let unauthenticated = CallerError::Unauthenticated.into_status();
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);
    assert_eq!(
        extract_error_info(&unauthenticated).unwrap().0,
        "TOKEN_INVALID"
    );
    let denied = CallerError::Denied.into_status();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(
        extract_error_info(&denied).unwrap().0,
        "INSUFFICIENT_PERMISSIONS"
    );
    let unavailable = CallerError::Unavailable {
        what: "token revocation state",
        detail: "down".into(),
    }
    .into_status();
    assert_eq!(unavailable.code(), Code::Unavailable);
}
