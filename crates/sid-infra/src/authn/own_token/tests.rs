// SPDX-License-Identifier: AGPL-3.0-only
//! A refused own token keeps the status services answered with: one
//! TOKEN_INVALID for every failed check, and a storage failure that tells
//! nothing about its cause.

use tonic::Code;

use super::*;
use crate::grpc_error::extract_error_info;

#[test]
fn refusals_keep_their_status() {
    let refused = OwnTokenError::Unauthenticated.into_status();
    assert_eq!(refused.code(), Code::Unauthenticated);
    assert_eq!(extract_error_info(&refused).unwrap().0, "TOKEN_INVALID");

    let failed = OwnTokenError::Storage(sid_core::Error::Storage("down".into())).into_status();
    assert_eq!(failed.code(), Code::Internal);
    assert!(!failed.message().contains("down"), "{failed:?}");
}
