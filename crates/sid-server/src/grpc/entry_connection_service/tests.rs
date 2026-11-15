// SPDX-License-Identifier: AGPL-3.0-only
//! Each refusal of an entry connection operation answers with the code and
//! `ErrorInfo` reason a client acts on.

use sid_core::models::EntryHandle;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

use super::*;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

/// Bug prevented: a client unable to tell a connection that is not there
/// from an issuer that already has one, from one it may not write, from one
/// that changed under it.
#[test]
fn refusals_have_their_code_and_reason() {
    let cases: Vec<(EntryConnectionError, Code, &str)> = vec![
        (
            EntryConnectionError::Internal,
            Code::Internal,
            "INTERNAL_ERROR",
        ),
        (
            EntryConnectionError::MissingField("client_secret"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            EntryConnectionError::InvalidField {
                field: "issuer",
                reason: "an https URL without query or fragment".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            EntryConnectionError::NotFound(EntryHandle::generate()),
            Code::NotFound,
            "ENTRY_CONNECTION_NOT_FOUND",
        ),
        (
            EntryConnectionError::UnknownIssuer("0123".into()),
            Code::NotFound,
            "OIDC_ISSUER_NOT_FOUND",
        ),
        (
            EntryConnectionError::IssuerTaken,
            Code::AlreadyExists,
            "ENTRY_CONNECTION_ALREADY_EXISTS",
        ),
        (
            EntryConnectionError::Provisioned,
            Code::FailedPrecondition,
            "SYSTEM_MANAGED",
        ),
        (
            EntryConnectionError::ChangedConcurrently,
            Code::Aborted,
            "CONCURRENT_MODIFICATION",
        ),
        (
            EntryConnectionError::Established,
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
    ];
    for (refused, code, name) in cases {
        let text = refused.to_string();
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{text}");
        assert_eq!(reason(&status), name, "{text}");
    }
}
