//! Each refusal of a machine operation keeps the status the service has
//! always answered with: its code and its `ErrorInfo` reason.

use super::*;
use sid_core::models::MachineUserId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

#[test]
fn refusals_keep_their_status() {
    let id = MachineUserId::generate();
    let cases: [(MachineError, Code, &str); 8] = [
        (
            MachineError::NotFound(id),
            Code::NotFound,
            "MACHINE_USER_NOT_FOUND",
        ),
        (
            MachineError::CredentialNotFound("kid_a".into()),
            Code::NotFound,
            "CREDENTIAL_NOT_FOUND",
        ),
        (
            MachineError::MachineState {
                id,
                state: "deleted",
                change: "suspended",
            },
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            MachineError::CredentialState {
                kid: "kid_a".into(),
                state: "revoked",
            },
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            MachineError::CredentialLimit(id),
            Code::ResourceExhausted,
            "QUOTA_EXCEEDED",
        ),
        (
            MachineError::MissingField("kid"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            MachineError::Caller(sid_authn::caller::CallerError::Denied),
            Code::PermissionDenied,
            "INSUFFICIENT_PERMISSIONS",
        ),
        (
            MachineError::Operation(sid_authn::operation::OperationError::KeyConflict),
            Code::AlreadyExists,
            "OPERATION_KEY_CONFLICT",
        ),
    ];
    for (error, code, expected) in cases {
        let status = refusal(error);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected, "{status:?}");
    }
    let state = refusal(MachineError::MachineState {
        id,
        state: "deleted",
        change: "suspended",
    });
    assert_eq!(
        state.message(),
        "a deleted machine user cannot be suspended"
    );
}
