use super::*;
use sid::authorization::AuthorizationError;
use sid_core::models::{AccessRequestId, ProfileId};
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Governance refusals answer with the code and reason clients branch on.
#[test]
fn governance_refusals_keep_their_status() {
    let request = AccessRequestId::generate();
    for (refused, code, expected) in [
        (
            AuthorizationError::ProfileNotFound(ProfileId::generate()),
            Code::NotFound,
            "PROFILE_NOT_FOUND",
        ),
        (
            AuthorizationError::AccessRequestNotFound(request),
            Code::NotFound,
            "ACCESS_REQUEST_NOT_FOUND",
        ),
        (
            AuthorizationError::AlreadyDecided(request),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            AuthorizationError::RequestedRoleDeleted("reader".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
