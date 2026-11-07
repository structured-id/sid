use super::*;
use sid_core::models::ProfileId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Administration refusals answer with the code and reason clients branch
/// on.
#[test]
fn refusals_keep_their_status() {
    let id = ProfileId::generate();
    for (refused, code, expected) in [
        (
            AdminError::ProfileNotFound(id),
            Code::NotFound,
            "PROFILE_NOT_FOUND",
        ),
        (
            AdminError::StatusNotChangeable(id),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            AdminError::MetadataNotFound {
                profile: id,
                key: "team".into(),
            },
            Code::NotFound,
            "PROFILE_METADATA_NOT_FOUND",
        ),
        (
            AdminError::AlreadyClaimed,
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            AdminError::ClaimMismatch,
            Code::PermissionDenied,
            "INSUFFICIENT_PERMISSIONS",
        ),
        (
            AdminError::InvalidField {
                field: "roles",
                reason: "installation administration is granted by role assignment".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (AdminError::Internal, Code::Internal, "INTERNAL_ERROR"),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
