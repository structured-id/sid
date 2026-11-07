use super::*;
use sid_core::models::ProfileId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Security refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            SecurityError::ProfileNotFound(ProfileId::generate()),
            Code::NotFound,
            "PROFILE_NOT_FOUND",
        ),
        (
            SecurityError::ClientNotFound("client".into()),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            SecurityError::MissingField("client_id"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            SecurityError::InvalidField {
                field: "cidr",
                reason: "not an IP address or CIDR block".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (SecurityError::Internal, Code::Internal, "INTERNAL_ERROR"),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
