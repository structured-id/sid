use super::*;
use sid::enrollment::Refusal;
use sid_core::models::InviteId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Enrollment refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            EnrollmentError::ModePinned(Refusal::Pinned(EnrollmentMode::AdminOnly)),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            EnrollmentError::InviteNotFound(InviteId::generate()),
            Code::NotFound,
            "INVITE_NOT_FOUND",
        ),
        (
            EnrollmentError::MissingField("count"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            EnrollmentError::InvalidField {
                field: "page_token",
                reason: "not a token this service issued".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (EnrollmentError::Internal, Code::Internal, "INTERNAL_ERROR"),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
