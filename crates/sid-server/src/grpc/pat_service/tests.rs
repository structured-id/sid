use super::*;
use sid_core::models::PatId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Personal access token refusals answer with the code and reason clients
/// branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            PatError::NotFound(PatId::generate()),
            Code::NotFound,
            "CREDENTIAL_NOT_FOUND",
        ),
        (PatError::Unusable, Code::Unauthenticated, "TOKEN_INVALID"),
        (
            PatError::QuotaReached,
            Code::ResourceExhausted,
            "QUOTA_EXCEEDED",
        ),
        (
            PatError::NotResourceBound(PatId::generate()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            PatError::MissingField("token"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            PatError::InvalidField {
                field: "expires_at",
                reason: "must be in the future".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
