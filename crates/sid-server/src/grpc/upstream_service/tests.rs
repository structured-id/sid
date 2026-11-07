use super::*;
use sid_core::models::UpstreamProviderId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Upstream provider refusals answer with the code and reason clients
/// branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            UpstreamError::NotFound(UpstreamProviderId::generate()),
            Code::NotFound,
            "UPSTREAM_PROVIDER_NOT_FOUND",
        ),
        (
            UpstreamError::NameTaken("Example".into()),
            Code::AlreadyExists,
            "UPSTREAM_PROVIDER_ALREADY_EXISTS",
        ),
        (
            UpstreamError::Disabled(UpstreamProviderId::generate()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            UpstreamError::MissingField("client_secret"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (UpstreamError::Internal, Code::Internal, "INTERNAL_ERROR"),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
