use super::*;
use sid_core::models::profile_email::ProfileEmailId;
use sid_core::models::profile_phone::ProfilePhoneId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Account refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            AccountError::ConsentNotFound("site".into()),
            Code::NotFound,
            "CONSENT_NOT_FOUND",
        ),
        (
            AccountError::ConsentInactive("site".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            AccountError::PhoneNotFound(ProfilePhoneId::new()),
            Code::NotFound,
            "PHONE_NOT_FOUND",
        ),
        (
            AccountError::EmailNotFound(ProfileEmailId::new()),
            Code::NotFound,
            "EMAIL_NOT_FOUND",
        ),
        (
            AccountError::MissingField("site_id"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            AccountError::InvalidField {
                field: "email",
                reason: "not a mailbox".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (AccountError::Internal, Code::Internal, "INTERNAL_ERROR"),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
}
