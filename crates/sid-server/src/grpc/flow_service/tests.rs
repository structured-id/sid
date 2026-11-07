use super::*;
use sid_core::models::FlowActionId;
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

/// Flow refusals answer with the code and reason clients branch on.
#[test]
fn refusals_keep_their_status() {
    for (refused, code, expected) in [
        (
            FlowError::ConfigNotFound("project:authentication".into()),
            Code::NotFound,
            "FLOW_CONFIG_NOT_FOUND",
        ),
        (
            FlowError::ActionNotFound(FlowActionId::generate()),
            Code::NotFound,
            "FLOW_ACTION_NOT_FOUND",
        ),
        (
            FlowError::MissingField("config"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            FlowError::InvalidField {
                field: "on_error",
                reason: "not an on-error policy".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(extract_error_info(&status).expect("ErrorInfo").0, expected);
    }
    let concurrent = refusal(FlowError::ChangedConcurrently);
    let expected = changed_concurrently();
    assert_eq!(concurrent.code(), expected.code());
}
