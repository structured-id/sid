use super::*;
use sid_core::models::BrandingConfigId;
use tonic_types::StatusExt;

/// An unknown config is BRANDING_NOT_FOUND; a config that is not a draft, or
/// a published one being deleted, is INVALID_STATE naming its status.
#[test]
fn test_branding_refusals_carry_their_reason() {
    let id = BrandingConfigId::generate();
    let missing = refusal(BrandingError::NotFound(id.to_string()));
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(
        missing.get_details_error_info().unwrap().reason,
        "BRANDING_NOT_FOUND"
    );
    for refused in [BrandingError::NotADraft(id), BrandingError::Published(id)] {
        let status = refusal(refused);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status.get_details_error_info().unwrap().reason,
            "INVALID_STATE"
        );
        assert_eq!(
            status
                .get_details_precondition_failure()
                .unwrap()
                .violations[0]
                .r#type,
            "BRANDING_STATUS"
        );
    }
    let unreadable = refusal(BrandingError::InvalidField {
        field: "pairs",
        reason: "a color is not #rgb or #rrggbb".into(),
    });
    assert_eq!(unreadable.code(), tonic::Code::InvalidArgument);
    let violation = unreadable
        .get_details_bad_request()
        .and_then(|b| b.field_violations.into_iter().next())
        .expect("field violation");
    assert_eq!(violation.field, "pairs");
}
