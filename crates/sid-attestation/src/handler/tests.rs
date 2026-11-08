use super::*;
use sid_core::models::DeviceId;

/// A malformed identifier names its field and never repeats the value.
#[test]
fn test_invalid_id_names_the_field_only() {
    let err = refusal(DeviceKeyError::InvalidId("device_id"));
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let violation = tonic_types::StatusExt::get_details_bad_request(&err)
        .and_then(|b| b.field_violations.into_iter().next())
        .expect("field violation");
    assert_eq!(violation.field, "device_id");
}

/// The access's own refusal reaches the caller unchanged.
#[test]
fn test_access_refusal_passes_through() {
    let status = Status::permission_denied("decided by the issuer");
    let err = refusal(DeviceKeyError::Access(status));
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert_eq!(err.message(), "decided by the issuer");
}

/// A device the caller may not reach is DEVICE_NOT_FOUND, as an unknown one.
#[test]
fn test_unreachable_device_is_not_found() {
    let err = refusal(DeviceKeyError::DeviceNotFound(DeviceId::generate()));
    assert_eq!(err.code(), tonic::Code::NotFound);
}
