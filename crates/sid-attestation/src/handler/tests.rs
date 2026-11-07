use super::*;
use sid_core::models::DeviceId;

/// A malformed identifier names its field and never repeats the value.
#[test]
fn test_invalid_id_names_the_field_only() {
    let err = refusal(
        DeviceKeyError::InvalidField {
            field: "device_id",
            reason: "not an identifier of its kind".into(),
        },
        None,
    );
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
    let err = refusal(DeviceKeyError::Access(status), None);
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert_eq!(err.message(), "decided by the issuer");
}

/// A device the caller may not reach is DEVICE_NOT_FOUND, as an unknown one.
#[test]
fn test_unreachable_device_is_not_found() {
    let err = refusal(DeviceKeyError::DeviceNotFound(DeviceId::generate()), None);
    assert_eq!(err.code(), tonic::Code::NotFound);
}

/// A proof that proves nothing is a failed authentication, naming no
/// binding it missed.
#[test]
fn test_a_failed_proof_is_a_failed_authentication() {
    let err = refusal(
        DeviceKeyError::Proof(sid_authn::device_key_proof::DeviceKeyProofError::Mismatch(
            "chl",
        )),
        None,
    );
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(!err.message().contains("chl"));
}

/// A keyed call without its operation context answers with the context's
/// own refusal.
#[test]
fn test_a_missing_context_answers_its_refusal() {
    let context = Status::invalid_argument("the operation key is missing");
    let err = refusal(DeviceKeyError::ContextRequired, Some(context));
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "the operation key is missing");
}

/// An expired and a superseded ceremony both ask the client to start again.
#[test]
fn test_a_ceremony_that_cannot_finish_is_started_again() {
    for e in [DeviceKeyError::CeremonyExpired, DeviceKeyError::Changed] {
        let err = refusal(e, None);
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}
