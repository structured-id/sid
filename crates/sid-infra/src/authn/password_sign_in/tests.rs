use super::*;

use crate::grpc_error::extract_error_info;

/// A host's sign-in refusal answers with the status the core's refusal
/// maps to, so a wrong password reads the same from every host.
#[test]
fn a_core_refusal_keeps_its_status() {
    let refused: Status = SignInStatus::from(PasswordSignInError::AuthenticationFailed).into();
    let expected = PasswordSignInError::AuthenticationFailed.into_status();
    assert_eq!(refused.code(), expected.code());
    assert_eq!(
        extract_error_info(&refused).map(|(reason, ..)| reason),
        extract_error_info(&expected).map(|(reason, ..)| reason),
    );
}

/// A status the host gives itself passes through unchanged.
#[test]
fn a_host_status_passes_through() {
    let refused: Status = SignInStatus::from(Status::unavailable("store")).into();
    assert_eq!(refused.code(), tonic::Code::Unavailable);
    assert_eq!(refused.message(), "store");
}

/// An absent or malformed login id is refused on its field before any
/// lookup.
#[test]
fn a_login_id_is_required_and_well_formed() {
    let absent = login_id(None).unwrap_err();
    assert_eq!(absent.code(), tonic::Code::InvalidArgument);
    let nil = sid_ids_proto::OpaqueLoginId { value: vec![0; 16] };
    assert_eq!(
        login_id(Some(&nil)).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    let id = OpaqueLoginId::generate();
    let wire: sid_ids_proto::OpaqueLoginId = id.into();
    assert_eq!(login_id(Some(&wire)).unwrap(), id);
}
