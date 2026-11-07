use super::*;
use sid_core::models::{CredentialId, DeviceId, PrincipalId, ProfileId};
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

/// Every Profile management refusal answers with the code and reason
/// clients branch on; moving the operations into the library changed none of
/// them.
#[test]
fn refusals_keep_their_status() {
    use IdentityError as E;
    let owner = ProfileId::generate();
    let credential = CredentialId(uuid::Uuid::now_v7());
    for (refused, code, expected) in [
        (
            E::ProfileNotFound("username".into()),
            Code::NotFound,
            "PROFILE_NOT_FOUND",
        ),
        (
            E::CredentialNotFound(credential),
            Code::NotFound,
            "CREDENTIAL_NOT_FOUND",
        ),
        (
            E::DeviceNotFound(DeviceId::generate()),
            Code::NotFound,
            "DEVICE_NOT_FOUND",
        ),
        (
            E::PrincipalNotFound(PrincipalId(uuid::Uuid::now_v7())),
            Code::NotFound,
            "PRINCIPAL_NOT_FOUND",
        ),
        (
            E::Taken(PrincipalType::Username),
            Code::AlreadyExists,
            "USERNAME_ALREADY_TAKEN",
        ),
        (
            E::Taken(PrincipalType::Email),
            Code::AlreadyExists,
            "EMAIL_ALREADY_REGISTERED",
        ),
        (
            E::Taken(PrincipalType::Phone),
            Code::AlreadyExists,
            "PHONE_ALREADY_REGISTERED",
        ),
        (
            E::SignupHandleRequired,
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            E::LastPrimary(credential),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::AddressUnconfirmed,
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::AccountState {
                record: AccountRecord::Closure,
                owner,
                why: "closing".into(),
            },
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::AccountRecordNotFound {
                record: AccountRecord::Closure,
                owner,
            },
            Code::NotFound,
            "CLOSURE_REQUEST_NOT_FOUND",
        ),
        (
            E::AccountRecordNotFound {
                record: AccountRecord::Export,
                owner,
            },
            Code::NotFound,
            "EXPORT_NOT_FOUND",
        ),
        (
            E::TrustedDeviceLimit,
            Code::ResourceExhausted,
            "QUOTA_EXCEEDED",
        ),
        (E::CancelLimit, Code::ResourceExhausted, "QUOTA_EXCEEDED"),
        (
            E::OtherProfileDevices,
            Code::PermissionDenied,
            "INSUFFICIENT_PERMISSIONS",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected);
    }
}

/// A new account without any handle names all three fields it could have
/// given.
#[test]
fn a_missing_signup_handle_names_each_field() {
    let status = refusal(IdentityError::SignupHandleRequired);
    let fields: Vec<_> = tonic_types::StatusExt::get_details_bad_request(&status)
        .expect("a BadRequest detail")
        .field_violations
        .into_iter()
        .map(|v| v.field)
        .collect();
    assert_eq!(fields, ["username", "email", "phone"]);
}

/// A deferring operation answers its missing context with the context's own
/// refusal, and any other refusal as itself.
#[test]
fn a_deferred_context_answers_with_its_own_refusal() {
    let context_refusal = || Status::invalid_argument("idempotency-key: required");
    let refused =
        deferred::<()>(Err(IdentityError::ContextRequired), Some(context_refusal())).unwrap_err();
    assert_eq!(refused.message(), "idempotency-key: required");

    let other = deferred::<()>(
        Err(IdentityError::OtherProfileDevices),
        Some(context_refusal()),
    )
    .unwrap_err();
    assert_eq!(reason(&other), "INSUFFICIENT_PERMISSIONS");
}

/// The last way to sign in is refused for every caller of the decision, the
/// sign-in ceremonies included.
#[test]
fn the_last_primary_credential_is_refused() {
    let id = CredentialId(uuid::Uuid::now_v7());
    let refused =
        sid::identity::last_primary(sid_core::models::CredentialRevocation::LastPrimary, id)
            .map_err(refusal)
            .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert!(
        sid::identity::last_primary(sid_core::models::CredentialRevocation::Revoked, id).is_ok()
    );
}
