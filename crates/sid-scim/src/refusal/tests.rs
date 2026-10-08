use super::*;
use sid_core::grpc_error::extract_error_info;
use tonic::Code;

/// (code, reason, scimType) of a refusal.
fn shape(status: &Status) -> (Code, String, Option<String>) {
    let (reason, _, metadata) = extract_error_info(status).expect("ErrorInfo");
    (status.code(), reason, metadata.get(SCIM_TYPE).cloned())
}

/// The refusal names neither the submitted value nor anything derived from
/// it, anywhere a client reads.
fn assert_not_echoed(status: &Status, value: &str) {
    assert!(!status.message().contains(value), "{status:?}");
    let violations = tonic_types::StatusExt::get_details_bad_request(status)
        .map(|b| b.field_violations)
        .unwrap_or_default();
    for v in violations {
        assert!(!v.field.contains(value) && !v.description.contains(value));
    }
}

#[test]
fn test_required_is_invalid_value() {
    assert_eq!(
        shape(&required("userName")),
        (
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING".into(),
            Some("invalidValue".into())
        )
    );
}

#[test]
fn test_invalid_filter_is_invalid_filter() {
    assert_eq!(shape(&invalid_filter()).2.as_deref(), Some("invalidFilter"));
}

/// RFC 7644 §3.12: a refused telephone number is `invalidValue`, and the
/// number is not sent back.
#[test]
fn test_invalid_phone_is_not_echoed() {
    let status = mapping(MappingError::InvalidPhone("+1 555 0100".into()));
    assert_eq!(
        shape(&status),
        (
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE".into(),
            Some("invalidValue".into())
        )
    );
    assert_not_echoed(&status, "555 0100");
}

#[test]
fn test_patch_errors_carry_their_scim_type() {
    let cases = [
        (PatchError::UnsupportedOp("move".into()), "invalidSyntax"),
        (
            PatchError::InvalidPath(r#"emails[value eq "a@sid.example.com"]"#.into()),
            "invalidPath",
        ),
        (
            PatchError::InvalidValue {
                path: "active".into(),
                reason: "secret-value".into(),
            },
            "invalidValue",
        ),
        (PatchError::ImmutableAttribute("id".into()), "mutability"),
    ];
    for (error, scim_type) in cases {
        let status = patch(error);
        assert_eq!(shape(&status).2.as_deref(), Some(scim_type));
        assert_not_echoed(&status, "a@sid.example.com");
        assert_not_echoed(&status, "secret-value");
    }
}

#[test]
fn test_taken_user_name_is_uniqueness() {
    let status = user_write(
        ProfileId::generate(),
        SidError::Conflict("login handle".into()),
    );
    assert_eq!(
        shape(&status),
        (
            Code::AlreadyExists,
            "USERNAME_ALREADY_TAKEN".into(),
            Some("uniqueness".into())
        )
    );
}

#[test]
fn test_taken_group_name_is_uniqueness() {
    let status = group_write(
        GroupId(uuid::Uuid::now_v7()),
        SidError::Conflict("g".into()),
    );
    assert_eq!(
        shape(&status),
        (
            Code::AlreadyExists,
            "GROUP_ALREADY_EXISTS".into(),
            Some("uniqueness".into())
        )
    );
}

#[test]
fn test_missing_resources_are_typed_not_found() {
    let id = ProfileId::generate();
    assert_eq!(
        shape(&user_write(id, SidError::NotFound("p".into()))).1,
        "PROFILE_NOT_FOUND"
    );
    let gid = GroupId(uuid::Uuid::now_v7());
    assert_eq!(
        shape(&group_write(gid, SidError::NotFound("g".into()))).1,
        "GROUP_NOT_FOUND"
    );
}

/// A stale read is retried at once; a storage failure tells the client
/// nothing about its cause.
#[test]
fn test_stale_and_failed_writes() {
    let id = ProfileId::generate();
    assert_eq!(
        shape(&user_write(id, SidError::InvalidState("stale".into()))).1,
        "CONCURRENT_MODIFICATION"
    );
    let status = user_write(id, SidError::Storage("connection reset by peer".into()));
    assert_eq!(status.code(), Code::Internal);
    assert_not_echoed(&status, "connection reset");
    // A refused user write is the server's own invariant, not the client's.
    assert_eq!(
        user_write(id, SidError::Validation("rule".into())).code(),
        Code::Internal
    );
    assert_eq!(
        group_write(
            GroupId(uuid::Uuid::now_v7()),
            SidError::Validation("rule".into())
        )
        .code(),
        Code::InvalidArgument
    );
}
