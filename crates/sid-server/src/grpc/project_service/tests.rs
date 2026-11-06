//! Each refusal of a project operation keeps the status the service has
//! always answered with: its code, its `ErrorInfo` reason and the details a
//! client acts on.

use super::*;
use sid_core::grpc_error::extract_error_info;
use sid_core::models::{
    ApplicationId, InitialAccessTokenId, ProjectId, ResourceId, ResourceIndicator, RoleId,
};
use tonic::Code;
use tonic_types::StatusExt;

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

#[test]
fn refusals_keep_their_code_and_reason() {
    let app = ApplicationId::generate();
    let resource = ResourceId::generate();
    let cases: Vec<(ProjectError, Code, &str)> = vec![
        (ProjectError::Internal, Code::Internal, "INTERNAL_ERROR"),
        (
            ProjectError::MissingField("name"),
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            ProjectError::InvalidField {
                field: "scopes",
                reason: "not a scope".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            ProjectError::Metadata {
                field: "jwks",
                message: "not a key set".into(),
            },
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            ProjectError::ProjectNotFound(ProjectId::generate()),
            Code::NotFound,
            "PROJECT_NOT_FOUND",
        ),
        (
            ProjectError::ApplicationNotFound(app),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            ProjectError::ClientNotFound("sid_a".into()),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            ProjectError::ClientGone("sid_a".into()),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            ProjectError::RequesterNotFound("sid_a".into()),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            ProjectError::ResourceNotFound(resource),
            Code::NotFound,
            "RESOURCE_NOT_FOUND",
        ),
        (
            ProjectError::RoleNotFound(RoleId::generate()),
            Code::NotFound,
            "ROLE_NOT_FOUND",
        ),
        (
            ProjectError::IatNotFound(InitialAccessTokenId::generate()),
            Code::NotFound,
            "INITIAL_ACCESS_TOKEN_NOT_FOUND",
        ),
        (
            ProjectError::IssuerNotFound("acme".into()),
            Code::NotFound,
            "OIDC_ISSUER_NOT_FOUND",
        ),
        (
            ProjectError::ProjectInUse(ProjectId::generate()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProjectError::SystemProject("delete"),
            Code::FailedPrecondition,
            "SYSTEM_MANAGED",
        ),
        (
            ProjectError::SystemManaged {
                application: app,
                what: "it cannot be deleted",
            },
            Code::FailedPrecondition,
            "SYSTEM_MANAGED",
        ),
        (
            ProjectError::RoleExists {
                application: app,
                role: "client",
            },
            Code::AlreadyExists,
            "APPLICATION_ROLE_EXISTS",
        ),
        (
            ProjectError::IndicatorTaken(
                ResourceIndicator::parse("https://resources.example/orders").unwrap(),
            ),
            Code::AlreadyExists,
            "RESOURCE_INDICATOR_TAKEN",
        ),
        (
            ProjectError::ResourceRetired(resource),
            Code::FailedPrecondition,
            "RESOURCE_RETIRED",
        ),
        (
            ProjectError::RetireByRemoval(resource),
            Code::FailedPrecondition,
            "RESOURCE_RETIRED",
        ),
        (
            ProjectError::IssuerMismatch(resource),
            Code::FailedPrecondition,
            "ISSUER_MISMATCH",
        ),
        (
            ProjectError::RoleTaken("editor".into()),
            Code::AlreadyExists,
            "ROLE_ALREADY_EXISTS",
        ),
        (
            ProjectError::RoleRequired,
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            ProjectError::SubjectRequired,
            Code::InvalidArgument,
            "REQUIRED_FIELD_MISSING",
        ),
        (
            ProjectError::SubjectMigrationRequired("sid_a".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProjectError::IatUnusable,
            Code::Unauthenticated,
            "TOKEN_INVALID",
        ),
        (
            ProjectError::IatEnded,
            Code::Unauthenticated,
            "TOKEN_INVALID",
        ),
        (
            ProjectError::RatInvalid,
            Code::Unauthenticated,
            "TOKEN_INVALID",
        ),
        (
            ProjectError::NotRegisteredDynamically("sid_a".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProjectError::IatDeleted(InitialAccessTokenId::generate()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            ProjectError::ChangedConcurrently,
            Code::Aborted,
            "CONCURRENT_MODIFICATION",
        ),
        (
            ProjectError::Caller(sid_authn::caller::CallerError::Denied),
            Code::PermissionDenied,
            "INSUFFICIENT_PERMISSIONS",
        ),
        (
            ProjectError::Operation(sid_authn::operation::OperationError::KeyConflict),
            Code::AlreadyExists,
            "OPERATION_KEY_CONFLICT",
        ),
    ];
    for (error, code, expected) in cases {
        let status = refusal(error);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected, "{status:?}");
    }
}

/// A refusal of a field names it in a `BadRequest` violation under
/// INVALID_FIELD_VALUE, so a client can point at the input.
#[test]
fn test_invalid_field_names_the_field() {
    let status = refusal(ProjectError::InvalidField {
        field: "resource.indicator",
        reason: "not an absolute URI".into(),
    });
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(reason(&status), "INVALID_FIELD_VALUE");
    let violations = status.get_details_bad_request().expect("BadRequest");
    assert_eq!(violations.field_violations[0].field, "resource.indicator");
}

/// Refused client metadata carries its RFC 7591 §3.2.2 code and field: the
/// request's own metadata as INVALID_FIELD_VALUE, what the initial access
/// token does not allow as INSUFFICIENT_PERMISSIONS.
#[test]
fn metadata_refusals_carry_their_oauth_error() {
    let metadata = |status: &Status| {
        let (_, _, metadata) = extract_error_info(status).expect("ErrorInfo");
        (
            metadata.get("oauthError").cloned(),
            metadata.get("field").cloned(),
        )
    };
    let refused = refusal(ProjectError::Metadata {
        field: "client_secret",
        message: "client_secret does not match the issued secret".into(),
    });
    assert_eq!(
        metadata(&refused),
        (
            Some("invalid_client_metadata".into()),
            Some("client_secret".into())
        )
    );
    assert_eq!(
        refused.message(),
        "client_secret does not match the issued secret"
    );

    let error = sid_authn::dcr::DcrError::InvalidRedirectUri("x".into());
    let (oauth_error, field) = error.metadata_error().expect("a metadata error");
    for (check, expected) in [
        (RegistrationCheck::Metadata, "INVALID_FIELD_VALUE"),
        (RegistrationCheck::TokenPolicy, "INSUFFICIENT_PERMISSIONS"),
    ] {
        let status = refusal(ProjectError::Registration {
            error: sid_authn::dcr::DcrError::InvalidRedirectUri("x".into()),
            check,
        });
        assert_eq!(reason(&status), expected);
        assert_eq!(
            metadata(&status),
            (Some(oauth_error.into()), Some(field.into()))
        );
    }
}

/// The preconditions a client resolves by itself name what to do.
#[test]
fn preconditions_name_what_failed() {
    let precondition = |error: ProjectError| {
        let status = refusal(error);
        let failure = status
            .get_details_precondition_failure()
            .expect("PreconditionFailure");
        let violation = failure.violations.into_iter().next().expect("a violation");
        (violation.r#type, violation.subject)
    };
    let project = ProjectId::generate();
    assert_eq!(
        precondition(ProjectError::ProjectInUse(project)),
        ("PROJECT_IN_USE".into(), project.to_string())
    );
    let resource = ResourceId::generate();
    assert_eq!(
        precondition(ProjectError::ResourceRetired(resource)),
        ("RESOURCE_STATE".into(), resource.to_string())
    );
    assert_eq!(
        precondition(ProjectError::RetireByRemoval(resource)),
        ("APPLICATION_REMOVED".into(), resource.to_string())
    );
    assert_eq!(
        precondition(ProjectError::IssuerMismatch(resource)),
        ("SAME_ISSUER".into(), resource.to_string())
    );
    assert_eq!(
        precondition(ProjectError::SubjectMigrationRequired("sid_a".into())),
        ("SUBJECT_TYPE".into(), "sid_a".into())
    );
}
