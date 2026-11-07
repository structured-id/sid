use super::*;
use sid_core::models::{CedarPolicyId, GroupId, ProvisioningConnectorId, Role, RoleAssignmentId};
use sid_infra::grpc_error::extract_error_info;
use tonic::Code;

// ── Request identifiers ─────────────────────────────────────────

/// Each identifier a request names becomes its domain type, the system
/// project and built-in roles included.
#[test]
fn test_wire_id_accepts_each_kind() {
    use sid_proto::sid::v1::ids as wire;
    let project = ProjectId::generate();
    assert_eq!(
        wire_id(Some(&wire::ProjectId::from(project)), "project_id").unwrap(),
        project
    );
    assert_eq!(
        wire_id(
            Some(&wire::ProjectId::from(ProjectId::SYSTEM)),
            "project_id"
        )
        .unwrap(),
        ProjectId::SYSTEM
    );
    let role = Role::token_inspector().id;
    assert_eq!(
        wire_id(Some(&wire::RoleId::from(role)), "role_id").unwrap(),
        role
    );
    let assignment = RoleAssignmentId::generate();
    assert_eq!(
        wire_id(
            Some(&wire::RoleAssignmentId::from(assignment)),
            "assignment_id"
        )
        .unwrap(),
        assignment
    );
}

/// Bug prevented: an absent or malformed identifier reaching storage as a
/// lookup key instead of being refused on its field.
#[test]
fn test_wire_id_refuses_on_its_field() {
    use sid_proto::sid::v1::ids as wire;
    let missing = wire_id::<wire::GroupId>(None, "group_id").unwrap_err();
    let short = wire_id(Some(&wire::GroupId { value: vec![1; 15] }), "group_id").unwrap_err();
    let v4 = wire::CedarPolicyId {
        value: uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .unwrap()
            .as_bytes()
            .to_vec(),
    };
    let wrong_version = wire_id(Some(&v4), "id").unwrap_err();
    for (refused, field) in [
        (missing, "group_id"),
        (short, "group_id"),
        (wrong_version, "id"),
    ] {
        assert_eq!(refused.code(), Code::InvalidArgument);
        let violations = tonic_types::StatusExt::get_details_bad_request(&refused)
            .expect("a BadRequest detail")
            .field_violations;
        assert_eq!(violations[0].field, field);
    }
}

// ── Management refusals ─────────────────────────────────────────

fn reason(status: &Status) -> String {
    extract_error_info(status).expect("ErrorInfo").0
}

/// Every management refusal answers with the code and reason clients branch
/// on; the move of the operations into the library changed none of them.
#[test]
fn test_refusals_keep_their_status() {
    use AuthorizationError as E;
    let resource = ResourceId::generate();
    let connector = ProvisioningConnectorId::generate();
    for (refused, code, expected) in [
        (
            E::RoleNotFound("r".into()),
            Code::NotFound,
            "ROLE_NOT_FOUND",
        ),
        (
            E::GroupNotFound(GroupId::generate().to_string()),
            Code::NotFound,
            "GROUP_NOT_FOUND",
        ),
        (
            E::PolicyNotFound(CedarPolicyId::generate()),
            Code::NotFound,
            "POLICY_NOT_FOUND",
        ),
        (
            E::ProjectNotFound(ProjectId::generate()),
            Code::NotFound,
            "PROJECT_NOT_FOUND",
        ),
        (
            E::ScopeResourceNotFound(resource),
            Code::NotFound,
            "RESOURCE_NOT_FOUND",
        ),
        (
            E::ResourceNotFound(resource),
            Code::NotFound,
            "RESOURCE_NOT_FOUND",
        ),
        (
            E::ConnectorNotFound(connector),
            Code::NotFound,
            "PROVISIONING_CONNECTOR_NOT_FOUND",
        ),
        (
            E::ClientNotFound("c".into()),
            Code::NotFound,
            "APPLICATION_NOT_FOUND",
        ),
        (
            E::RoleTaken("r".into()),
            Code::AlreadyExists,
            "ROLE_ALREADY_EXISTS",
        ),
        (
            E::GroupTaken("g".into()),
            Code::AlreadyExists,
            "GROUP_ALREADY_EXISTS",
        ),
        (
            E::PolicyTaken("p".into()),
            Code::AlreadyExists,
            "POLICY_ALREADY_EXISTS",
        ),
        (
            E::Denied,
            Code::PermissionDenied,
            "INSUFFICIENT_PERMISSIONS",
        ),
        (
            E::PublicClient,
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            E::Assignment(AssignmentRule::ServicePrincipal),
            Code::InvalidArgument,
            "INVALID_FIELD_VALUE",
        ),
        (
            E::CeilingExceeded("why".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::LastAdministrator("why".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::GrantorOutsideGroup("why".into()),
            Code::FailedPrecondition,
            "INVALID_STATE",
        ),
        (
            E::ResourceRetired(resource),
            Code::FailedPrecondition,
            "RESOURCE_RETIRED",
        ),
        (
            E::ConnectorRetired(connector),
            Code::FailedPrecondition,
            "RESOURCE_RETIRED",
        ),
    ] {
        let status = refusal(refused);
        assert_eq!(status.code(), code, "{status:?}");
        assert_eq!(reason(&status), expected);
    }
}

/// A refused assignment shape and an invalid field name the field the
/// caller sent; a missing one is named as missing.
#[test]
fn test_field_refusals_name_their_field() {
    for (refused, field) in [
        (
            AuthorizationError::Assignment(AssignmentRule::InstallationScope),
            "scope",
        ),
        (
            AuthorizationError::Assignment(AssignmentRule::AdministratorToProfile),
            "principal",
        ),
        (AuthorizationError::PublicClient, "oauth_client_id"),
        (
            AuthorizationError::InvalidAssignment("why".into()),
            "assignment",
        ),
        (AuthorizationError::MissingField("principal"), "principal"),
    ] {
        let status = refusal(refused);
        let violations = tonic_types::StatusExt::get_details_bad_request(&status)
            .expect("a BadRequest detail")
            .field_violations;
        assert_eq!(violations[0].field, field);
    }
}
