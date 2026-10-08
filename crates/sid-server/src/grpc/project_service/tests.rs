use super::*;
use tonic_types::StatusExt;

#[test]
fn test_project_to_proto() {
    let project = Project::new("Test Project", None);
    let proto = project_to_proto(&project);
    assert_eq!(proto.name, "Test Project");
    assert!(proto.description.is_empty());
    assert!(proto.owner_profile_id.is_empty());
    assert!(!proto.is_system);
    assert!(proto.created_at.is_some());
    assert!(proto.updated_at.is_some());
}

#[test]
fn test_project_to_proto_with_owner() {
    let owner = sid_core::models::ProfileId::generate();
    let project = Project::new("Owned", Some(owner));
    let proto = project_to_proto(&project);
    assert_eq!(proto.owner_profile_id, owner.to_string());
}

#[test]
fn test_system_project_to_proto() {
    let project = Project::system();
    let proto = project_to_proto(&project);
    assert_eq!(proto.name, "SID");
    assert!(proto.is_system);
}

#[test]
fn test_role_to_proto() {
    let project_id = ProjectId::new();
    let mut role = Role::new(project_id, "editor", "Editor");
    role.description = Some("Can edit content".to_string());
    role.permissions = vec!["profiles:read".into(), "profiles:write".into()];

    let proto = role_to_proto(&role);
    assert_eq!(proto.name, "editor"); // proto.name = core.key
    assert_eq!(proto.description, Some("Can edit content".to_string()));
    assert_eq!(proto.permissions, vec!["profiles:read", "profiles:write"]);
    assert!(proto.created_at.is_some());
}

#[test]
fn test_parse_project_id_valid() {
    let id = uuid::Uuid::now_v7();
    let result = parse_project_id(&id.to_string());
    assert!(result.is_ok());
    assert_eq!(result.unwrap().0, id);
}

#[test]
fn test_parse_project_id_invalid() {
    let result = parse_project_id("not-a-uuid");
    assert!(result.is_err());
}

#[test]
fn test_parse_project_id_nil() {
    let result = parse_project_id(&uuid::Uuid::nil().to_string());
    assert!(result.is_ok());
    assert!(result.unwrap().is_system());
}

#[test]
fn test_proto_to_app_type() {
    assert_eq!(
        proto_to_app_type(sid_proto::sid::v1::ApplicationType::Web.into()),
        ApplicationType::Web
    );
    assert_eq!(
        proto_to_app_type(sid_proto::sid::v1::ApplicationType::Native.into()),
        ApplicationType::Native
    );
    assert_eq!(
        proto_to_app_type(sid_proto::sid::v1::ApplicationType::Api.into()),
        ApplicationType::Api
    );
    assert_eq!(
        proto_to_app_type(sid_proto::sid::v1::ApplicationType::Spa.into()),
        ApplicationType::Spa
    );
    // Unspecified defaults to Web
    assert_eq!(
        proto_to_app_type(sid_proto::sid::v1::ApplicationType::Unspecified.into()),
        ApplicationType::Web
    );
}

#[test]
fn test_generate_client_secret_length() {
    let secret = generate_client_secret();
    assert_eq!(secret.expose_secret().len(), 64); // 32 bytes * 2 hex chars
}

#[test]
fn test_generate_client_secret_unique() {
    let s1 = generate_client_secret();
    let s2 = generate_client_secret();
    assert_ne!(s1.expose_secret(), s2.expose_secret());
}

#[test]
fn test_hash_secret_produces_argon2_hash() {
    let secret = "test_secret_value";
    let hash = hash_secret(secret).unwrap();
    assert!(hash.starts_with("$argon2id$"));
}

#[test]
fn test_hash_secret_different_salts() {
    let secret = "same_secret";
    let h1 = hash_secret(secret).unwrap();
    let h2 = hash_secret(secret).unwrap();
    assert_ne!(h1, h2); // different salts
}

#[test]
fn test_application_type_mapping_roundtrip() {
    for app_type in [
        ApplicationType::Web,
        ApplicationType::Native,
        ApplicationType::Api,
        ApplicationType::Spa,
    ] {
        let proto_type = super::super::application_view::application_type_to_proto(app_type);
        let back = proto_to_app_type(proto_type.into());
        assert_eq!(back, app_type);
    }
}

/// A refusal of a field names it in a `BadRequest` violation under
/// INVALID_FIELD_VALUE, so a client can point at the input.
#[test]
fn test_invalid_field_names_the_field() {
    let status = invalid_field("resource.indicator", "not an absolute URI");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    let (reason, _, _) = sid_core::grpc_error::extract_error_info(&status).expect("ErrorInfo");
    assert_eq!(reason, "INVALID_FIELD_VALUE");
    let violations = status.get_details_bad_request().expect("BadRequest");
    assert_eq!(violations.field_violations[0].field, "resource.indicator");
}
