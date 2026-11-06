use super::*;
use tonic_types::StatusExt;

#[test]
fn test_project_to_proto() {
    let project = Project::new("Test Project", None);
    let proto = project_to_proto(&project);
    assert_eq!(proto.id, Some(project.id.into()));
    assert_eq!(proto.name, "Test Project");
    assert!(proto.description.is_empty());
    assert!(proto.owner_profile_id.is_none());
    assert!(!proto.is_system);
    assert!(proto.created_at.is_some());
    assert!(proto.updated_at.is_some());
}

#[test]
fn test_project_to_proto_with_owner() {
    let owner = sid_core::models::ProfileId::generate();
    let project = Project::new("Owned", Some(owner));
    let proto = project_to_proto(&project);
    assert_eq!(proto.owner_profile_id, Some(owner.into()));
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
    let project_id = ProjectId::generate();
    let mut role = Role::new(project_id, "editor", "Editor");
    role.description = Some("Can edit content".to_string());
    role.permissions = vec!["profiles:read".into(), "profiles:write".into()];

    let proto = role_to_proto(&role);
    assert_eq!(proto.name, "editor"); // proto.name = core.key
    assert_eq!(proto.description, Some("Can edit content".to_string()));
    assert_eq!(proto.permissions, vec!["profiles:read", "profiles:write"]);
    assert!(proto.created_at.is_some());
}

/// A project and an initial access token travel as their identifiers'
/// bytes; the system project's nil identifier is read back as the system
/// project, and a malformed one is refused on its field.
#[test]
fn test_project_and_iat_wire_ids() {
    let project = ProjectId::generate();
    let wire: sid_ids_proto::ProjectId = project.into();
    assert_eq!(
        convert::wire_id(Some(&wire), "project_id").unwrap(),
        project
    );
    let system: sid_ids_proto::ProjectId = ProjectId::SYSTEM.into();
    let read: ProjectId = convert::wire_id(Some(&system), "project_id").unwrap();
    assert!(read.is_system());
    let bad = sid_ids_proto::ProjectId { value: vec![0; 3] };
    let status = convert::wire_id(Some(&bad), "project_id").unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    let iat = InitialAccessTokenId::generate();
    let wire: sid_ids_proto::InitialAccessTokenId = iat.into();
    assert_eq!(convert::wire_id(Some(&wire), "id").unwrap(), iat);
}

/// An initial access token shows its creator as the administrator's
/// profile identifier, not a string.
#[test]
fn test_iat_to_proto_types_its_ids() {
    let now = chrono::Utc::now();
    let creator = sid_core::models::ProfileId::generate();
    let token = InitialAccessToken {
        id: InitialAccessTokenId::generate(),
        token_hash: vec![1; 32],
        project_id: ProjectId::generate(),
        max_clients: 2,
        clients_registered: 0,
        allowed_scopes: vec![],
        allowed_grant_types: vec![],
        allowed_redirect_patterns: vec![],
        expires_at: now,
        created_at: now,
        created_by: creator,
        revoked: false,
    };
    let proto = iat_to_proto(&token);
    assert_eq!(proto.id, Some(token.id.into()));
    assert_eq!(proto.project_id, Some(token.project_id.into()));
    assert_eq!(proto.created_by, Some(creator.into()));
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
