use super::*;
use chrono::Utc;
use sid_core::models::{
    ApplicationId, InitialAccessTokenId, IssuerId, ProjectId, ResourceId, ResourceIndicator,
};

const ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";

fn client(kind: ApplicationType) -> OAuth2Client {
    OAuth2Client {
        client_id: "sid_test123".to_string(),
        project_id: ProjectId::SYSTEM,
        application_id: ApplicationId::generate(),
        default_resource: Some(ResourceId::generate()),
        application_type: kind,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        client_name: "Test App".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: sid_core::models::EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec!["https://app.sid.example.com/signed-out".into()],
        claim_mappings: vec![],
        login_strategy: sid_core::models::LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 3,
        created_at: Utc::now(),
    }
}

/// The client role carries its application, issuer, default resource and
/// revision: what a relying party configures and an administrator manages.
#[test]
fn test_client_to_proto() {
    let c = client(ApplicationType::Web);
    let proto = client_to_proto(&c, ISSUER);
    assert_eq!(proto.client_id, "sid_test123");
    assert_eq!(proto.application_id, Some(c.application_id.into()));
    assert_eq!(proto.issuer, ISSUER);
    assert_eq!(proto.name, "Test App");
    assert_eq!(proto.r#type, i32::from(proto::ApplicationType::Web));
    assert_eq!(
        proto.default_resource_id,
        c.default_resource.map(Into::into)
    );
    assert_eq!(proto.revision, 3);
    assert!(proto.active);
    assert!(!proto.dynamically_registered);
    assert_eq!(
        proto.post_logout_redirect_uris,
        ["https://app.sid.example.com/signed-out"]
    );
}

#[test]
fn test_application_type_mapping() {
    for (kind, expected) in [
        (ApplicationType::Web, proto::ApplicationType::Web),
        (ApplicationType::Native, proto::ApplicationType::Native),
        (ApplicationType::Api, proto::ApplicationType::Api),
        (ApplicationType::Spa, proto::ApplicationType::Spa),
    ] {
        assert_eq!(application_type_to_proto(kind), expected);
    }
}

/// A resource shows its indicator (the audience), issuer and state; a retired
/// one has no application.
#[test]
fn test_resource_to_proto() {
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: None,
        issuer_id: IssuerId::generate(),
        indicator: ResourceIndicator::parse("https://resources.example/orders").unwrap(),
        scopes: vec!["orders.read".into()],
        state: ResourceState::Retired,
        revision: 2,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let proto = resource_to_proto(&resource, ISSUER);
    assert_eq!(proto.id, Some(resource.id.into()));
    assert_eq!(proto.application_id, None);
    assert_eq!(proto.indicator, "https://resources.example/orders");
    assert_eq!(proto.issuer, ISSUER);
    assert_eq!(proto.state, i32::from(proto::ResourceState::Retired));
    assert_eq!(proto.scopes, vec!["orders.read"]);
}

#[test]
fn test_resource_state_mapping() {
    for (state, expected) in [
        (ResourceState::Active, proto::ResourceState::Active),
        (ResourceState::Inactive, proto::ResourceState::Inactive),
        (ResourceState::Retired, proto::ResourceState::Retired),
    ] {
        assert_eq!(resource_state_to_proto(state), expected);
    }
}

#[test]
fn test_application_to_proto_carries_its_roles() {
    let c = client(ApplicationType::Spa);
    let app = Application {
        id: c.application_id,
        project_id: c.project_id,
        name: "Orders".into(),
        system: None,
        revision: 1,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let proto = application_to_proto(&app, Some(client_to_proto(&c, ISSUER)), None);
    assert_eq!(proto.id, Some(app.id.into()));
    assert_eq!(proto.name, "Orders");
    assert_eq!(proto.client.unwrap().client_id, c.client_id);
    assert!(proto.resource.is_none());
    assert_eq!(proto.revision, 1);
    assert_eq!(
        proto.system_integration,
        proto::SystemIntegration::Unspecified as i32
    );
}

/// The installation's own account integration is shown as system-managed.
#[test]
fn test_system_integration_is_shown() {
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::SYSTEM,
        name: "Account".into(),
        system: Some(sid_core::models::SystemIntegration::Account),
        revision: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let proto = application_to_proto(&app, None, None);
    assert_eq!(
        proto.system_integration,
        proto::SystemIntegration::Account as i32
    );
}

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

/// An initial access token shows its creator as the administrator's
/// profile identifier, not a string.
#[test]
fn test_iat_to_proto_types_its_ids() {
    let now = Utc::now();
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
