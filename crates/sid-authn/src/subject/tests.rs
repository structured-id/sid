use super::*;
use chrono::Utc;
use sid_core::models::oauth2_client::{
    ApplicationType, LoginStrategy, SubjectType, TokenEndpointAuthMethod,
};
use sid_core::models::oidc_issuer::IssuerHandle;
use sid_core::models::security_policy::EnforcementMode;
use sid_core::models::{BindingId, IssuerId, OrgId, Profile, ProjectId};
use sid_storage::sqlite::SqliteBackend;

fn org_a() -> OrgId {
    OrgId::parse("0192f3a4-7c1e-7b2a-8000-000000000001").unwrap()
}

fn org_b() -> OrgId {
    OrgId::parse("0192f3a5-1d2b-7c3d-8000-000000000002").unwrap()
}

/// The local issuer of an installation whose organization is `org`.
fn local_issuer(org: OrgId) -> OidcIssuer {
    let handle = IssuerHandle::generate();
    OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org,
        created_at: Utc::now(),
    }
}

async fn storage_with_profile() -> (SqliteBackend, ProfileId) {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let profile = Profile::new(Some("subject-holder"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    (storage, profile.id)
}

fn make_client(subject_type: SubjectType) -> OAuth2Client {
    OAuth2Client {
        client_id: "test-client".to_string(),
        project_id: ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: Some(b"hash".to_vec()),
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: "Test".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        response_types: vec!["code".into()],
        subject_type,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(org_a()),
        revision: 0,
        created_at: Utc::now(),
    }
}

async fn binding_sub(storage: &SqliteBackend, pid: ProfileId, client: &OAuth2Client) -> String {
    resolve_subject(storage, pid, client, SubjectRule::OrganizationBinding)
        .await
        .unwrap()
}

/// A local issuer serves its installation's own organization, whose Profiles
/// it manages: the hop to that organization's application is the managed
/// Profile rule whatever subject type the client registered with.
#[test]
fn test_local_issuer_to_own_application_is_managed_profile() {
    let issuer = local_issuer(org_a());
    for subject_type in [SubjectType::Public, SubjectType::Pairwise] {
        assert_eq!(
            SubjectRule::for_hop(&issuer, &make_client(subject_type)).unwrap(),
            SubjectRule::ManagedProfile
        );
    }
}

/// A registered resource of a local issuer belongs to its organization: the
/// hop to it follows the same rule as the hop to that organization's clients.
#[test]
fn test_local_issuer_to_its_resource_is_managed_profile() {
    let issuer = local_issuer(org_a());
    assert_eq!(
        SubjectRule::for_resource(&issuer),
        SubjectRule::for_hop(&issuer, &make_client(SubjectType::Public)).unwrap()
    );
}

/// A client of another organization, or of none, is not a recipient of the
/// issuer: no rule is guessed for it.
#[test]
fn test_client_outside_the_issuers_organization_has_no_rule() {
    let issuer = local_issuer(org_b());
    assert!(SubjectRule::for_hop(&issuer, &make_client(SubjectType::Public)).is_err());
    let mut orphan = make_client(SubjectType::Public);
    orphan.org_id = None;
    assert!(SubjectRule::for_hop(&local_issuer(org_a()), &orphan).is_err());
}

/// The managed Profile rule gives the ProfileId and allocates no binding,
/// even for a client stored with pairwise metadata.
#[tokio::test]
async fn test_managed_profile_is_the_profile_id() {
    let (storage, pid) = storage_with_profile().await;
    let client = make_client(SubjectType::Pairwise);
    let sub = resolve_subject(&storage, pid, &client, SubjectRule::ManagedProfile)
        .await
        .unwrap();
    assert_eq!(sub, pid.to_string());
    assert!(
        storage
            .find_service_binding(pid, &binding_scope(&client).unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

/// The organization Binding rule gives the BindingId: a bare UUIDv7, never
/// the ProfileId, no prefix, and not derived from a secret, even for a client
/// stored with public metadata.
#[tokio::test]
async fn test_organization_binding_is_the_binding_id() {
    let (storage, pid) = storage_with_profile().await;
    let client = make_client(SubjectType::Public);
    let res = binding_sub(&storage, pid, &client).await;

    let binding_id = BindingId::parse(&res).expect("the subject is a BindingId");
    assert_ne!(res, pid.to_string());
    let stored = storage
        .find_service_binding(pid, &binding_scope(&client).unwrap())
        .await
        .unwrap()
        .expect("the first visit allocated a binding");
    assert_eq!(stored.binding_id, binding_id);
}

#[tokio::test]
async fn test_binding_is_stable() {
    let (storage, pid) = storage_with_profile().await;
    let client = make_client(SubjectType::Public);
    let first = binding_sub(&storage, pid, &client).await;
    let again = binding_sub(&storage, pid, &client).await;
    assert_eq!(first, again, "same profile and organization, same sub");
}

/// Clients of different organizations see unlinkable subjects.
#[tokio::test]
async fn test_different_orgs_different_binding() {
    let (storage, pid) = storage_with_profile().await;
    let client_a = make_client(SubjectType::Public);
    let mut client_b = make_client(SubjectType::Public);
    client_b.org_id = Some(org_b());

    assert_ne!(
        binding_sub(&storage, pid, &client_a).await,
        binding_sub(&storage, pid, &client_b).await,
        "different organizations must produce different subs"
    );
}

/// The sector document a client registered with does not choose its
/// subjects: two clients of one organization with different sectors share
/// them, so a registrant cannot enter another organization's subject space
/// by naming its sector.
#[tokio::test]
async fn test_sector_does_not_choose_the_scope() {
    let (storage, pid) = storage_with_profile().await;
    let mut client_a = make_client(SubjectType::Public);
    client_a.client_id = "client-a".to_string();
    client_a.sector_identifier_uri = Some("https://a.sid.example.com/uris.json".to_string());
    let mut client_b = make_client(SubjectType::Public);
    client_b.client_id = "client-b".to_string();
    client_b.sector_identifier_uri = Some("https://b.sid.example.com/uris.json".to_string());

    assert_eq!(
        binding_sub(&storage, pid, &client_a).await,
        binding_sub(&storage, pid, &client_b).await,
    );
}

/// Looking up the subject a client knows allocates nothing: before the first
/// visit there is none, after it the same value the token carried; under the
/// managed Profile rule it is the ProfileId.
#[tokio::test]
async fn test_known_subject_allocates_nothing() {
    let (storage, pid) = storage_with_profile().await;
    let client = make_client(SubjectType::Public);
    let known = |rule| known_subject(&storage, pid, &client, rule);
    assert_eq!(known(SubjectRule::OrganizationBinding).await.unwrap(), None);

    let issued = binding_sub(&storage, pid, &client).await;
    assert_eq!(
        known(SubjectRule::OrganizationBinding).await.unwrap(),
        Some(issued)
    );
    assert_eq!(
        known(SubjectRule::ManagedProfile).await.unwrap(),
        Some(pid.to_string())
    );
}

/// Projects do not split an organization's subjects: clients in two projects
/// of one organization see the same subject.
#[tokio::test]
async fn test_projects_of_one_org_share_the_binding() {
    let (storage, pid) = storage_with_profile().await;
    let client_a = make_client(SubjectType::Public);
    let mut client_b = make_client(SubjectType::Public);
    client_b.client_id = "other-project-client".to_string();
    client_b.project_id = ProjectId::new();

    assert_eq!(
        binding_sub(&storage, pid, &client_a).await,
        binding_sub(&storage, pid, &client_b).await,
    );
}

/// The scope is the client's organization, never a host.
#[test]
fn test_scope_is_the_organization() {
    let mut client = make_client(SubjectType::Public);
    client.sector_identifier_uri =
        Some("https://sector.sid.example.com/redirect_uris.json".to_string());
    assert_eq!(
        binding_scope(&client).unwrap().as_str(),
        org_a().to_string()
    );
}

/// A client registered outside any organization gets no binding: its scope
/// is never guessed from a host or the client id, which anyone registering
/// could choose.
#[test]
fn test_client_without_org_has_no_scope() {
    let mut client = make_client(SubjectType::Public);
    client.org_id = None;
    assert!(binding_scope(&client).is_err());
}

#[tokio::test]
async fn test_org_id_stable_across_domain_rename() {
    let (storage, pid) = storage_with_profile().await;
    let mut before = make_client(SubjectType::Public);
    before.redirect_uris = vec!["https://old-domain.com/cb".to_string()];
    let mut after = before.clone();
    after.redirect_uris = vec!["https://new-domain.com/cb".to_string()];

    assert_eq!(
        binding_sub(&storage, pid, &before).await,
        binding_sub(&storage, pid, &after).await,
        "domain change must NOT affect sub when org_id is set"
    );
}

/// Several applications of one organization share its binding.
#[tokio::test]
async fn test_same_org_different_clients_same_binding() {
    let (storage, pid) = storage_with_profile().await;
    let mut client_a = make_client(SubjectType::Public);
    client_a.client_id = "client-alpha".to_string();
    client_a.redirect_uris = vec!["https://alpha.sid.example.com/cb".to_string()];
    let mut client_b = client_a.clone();
    client_b.client_id = "client-beta".to_string();
    client_b.redirect_uris = vec!["https://beta.sid.example.com/cb".to_string()];

    assert_eq!(
        binding_sub(&storage, pid, &client_a).await,
        binding_sub(&storage, pid, &client_b).await,
        "all clients in same org must produce the same binding"
    );
}
