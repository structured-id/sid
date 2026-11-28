// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 integration tests with real PostgreSQL.
//!
//! Requires running PostgreSQL: `cd sid && docker compose -f docker-compose.test.yml up -d`
//! Run with: `cargo nextest run -p sid-scim --test scim_integration` (its setup
//! script prepares the database).

use std::sync::Arc;

use secrecy::ExposeSecret as _;
use sid_authn::bearer_secret;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::provisioning_connector::SCIM_BEARER_PREFIX;
use sid_core::models::{
    AuditEntry, DirectoryRight, DirectoryRights, GroupId, OrgId, Principal, PrincipalType, Profile,
    ProfileId, ProfileStatus, ProfileType, ProjectId, ProvisioningConnector,
    ProvisioningConnectorId, ProvisioningCredential, ProvisioningDirection, ResourceId, Role,
    RoleAssignment, RoleAssignmentPrincipal, SCIM_ACTIONS, SCIM_GROUP_CREATE, SCIM_GROUP_READ,
    SCIM_GROUP_UPDATE, SCIM_USER_READ, Session,
};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1 as proto;
use sid_proto::sid::v1::scim_service_server::ScimService;
use sid_scim::grpc::{ScimDirectory, ScimServiceImpl};
use sid_scim::mapping::ScimOrgContext;
use tonic::Request;
use uuid::Uuid;

/// A pool on the test database, to read what the trait does not return
/// (the audit trail).
async fn storage_pool() -> sqlx::PgPool {
    sid_storage::testing::prepared_postgres()
        .await
        .pool()
        .clone()
}

async fn setup() -> (ScimServiceImpl, Arc<dyn StorageBackend>) {
    let (service, storage, _) = setup_with_revocation().await;
    (service, storage)
}

/// The service, its storage and the revocation cache its cascade writes to.
async fn setup_with_revocation() -> (
    ScimServiceImpl,
    Arc<dyn StorageBackend>,
    Arc<RevocationCache>,
) {
    let (service, storage, revocation, _) = setup_directory().await;
    (service, storage, revocation)
}

/// [`setup_with_revocation`] plus the directory the service serves.
async fn setup_directory() -> (
    ScimServiceImpl,
    Arc<dyn StorageBackend>,
    Arc<RevocationCache>,
    ScimDirectory,
) {
    let storage: Arc<dyn StorageBackend> =
        Arc::new(sid_storage::testing::prepared_postgres().await);

    // Create a project for SCIM group scoping
    let project_id = ProjectId::SYSTEM;

    let org_ctx = ScimOrgContext {
        org_domain: "acme.corp".into(),
        project_id,
    };

    let revocation = Arc::new(RevocationCache::new(
        std::time::Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ));
    let directory = ScimDirectory {
        org: OrgId::generate(),
        resource: registered_directory(storage.as_ref()).await,
    };
    let service = ScimServiceImpl::new(
        storage.clone(),
        org_ctx,
        "https://sid.example.com".into(),
        directory,
        Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
        revocation.clone(),
    );
    let secret = connector_secret(&storage, directory, &SCIM_ACTIONS).await;
    CONNECTOR_SECRET.with(|s| *s.borrow_mut() = secret);

    (service, storage, revocation, directory)
}

/// The installation's registered SCIM directory resource, as the server
/// registers it at start: a decision on a resource reads its registration.
async fn registered_directory(storage: &dyn StorageBackend) -> ResourceId {
    storage
        .ensure_system_project(AuditEntry::system("project.ensure_system", "system").into())
        .await
        .unwrap();
    let organization = sid_authn::instance_org::ensure(storage, "sid.example.com")
        .await
        .unwrap();
    let keys = sid_keys::SoftwareKeyManager::new(
        secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
        vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
        Arc::new(sid_crypto::RustCryptoPrimitives::new()),
    )
    .expect("test key manager");
    let issuer = sid_authn::issuer::ensure_local_issuer(
        storage,
        &keys,
        &url::Url::parse("https://sid.example.com").unwrap(),
        organization.id,
    )
    .await
    .unwrap();
    sid_authn::issuer::ensure_scim_resource(storage, &issuer)
        .await
        .unwrap()
        .id
}

thread_local! {
    /// The secret of the connector the current test's service accepts: a
    /// test runs on its own thread, and every request helper reads it.
    static CONNECTOR_SECRET: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// A new active inbound connector of `directory`'s organization holding a
/// role with `actions` on its resource and managing every user of the
/// directory whole; returns the connector's secret.
async fn connector_secret(
    storage: &Arc<dyn StorageBackend>,
    directory: ScimDirectory,
    actions: &[&str],
) -> String {
    let rights = DirectoryRights::of(&DirectoryRight::ALL);
    connector_managing(storage, directory, actions, rights)
        .await
        .1
}

/// [`connector_secret`] for a connector that manages `rights` of every user
/// of the directory; the connector with its secret.
async fn connector_managing(
    storage: &Arc<dyn StorageBackend>,
    directory: ScimDirectory,
    actions: &[&str],
    rights: DirectoryRights,
) -> (ProvisioningConnector, String) {
    let audit = || AuditEntry::system("test", "scim-connector").into();
    let connector =
        ProvisioningConnector::new(directory.org, ProvisioningDirection::Inbound, "HR sync");
    storage
        .create_provisioning_connector(&connector, audit())
        .await
        .unwrap();
    // As its manager selects it: by the revision the manager read.
    assert!(
        storage
            .set_directory_rights(connector.id, connector.revision, rights, audit())
            .await
            .unwrap()
    );
    let issued = bearer_secret::issue(SCIM_BEARER_PREFIX);
    assert!(
        storage
            .add_provisioning_credential(
                &ProvisioningCredential::new(
                    connector.id,
                    sid_core::models::ConnectorCredentialKind::ScimBearer,
                    issued.verifier.clone(),
                ),
                audit(),
            )
            .await
            .unwrap()
    );
    storage.ensure_system_project(audit()).await.unwrap();
    let key = format!("scim-test-{}", Uuid::now_v7().simple());
    let mut role = Role::new(ProjectId::SYSTEM, &key, &key);
    role.permissions = actions.iter().map(|a| (*a).to_owned()).collect();
    storage.create_role(&role, audit()).await.unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(
                RoleAssignmentPrincipal::ProvisioningConnector(connector.id),
                role.id,
            )
            .on_resource(directory.resource),
            audit(),
        )
        .await
        .unwrap();
    (connector, issued.secret.expose_secret().clone())
}

fn test_jwt() -> Arc<JwtService> {
    Arc::new(
        JwtService::new(
            include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
            include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
            "https://sid.example.com".to_string(),
        )
        .expect("JWT creation failed"),
    )
}

/// A token for `profile`, as a signed-in session issues it.
fn token_for(profile: &Profile) -> String {
    let session = Session::new(
        profile.id,
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    test_jwt()
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            &profile.roles,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap()
}

/// A request from the provisioning connector the test's service accepts.
fn provisioned<T>(msg: T) -> Request<T> {
    CONNECTOR_SECRET.with(|s| with_token(msg, &s.borrow()))
}

fn with_token<T>(msg: T, token: &str) -> Request<T> {
    let mut req = <Request<T>>::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn unique_username() -> String {
    format!("scim_test_{}", Uuid::now_v7().simple())
}

/// The account behind the user a client knows as `scim_id`. The SCIM id is
/// the directory resource's own identifier, never the account's.
async fn account_of(storage: &Arc<dyn StorageBackend>, scim_id: &str) -> ProfileId {
    let resource = sid_core::models::DirectoryUserId::parse(scim_id).expect("a resource id");
    if let Ok(as_account) = ProfileId::parse(scim_id) {
        assert!(
            storage.get_profile(as_account).await.unwrap().is_none(),
            "the SCIM id names an account"
        );
    }
    storage
        .find_directory_user(resource)
        .await
        .unwrap()
        .expect("the user's resource is stored")
        .profile_id
}

fn create_user_request(user_name: &str) -> proto::ScimCreateUserRequest {
    proto::ScimCreateUserRequest {
        external_id: format!("EMP-{}", user_name),
        user_name: user_name.into(),
        name: Some(proto::ScimName {
            formatted: format!("Test User {}", user_name),
            given_name: "Test".into(),
            family_name: "User".into(),
            ..Default::default()
        }),
        display_name: format!("Test User {}", user_name),
        emails: vec![proto::ScimEmail {
            value: format!("{}@acme.example.com", user_name),
            r#type: "work".into(),
            primary: true,
        }],
        phone_numbers: vec![proto::ScimPhoneNumber {
            // E.164 format, 8 random digits per test
            value: format!("+1{:08}", Uuid::new_v4().as_u128() % 100_000_000),
            r#type: "work".into(),
            primary: true,
        }],
        department: "Engineering".into(),
        title: "Engineer".into(),
        active: true,
        employee_number: String::new(),
    }
}

// ─── CreateUser ───

#[tokio::test]
async fn test_create_user_stores_profile_and_identifiers() {
    let (service, storage) = setup().await;
    let username = unique_username();
    let req = create_user_request(&username);

    let response = service
        .create_user(provisioned(req))
        .await
        .expect("create_user failed");

    let user = response.into_inner();

    // Verify SCIM response
    assert!(!user.id.is_empty());
    assert_eq!(user.user_name, username);
    // display_name = formatted_name() from structured given_name + family_name
    assert_eq!(user.display_name, "Test User");
    assert!(user.active);
    assert_eq!(user.emails.len(), 1);
    assert_eq!(
        user.emails[0].value,
        format!("{}@acme.example.com", username)
    );
    assert_eq!(user.phone_numbers.len(), 1);
    assert_eq!(user.department, "Engineering");
    assert_eq!(user.title, "Engineer");
    assert!(user.meta.is_some());

    // Verify persisted profile
    let profile_id = account_of(&storage, &user.id).await;
    let profile = storage
        .get_profile(profile_id)
        .await
        .unwrap()
        .expect("profile not found in DB");
    assert_eq!(profile.profile_type, ProfileType::Corporate);
    assert_eq!(profile.status, ProfileStatus::Provisioned);
    assert_eq!(profile.username, Some(profile.id.to_string())); // Corporate profiles use profileId as placeholder

    // Verify corporate login principal
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    let login = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Username)
        .expect("corporate login principal not found");
    assert_eq!(login.value, format!("{}#acme.corp", username));
    assert!(!login.verified);

    // Verify email principal (contact)
    let email = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .expect("email principal not found");
    assert!(!email.verified);

    // Verify phone principal (contact)
    let phone = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Phone)
        .expect("phone principal not found");
    assert!(!phone.verified);

    // Verify Profile fields (structured name)
    assert_eq!(profile.given_name.as_deref(), Some("Test"));
    assert_eq!(profile.family_name.as_deref(), Some("User"));
    // Email/phone are now in profile_emails/profile_phones tables, not on Profile

    // Verify metadata (org-specific fields only, NOT name — name is in Profile)
    let metadata = storage.list_profile_metadata(profile_id).await.unwrap();
    let keys: Vec<&str> = metadata.iter().map(|m| m.key.as_str()).collect();
    // externalId is the creating source's identifier of the user, kept with
    // its correlation and never as an attribute of the account.
    assert!(!keys.contains(&"employee_id"));
    assert!(keys.contains(&"department"));
    assert!(keys.contains(&"title"));
    // given_name/family_name are Profile fields, NOT metadata
    assert!(!keys.contains(&"given_name"));
    assert!(!keys.contains(&"family_name"));

    // Verify ProfileEmail contact record (multi-valued contacts)
    let emails = storage.list_profile_emails(profile_id).await.unwrap();
    assert_eq!(emails.len(), 1, "should have 1 ProfileEmail");
    assert_eq!(emails[0].email, format!("{}@acme.example.com", username));
    assert!(emails[0].is_primary);
    assert!(!emails[0].verified);

    // Verify ProfilePhone contact record
    let phones = storage.list_profile_phones(profile_id).await.unwrap();
    assert_eq!(phones.len(), 1, "should have 1 ProfilePhone");
    assert!(phones[0].is_primary);
    assert!(
        phones[0].e164 > 0,
        "e164 should be parsed from phone string"
    );
    assert!(!phones[0].verified);
}

#[tokio::test]
async fn test_create_user_duplicate_username_rejected() {
    let (service, _) = setup().await;
    let username = unique_username();

    // First create succeeds
    service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .expect("first create failed");

    // Second create with same userName should fail
    let err = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .expect_err("duplicate should be rejected");

    // RFC 7644 §3.3: a taken userName is 409 with scimType `uniqueness`.
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    let (reason, _, metadata) = sid_infra::grpc_error::extract_error_info(&err).unwrap();
    assert_eq!(reason, "USERNAME_ALREADY_TAKEN");
    assert_eq!(
        metadata.get("scimType").map(String::as_str),
        Some("uniqueness")
    );
}

/// A create that cannot be stored whole stores nothing: two primary emails
/// (RFC 7643 §2.4 allows `primary` true at most once) used to leave the
/// profile and its login handle behind after the second email failed, and
/// the directory's retry then got "userName already exists".
#[tokio::test]
async fn test_create_user_failure_leaves_no_partial_account() {
    let (service, storage) = setup().await;
    let username = unique_username();
    let mut req = create_user_request(&username);
    req.emails.push(proto::ScimEmail {
        value: format!("{username}.second@acme.example.com"),
        r#type: "home".into(),
        primary: true,
    });

    let err = service
        .create_user(provisioned(req))
        .await
        .expect_err("two primary emails");

    let left = storage
        .get_profile_by_principal(PrincipalType::Username, &format!("{username}#acme.corp"))
        .await
        .unwrap();
    assert!(left.is_none(), "a partial account was left behind");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

/// Two directories creating the same userName at once end with one account.
#[tokio::test]
async fn test_concurrent_create_same_username_single_account() {
    let (service, _) = setup().await;
    let username = unique_username();
    let (a, b) = tokio::join!(
        service.create_user(provisioned(create_user_request(&username))),
        service.create_user(provisioned(create_user_request(&username))),
    );
    let created = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(created, 1, "{a:?} {b:?}");
    let refused = if a.is_ok() { b } else { a };
    assert_eq!(refused.unwrap_err().code(), tonic::Code::AlreadyExists);
}

#[tokio::test]
async fn test_create_user_empty_username_rejected() {
    let (service, _) = setup().await;

    let mut req = create_user_request("dummy");
    req.user_name = String::new();

    let err = service
        .create_user(provisioned(req))
        .await
        .expect_err("empty userName should be rejected");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ─── GetUser ───

#[tokio::test]
async fn test_get_user_returns_full_representation() {
    let (service, _) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let fetched = service
        .get_user(provisioned(proto::ScimGetUserRequest {
            id: created.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.user_name, username);
    assert_eq!(fetched.emails.len(), 1);
    assert_eq!(fetched.phone_numbers.len(), 1);
    assert_eq!(fetched.department, "Engineering");
}

#[tokio::test]
async fn test_get_user_not_found() {
    let (service, _) = setup().await;

    let err = service
        .get_user(provisioned(proto::ScimGetUserRequest {
            id: Uuid::now_v7().to_string(),
        }))
        .await
        .expect_err("should return not found");

    assert_eq!(err.code(), tonic::Code::NotFound);
    let (reason, _, _) = sid_infra::grpc_error::extract_error_info(&err).unwrap();
    assert_eq!(reason, "PROFILE_NOT_FOUND");
}

// ─── ListUsers ───

#[tokio::test]
async fn test_list_users_pagination() {
    let (service, _) = setup().await;

    // Create 3 users
    for i in 0..3 {
        let username = format!("{}_{}", unique_username(), i);
        service
            .create_user(provisioned(create_user_request(&username)))
            .await
            .unwrap();
    }

    let response = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: String::new(),
            start_index: 1,
            count: 2,
        }))
        .await
        .unwrap()
        .into_inner();

    // Should return at most 2 resources (page size)
    assert!(response.resources.len() <= 2);
    assert!(response.total_results >= 3);
    assert_eq!(response.start_index, 1);
    assert_eq!(response.items_per_page, 2);
}

// ─── ListUsers with Filter ───

#[tokio::test]
async fn test_list_users_filter_username_eq() {
    let (service, _) = setup().await;

    let username = unique_username();
    service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap();

    // Also create a user that should NOT match
    let other = unique_username();
    service
        .create_user(provisioned(create_user_request(&other)))
        .await
        .unwrap();

    let response = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: format!(r#"userName eq "{}""#, username),
            start_index: 1,
            count: 100,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.resources.len(), 1);
    assert_eq!(response.resources[0].user_name, username);
}

/// A user created after more than ten thousand others is found by a
/// userName filter: the filter runs over the whole directory, not over its
/// first ten thousand profiles (the bug this guards against answered an
/// empty, error-free list).
#[tokio::test]
async fn test_list_users_filter_finds_a_user_beyond_ten_thousand() {
    let (service, storage) = setup().await;
    // Only their number matters: seeded in one statement, without the
    // audited write each profile created through the store pays for.
    let shortfall = 10_001u64.saturating_sub(storage.count_profiles().await.unwrap());
    let like = Profile::new(None::<String>);
    let pool = storage_pool().await;
    sqlx::query(
        "INSERT INTO profiles (
            id, profile_type, roles, status, visibility, max_assurance,
            migration_pending, created_at, updated_at
         )
         SELECT uuidv7(), $2, $3, $4, $5, $6, $7, now(), now()
         FROM generate_series(1, $1)",
    )
    .bind(i64::try_from(shortfall).unwrap())
    .bind(like.profile_type.as_str())
    .bind(like.roles.join(" "))
    .bind(like.status.as_str())
    .bind(like.visibility.as_str())
    .bind(like.max_assurance.as_str())
    .bind(like.migration_pending)
    .execute(&pool)
    .await
    .unwrap();
    let username = unique_username();
    service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap();

    let response = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: format!(r#"userName eq "{username}""#),
            start_index: 1,
            count: 100,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.total_results, 1);
    assert_eq!(response.resources.len(), 1);
    assert_eq!(response.resources[0].user_name, username);
    assert_eq!(response.items_per_page, 1, "the resources returned");
}

/// `itemsPerPage` is the number of resources on the page, not the count
/// asked for (RFC 7644 §3.4.2): a last page holds fewer.
#[tokio::test]
async fn test_list_users_items_per_page_counts_the_page() {
    let (service, _) = setup().await;
    let prefix = unique_username();
    for i in 0..3 {
        service
            .create_user(provisioned(create_user_request(&format!("{prefix}_{i}"))))
            .await
            .unwrap();
    }
    let response = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: format!(r#"userName sw "{prefix}""#),
            start_index: 3,
            count: 2,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.total_results, 3);
    assert_eq!(response.resources.len(), 1);
    assert_eq!(response.items_per_page, 1);
}

/// An attribute the directory does not hold, or a comparison its type does
/// not support, is an invalid filter, never an empty result.
#[tokio::test]
async fn test_list_users_unsupported_filter_is_invalid() {
    let (service, _) = setup().await;
    for filter in [r#"nickName eq "x""#, "active gt true"] {
        let err = service
            .list_users(provisioned(proto::ScimListUsersRequest {
                filter: filter.into(),
                start_index: 1,
                count: 10,
            }))
            .await
            .expect_err(filter);
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{filter}");
    }
}

#[tokio::test]
async fn test_list_users_filter_department_eq() {
    let (service, _) = setup().await;

    let username = unique_username();
    let mut req = create_user_request(&username);
    req.department = "UniqueTestDept_42".into();
    service.create_user(provisioned(req)).await.unwrap();

    let response = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: r#"department eq "UniqueTestDept_42""#.into(),
            start_index: 1,
            count: 100,
        }))
        .await
        .unwrap()
        .into_inner();

    // At least 1 result matching our unique department
    assert!(
        response
            .resources
            .iter()
            .any(|u| u.department == "UniqueTestDept_42")
    );
    assert!(
        response
            .resources
            .iter()
            .all(|u| u.department == "UniqueTestDept_42")
    );
}

#[tokio::test]
async fn test_list_users_filter_invalid_syntax() {
    let (service, _) = setup().await;

    let err = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: "invalid!!!".into(),
            start_index: 1,
            count: 100,
        }))
        .await
        .expect_err("invalid filter should be rejected");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ─── ReplaceUser ───

#[tokio::test]
async fn test_replace_user_updates_all_fields() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Replace with updated data
    let replaced = service
        .replace_user(provisioned(proto::ScimReplaceUserRequest {
            id: created.id.clone(),
            external_id: "EMP-NEW".into(),
            user_name: username.clone(),
            name: Some(proto::ScimName {
                formatted: "Updated Name".into(),
                given_name: "Updated".into(),
                family_name: "Name".into(),
                ..Default::default()
            }),
            display_name: "Updated Name".into(),
            emails: vec![proto::ScimEmail {
                value: format!("new_{}@acme.example.com", username),
                r#type: "work".into(),
                primary: true,
            }],
            phone_numbers: vec![], // Remove phone
            department: "Product".into(),
            title: "Manager".into(),
            active: true,
            employee_number: "701985".into(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(replaced.display_name, "Updated Name");
    assert_eq!(replaced.department, "Product");
    assert_eq!(replaced.title, "Manager");
    // The source that created the user replaces its own identifier of it.
    assert_eq!(replaced.external_id, "EMP-NEW");
    assert_eq!(replaced.employee_number, "701985");
    assert_eq!(replaced.emails.len(), 1);
    assert_eq!(
        replaced.emails[0].value,
        format!("new_{}@acme.example.com", username)
    );
    assert_eq!(replaced.phone_numbers.len(), 0);

    // Verify old email principal was removed
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    let emails: Vec<&Principal> = principals
        .iter()
        .filter(|p| p.principal_type == PrincipalType::Email)
        .collect();
    assert_eq!(emails.len(), 1);
    assert_eq!(
        emails[0].value,
        format!("new_{}@acme.example.com", username)
    );

    // Corporate login should still exist
    let login = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Username);
    assert!(login.is_some());

    // Verify ProfileEmail contacts replaced
    let contact_emails = storage.list_profile_emails(profile_id).await.unwrap();
    assert_eq!(
        contact_emails.len(),
        1,
        "should have 1 ProfileEmail after replace"
    );
    assert_eq!(
        contact_emails[0].email,
        format!("new_{}@acme.example.com", username)
    );

    // Verify ProfilePhone contacts removed (phone_numbers was empty in replace)
    let contact_phones = storage.list_profile_phones(profile_id).await.unwrap();
    assert_eq!(
        contact_phones.len(),
        0,
        "should have 0 ProfilePhones after replace with empty phones"
    );
}

// ─── externalId ───

/// `externalId` is the asking client's own identifier of a user (RFC 7643
/// 3.1): the source that created the user is shown it and finds the user by
/// it, another source of the same directory sees none, matches nothing by
/// it, gains none by writing to the user, and may use the same value for a
/// user of its own. One source gives a value to one user (RFC 7644 3.3,
/// `uniqueness`), may change it, and has it back when the user is deleted.
#[tokio::test]
async fn test_external_id_is_each_sources_own() {
    let (service, storage, _, directory) = setup_directory().await;
    let other_source = connector_secret(&storage, directory, &SCIM_ACTIONS).await;
    let username = unique_username();
    let external_id = format!("EMP-{username}");
    let found_by = async |token: Option<&str>, value: &str| {
        let request = proto::ScimListUsersRequest {
            filter: format!(r#"externalId eq "{value}""#),
            start_index: 1,
            count: 100,
        };
        let request = match token {
            Some(token) => with_token(request, token),
            None => provisioned(request),
        };
        service
            .list_users(request)
            .await
            .unwrap()
            .into_inner()
            .resources
    };

    // The employee number is a third value: the user's own attribute, the
    // same for every source, and neither source's identifier.
    let employee_number = format!("N-{username}");
    let created = service
        .create_user(provisioned(proto::ScimCreateUserRequest {
            employee_number: employee_number.clone(),
            ..create_user_request(&username)
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.external_id, external_id);
    assert_eq!(created.employee_number, employee_number);
    let get = proto::ScimGetUserRequest {
        id: created.id.clone(),
    };
    let own = service
        .get_user(provisioned(get.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(own.external_id, external_id);
    assert_eq!(own.employee_number, employee_number);
    let foreign = service
        .get_user(with_token(get.clone(), &other_source))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(foreign.external_id, "");
    assert_eq!(foreign.employee_number, employee_number);
    assert!(found_by(None, &employee_number).await.is_empty());

    let listed = found_by(None, &external_id).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, created.id);
    assert_eq!(listed[0].external_id, external_id);
    assert!(found_by(Some(&other_source), &external_id).await.is_empty());

    // A source that does not know the user is made one only by its manager:
    // a request that names an identifier for the user is refused whole, so
    // the attribute it carried with it is not written either.
    let replace = |external_id: &str| proto::ScimReplaceUserRequest {
        id: created.id.clone(),
        external_id: external_id.into(),
        user_name: username.clone(),
        name: own.name.clone(),
        emails: own.emails.clone(),
        phone_numbers: own.phone_numbers.clone(),
        active: true,
        employee_number: format!("{employee_number}-2"),
        department: own.department.clone(),
        title: own.title.clone(),
        ..Default::default()
    };
    let refused = service
        .replace_user(with_token(replace("OTHER-1"), &other_source))
        .await
        .expect_err("a request does not make its connector a source of the user");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    let unchanged = service
        .get_user(provisioned(get.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unchanged.employee_number, employee_number);
    assert!(found_by(Some(&other_source), "OTHER-1").await.is_empty());

    // Naming none, it changes what it manages of the user and still has no
    // identifier of it; the creating source keeps its own.
    let replaced = service
        .replace_user(with_token(replace(""), &other_source))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replaced.external_id, "");
    // The employee number it wrote is the user's, for every source.
    assert_eq!(replaced.employee_number, format!("{employee_number}-2"));
    let own = service
        .get_user(provisioned(get.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(own.employee_number, format!("{employee_number}-2"));
    assert_eq!(own.external_id, external_id);
    assert!(found_by(Some(&other_source), "OTHER-1").await.is_empty());
    assert_eq!(found_by(None, &external_id).await.len(), 1);

    // The same value names one user per source.
    let taken = service
        .create_user(provisioned(proto::ScimCreateUserRequest {
            external_id: external_id.clone(),
            ..create_user_request(&unique_username())
        }))
        .await
        .expect_err("the source already knows a user by this identifier");
    assert_eq!(taken.code(), tonic::Code::AlreadyExists);
    let (reason, _, metadata) = sid_infra::grpc_error::extract_error_info(&taken).unwrap();
    assert_eq!(reason, "PROFILE_ALREADY_EXISTS");
    assert_eq!(
        metadata.get("scimType").map(String::as_str),
        Some("uniqueness")
    );
    let elsewhere = service
        .create_user(with_token(
            proto::ScimCreateUserRequest {
                external_id: external_id.clone(),
                ..create_user_request(&unique_username())
            },
            &other_source,
        ))
        .await
        .expect("another source's identifiers are its own")
        .into_inner();
    assert_eq!(elsewhere.external_id, external_id);
    let listed = found_by(Some(&other_source), &external_id).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, elsewhere.id);

    // The source renames its identifier; the old value finds nothing.
    let renamed = format!("{external_id}-2");
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "externalId".into(),
                value: renamed.clone(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(patched.external_id, renamed);
    assert!(found_by(None, &external_id).await.is_empty());
    // A change that does not name externalId leaves it.
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "title".into(),
                value: "Lead".into(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(patched.external_id, renamed);

    // A deleted user gives its identifier back to the source.
    service
        .delete_user(provisioned(proto::ScimDeleteUserRequest {
            id: created.id.clone(),
        }))
        .await
        .unwrap();
    let again = service
        .create_user(provisioned(proto::ScimCreateUserRequest {
            external_id: renamed.clone(),
            ..create_user_request(&unique_username())
        }))
        .await
        .expect("the identifier is free again")
        .into_inner();
    assert_eq!(again.external_id, renamed);
}

// ─── PatchUser ───

#[tokio::test]
async fn test_patch_user_replace_display_name() {
    let (service, _) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "displayName".into(),
                value: "New Display Name".into(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    // displayName PATCH writes to given_name and clears family_name/middle_name
    // (unstructured fallback — use name.givenName/name.familyName for structured updates)
    assert_eq!(patched.display_name, "New Display Name");
}

#[tokio::test]
async fn test_patch_user_deactivate_and_reactivate() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Deactivate
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "false".into(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(!patched.active);

    // Verify in DB
    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Suspended);

    // Reactivate
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "true".into(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(patched.active);

    // SCIM-provisioned profiles have unverified identifiers → never claimed.
    // Reactivation returns to Provisioned, not Active.
    // Active requires secure channel claim (the user binds an OPAQUE password).
    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Provisioned);
}

/// RFC 7644 §3.5.2: an email added as primary makes the current primary
/// email non-primary; the account never holds two primaries (the second
/// used to fail on the one-primary index and was dropped by `let _`).
#[tokio::test]
async fn test_patch_user_add_primary_email_demotes_current() {
    let (service, storage) = setup().await;
    let username = unique_username();
    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();
    let profile_id = account_of(&storage, &created.id).await;

    let new_primary = format!("primary-{}@acme.example.com", Uuid::now_v7().simple());
    service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "add".into(),
                path: "emails".into(),
                value: format!(r#"{{"value":"{new_primary}","type":"work","primary":true}}"#),
            }],
        }))
        .await
        .expect("a new primary email");

    let contacts = storage.list_profile_emails(profile_id).await.unwrap();
    assert_eq!(contacts.len(), 2);
    let primaries: Vec<&str> = contacts
        .iter()
        .filter(|e| e.is_primary)
        .map(|e| e.email.as_str())
        .collect();
    assert_eq!(primaries, vec![new_primary.as_str()]);
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    let primary_principals: Vec<&str> = principals
        .iter()
        .filter(|p| p.principal_type == PrincipalType::Email && p.is_primary)
        .map(|p| p.value.as_str())
        .collect();
    assert_eq!(primary_principals, vec![new_primary.as_str()]);
}

#[tokio::test]
async fn test_patch_user_add_email() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Add a second email (unique per test run)
    let second_email = format!("second-{}@acme.example.com", Uuid::now_v7().simple());
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "add".into(),
                path: "emails".into(),
                value: format!(
                    r#"{{"value":"{}","type":"work","primary":false}}"#,
                    second_email
                ),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(patched.emails.len(), 2);

    // Verify Principals in DB
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    let emails: Vec<&Principal> = principals
        .iter()
        .filter(|p| p.principal_type == PrincipalType::Email)
        .collect();
    assert_eq!(emails.len(), 2);

    // Verify ProfileEmail contacts in DB
    let contact_emails = storage.list_profile_emails(profile_id).await.unwrap();
    assert_eq!(
        contact_emails.len(),
        2,
        "should have 2 ProfileEmails after PATCH add"
    );
}

#[tokio::test]
async fn test_patch_user_remove_email() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;
    let email_value = format!("{}@acme.example.com", username);

    // Remove the email
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "remove".into(),
                path: format!(r#"emails[value eq "{}"]"#, email_value),
                value: String::new(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(patched.emails.len(), 0);

    // Verify Principals in DB
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    let emails: Vec<&Principal> = principals
        .iter()
        .filter(|p| p.principal_type == PrincipalType::Email)
        .collect();
    assert_eq!(emails.len(), 0);

    // Verify ProfileEmail contacts removed
    let contact_emails = storage.list_profile_emails(profile_id).await.unwrap();
    assert_eq!(
        contact_emails.len(),
        0,
        "should have 0 ProfileEmails after PATCH remove"
    );
}

#[tokio::test]
async fn test_patch_user_immutable_field_rejected() {
    let (service, _) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let err = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "id".into(),
                value: "new-id".into(),
            }],
        }))
        .await
        .expect_err("patching id should fail");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ─── DeleteUser ───

#[tokio::test]
/// Regression: DELETE only suspended the account, so the deleted user was
/// still read, listed, changed and deleted again. RFC 7644 3.6: after the
/// first DELETE every operation on the id is not found and the user is in no
/// query; the account's record stays, suspended.
async fn test_delete_user_removes_the_resource() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();
    let profile_id = account_of(&storage, &created.id).await;
    let group = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("DeleteGroup_{}", Uuid::now_v7().simple()),
            members: vec![proto::ScimMemberRef {
                value: created.id.clone(),
                display: String::new(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(group.members.len(), 1);
    assert_eq!(group.members[0].value, created.id);

    service
        .delete_user(provisioned(proto::ScimDeleteUserRequest {
            id: created.id.clone(),
        }))
        .await
        .expect("delete_user failed");

    let not_found = |status: tonic::Status| {
        assert_eq!(status.code(), tonic::Code::NotFound, "{status:?}");
        assert!(
            !format!("{status:?}").contains(&profile_id.to_string()),
            "a refusal names the account: {status:?}"
        );
    };
    not_found(
        service
            .get_user(provisioned(proto::ScimGetUserRequest {
                id: created.id.clone(),
            }))
            .await
            .expect_err("a deleted user is read"),
    );
    not_found(
        service
            .replace_user(provisioned(proto::ScimReplaceUserRequest {
                id: created.id.clone(),
                user_name: username.clone(),
                active: true,
                ..Default::default()
            }))
            .await
            .expect_err("a deleted user is replaced"),
    );
    not_found(
        service
            .patch_user(provisioned(proto::ScimPatchUserRequest {
                id: created.id.clone(),
                operations: vec![proto::ScimPatchOp {
                    op: "replace".into(),
                    path: "active".into(),
                    value: "true".into(),
                }],
            }))
            .await
            .expect_err("a deleted user is patched"),
    );
    not_found(
        service
            .delete_user(provisioned(proto::ScimDeleteUserRequest {
                id: created.id.clone(),
            }))
            .await
            .expect_err("a deleted user is deleted again"),
    );

    // In no query, and no longer a member the directory serves.
    let listed = service
        .list_users(provisioned(proto::ScimListUsersRequest {
            filter: format!("userName eq \"{username}\""),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.total_results, 0);
    assert!(listed.resources.is_empty());
    let read = service
        .get_group(provisioned(proto::ScimGetGroupRequest {
            id: group.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(read.members.is_empty(), "{:?}", read.members);
    // Nor can it be made a member again.
    let readded = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("DeleteGroup_{}", Uuid::now_v7().simple()),
            members: vec![proto::ScimMemberRef {
                value: created.id.clone(),
                display: String::new(),
            }],
        }))
        .await
        .expect_err("a deleted user is added to a group");
    assert_eq!(readded.code(), tonic::Code::InvalidArgument);

    // The account's record stays, suspended, with its access ended.
    let profile = storage
        .get_profile(profile_id)
        .await
        .unwrap()
        .expect("the account's record stays");
    assert_eq!(profile.status, ProfileStatus::Suspended);
    let resource = storage
        .find_directory_user(sid_core::models::DirectoryUserId::parse(&created.id).unwrap())
        .await
        .unwrap()
        .expect("a deleted resource is kept");
    assert!(!resource.is_live());
}

/// Regression: DELETE wrote `Suspended` over whatever state the account was
/// in, so a deletion released a legal hold and reopened a closed account to
/// reactivation. Ending local access keeps a hold and a terminal state; the
/// resource is deleted all the same.
#[tokio::test]
async fn test_delete_user_keeps_a_hold_and_a_terminal_state() {
    let (service, storage) = setup().await;
    for held in [
        ProfileStatus::LegalHold,
        ProfileStatus::ClosureRequested,
        ProfileStatus::Closed,
    ] {
        let created = service
            .create_user(provisioned(create_user_request(&unique_username())))
            .await
            .unwrap()
            .into_inner();
        let profile_id = account_of(&storage, &created.id).await;
        let mut profile = storage.get_profile(profile_id).await.unwrap().unwrap();
        profile.status = held;
        assert!(
            storage
                .update_profile(
                    &profile,
                    sid_core::models::AuditEntry::system("test.state", profile_id.to_string())
                        .into(),
                )
                .await
                .unwrap()
        );

        service
            .delete_user(provisioned(proto::ScimDeleteUserRequest {
                id: created.id.clone(),
            }))
            .await
            .unwrap_or_else(|e| panic!("delete of a {held} account: {e:?}"));

        assert_eq!(
            storage
                .get_profile(profile_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            held,
            "a deletion rewrote the account's state"
        );
        let resource = storage
            .find_directory_user(sid_core::models::DirectoryUserId::parse(&created.id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(
            !resource.is_live(),
            "the resource of a {held} account stays"
        );
    }
}

/// Regression: a client that deletes a user and then removes it from its
/// groups was refused, with every other change of that PATCH: a member was
/// accepted only while its resource was live. A removal names a deleted
/// user too, and withdraws the membership; an id never assigned is still no
/// user, and a deleted user is still not added.
#[tokio::test]
async fn test_group_removal_of_a_deleted_user() {
    let (service, storage) = setup().await;
    let created = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    let group = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("RemovalGroup_{}", Uuid::now_v7().simple()),
            members: vec![proto::ScimMemberRef {
                value: created.id.clone(),
                display: String::new(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();
    let group_id = GroupId::parse(&group.id).unwrap();
    service
        .delete_user(provisioned(proto::ScimDeleteUserRequest {
            id: created.id.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(storage.list_group_members(group_id).await.unwrap().len(), 1);

    let remove = |id: String| proto::ScimPatchOp {
        op: "remove".into(),
        path: format!(r#"members[value eq "{id}"]"#),
        value: String::new(),
    };
    let renamed = format!("Renamed_{}", Uuid::now_v7().simple());
    let patched = service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![
                remove(created.id.clone()),
                proto::ScimPatchOp {
                    op: "replace".into(),
                    path: "displayName".into(),
                    value: renamed.clone(),
                },
            ],
        }))
        .await
        .expect("a deleted user is removed from its group")
        .into_inner();
    assert_eq!(patched.display_name, renamed);
    assert!(patched.members.is_empty());
    assert!(
        storage
            .list_group_members(group_id)
            .await
            .unwrap()
            .is_empty(),
        "the membership of the deleted user stays"
    );
    // A repeat changes nothing and succeeds.
    service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![remove(created.id.clone())],
        }))
        .await
        .expect("a repeated removal");

    // An identifier the directory never assigned names no user.
    let unknown = service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![remove(Uuid::now_v7().to_string())],
        }))
        .await
        .expect_err("an unknown member is removed");
    assert_eq!(unknown.code(), tonic::Code::InvalidArgument);
    // And a deleted user is still not added.
    let added = service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "add".into(),
                path: "members".into(),
                value: format!(r#"[{{"value":"{}"}}]"#, created.id),
            }],
        }))
        .await
        .expect_err("a deleted user is added");
    assert_eq!(added.code(), tonic::Code::InvalidArgument);
}

/// Regression: `active=false` by PUT or PATCH wrote `Suspended` over a legal
/// hold or a closure under way, as DELETE did. A deactivation keeps such a
/// state, and ends the account's access all the same.
#[tokio::test]
async fn test_deactivation_keeps_a_hold_and_a_closure() {
    let (service, storage, revocation) = setup_with_revocation().await;
    for held in [ProfileStatus::LegalHold, ProfileStatus::ClosureRequested] {
        for by_put in [true, false] {
            let (id, profile_id, session, pat) = signed_in_employee(&service, &storage).await;
            let created = service
                .get_user(provisioned(proto::ScimGetUserRequest { id }))
                .await
                .unwrap()
                .into_inner();
            let username = created.user_name.clone();
            let mut profile = storage.get_profile(profile_id).await.unwrap().unwrap();
            profile.status = held;
            assert!(
                storage
                    .update_profile(
                        &profile,
                        sid_core::models::AuditEntry::system("test.state", profile_id.to_string())
                            .into(),
                    )
                    .await
                    .unwrap()
            );

            if by_put {
                service
                    .replace_user(provisioned(proto::ScimReplaceUserRequest {
                        id: created.id.clone(),
                        user_name: username.clone(),
                        active: false,
                        ..Default::default()
                    }))
                    .await
                    .unwrap_or_else(|e| panic!("PUT on a {held} account: {e:?}"));
            } else {
                service
                    .patch_user(provisioned(proto::ScimPatchUserRequest {
                        id: created.id.clone(),
                        operations: vec![proto::ScimPatchOp {
                            op: "replace".into(),
                            path: "active".into(),
                            value: "false".into(),
                        }],
                    }))
                    .await
                    .unwrap_or_else(|e| panic!("PATCH on a {held} account: {e:?}"));
            }
            assert_eq!(
                storage
                    .get_profile(profile_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                held,
                "a deactivation (PUT: {by_put}) rewrote the account's state"
            );
            assert_access_ended(&storage, &revocation, &session, &pat).await;
            // The client reads back what it asked for: the user is inactive,
            // in its representation and for a filter alike.
            let read = service
                .get_user(provisioned(proto::ScimGetUserRequest {
                    id: created.id.clone(),
                }))
                .await
                .unwrap()
                .into_inner();
            assert!(!read.active, "a deactivated {held} account reads as active");
            let listed = service
                .list_users(provisioned(proto::ScimListUsersRequest {
                    filter: format!(r#"userName eq "{}" and active eq false"#, read.user_name),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                listed.total_results, 1,
                "a deactivated {held} account is not found inactive"
            );
        }
    }
}

/// `active=false` is not a deletion: the user stays addressable, inactive.
#[tokio::test]
async fn test_deactivated_user_stays_addressable() {
    let (service, _storage) = setup().await;
    let created = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "false".into(),
            }],
        }))
        .await
        .expect("deactivation");
    let read = service
        .get_user(provisioned(proto::ScimGetUserRequest {
            id: created.id.clone(),
        }))
        .await
        .expect("a deactivated user is read")
        .into_inner();
    assert_eq!(read.id, created.id);
    assert!(!read.active);
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let (service, _) = setup().await;

    let err = service
        .delete_user(provisioned(proto::ScimDeleteUserRequest {
            id: Uuid::now_v7().to_string(),
        }))
        .await
        .expect_err("should return not found");

    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ─── Group CRUD ───

#[tokio::test]
async fn test_create_group_and_get() {
    let (service, _storage) = setup().await;

    let response = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("TestGroup_{}", Uuid::now_v7().simple()),
            members: vec![],
        }))
        .await
        .expect("create_group failed");

    let group = response.into_inner();
    assert!(!group.id.is_empty());
    assert!(group.display_name.starts_with("TestGroup_"));
    assert!(group.meta.is_some());

    // Get it back
    let fetched = service
        .get_group(provisioned(proto::ScimGetGroupRequest {
            id: group.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(fetched.id, group.id);
    assert_eq!(fetched.display_name, group.display_name);
}

#[tokio::test]
async fn test_group_add_and_remove_members() {
    let (service, storage) = setup().await;
    let username = unique_username();

    // Create a user first
    let user = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    // Create group
    let group = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("TestGroup_{}", Uuid::now_v7().simple()),
            members: vec![],
        }))
        .await
        .unwrap()
        .into_inner();

    // Add member via PATCH
    let patched = service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "add".into(),
                path: "members".into(),
                value: format!(r#"[{{"value":"{}"}}]"#, user.id),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(patched.members.len(), 1);
    assert_eq!(patched.members[0].value, user.id);

    // Verify in DB
    let group_id = GroupId::parse(&group.id).unwrap();
    let members = storage.list_group_members(group_id).await.unwrap();
    assert_eq!(members.len(), 1);

    // Remove member via PATCH
    let patched = service
        .patch_group(provisioned(proto::ScimPatchGroupRequest {
            id: group.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "remove".into(),
                path: format!(r#"members[value eq "{}"]"#, user.id),
                value: String::new(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(patched.members.len(), 0);

    let members = storage.list_group_members(group_id).await.unwrap();
    assert_eq!(members.len(), 0);
}

#[tokio::test]
async fn test_delete_group() {
    let (service, storage) = setup().await;

    let group = service
        .create_group(provisioned(proto::ScimCreateGroupRequest {
            display_name: format!("DeleteMe_{}", Uuid::now_v7().simple()),
            members: vec![],
        }))
        .await
        .unwrap()
        .into_inner();

    let group_id = GroupId::parse(&group.id).unwrap();

    service
        .delete_group(provisioned(proto::ScimDeleteGroupRequest {
            id: group.id.clone(),
        }))
        .await
        .expect("delete_group failed");

    let deleted = storage.get_group(group_id).await.unwrap();
    assert!(deleted.is_none());
}

// ─── Discovery Endpoints ───

#[tokio::test]
async fn test_service_provider_config() {
    let (service, _) = setup().await;

    let response = service
        .get_service_provider_config(provisioned(proto::ScimGetServiceProviderConfigRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert!(response.patch.unwrap().supported);
    assert!(!response.bulk.unwrap().supported);
    assert!(response.filter.unwrap().supported);
    assert!(!response.change_password.unwrap().supported);
    assert_eq!(response.authentication_schemes.len(), 1);
    assert_eq!(
        response.authentication_schemes[0].r#type,
        "oauthbearertoken"
    );
}

#[tokio::test]
async fn test_resource_types() {
    let (service, _) = setup().await;

    let response = service
        .get_resource_types(provisioned(proto::ScimGetResourceTypesRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.resources.len(), 2);
    let names: Vec<&str> = response.resources.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"User"));
    assert!(names.contains(&"Group"));

    // RFC 7643 §6: the User type names the enterprise extension as optional
    // and the schemas listing describes it; Group has no extension.
    let extensions = |name: &str| {
        let resource = response.resources.iter().find(|r| r.name == name).unwrap();
        resource
            .schema_extensions
            .iter()
            .map(|e| (e.schema.clone(), e.required))
            .collect::<Vec<_>>()
    };
    let enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    assert_eq!(extensions("User"), [(enterprise.to_owned(), false)]);
    assert!(extensions("Group").is_empty());
    let schemas = service
        .get_schemas(provisioned(proto::ScimGetSchemasRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(schemas.resources.iter().any(|s| s.id == enterprise));
}

#[tokio::test]
async fn test_schemas() {
    let (service, _) = setup().await;

    let response = service
        .get_schemas(provisioned(proto::ScimGetSchemasRequest {}))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.resources.len(), 3);
    // The enterprise extension's attributes are served under its own URI.
    let enterprise: Vec<&str> = response
        .resources
        .iter()
        .find(|s| s.id == "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
        .expect("the enterprise User schema is listed")
        .attributes
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(enterprise, ["employeeNumber", "department"]);
    let user_schema = response
        .resources
        .iter()
        .find(|s| s.name == "User")
        .expect("User schema missing");
    assert!(!user_schema.attributes.is_empty());

    let group_schema = response
        .resources
        .iter()
        .find(|s| s.name == "Group")
        .expect("Group schema missing");
    assert!(!group_schema.attributes.is_empty());
}

// ─── Full Lifecycle: Joiner → Mover → Leaver ───

#[tokio::test]
async fn test_joiner_mover_leaver_lifecycle() {
    let (service, storage) = setup().await;
    let username = unique_username();

    // 1. JOINER: HR creates employee
    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Verify: Provisioned, Corporate, identifiers correct
    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Provisioned);
    assert_eq!(profile.profile_type, ProfileType::Corporate);

    // 2. MOVER: Employee transfers departments
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![
                proto::ScimPatchOp {
                    op: "replace".into(),
                    path: "department".into(),
                    value: "Sales".into(),
                },
                proto::ScimPatchOp {
                    op: "replace".into(),
                    path: "title".into(),
                    value: "Sales Lead".into(),
                },
            ],
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(patched.department, "Sales");
    assert_eq!(patched.title, "Sales Lead");

    // 3. LEAVER: Employee deactivated
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "false".into(),
            }],
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(!patched.active);

    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Suspended);

    // Principals still exist (can be reactivated)
    let principals = storage.get_principals_by_profile(profile_id).await.unwrap();
    assert!(!principals.is_empty());
}

/// Provisioned profile that was suspended and reactivated via SCIM
/// MUST return to Provisioned — NOT Active.
/// Active requires secure channel claim (the user binds an OPAQUE password).
#[tokio::test]
async fn test_provisioned_suspend_reactivate_returns_to_provisioned() {
    let (service, storage) = setup().await;
    let username = unique_username();

    // Create provisioned profile
    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Verify starts Provisioned
    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Provisioned);

    // Suspend via PATCH
    service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "false".into(),
            }],
        }))
        .await
        .unwrap();

    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Suspended);

    // Reactivate via PATCH — MUST return to Provisioned, NOT Active
    service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "true".into(),
            }],
        }))
        .await
        .unwrap();

    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(
        profile.status,
        ProfileStatus::Provisioned,
        "Unclaimed profile must return to Provisioned, not Active. \
         Active requires secure channel claim."
    );
}

/// Same test via replace_user (PUT)
#[tokio::test]
async fn test_provisioned_suspend_reactivate_via_put_returns_to_provisioned() {
    let (service, storage) = setup().await;
    let username = unique_username();

    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();

    let profile_id = account_of(&storage, &created.id).await;

    // Suspend via PUT active=false
    service
        .replace_user(provisioned(proto::ScimReplaceUserRequest {
            id: created.id.clone(),
            user_name: username.clone(),
            active: false,
            ..Default::default()
        }))
        .await
        .unwrap();

    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(profile.status, ProfileStatus::Suspended);

    // Reactivate via PUT active=true
    service
        .replace_user(provisioned(proto::ScimReplaceUserRequest {
            id: created.id.clone(),
            user_name: username.clone(),
            active: true,
            ..Default::default()
        }))
        .await
        .unwrap();

    let profile = storage.get_profile(profile_id).await.unwrap().unwrap();
    assert_eq!(
        profile.status,
        ProfileStatus::Provisioned,
        "PUT reactivation of unclaimed profile must return to Provisioned"
    );
}

// ─── Authorization ───

/// Regression:without a token nobody creates corporate accounts, lists
/// the directory or deactivates a user.
#[tokio::test]
async fn test_scim_requires_a_token() {
    let (service, storage) = setup().await;
    let username = unique_username();
    let err = service
        .create_user(<Request<_>>::new(create_user_request(&username)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let corporate_login = format!("{username}#acme.corp");
    assert!(
        storage
            .get_profile_by_principal(PrincipalType::Username, &corporate_login)
            .await
            .unwrap()
            .is_none(),
        "nothing created"
    );

    let err = service
        .list_users(<Request<_>>::new(proto::ScimListUsersRequest::default()))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// Regression:a user's sign-in is no connector credential. Neither
/// a user's nor an administrator's access token provisions or deactivates
/// an account; nothing is created.
#[tokio::test]
async fn test_scim_refuses_a_sign_in_token() {
    let (service, storage) = setup().await;
    let created = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    let mut administrator = Profile::new(Some("scim-admin"));
    administrator.roles = vec!["admin".to_string()];
    for token in [
        token_for(&Profile::new(Some("mallory"))),
        token_for(&administrator),
    ] {
        let username = unique_username();
        let err = service
            .create_user(with_token(create_user_request(&username), &token))
            .await
            .expect_err("a sign-in token provisioned");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(
            storage
                .get_profile_by_principal(PrincipalType::Username, &format!("{username}#acme.corp"))
                .await
                .unwrap()
                .is_none()
        );
        let err = service
            .delete_user(with_token(
                proto::ScimDeleteUserRequest {
                    id: created.id.clone(),
                },
                &token,
            ))
            .await
            .expect_err("a sign-in token deactivated");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}

/// A connector acts only through the roles it holds on this directory:
/// one with read alone cannot create, one whose role lies on another
/// resource can do nothing here, and one of another organization is not
/// authenticated at all.
#[tokio::test]
async fn test_scim_connector_is_held_to_its_grants() {
    let (service, storage, _, directory) = setup_directory().await;
    let reader = connector_secret(&storage, directory, &[SCIM_USER_READ]).await;
    let elsewhere = connector_secret(
        &storage,
        ScimDirectory {
            org: directory.org,
            resource: ResourceId::generate(),
        },
        &SCIM_ACTIONS,
    )
    .await;
    let foreign = connector_secret(
        &storage,
        ScimDirectory {
            org: OrgId::generate(),
            resource: directory.resource,
        },
        &SCIM_ACTIONS,
    )
    .await;

    service
        .list_users(with_token(proto::ScimListUsersRequest::default(), &reader))
        .await
        .expect("a reader lists users");
    for (token, code) in [
        (&reader, tonic::Code::PermissionDenied),
        (&elsewhere, tonic::Code::PermissionDenied),
        (&foreign, tonic::Code::Unauthenticated),
    ] {
        let err = service
            .create_user(with_token(create_user_request(&unique_username()), token))
            .await
            .expect_err("created without the grant");
        assert_eq!(err.code(), code, "{err:?}");
    }
    let err = service
        .list_users(with_token(
            proto::ScimListUsersRequest::default(),
            &elsewhere,
        ))
        .await
        .expect_err("a role on another resource reads this directory");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

/// A group created with members, or patched to change them, needs the
/// membership action beside the group action.
#[tokio::test]
async fn test_scim_membership_needs_its_own_grant() {
    let (service, storage, _, directory) = setup_directory().await;
    let member = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    let no_membership = connector_secret(
        &storage,
        directory,
        &[SCIM_GROUP_CREATE, SCIM_GROUP_UPDATE, SCIM_GROUP_READ],
    )
    .await;
    let with_member = proto::ScimCreateGroupRequest {
        display_name: format!("g-{}", Uuid::now_v7().simple()),
        members: vec![proto::ScimMemberRef {
            value: member.id.clone(),
            ..Default::default()
        }],
    };
    let err = service
        .create_group(with_token(with_member, &no_membership))
        .await
        .expect_err("members set without the membership grant");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let group = service
        .create_group(with_token(
            proto::ScimCreateGroupRequest {
                display_name: format!("g-{}", Uuid::now_v7().simple()),
                ..Default::default()
            },
            &no_membership,
        ))
        .await
        .expect("an empty group needs no membership grant")
        .into_inner();
    let err = service
        .patch_group(with_token(
            proto::ScimPatchGroupRequest {
                id: group.id.clone(),
                operations: vec![proto::ScimPatchOp {
                    op: "add".into(),
                    path: "members".into(),
                    value: format!(r#"[{{"value":"{}"}}]"#, member.id),
                }],
            },
            &no_membership,
        ))
        .await
        .expect_err("members added without the membership grant");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        storage
            .list_group_members(GroupId::parse(&group.id).unwrap())
            .await
            .unwrap()
            .is_empty()
    );
}

/// Every SCIM write is attributed to the connector and the credential it
/// used, never to "system".
#[tokio::test]
async fn test_scim_writes_are_attributed_to_the_connector() {
    let (service, storage) = setup().await;
    let created = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    // The installation's audit names the account the write changed.
    let account = account_of(&storage, &created.id).await.to_string();
    let pool = storage_pool().await;
    let (actor_type, actor_id, metadata): (String, String, serde_json::Value) = sqlx::query_as(
        "SELECT actor_type, actor_id, metadata FROM audit_records \
         WHERE action = 'scim.user.create' AND resource = $1",
    )
    .bind(&account)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actor_type, "connector");
    assert!(
        ProvisioningConnectorId::parse(&actor_id).is_ok(),
        "{actor_id}"
    );
    assert!(metadata["credential_id"].is_string(), "{metadata}");
    assert_eq!(metadata["direction"], "inbound");
}

/// A signed-in session and a PAT of a freshly provisioned employee.
async fn signed_in_employee(
    service: &ScimServiceImpl,
    storage: &Arc<dyn StorageBackend>,
) -> (
    String,
    ProfileId,
    Session,
    sid_core::models::PersonalAccessToken,
) {
    let created = service
        .create_user(provisioned(create_user_request(&unique_username())))
        .await
        .unwrap()
        .into_inner();
    let profile_id = account_of(storage, &created.id).await;
    let (session, pat) = sign_in(storage, profile_id).await;
    (created.id, profile_id, session, pat)
}

/// A signed-in session and a PAT of the account `profile_id`.
async fn sign_in(
    storage: &Arc<dyn StorageBackend>,
    profile_id: ProfileId,
) -> (Session, sid_core::models::PersonalAccessToken) {
    let session = Session::new(
        profile_id,
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "s").into(),
        )
        .await
        .unwrap();
    let pat = sid_core::models::PersonalAccessToken::new(
        profile_id,
        "ci",
        format!("hash-{}", Uuid::now_v7().simple()),
        format!("sid_pat_{}", &Uuid::now_v7().simple().to_string()[..8]),
        vec![],
    );
    storage
        .create_pat(
            &pat,
            None,
            sid_core::models::AuditEntry::system("test", "p").into(),
        )
        .await
        .unwrap();
    (session, pat)
}

/// The organization's login of a user (`userName`, RFC 7643 8.7.1
/// `readWrite`) is renamed by a connector its manager delegated that to, by
/// PUT and by PATCH alike. The user keeps its id and the connector's own
/// identifier of it, and the name it leaves is free at once for another
/// user, who is another resource. Without the delegation the rename is
/// refused, a name held by another user conflicts, and neither writes any
/// part of its request. The value restated, in any letter case (it is not
/// case-exact), is no change.
#[tokio::test]
async fn test_user_name_is_renamed_by_delegation() {
    let (service, storage, _, directory) = setup_directory().await;
    let schemas = service
        .get_schemas(provisioned(proto::ScimGetSchemasRequest {}))
        .await
        .unwrap()
        .into_inner();
    let declared = schemas
        .resources
        .iter()
        .find(|schema| schema.name == "User")
        .and_then(|schema| schema.attributes.iter().find(|a| a.name == "userName"))
        .expect("the User schema declares userName");
    assert_eq!(declared.mutability, "readWrite");

    let username = unique_username();
    let created = service
        .create_user(provisioned(create_user_request(&username)))
        .await
        .unwrap()
        .into_inner();
    let replace = |user_name: &str, title: &str| proto::ScimReplaceUserRequest {
        id: created.id.clone(),
        external_id: created.external_id.clone(),
        user_name: user_name.into(),
        name: created.name.clone(),
        emails: created.emails.clone(),
        phone_numbers: created.phone_numbers.clone(),
        active: true,
        department: created.department.clone(),
        title: title.into(),
        ..Default::default()
    };
    let read = async || {
        service
            .get_user(provisioned(proto::ScimGetUserRequest {
                id: created.id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
    };

    // Every other part of the user, but not its login.
    let rights: Vec<_> = DirectoryRight::ALL
        .into_iter()
        .filter(|right| *right != DirectoryRight::UserName)
        .collect();
    let (_, undelegated) = connector_managing(
        &storage,
        directory,
        &SCIM_ACTIONS,
        DirectoryRights::of(&rights),
    )
    .await;
    let refused = service
        .replace_user(with_token(
            // It is no source of the user and names no identifier of it.
            proto::ScimReplaceUserRequest {
                external_id: String::new(),
                ..replace(&unique_username(), "Refused")
            },
            &undelegated,
        ))
        .await
        .expect_err("the login is not this connector's to rename");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(read().await.user_name, username);
    assert_eq!(
        read().await.title,
        "Engineer",
        "a refused request writes nothing"
    );

    // Restated in another case: no rename, the rest of the request applies.
    let restated = service
        .replace_user(with_token(
            proto::ScimReplaceUserRequest {
                external_id: String::new(),
                ..replace(&username.to_uppercase(), "Restated")
            },
            &undelegated,
        ))
        .await
        .expect("the userName restated")
        .into_inner();
    assert_eq!(restated.user_name, username);
    assert_eq!(restated.title, "Restated");

    // A name another user holds conflicts and nothing is written.
    let other = unique_username();
    service
        .create_user(provisioned(create_user_request(&other)))
        .await
        .unwrap();
    let taken = service
        .replace_user(provisioned(replace(&other, "Conflict")))
        .await
        .expect_err("the name is held by another user");
    assert_eq!(taken.code(), tonic::Code::AlreadyExists);
    assert_eq!(read().await.user_name, username);
    assert_eq!(read().await.title, "Restated");

    // Renamed by PUT: same resource, same identifier of its source.
    let renamed = unique_username();
    let replaced = service
        .replace_user(provisioned(replace(&renamed, "Restated")))
        .await
        .expect("the delegated connector renames the login")
        .into_inner();
    assert_eq!(replaced.user_name, renamed);
    assert_eq!(replaced.id, created.id);
    assert_eq!(replaced.external_id, created.external_id);
    assert!(
        storage
            .get_principal_by_value(PrincipalType::Username, &format!("{username}#acme.corp"))
            .await
            .unwrap()
            .is_none(),
        "the old login still resolves"
    );

    // The name it left is free at once, for a user of its own.
    let successor = service
        .create_user(provisioned(proto::ScimCreateUserRequest {
            external_id: format!("EMP-next-{username}"),
            ..create_user_request(&username)
        }))
        .await
        .expect("the released name is assigned again")
        .into_inner();
    assert_ne!(successor.id, created.id);

    // And by PATCH, through the same path.
    let again = unique_username();
    let patched = service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id: created.id.clone(),
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "userName".into(),
                value: again.clone(),
            }],
        }))
        .await
        .expect("PATCH renames the login")
        .into_inner();
    assert_eq!(patched.user_name, again);
    assert_eq!(patched.id, created.id);
}

/// A connector manages what its manager selected and nothing else: a change
/// outside it is refused, a request mixing both is refused whole and writes
/// nothing, and a value restated takes no right. Deleting a managed account
/// ends its access, so the right to delete alone does not do it.
#[tokio::test]
async fn test_connector_changes_only_what_it_manages() {
    let (service, storage, revocation, directory) = setup_directory().await;
    let managing = async |rights: &[DirectoryRight]| {
        connector_managing(
            &storage,
            directory,
            &SCIM_ACTIONS,
            DirectoryRights::of(rights),
        )
        .await
        .1
    };
    let titles = managing(&[DirectoryRight::Title]).await;
    let (id, _, session, pat) = signed_in_employee(&service, &storage).await;
    let op = |path: &str, value: &str| proto::ScimPatchOp {
        op: "replace".into(),
        path: path.into(),
        value: value.into(),
    };
    let patch = |operations: Vec<proto::ScimPatchOp>| proto::ScimPatchUserRequest {
        id: id.clone(),
        operations,
    };
    let read = async || {
        service
            .get_user(provisioned(proto::ScimGetUserRequest { id: id.clone() }))
            .await
            .unwrap()
            .into_inner()
    };

    let patched = service
        .patch_user(with_token(patch(vec![op("title", "Lead")]), &titles))
        .await
        .expect("the title is the connector's to change")
        .into_inner();
    assert_eq!(patched.title, "Lead");

    for operations in [
        vec![op("department", "Sales")],
        vec![op("name.givenName", "Renamed")],
        vec![op("active", "false")],
        // What it manages, with what it does not: nothing of it is written.
        vec![op("title", "Chief"), op("department", "Sales")],
    ] {
        let refused = service
            .patch_user(with_token(patch(operations.clone()), &titles))
            .await
            .expect_err("a change outside what the connector manages");
        assert_eq!(
            refused.code(),
            tonic::Code::PermissionDenied,
            "{operations:?}"
        );
    }
    let refused = service
        .delete_user(with_token(
            proto::ScimDeleteUserRequest { id: id.clone() },
            &titles,
        ))
        .await
        .expect_err("the user is not the connector's to delete");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    let kept = read().await;
    assert_eq!(kept.title, "Lead");
    assert_eq!(kept.department, "Engineering");
    assert_eq!(kept.name.as_ref().unwrap().given_name, "Test");
    assert!(kept.active);

    // A value the user already has is no change of it.
    service
        .patch_user(with_token(
            patch(vec![op("department", "Engineering"), op("active", "true")]),
            &titles,
        ))
        .await
        .expect("a restated value takes no right");

    // Deleting an account the directory manages whole is its offboarding:
    // without the right to deactivate it nothing is written.
    let deleting = managing(&[DirectoryRight::Delete]).await;
    let refused = service
        .delete_user(with_token(
            proto::ScimDeleteUserRequest { id: id.clone() },
            &deleting,
        ))
        .await
        .expect_err("a deletion that would end access it may not end");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert!(read().await.active);
    assert!(storage.get_session(session.id).await.unwrap().is_some());

    let offboarding = managing(&[DirectoryRight::Delete, DirectoryRight::Active]).await;
    service
        .delete_user(with_token(
            proto::ScimDeleteUserRequest { id: id.clone() },
            &offboarding,
        ))
        .await
        .expect("the whole offboarding is the connector's");
    assert_access_ended(&storage, &revocation, &session, &pat).await;
}

/// A user that is an identity signing in elsewhere is a relationship, not
/// an account of the directory: deactivating it is the relationship's own
/// state, shown the same by a read and a filter, and deleting it ends the
/// relationship. Neither suspends the identity or ends its sign-ins, and the
/// right to delete is enough for the deletion.
#[tokio::test]
async fn test_relationship_ends_without_the_identity() {
    let (service, storage, _, directory) = setup_directory().await;
    let mut identity = Profile::new(None::<String>);
    identity.profile_type = ProfileType::Federated;
    identity.status = ProfileStatus::Active;
    storage
        .create_profile(&identity, AuditEntry::system("test", "identity").into())
        .await
        .unwrap();
    let resource = storage.directory_users_of(&[identity.id]).await.unwrap()[0];
    let id = resource.id.to_string();
    let (session, pat) = sign_in(&storage, identity.id).await;
    let set_active = async |value: &str| {
        service
            .patch_user(provisioned(proto::ScimPatchUserRequest {
                id: id.clone(),
                operations: vec![proto::ScimPatchOp {
                    op: "replace".into(),
                    path: "active".into(),
                    value: value.into(),
                }],
            }))
            .await
            .unwrap()
            .into_inner()
    };
    let found_inactive = async || {
        service
            .list_users(provisioned(proto::ScimListUsersRequest {
                filter: "active eq false".into(),
                start_index: 1,
                count: 1000,
            }))
            .await
            .unwrap()
            .into_inner()
            .resources
            .iter()
            .any(|user| user.id == id)
    };
    let untouched = async || {
        let account = storage.get_profile(identity.id).await.unwrap().unwrap();
        assert_eq!(account.status, ProfileStatus::Active);
        assert!(storage.get_session(session.id).await.unwrap().is_some());
        assert!(storage.get_pat(pat.id).await.unwrap().unwrap().is_usable());
    };

    assert!(!set_active("false").await.active);
    let read = service
        .get_user(provisioned(proto::ScimGetUserRequest { id: id.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert!(!read.active);
    assert!(found_inactive().await);
    untouched().await;

    assert!(set_active("true").await.active);
    assert!(!found_inactive().await);

    let deleting = connector_managing(
        &storage,
        directory,
        &SCIM_ACTIONS,
        DirectoryRights::of(&[DirectoryRight::Delete]),
    )
    .await
    .1;
    service
        .delete_user(with_token(
            proto::ScimDeleteUserRequest { id: id.clone() },
            &deleting,
        ))
        .await
        .expect("the relationship is the connector's to end");
    untouched().await;
    let gone = service
        .get_user(provisioned(proto::ScimGetUserRequest { id: id.clone() }))
        .await
        .expect_err("a deleted resource is served by no read");
    assert_eq!(gone.code(), tonic::Code::NotFound);
}

/// Asserts the employee can no longer use the session or the PAT.
async fn assert_access_ended(
    storage: &Arc<dyn StorageBackend>,
    revocation: &RevocationCache,
    session: &Session,
    pat: &sid_core::models::PersonalAccessToken,
) {
    assert!(
        storage.get_session(session.id).await.unwrap().is_none(),
        "session must be gone"
    );
    assert!(
        revocation
            .is_revoked("", &session.id.to_string())
            .await
            .unwrap(),
        "access tokens of the session must be refused at once"
    );
    let pat = storage.get_pat(pat.id).await.unwrap().unwrap();
    assert!(!pat.is_usable(), "PAT must be revoked");
}

/// Regression:SCIM deprovisioning (DELETE, PUT active=false, PATCH
/// active=false) ends every live sign-in of the employee at once. Before, it
/// only set the status and published an event nobody acted on, so sessions,
/// refresh tokens and PATs kept working until they expired.
#[tokio::test]
async fn test_scim_deactivation_ends_sessions_and_pats() {
    let (service, storage, revocation) = setup_with_revocation().await;

    // DELETE
    let (id, _, session, pat) = signed_in_employee(&service, &storage).await;
    service
        .delete_user(provisioned(proto::ScimDeleteUserRequest { id }))
        .await
        .unwrap();
    assert_access_ended(&storage, &revocation, &session, &pat).await;

    // PUT active=false
    let (id, _, session, pat) = signed_in_employee(&service, &storage).await;
    let held = service
        .get_user(provisioned(proto::ScimGetUserRequest { id: id.clone() }))
        .await
        .unwrap()
        .into_inner();
    let mut replace = create_user_request(&unique_username());
    replace.active = false;
    service
        .replace_user(provisioned(proto::ScimReplaceUserRequest {
            id,
            external_id: replace.external_id,
            // The login handle is the user's own; the rest is replaced.
            user_name: held.user_name,
            name: replace.name,
            display_name: replace.display_name,
            emails: replace.emails,
            phone_numbers: replace.phone_numbers,
            department: replace.department,
            title: replace.title,
            active: false,
            employee_number: replace.employee_number,
        }))
        .await
        .unwrap();
    assert_access_ended(&storage, &revocation, &session, &pat).await;

    // PATCH active=false
    let (id, profile_id, session, pat) = signed_in_employee(&service, &storage).await;
    service
        .patch_user(provisioned(proto::ScimPatchUserRequest {
            id,
            operations: vec![proto::ScimPatchOp {
                op: "replace".into(),
                path: "active".into(),
                value: "false".into(),
            }],
        }))
        .await
        .unwrap();
    assert_eq!(
        storage
            .get_profile(profile_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ProfileStatus::Suspended
    );
    assert_access_ended(&storage, &revocation, &session, &pat).await;
}
