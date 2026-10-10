// SPDX-License-Identifier: AGPL-3.0-only
//! Shared test functions for StorageBackend implementations.
//!
//! Each function takes `&dyn StorageBackend` — the same test logic runs
//! against both PostgreSQL and SQLite backends to verify trait compliance.

use chrono::{Duration, Utc};
use sid_core::models::{
    AuditEntry, AuthCodeRedemption, AuthorizationCode, LoginStrategy, MutationContext,
    OAuth2Client, PolicyEvidence, Principal, PrincipalId, PrincipalType, Profile, ProfileId,
    ProjectId, RefreshToken, Session,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

pub mod admin_claim;
pub mod application;
pub mod audit_retention;
pub mod branding;
pub mod browser_session;
pub mod cleanup;
pub mod config;
pub mod consent;
pub mod device;
pub mod device_auth;
pub mod directory;
pub mod email_policy;
pub mod export_job;
pub mod flow_action;
pub mod group;
pub mod history_keys;
pub mod job_lock;
pub mod machine;
pub mod oidc_issuer;
pub mod operation;
pub mod organization;
pub mod password_history;
pub mod principal_assignment;
pub mod project;
pub mod provisioning_connector;
pub mod role;
pub mod service_binding;
pub mod session;
pub mod session_elevation;
pub mod upstream;
pub mod webauthn_user_handle;
pub mod work;

// ─── Builders ───

pub fn test_audit() -> MutationContext {
    AuditEntry::system("test", "test-resource").into()
}

/// The backend's installation organization, created by the first test that
/// needs one: clients reference an existing organization.
pub async fn instance_org(backend: &dyn StorageBackend) -> sid_core::models::OrgId {
    let org = sid_core::models::Organization::implicit_community("sid.example.com");
    backend
        .insert_instance_organization(&org, test_audit())
        .await
        .unwrap();
    backend.instance_organization().await.unwrap().unwrap().id
}

pub fn test_session_end() -> sid_core::models::SessionEnd {
    sid_core::models::SessionEnd::new(sid_core::models::RevocationReason::Admin, "system")
}

pub fn create_test_profile(username: &str) -> Profile {
    use sid_core::models::{ProfileAssurance, ProfileStatus, ProfileType, ProfileVisibility};
    let now = Utc::now();
    let unique = format!("{}_{}", username, Uuid::now_v7().simple());
    Profile {
        id: ProfileId::generate(),
        profile_type: ProfileType::Personal,
        username: Some(unique.clone()),
        given_name: Some(format!("Test {}", username)),
        family_name: Some("User".to_string()),
        middle_name: None,
        honorific_prefix: None,
        honorific_suffix: None,
        roles: vec![],
        status: ProfileStatus::Active,
        visibility: ProfileVisibility::Public,
        max_assurance: ProfileAssurance::Anonymous,
        manager_id: None,
        migration_pending: false,
        migration_started_at: None,
        migration_completed_at: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

pub fn create_test_session(profile_id: ProfileId) -> Session {
    Session::new(
        profile_id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    )
}

pub fn create_test_oauth2_client(client_id: &str) -> OAuth2Client {
    OAuth2Client {
        client_id: client_id.to_string(),
        project_id: ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: sid_core::models::ApplicationType::default(),
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: "Test Client".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: sid_core::models::TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: sid_core::models::SubjectType::Pairwise,
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
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: None,
        revision: 0,
        created_at: Utc::now(),
    }
}

// ─── Profile CRUD ───

pub async fn test_profile_create_and_get(backend: &dyn StorageBackend) {
    let profile = create_test_profile("create");
    backend
        .create_profile(&profile, test_audit())
        .await
        .expect("save failed");

    let retrieved = backend.get_profile(profile.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, profile.id);
    assert_eq!(retrieved.username, profile.username);
    assert_eq!(retrieved.given_name, profile.given_name);
    assert_eq!(retrieved.family_name, profile.family_name);
    assert_eq!(retrieved.status, profile.status);
}

pub async fn test_profile_get_by_username(backend: &dyn StorageBackend) {
    let profile = create_test_profile("username");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_profile_by_username(profile.username.as_deref().unwrap())
        .await
        .unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, profile.id);
}

pub async fn test_profile_get_by_email(backend: &dyn StorageBackend) {
    use sid_core::models::{EmailLabel, ProfileEmail, ProfileEmailId};
    let profile = create_test_profile("email");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email_addr = format!("{}@example.com", profile.username.as_deref().unwrap());
    let pe = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: email_addr.clone(),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_email(&pe, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_profile_by_email(&email_addr).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, profile.id);
}

pub async fn test_profile_get_nonexistent(backend: &dyn StorageBackend) {
    let result = backend.get_profile(ProfileId::generate()).await.unwrap();
    assert!(result.is_none());
}

pub async fn test_profile_get_by_email_not_found(backend: &dyn StorageBackend) {
    let result = backend
        .get_profile_by_email("nonexistent@sid.example.com")
        .await
        .unwrap();
    assert!(result.is_none());
}

pub async fn test_profile_get_by_username_not_found(backend: &dyn StorageBackend) {
    let result = backend
        .get_profile_by_username("nonexistent_user_12345")
        .await
        .unwrap();
    assert!(result.is_none());
}

/// An update applies over the revision it read and moves it on. A copy read
/// before a suspension cannot write the account back to active, a create
/// never replaces a stored profile, and a deleted profile is never recreated.
pub async fn test_profile_update(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileStatus;

    let mut profile = create_test_profile("update");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    profile.given_name = Some("Updated".to_string());
    profile.family_name = Some("Name".to_string());
    assert!(
        backend
            .update_profile(&profile, test_audit())
            .await
            .unwrap()
    );
    let retrieved = backend.get_profile(profile.id).await.unwrap().unwrap();
    assert_eq!(retrieved.given_name, Some("Updated".to_string()));
    assert_eq!(retrieved.family_name, Some("Name".to_string()));
    assert_eq!(retrieved.revision, profile.revision + 1);

    // The owner reads, an administrator suspends, the owner writes names.
    let owner_copy = retrieved.clone();
    let mut suspended = retrieved.clone();
    suspended.status = ProfileStatus::Suspended;
    assert!(
        backend
            .update_profile(&suspended, test_audit())
            .await
            .unwrap()
    );
    let mut renamed = owner_copy;
    renamed.given_name = Some("Stale".to_string());
    assert!(
        !backend
            .update_profile(&renamed, test_audit())
            .await
            .unwrap(),
        "a stale copy was written"
    );
    let stored = backend.get_profile(profile.id).await.unwrap().unwrap();
    assert_eq!(
        stored.status,
        ProfileStatus::Suspended,
        "a suspension was undone"
    );
    assert_eq!(stored.given_name, Some("Updated".to_string()));

    let err = backend
        .create_profile(&stored, test_audit())
        .await
        .expect_err("a create over an existing profile");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    backend
        .delete_profile(profile.id, test_audit())
        .await
        .unwrap();
    assert!(!backend.update_profile(&stored, test_audit()).await.unwrap());
    assert!(
        backend.get_profile(profile.id).await.unwrap().is_none(),
        "a deleted profile was recreated"
    );
}

pub async fn test_profile_delete(backend: &dyn StorageBackend) {
    let profile = create_test_profile("delete");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    backend
        .delete_profile(profile.id, test_audit())
        .await
        .unwrap();

    let result = backend.get_profile(profile.id).await.unwrap();
    assert!(result.is_none());
}

pub async fn test_profile_list(backend: &dyn StorageBackend) {
    for i in 0..3 {
        let p = create_test_profile(&format!("list_{}", i));
        backend.create_profile(&p, test_audit()).await.unwrap();
    }

    let list = backend.list_profiles(0, 10).await.unwrap();
    assert!(list.len() >= 3);

    let count = backend.count_profiles().await.unwrap();
    assert!(count >= 3);
}

/// Paging through profiles by offset sees every profile exactly once, also
/// when several share a creation time: the order is total and the same on
/// every page. The profiles here predate any other test's, so profiles other
/// tests create meanwhile sort after them and do not shift these pages.
pub async fn test_profile_list_pages_cover_each_profile_once(backend: &dyn StorageBackend) {
    let created_at = chrono::DateTime::parse_from_rfc3339("1990-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let mut ids = std::collections::BTreeSet::new();
    for i in 0..7 {
        let mut p = create_test_profile(&format!("page_{tag}_{i}"));
        p.created_at = created_at;
        p.updated_at = created_at;
        backend.create_profile(&p, test_audit()).await.unwrap();
        ids.insert(p.id);
    }

    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let page = backend.list_profiles(offset, 2).await.unwrap();
        seen.extend(page.iter().map(|p| p.id).filter(|id| ids.contains(id)));
        if page.len() < 2 || seen.len() == ids.len() {
            break;
        }
        offset += 2;
    }
    assert_eq!(seen.len(), ids.len(), "every profile once, none twice");
    assert_eq!(
        seen.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
}

pub async fn test_profile_username_uniqueness(backend: &dyn StorageBackend) {
    let profile1 = create_test_profile("unique");
    let mut profile2 = create_test_profile("unique");
    profile2.id = ProfileId::generate();
    profile2.username = profile1.username.clone();

    backend
        .create_profile(&profile1, test_audit())
        .await
        .unwrap();

    let result = backend.create_profile(&profile2, test_audit()).await;
    assert!(result.is_err(), "Should fail due to unique constraint");
}

// ─── Session CRUD ───

pub async fn test_session_save_and_get(backend: &dyn StorageBackend) {
    let profile = create_test_profile("session");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_session(session.id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, session.id);
    assert_eq!(retrieved.profile_id, profile.id);
    assert_eq!(retrieved.ip_address, "127.0.0.1");
}

/// A profile keeps at least one active primary credential: the last one is
/// not revoked, second factors are always revocable, a revoked credential
/// stays stored (revoked, not deleted), and revoking again changes nothing.
/// Two concurrent revocations of the last two passkeys revoke exactly one.
pub async fn test_revoke_credential_keeps_last_primary(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialRevocation, CredentialType};

    let profile = create_test_profile("last_primary");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let passkey = |n: u8| Credential::new(profile.id, CredentialType::WebAuthn, vec![n], None);
    let (first, second) = (passkey(1), passkey(2));
    let totp = Credential::new(profile.id, CredentialType::Totp, vec![9], None);
    for c in [&first, &second, &totp] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }

    assert_eq!(
        backend
            .revoke_credential(totp.id, test_audit())
            .await
            .unwrap(),
        CredentialRevocation::Revoked,
        "a second factor is always revocable"
    );
    let (a, b) = tokio::join!(
        backend.revoke_credential(first.id, test_audit()),
        backend.revoke_credential(second.id, test_audit()),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o as u8);
    assert_eq!(
        outcomes,
        [
            CredentialRevocation::Revoked,
            CredentialRevocation::LastPrimary
        ],
        "both of the last two sign-in methods were removed"
    );

    let stored = backend
        .get_credentials_by_profile(profile.id, None)
        .await
        .unwrap();
    assert_eq!(stored.len(), 3, "a revocation deleted the record");
    assert_eq!(stored.iter().filter(|c| c.status.is_active()).count(), 1);
    let last = stored.iter().find(|c| c.status.is_active()).unwrap();
    assert_eq!(
        backend
            .revoke_credential(last.id, test_audit())
            .await
            .unwrap(),
        CredentialRevocation::LastPrimary
    );
    assert_eq!(
        backend
            .revoke_credential(totp.id, test_audit())
            .await
            .unwrap(),
        CredentialRevocation::AlreadyGone
    );
}

/// A role keeps its machine key, display name, grouping label and
/// permissions through storage; an update replaces them.
pub async fn test_role_roundtrip(backend: &dyn StorageBackend) {
    let key = format!("editor_{}", Uuid::now_v7().simple());
    let name = format!("Content Editor {key}");
    let mut role = sid_core::models::Role::new(ProjectId::system(), &key, &name);
    role.group = Some("Content".into());
    role.description = Some("edits content".into());
    role.permissions = vec!["content:read".into(), "content:write".into()];
    backend.create_role(&role, test_audit()).await.unwrap();

    let stored = backend
        .get_role(role.id)
        .await
        .unwrap()
        .expect("role stored");
    assert_eq!(stored.key, key);
    assert_eq!(stored.name, name);
    assert_eq!(stored.group.as_deref(), Some("Content"));
    assert_eq!(stored.description.as_deref(), Some("edits content"));
    assert_eq!(stored.permissions, role.permissions);

    role.group = None;
    role.permissions = vec!["content:read".into()];
    assert!(backend.update_role(&role, test_audit()).await.unwrap());
    let updated = backend.get_role(role.id).await.unwrap().unwrap();
    assert_eq!(updated.group, None);
    assert_eq!(updated.permissions, ["content:read"]);
}

/// A Cedar policy is created once and updated only over the revision it was
/// read at: a second create never replaces it, a stale copy never re-enables
/// a policy disabled since, and an update never recreates a deleted policy.
pub async fn test_cedar_policy_write_contract(backend: &dyn StorageBackend) {
    use sid_core::models::{CedarPolicy, PolicyEffect};

    let name = format!("deny_export_{}", Uuid::now_v7().simple());
    let policy = CedarPolicy::new(
        ProjectId::system(),
        &name,
        r#"forbid(principal, action == Action::"export", resource);"#,
        PolicyEffect::Forbid,
    );
    backend
        .create_cedar_policy(&policy, test_audit())
        .await
        .unwrap();

    let mut replacement = policy.clone();
    replacement.effect = PolicyEffect::Permit;
    let err = backend
        .create_cedar_policy(&replacement, test_audit())
        .await
        .expect_err("a second create must not replace the policy");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    let stored = backend
        .get_cedar_policy(policy.id)
        .await
        .unwrap()
        .expect("policy stored");
    assert_eq!(stored.effect, PolicyEffect::Forbid);
    assert_eq!(stored.revision, 0);

    // Two admins read the same revision; the first disables the policy.
    let stale = stored.clone();
    let mut disable = stored;
    disable.enabled = false;
    assert!(
        backend
            .update_cedar_policy(&disable, test_audit())
            .await
            .unwrap()
    );
    let mut stale_edit = stale;
    stale_edit.description = Some("reworded".into());
    assert!(
        !backend
            .update_cedar_policy(&stale_edit, test_audit())
            .await
            .unwrap(),
        "an update over a stale revision must not apply"
    );
    let current = backend.get_cedar_policy(policy.id).await.unwrap().unwrap();
    assert!(!current.enabled, "a stale copy re-enabled the policy");
    assert_eq!(current.description, None);
    assert_eq!(current.revision, 1);

    backend
        .delete_cedar_policy(policy.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .update_cedar_policy(&current, test_audit())
            .await
            .unwrap(),
        "an update must not recreate a deleted policy"
    );
    assert!(backend.get_cedar_policy(policy.id).await.unwrap().is_none());
}

/// A project is created once; an edit writes only the fields it carries,
/// never touches a system project and never recreates a deleted one.
pub async fn test_project_write_contract(backend: &dyn StorageBackend) {
    use sid_core::models::{Project, ProjectChange};

    let project = Project::new(format!("proj_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let mut replacement = project.clone();
    replacement.name = "taken over".into();
    let err = backend
        .create_project(&replacement, test_audit())
        .await
        .expect_err("a second create must not replace the project");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    // Two edits of different fields both stay.
    let rename = ProjectChange {
        name: Some("renamed".into()),
        description: None,
        updated_at: chrono::Utc::now(),
    };
    let describe = ProjectChange {
        name: None,
        description: Some("described".into()),
        updated_at: chrono::Utc::now(),
    };
    backend
        .update_project(project.id, &rename, test_audit())
        .await
        .unwrap()
        .expect("project updated");
    let stored = backend
        .update_project(project.id, &describe, test_audit())
        .await
        .unwrap()
        .expect("project updated");
    assert_eq!(stored.name, "renamed");
    assert_eq!(stored.description, "described");
    assert_eq!(
        backend.get_project(project.id).await.unwrap().unwrap().name,
        "renamed"
    );

    backend.ensure_system_project(test_audit()).await.unwrap();
    assert!(
        backend
            .update_project(ProjectId::system(), &rename, test_audit())
            .await
            .unwrap()
            .is_none(),
        "a system project is never edited"
    );
    assert_ne!(
        backend
            .get_project(ProjectId::system())
            .await
            .unwrap()
            .unwrap()
            .name,
        "renamed"
    );

    backend
        .delete_project(project.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .update_project(project.id, &rename, test_audit())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend.get_project(project.id).await.unwrap().is_none(),
        "an edit recreated a deleted project"
    );
}

/// A profile grant keeps each of its role keys through storage and is found
/// by profile and by project; a second create never replaces it.
pub async fn test_profile_grant_write_contract(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileGrant;

    let profile = create_test_profile("grant");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    backend.ensure_system_project(test_audit()).await.unwrap();
    let mut grant = ProfileGrant::new(
        ProjectId::system(),
        profile.id,
        vec!["admin".into(), "editor".into()],
    );
    grant.granted_by = Some("system".into());
    backend
        .create_profile_grant(&grant, test_audit())
        .await
        .unwrap();

    let stored = backend
        .get_profile_grant(grant.id)
        .await
        .unwrap()
        .expect("grant stored");
    assert_eq!(stored.role_keys, ["admin", "editor"]);
    let by_profile = backend
        .list_profile_grants_for_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(by_profile.len(), 1);
    assert_eq!(by_profile[0].role_keys, ["admin", "editor"]);
    assert!(
        backend
            .list_profile_grants_for_project(ProjectId::system())
            .await
            .unwrap()
            .iter()
            .any(|g| g.id == grant.id)
    );

    let mut widened = grant.clone();
    widened.role_keys = vec!["owner".into()];
    let err = backend
        .create_profile_grant(&widened, test_audit())
        .await
        .expect_err("a second create must not replace the grant");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert_eq!(
        backend
            .get_profile_grant(grant.id)
            .await
            .unwrap()
            .unwrap()
            .role_keys,
        ["admin", "editor"]
    );
}

/// Replicas starting together each ensure the system project: all succeed.
pub async fn test_ensure_system_project_concurrent(backend: &dyn StorageBackend) {
    let (a, b, c) = tokio::join!(
        backend.ensure_system_project(test_audit()),
        backend.ensure_system_project(test_audit()),
        backend.ensure_system_project(test_audit()),
    );
    a.unwrap();
    b.unwrap();
    c.unwrap();
    assert!(
        backend
            .get_project(ProjectId::system())
            .await
            .unwrap()
            .expect("system project")
            .is_system
    );
}

/// Two writers updating the same policy revision: exactly one applies.
pub async fn test_cedar_policy_concurrent_update(backend: &dyn StorageBackend) {
    use sid_core::models::{CedarPolicy, PolicyEffect};

    let policy = CedarPolicy::new(
        ProjectId::system(),
        format!("race_{}", Uuid::now_v7().simple()),
        "permit(principal, action, resource);",
        PolicyEffect::Permit,
    );
    backend
        .create_cedar_policy(&policy, test_audit())
        .await
        .unwrap();
    let mut a = policy.clone();
    a.enabled = false;
    let mut b = policy.clone();
    b.description = Some("b".into());
    let (ra, rb) = tokio::join!(
        backend.update_cedar_policy(&a, test_audit()),
        backend.update_cedar_policy(&b, test_audit()),
    );
    assert_eq!(
        [ra.unwrap(), rb.unwrap()].iter().filter(|w| **w).count(),
        1,
        "exactly one writer over the same revision applies"
    );
    let stored = backend.get_cedar_policy(policy.id).await.unwrap().unwrap();
    assert_eq!(stored.revision, 1);
}

/// A consent and its claim grants are stored, found by id, by client and
/// per profile, updated, revoked with the profile's other consents and
/// deleted with their grants.
pub async fn test_consent_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::consent::{ClaimType, ConsentRecord, ConsentStatus};

    let profile = create_test_profile("consent");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, "rp-consent");
    consent.grant_claim("email", ClaimType::Data);
    consent.grant_claim("age_over_18", ClaimType::Attestation);
    consent
        .as_requested()
        .expect("new consent is requested")
        .grant();
    backend
        .create_consent(&consent, test_audit())
        .await
        .unwrap();

    let stored = backend
        .get_consent(consent.id)
        .await
        .unwrap()
        .expect("consent stored");
    assert_eq!(stored.client_id, "rp-consent");
    assert_eq!(stored.status, ConsentStatus::Active);
    let mut claims: Vec<_> = stored
        .grants
        .iter()
        .map(|g| (g.claim_name.as_str(), g.claim_type.as_str()))
        .collect();
    claims.sort();
    assert_eq!(
        claims,
        [
            ("age_over_18", ClaimType::Attestation.as_str()),
            ("email", ClaimType::Data.as_str())
        ]
    );
    let by_client = backend
        .get_consent_by_client(profile.id, "rp-consent")
        .await
        .unwrap()
        .expect("found by client");
    assert_eq!(by_client.id, consent.id);
    assert!(
        backend
            .get_consent_by_client(profile.id, "another-rp")
            .await
            .unwrap()
            .is_none()
    );

    // One claim withdrawn: the grant keeps its row, marked revoked.
    backend
        .change_claim_grant(
            consent.id,
            "email",
            sid_core::models::consent::ClaimDecision::Revoke,
            test_audit(),
        )
        .await
        .unwrap();
    let updated = backend.get_consent(consent.id).await.unwrap().unwrap();
    let email = updated
        .grants
        .iter()
        .find(|g| g.claim_name == "email")
        .unwrap();
    assert!(email.revoked_at.is_some());

    let second = {
        let mut c = ConsentRecord::new(profile.id, "rp-other");
        c.as_requested().unwrap().grant();
        c
    };
    backend.create_consent(&second, test_audit()).await.unwrap();
    assert_eq!(
        backend
            .list_consents_by_profile(profile.id)
            .await
            .unwrap()
            .len(),
        2
    );

    assert_eq!(
        backend
            .revoke_consents_by_profile(profile.id, test_audit())
            .await
            .unwrap(),
        2
    );
    for c in backend.list_consents_by_profile(profile.id).await.unwrap() {
        assert_eq!(c.status, ConsentStatus::Revoked);
        assert!(c.revoked_at.is_some());
    }

    assert!(
        backend
            .delete_consent(consent.id, test_audit())
            .await
            .unwrap()
    );
    assert!(backend.get_consent(consent.id).await.unwrap().is_none());
    assert_eq!(
        backend
            .list_consents_by_profile(profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

fn test_invite(created_by: ProfileId, max_uses: u32) -> sid_core::models::Invite {
    sid_core::models::Invite {
        id: sid_core::models::InviteId::new(),
        code: sid_core::models::generate_invite_code(),
        created_by,
        created_by_name: String::new(),
        metadata: [("department".to_string(), "qa".to_string())].into(),
        max_uses,
        use_count: 0,
        expires_at: None,
        active: true,
        created_at: Utc::now(),
    }
}

/// Paging through invites by offset sees every invite exactly once, also
/// when several share a creation time (a bulk creation): the order is total
/// and the same on every page. The invites here are dated after any other
/// test's, so invites other tests create meanwhile sort after them (newest
/// first) and do not shift these pages.
pub async fn test_invite_list_pages_cover_each_invite_once(backend: &dyn StorageBackend) {
    let admin = create_test_profile("pager");
    backend.create_profile(&admin, test_audit()).await.unwrap();
    let created_at = chrono::DateTime::parse_from_rfc3339("2990-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..7 {
        let mut invite = test_invite(admin.id, 1);
        invite.created_at = created_at;
        backend.create_invite(&invite, test_audit()).await.unwrap();
        ids.insert(invite.id.0);
    }

    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let page = backend
            .list_invites(&sid_core::models::InviteFilter::default(), offset, 2)
            .await
            .unwrap();
        seen.extend(page.iter().map(|i| i.id.0).filter(|id| ids.contains(id)));
        if page.len() < 2 || seen.len() == ids.len() {
            break;
        }
        offset += 2;
    }
    assert_eq!(seen.len(), ids.len(), "every invite once, none twice");
    assert_eq!(
        seen.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        ids
    );
}

/// An invite is found by id and by its code in any case, is used at most
/// `max_uses` times (once across concurrent registrations), never after it
/// expired or was revoked (a repeated create does not bring it back), and a
/// status filter applies before paging and counting.
pub async fn test_invite_lifecycle(backend: &dyn StorageBackend) {
    use sid_core::models::{InviteFilter, InviteStatus};

    let admin = create_test_profile("inviter");
    backend.create_profile(&admin, test_audit()).await.unwrap();

    let twice = test_invite(admin.id, 2);
    backend.create_invite(&twice, test_audit()).await.unwrap();
    let stored = backend.get_invite(twice.id).await.unwrap().expect("stored");
    assert_eq!(stored.code, twice.code);
    assert_eq!(stored.metadata, twice.metadata);
    let by_code = backend
        .get_invite_by_code(&twice.code.to_lowercase())
        .await
        .unwrap()
        .expect("code is case-insensitive");
    assert_eq!(by_code.id, twice.id);

    for expected in [1, 2] {
        let used = backend
            .try_use_invite(twice.id, test_audit())
            .await
            .unwrap()
            .expect("uses left");
        assert_eq!(used.use_count, expected);
    }
    assert!(
        backend
            .try_use_invite(twice.id, test_audit())
            .await
            .unwrap()
            .is_none(),
        "a third use of a two-use invite"
    );

    let mut expired = test_invite(admin.id, 0);
    expired.expires_at = Some(Utc::now() - Duration::minutes(1));
    backend.create_invite(&expired, test_audit()).await.unwrap();
    assert!(
        backend
            .try_use_invite(expired.id, test_audit())
            .await
            .unwrap()
            .is_none()
    );

    let revoked = test_invite(admin.id, 0);
    backend.create_invite(&revoked, test_audit()).await.unwrap();
    backend
        .revoke_invite(revoked.id, test_audit())
        .await
        .unwrap();
    // Sending the same invite again never reactivates it.
    let err = backend
        .create_invite(&revoked, test_audit())
        .await
        .expect_err("a create over a revoked invite");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert!(
        backend
            .try_use_invite(revoked.id, test_audit())
            .await
            .unwrap()
            .is_none()
    );

    // The newest invite is active: a filter applied after paging would
    // return an empty first page of revoked invites.
    let newest = test_invite(admin.id, 0);
    backend.create_invite(&newest, test_audit()).await.unwrap();
    let revoked_only = InviteFilter {
        status: Some(InviteStatus::Revoked),
        search: None,
    };
    let page = backend.list_invites(&revoked_only, 0, 1).await.unwrap();
    assert_eq!(page.len(), 1, "first page of revoked invites is empty");
    assert_eq!(page[0].status(), InviteStatus::Revoked);
    let revoked_count = backend.count_invites(&revoked_only).await.unwrap();
    assert!(revoked_count >= 1);
    assert!(
        backend
            .count_invites(&InviteFilter::default())
            .await
            .unwrap()
            > revoked_count,
        "the revoked count includes invites that are not revoked"
    );
}

/// The search finds invites whose code or creator's name contains the text,
/// ignoring ASCII case, combined with the status filter; the text's own
/// `%` and `_` match only themselves.
pub async fn test_invite_search(backend: &dyn StorageBackend) {
    use sid_core::models::{Invite, InviteFilter, InviteStatus};

    let admin = create_test_profile("searcher");
    backend.create_profile(&admin, test_audit()).await.unwrap();
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let mut by_name = test_invite(admin.id, 1);
    by_name.created_by_name = format!("Grace {tag} Hopper");
    let mut wild = test_invite(admin.id, 1);
    wild.created_by_name = format!("50%_{tag}");
    let mut revoked = test_invite(admin.id, 1);
    revoked.created_by_name = format!("Grace {tag} Revoked");
    for invite in [&by_name, &wild, &revoked] {
        backend.create_invite(invite, test_audit()).await.unwrap();
    }
    backend
        .revoke_invite(revoked.id, test_audit())
        .await
        .unwrap();

    let found = |search: &str, status: Option<InviteStatus>| {
        let filter = InviteFilter {
            status,
            search: Some(search.to_string()),
        };
        async move {
            let ids: std::collections::BTreeSet<_> = backend
                .list_invites(&filter, 0, 50)
                .await
                .unwrap()
                .into_iter()
                .map(|i| i.id.0)
                .collect();
            let count = backend.count_invites(&filter).await.unwrap();
            assert_eq!(count, ids.len() as u64, "the count matches the listing");
            ids
        }
    };
    let set = |invites: &[&Invite]| invites.iter().map(|i| i.id.0).collect();

    // The creator's name, in another case.
    assert_eq!(
        found(&format!("GRACE {tag}"), None).await,
        set(&[&by_name, &revoked])
    );
    // Combined with the status.
    assert_eq!(
        found(&format!("grace {tag}"), Some(InviteStatus::Active)).await,
        set(&[&by_name])
    );
    // The code, in lower case.
    assert_eq!(
        found(&by_name.code.to_lowercase(), None).await,
        set(&[&by_name])
    );
    // Wildcards in the text match themselves only.
    assert_eq!(found(&format!("%_{tag}"), None).await, set(&[&wild]));
    assert!(found(&format!("Grace_{tag}"), None).await.is_empty());
}

/// A profile's registration source is stored with its registration and
/// counts towards its type and its referrer; a source naming no stored
/// referrer fails the registration, which then writes nothing.
pub async fn test_registration_source_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{NewRegistration, RegistrationSource, RegistrationSourceType};

    let since = Utc::now() - Duration::seconds(1);
    let referrer = create_test_profile("referrer");
    backend
        .create_profile(&referrer, test_audit())
        .await
        .unwrap();
    let joined = create_test_profile("referred");
    let name = joined.username.clone().expect("username");

    let mut source = RegistrationSource::from_invite("ABCD2345", Some("web".into()));
    source.referrer_id = Some(referrer.id);
    source.utm.campaign = "spring".into();
    backend
        .register_profile(
            &NewRegistration::new(
                joined.clone(),
                sid_core::models::SignupIdentifier::Username(&name),
                None,
            )
            .unwrap()
            .with_source(source),
            test_audit(),
        )
        .await
        .unwrap();

    let orphan = create_test_profile("orphan");
    let orphan_name = orphan.username.clone().expect("username");
    let mut dangling = RegistrationSource::self_signup(None);
    dangling.referrer_id = Some(sid_core::models::ProfileId::generate());
    assert!(
        backend
            .register_profile(
                &NewRegistration::new(
                    orphan.clone(),
                    sid_core::models::SignupIdentifier::Username(&orphan_name),
                    None,
                )
                .unwrap()
                .with_source(dangling),
                test_audit(),
            )
            .await
            .is_err()
    );
    assert!(
        backend.get_profile(orphan.id).await.unwrap().is_none(),
        "a failed source write left the account behind"
    );

    let stored = backend
        .get_registration_source(joined.id)
        .await
        .unwrap()
        .expect("source recorded");
    assert_eq!(stored.source_type, RegistrationSourceType::Invite);
    assert_eq!(stored.source_id, "invite:ABCD2345");
    assert_eq!(stored.referrer_id, Some(referrer.id));
    assert_eq!(stored.utm.campaign, "spring");
    assert_eq!(stored.client_id.as_deref(), Some("web"));

    let by_type = backend.count_registrations_by_source(since).await.unwrap();
    assert!(
        by_type
            .iter()
            .any(|(t, n)| *t == RegistrationSourceType::Invite && *n >= 1)
    );
    let referrers = backend.top_referrers(since, 1000).await.unwrap();
    assert!(referrers.contains(&(referrer.id, 1)));
}

/// An access request is stored and listed while pending; a decision is
/// recorded only on a request still pending in storage, so of two
/// concurrent reviewers exactly one decides and the other changes nothing.
pub async fn test_access_request_decided_once(backend: &dyn StorageBackend) {
    use sid_core::models::{AccessRequest, AccessRequestStatus};

    let requester = create_test_profile("requester");
    backend
        .create_profile(&requester, test_audit())
        .await
        .unwrap();
    let reviewer = create_test_profile("reviewer");
    backend
        .create_profile(&reviewer, test_audit())
        .await
        .unwrap();

    let mut request = AccessRequest::new(requester.id, ProjectId::system(), "staging-access");
    request.justification = Some("on call".into());
    request.requested_duration_hours = Some(8);
    backend
        .create_access_request(&request, test_audit())
        .await
        .unwrap();
    let mut resent = request.clone();
    resent.role_key = "prod-access".into();
    assert!(matches!(
        backend.create_access_request(&resent, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    let stored = backend
        .get_access_request(request.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.role_key, "staging-access");
    assert_eq!(stored.justification.as_deref(), Some("on call"));
    assert_eq!(stored.requested_duration_hours, Some(8));
    assert!(
        backend
            .list_pending_access_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == request.id)
    );

    backend.ensure_system_project(test_audit()).await.unwrap();
    let role = sid_core::models::Role::new(
        ProjectId::system(),
        format!("staging-access-{}", Uuid::now_v7().simple()),
        format!("Staging access {}", Uuid::now_v7().simple()),
    );
    backend.create_role(&role, test_audit()).await.unwrap();
    let grant = sid_core::models::RoleAssignment::new(
        sid_core::models::RoleAssignmentPrincipal::Profile(requester.id),
        role.id,
    );
    let mut approved = stored.clone();
    approved.approve(reviewer.id, None).unwrap();
    let mut denied = stored.clone();
    denied.deny(reviewer.id, Some("not now".into())).unwrap();
    let (a, d) = tokio::join!(
        backend.approve_access_request(&approved, &grant, test_audit()),
        backend.decide_access_request(&denied, test_audit()),
    );
    let (a, d) = (a.unwrap(), d.unwrap());
    assert!(
        a ^ d,
        "exactly one decision is recorded (approve {a}, deny {d})"
    );

    let decided = backend
        .get_access_request(request.id)
        .await
        .unwrap()
        .unwrap();
    let winner = if a {
        AccessRequestStatus::Approved
    } else {
        AccessRequestStatus::Denied
    };
    assert_eq!(decided.status, winner);
    assert_eq!(decided.reviewed_by, Some(reviewer.id));
    assert!(decided.reviewed_at.is_some());
    let comment = if a { None } else { Some("not now") };
    assert_eq!(decided.review_comment.as_deref(), comment);
    assert!(
        backend
            .get_access_request(sid_core::models::AccessRequestId(uuid::Uuid::now_v7()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !backend
            .list_pending_access_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == request.id)
    );
    assert!(
        !backend
            .decide_access_request(&denied, test_audit())
            .await
            .unwrap(),
        "a decided request is decided again"
    );
}

/// Approval and the role it grants are one write: the request is approved
/// only together with its assignment. An assignment that cannot be stored
/// (its role is gone) leaves the request pending and grants nothing; of an
/// approval and a denial racing, one wins, and a won approval holds exactly
/// one assignment. A decision other than approval never carries a role, and
/// an approval is not recorded through the plain decision.
pub async fn test_access_request_approval_grants_the_role(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AccessRequest, AccessRequestStatus, Role, RoleAssignment, RoleAssignmentPrincipal,
    };

    backend.ensure_system_project(test_audit()).await.unwrap();
    let requester = create_test_profile(&format!("req_{}", Uuid::now_v7().simple()));
    backend
        .create_profile(&requester, test_audit())
        .await
        .unwrap();
    let reviewer = create_test_profile(&format!("rev_{}", Uuid::now_v7().simple()));
    backend
        .create_profile(&reviewer, test_audit())
        .await
        .unwrap();
    let role = Role::new(
        ProjectId::system(),
        format!("staging-{}", Uuid::now_v7().simple()),
        format!("Staging {}", Uuid::now_v7().simple()),
    );
    backend.create_role(&role, test_audit()).await.unwrap();
    let pending = || AccessRequest::new(requester.id, ProjectId::system(), role.key.clone());
    let grant =
        |role_id| RoleAssignment::new(RoleAssignmentPrincipal::Profile(requester.id), role_id);

    // An approval whose role cannot be assigned records nothing.
    let request = pending();
    backend
        .create_access_request(&request, test_audit())
        .await
        .unwrap();
    let mut approved = request.clone();
    approved.approve(reviewer.id, None).unwrap();
    let orphan = grant(sid_core::models::RoleId::new());
    assert!(
        backend
            .approve_access_request(&approved, &orphan, test_audit())
            .await
            .is_err()
    );
    let still = backend
        .get_access_request(request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still.status, AccessRequestStatus::Pending);
    assert!(
        backend
            .list_role_assignments_for_profile(requester.id)
            .await
            .unwrap()
            .is_empty(),
        "a failed approval granted a role"
    );

    // An approval is not recorded without its assignment.
    assert!(
        backend
            .decide_access_request(&approved, test_audit())
            .await
            .is_err()
    );
    assert_eq!(
        backend
            .get_access_request(request.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );

    // Approval and denial race: one decides; the approval brings its role.
    let mut denied = request.clone();
    denied.deny(reviewer.id, Some("no".into())).unwrap();
    let assignment = grant(role.id);
    let (a, d) = tokio::join!(
        backend.approve_access_request(&approved, &assignment, test_audit()),
        backend.decide_access_request(&denied, test_audit()),
    );
    let (a, d) = (a.unwrap(), d.unwrap());
    assert!(a ^ d, "exactly one decision (approve {a}, deny {d})");
    let assigned = backend
        .list_role_assignments_for_profile(requester.id)
        .await
        .unwrap();
    if a {
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].id, assignment.id);
        assert_eq!(assigned[0].role_id, role.id);
    } else {
        assert!(assigned.is_empty(), "a denied request granted a role");
    }

    // A decided request is not approved again, and grants nothing more.
    assert!(
        !backend
            .approve_access_request(&approved, &grant(role.id), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend
            .list_role_assignments_for_profile(requester.id)
            .await
            .unwrap()
            .len(),
        usize::from(a)
    );
}

/// A device holds one live attestation: a second one is refused, rotation
/// replaces the key of the live one only, a revoked key is never rotated back
/// to life, and a new enrollment replaces a revoked one. It is found by id,
/// by device while not revoked and per profile, and removed with the device.
pub async fn test_device_attestation_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AttestationStatus, DeviceAttestation, DeviceAttestationFormat, DeviceId, KeyStorageType,
    };

    let owner = create_test_profile("attested");
    backend.create_profile(&owner, test_audit()).await.unwrap();
    let device = DeviceId::generate();
    let mut att = DeviceAttestation::new_ce(
        device,
        owner.id,
        DeviceAttestationFormat::Apple,
        KeyStorageType::SecureEnclave,
        vec![0x04, 0x01],
    );
    att.aaguid = Some("2fc0579f-8113-47ea-b116-bb5a8db9202a".into());
    backend
        .create_device_attestation(&att, test_audit())
        .await
        .unwrap();
    let mut second = att.clone();
    second.id = sid_core::models::DeviceAttestationId::new();
    let err = backend
        .create_device_attestation(&second, test_audit())
        .await
        .expect_err("a second live attestation");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    let stored = backend
        .get_device_attestation(att.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.device_id, device);
    assert_eq!(stored.format, DeviceAttestationFormat::Apple);
    assert_eq!(stored.key_storage, KeyStorageType::SecureEnclave);
    assert_eq!(stored.status, AttestationStatus::Unverified);
    assert_eq!(stored.device_public_key, [0x04, 0x01]);
    assert_eq!(stored.aaguid, att.aaguid);

    assert!(
        backend
            .rotate_device_attestation(device, &[0x04, 0x02], None, None, test_audit())
            .await
            .unwrap()
    );
    let rotated = backend
        .get_device_attestation_by_device_id(device)
        .await
        .unwrap()
        .expect("found by device");
    assert_eq!(rotated.device_public_key, [0x04, 0x02]);
    assert_eq!(rotated.status, AttestationStatus::Unverified);
    assert_eq!(
        backend
            .list_device_attestations_by_profile(owner.id)
            .await
            .unwrap()
            .len(),
        1
    );

    assert!(
        backend
            .revoke_device_attestation(device, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .revoke_device_attestation(device, test_audit())
            .await
            .unwrap(),
        "a revoked key was revoked again"
    );
    assert!(
        backend
            .get_device_attestation_by_device_id(device)
            .await
            .unwrap()
            .is_none(),
        "a revoked key is still found for its device"
    );
    assert!(
        !backend
            .rotate_device_attestation(device, &[0x04, 0x03], None, None, test_audit())
            .await
            .unwrap(),
        "a revoked key was rotated"
    );
    let revoked = backend
        .get_device_attestation(att.id)
        .await
        .unwrap()
        .expect("kept as revoked");
    assert_eq!(revoked.status, AttestationStatus::Revoked);
    assert_eq!(revoked.device_public_key, [0x04, 0x02]);

    // A new enrollment replaces the revoked attestation.
    let renewed = DeviceAttestation::new_ce(
        device,
        owner.id,
        DeviceAttestationFormat::Apple,
        KeyStorageType::SecureEnclave,
        vec![0x04, 0x09],
    );
    backend
        .create_device_attestation(&renewed, test_audit())
        .await
        .unwrap();
    let live = backend
        .get_device_attestation_by_device_id(device)
        .await
        .unwrap()
        .expect("the new enrollment");
    assert_eq!(live.id, renewed.id);
    assert_eq!(live.device_public_key, [0x04, 0x09]);

    backend
        .delete_device_attestation(device, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_device_attestation(renewed.id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Revoking a device's key also stops counting the device as
/// hardware-attested, in the same write.
pub async fn test_revoked_key_clears_hardware_attestation(backend: &dyn StorageBackend) {
    use sid_core::models::{
        DeviceAttestation, DeviceAttestationFormat, DeviceType, KeyStorageType,
    };

    let owner = create_test_profile("hw_attested");
    backend.create_profile(&owner, test_audit()).await.unwrap();
    let mut device = sid_core::models::Device::new(owner.id, DeviceType::Mobile);
    device.hardware_attested = true;
    backend.create_device(&device, test_audit()).await.unwrap();
    let att = DeviceAttestation::new_ce(
        device.id,
        owner.id,
        DeviceAttestationFormat::Tpm,
        KeyStorageType::Tpm,
        vec![0x04, 0x01],
    );
    backend
        .create_device_attestation(&att, test_audit())
        .await
        .unwrap();

    assert!(
        backend
            .revoke_device_attestation(device.id, test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert!(
        !stored.hardware_attested,
        "a revoked key still attests the device"
    );
}

/// Security signals persist: anomaly events are listed newest first and by
/// rule, an IP's reputation is `f / (f + s + 1)` over its failures and
/// successes, and
/// allowlist entries are added (a repeat replaces the description), listed
/// and removed.
pub async fn test_security_signals_persist(backend: &dyn StorageBackend) {
    use sid_core::models::{AnomalyEventId, AnomalyEventRecord};

    let rule = format!("brute_force_{}", Uuid::now_v7().simple());
    for (score, minutes_ago) in [(40, 2), (80, 1)] {
        backend
            .save_anomaly_event(&AnomalyEventRecord {
                id: AnomalyEventId(Uuid::now_v7()),
                rule_id: rule.clone(),
                profile_id: String::new(),
                ip_address: "203.0.113.7".into(),
                description: "failed logins".into(),
                risk_score: score,
                reaction: "challenge".into(),
                timestamp: Utc::now() - Duration::minutes(minutes_ago),
            })
            .await
            .unwrap();
    }
    let events = backend
        .list_anomaly_events(Some(&rule), 10, 0)
        .await
        .unwrap();
    assert_eq!(
        events.iter().map(|e| e.risk_score).collect::<Vec<_>>(),
        [80, 40]
    );

    // An address of the documentation prefix (RFC 3849) no other run used:
    // the shared database keeps earlier runs' counters.
    let ip = std::net::Ipv6Addr::from(
        (0x2001_0db8_u128 << 96) | (Uuid::new_v4().as_u128() & ((1_u128 << 96) - 1)),
    )
    .to_string();
    for _ in 0..3 {
        backend
            .record_ip_reputation_event(&ip, false)
            .await
            .unwrap();
    }
    backend.record_ip_reputation_event(&ip, true).await.unwrap();
    let score = backend
        .get_ip_reputation_score(&ip)
        .await
        .unwrap()
        .expect("scored");
    assert!((score - 3.0 / 5.0).abs() < 1e-6, "score {score}");
    assert!(
        backend
            .list_suspicious_ips(0.59, 10_000)
            .await
            .unwrap()
            .iter()
            .any(|(i, _)| *i == ip)
    );

    let cidr = format!("10.{}.0.0/16", Uuid::now_v7().as_u128() % 250);
    backend
        .add_ip_allowlist_entry(&cidr, "office")
        .await
        .unwrap();
    backend
        .add_ip_allowlist_entry(&cidr, "head office")
        .await
        .unwrap();
    let listed = backend.list_ip_allowlist_entries().await.unwrap();
    let entry = listed.iter().find(|(c, _, _)| *c == cidr).expect("listed");
    assert_eq!(entry.1, "head office");
    backend.remove_ip_allowlist_entry(&cidr).await.unwrap();
    assert!(
        !backend
            .list_ip_allowlist_entries()
            .await
            .unwrap()
            .iter()
            .any(|(c, _, _)| *c == cidr)
    );
}

/// The login history anomaly rules read: the latest session's IP, whether an
/// IP or a device was seen recently, and the countries that became
/// designated after enough logins.
pub async fn test_login_history_signals(backend: &dyn StorageBackend) {
    let profile = create_test_profile("travels");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let device = Uuid::now_v7();
    let mut earlier = create_test_session(profile.id);
    earlier.ip_address = "192.0.2.10".into();
    earlier.created_at = Utc::now() - Duration::minutes(10);
    backend
        .create_session(&earlier, test_audit())
        .await
        .unwrap();
    let mut latest = create_test_session(profile.id);
    latest.ip_address = "192.0.2.20".into();
    latest.device_id = Some(device);
    backend.create_session(&latest, test_audit()).await.unwrap();

    let (ip, _) = backend
        .get_most_recent_session_ip(profile.id)
        .await
        .unwrap()
        .expect("a session exists");
    assert_eq!(ip, "192.0.2.20");
    let hour = std::time::Duration::from_secs(3600);
    assert!(
        backend
            .has_recent_session_from_ip(profile.id, "192.0.2.10", hour)
            .await
            .unwrap()
    );
    assert!(
        !backend
            .has_recent_session_from_ip(profile.id, "192.0.2.99", hour)
            .await
            .unwrap()
    );
    assert!(
        backend
            .has_recent_session_from_device(profile.id, device, hour)
            .await
            .unwrap()
    );
    assert!(
        !backend
            .has_recent_session_from_device(profile.id, Uuid::now_v7(), hour)
            .await
            .unwrap()
    );

    backend
        .record_login_location(profile.id, "UA", 50.45, 30.52, 2)
        .await
        .unwrap();
    assert!(
        backend
            .get_designated_countries(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
    backend
        .record_login_location(profile.id, "UA", 50.45, 30.52, 2)
        .await
        .unwrap();
    assert_eq!(
        backend.get_designated_countries(profile.id).await.unwrap(),
        ["UA"]
    );
}

/// Integrity counts report only real orphans: a role assigned to a group (no
/// profile by design) is not an orphaned assignment. Foreign keys keep real
/// orphans from existing, so every count is zero.
pub async fn test_integrity_counts_ignore_group_assignments(backend: &dyn StorageBackend) {
    use sid_core::models::{Group, Role, RoleAssignment, RoleAssignmentPrincipal};

    let key = format!("viewer_{}", Uuid::now_v7().simple());
    let role = Role::new(ProjectId::system(), &key, format!("Viewer {key}"));
    backend.create_role(&role, test_audit()).await.unwrap();
    let group = Group::new(
        ProjectId::system(),
        format!("ops_{}", Uuid::now_v7().simple()),
    );
    backend.create_group(&group, test_audit()).await.unwrap();
    backend
        .create_role_assignment(
            &RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), role.id),
            test_audit(),
        )
        .await
        .unwrap();

    assert_eq!(backend.count_orphaned_role_assignments().await.unwrap(), 0);
    assert_eq!(backend.count_orphaned_sessions().await.unwrap(), 0);
    assert_eq!(backend.count_orphaned_credentials().await.unwrap(), 0);
}

fn opaque_password(profile_id: ProfileId, byte: u8) -> sid_core::models::Credential {
    sid_core::models::Credential::new(
        profile_id,
        sid_core::models::CredentialType::Opaque,
        vec![byte; 8],
        None,
    )
}

/// A password reset is verified once and completed once, each only while it
/// is in the right state and unexpired. Of concurrent completions exactly
/// one installs its password; the completion ends every session of the
/// profile in the same transaction and returns them.
pub async fn test_password_reset_completes_once(backend: &dyn StorageBackend) {
    use sid_core::models::{PasswordResetSession, ResetSessionStatus};

    let profile = create_test_profile("resets");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    let reset = PasswordResetSession::new(profile.id, "r@sid.example.com".into(), "hash".into());
    backend
        .create_reset_session(&reset, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .count_active_reset_sessions(profile.id)
            .await
            .unwrap(),
        1
    );

    // Not verified yet: nothing to complete.
    assert!(
        backend
            .complete_password_reset(
                reset.id,
                &opaque_password(profile.id, 1),
                None,
                &test_session_end(),
                test_audit()
            )
            .await
            .unwrap()
            .is_none()
    );

    let (v1, v2) = tokio::join!(
        backend.verify_reset_session(reset.id, test_audit()),
        backend.verify_reset_session(reset.id, test_audit()),
    );
    assert!(v1.unwrap() ^ v2.unwrap(), "the token is verified once");

    let first = opaque_password(profile.id, 1);
    let second = opaque_password(profile.id, 2);
    let end = test_session_end();
    let (a, b) = tokio::join!(
        backend.complete_password_reset(reset.id, &first, None, &end, test_audit()),
        backend.complete_password_reset(reset.id, &second, None, &end, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a.is_some() ^ b.is_some(), "the reset completes once");
    let ended = a.clone().or(b.clone()).unwrap();
    assert_eq!(ended.iter().map(|s| s.id).collect::<Vec<_>>(), [session.id]);
    assert!(backend.get_session(session.id).await.unwrap().is_none());

    let winner = if a.is_some() { &first } else { &second };
    let passwords = backend
        .get_credentials_by_profile(profile.id, Some(sid_core::models::CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].id, winner.id);
    assert_eq!(
        backend
            .get_reset_session(reset.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ResetSessionStatus::Completed
    );

    let mut expired =
        PasswordResetSession::new(profile.id, "r@sid.example.com".into(), "hash2".into());
    expired.expires_at = Utc::now() - Duration::seconds(1);
    backend
        .create_reset_session(&expired, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .verify_reset_session(expired.id, test_audit())
            .await
            .unwrap(),
        "an expired reset is verified"
    );
}

/// A SCIM outbound target keeps its configuration, is listed while enabled,
/// holds its sync records and dead letters, and takes them along when
/// deleted.
pub async fn test_scim_outbound_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AttributeMapping, GroupPushConfig, OutboundAuthConfig, OutboundDlqEntry,
        OutboundEntityType, OutboundSyncConfig, ScimOutboundRecord, ScimOutboundTarget,
        ScimOutboundTargetId,
    };

    let now = Utc::now();
    let target = ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: "downstream-app".into(),
        project_id: ProjectId::system(),
        display_name: "Downstream".into(),
        endpoint_url: "https://scim.sid.example.com/v2".into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "sealed-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig::default(),
        sync_config: OutboundSyncConfig::default(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    backend
        .create_scim_outbound_target(&target, test_audit())
        .await
        .unwrap();
    let mut takeover = target.clone();
    takeover.endpoint_url = "https://attacker.sid.example.com/v2".into();
    assert!(matches!(
        backend
            .create_scim_outbound_target(&takeover, test_audit())
            .await,
        Err(sid_core::Error::Conflict(_))
    ));
    let stored = backend
        .get_scim_outbound_target(target.id)
        .await
        .unwrap()
        .expect("target stored");
    assert_eq!(stored.endpoint_url, target.endpoint_url);
    assert!(matches!(
        stored.auth,
        OutboundAuthConfig::Bearer { ref token_secret } if token_secret == "sealed-token"
    ));
    assert!(
        backend
            .list_scim_outbound_targets(ProjectId::system())
            .await
            .unwrap()
            .iter()
            .any(|t| t.id == target.id)
    );

    let user = Uuid::now_v7();
    let record = ScimOutboundRecord {
        target_id: target.id,
        sid_entity_id: user,
        entity_type: OutboundEntityType::User,
        downstream_id: "ext-42".into(),
        last_synced_at: now,
        last_error: None,
        failure_count: 0,
        created_at: now,
        updated_at: now,
    };
    backend
        .record_scim_outbound_sync(&record, test_audit())
        .await
        .unwrap();
    let synced = backend
        .get_scim_outbound_record(target.id, user, OutboundEntityType::User)
        .await
        .unwrap()
        .expect("record stored");
    assert_eq!(synced.downstream_id, "ext-42");
    assert!(matches!(
        backend
            .create_scim_outbound_record(&record, test_audit())
            .await,
        Err(sid_core::Error::Conflict(_))
    ));

    // Concurrent failures are all counted and keep the downstream id.
    let (a, b) = tokio::join!(
        backend.record_scim_outbound_failure(
            target.id,
            user,
            OutboundEntityType::User,
            "503",
            now,
            test_audit()
        ),
        backend.record_scim_outbound_failure(
            target.id,
            user,
            OutboundEntityType::User,
            "504",
            now,
            test_audit()
        ),
    );
    assert!(a.unwrap() && b.unwrap());
    let failing = backend
        .get_scim_outbound_record(target.id, user, OutboundEntityType::User)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failing.failure_count, 2, "a concurrent failure was lost");
    assert_eq!(failing.downstream_id, "ext-42");
    assert!(failing.last_error.is_some());
    assert!(
        !backend
            .record_scim_outbound_failure(
                target.id,
                Uuid::now_v7(),
                OutboundEntityType::User,
                "503",
                now,
                test_audit()
            )
            .await
            .unwrap(),
        "a failure without a mapping records nothing"
    );

    // A later success points at the new downstream id and clears the error,
    // keeping the mapping's creation time.
    let mut resynced = record.clone();
    resynced.downstream_id = "ext-43".into();
    resynced.last_synced_at = now + Duration::seconds(5);
    resynced.created_at = now + Duration::seconds(5);
    backend
        .record_scim_outbound_sync(&resynced, test_audit())
        .await
        .unwrap();
    let cleared = backend
        .get_scim_outbound_record(target.id, user, OutboundEntityType::User)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cleared.downstream_id, "ext-43");
    assert_eq!(cleared.failure_count, 0);
    assert_eq!(cleared.last_error, None);
    assert_eq!(
        cleared.created_at.timestamp_millis(),
        synced.created_at.timestamp_millis()
    );
    assert!(
        backend
            .get_scim_outbound_record(target.id, user, OutboundEntityType::Group)
            .await
            .unwrap()
            .is_none()
    );

    let letter = OutboundDlqEntry {
        id: Uuid::now_v7(),
        target_id: target.id,
        event_type: "sid.user.created.v1".into(),
        payload: serde_json::json!({ "id": user }),
        sid_entity_id: user,
        entity_type: OutboundEntityType::User,
        error: "503".into(),
        attempts: 5,
        first_attempt: now,
        last_attempt: now,
    };
    backend
        .create_outbound_dlq_entry(&letter, test_audit())
        .await
        .unwrap();
    let mut rewritten = letter.clone();
    rewritten.payload = serde_json::json!({ "id": "other" });
    assert!(matches!(
        backend
            .create_outbound_dlq_entry(&rewritten, test_audit())
            .await,
        Err(sid_core::Error::Conflict(_))
    ));
    let letters = backend.list_outbound_dlq_entries(target.id).await.unwrap();
    assert_eq!(letters.len(), 1);
    assert_eq!(letters[0].payload, letter.payload);

    // Disabled targets are not listed for delivery.
    let disabled = ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        enabled: false,
        ..target.clone()
    };
    backend
        .create_scim_outbound_target(&disabled, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .list_scim_outbound_targets(ProjectId::system())
            .await
            .unwrap()
            .iter()
            .any(|t| t.id == disabled.id)
    );

    backend
        .delete_scim_outbound_target(target.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_scim_outbound_target(target.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .get_scim_outbound_record(target.id, user, OutboundEntityType::User)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .list_outbound_dlq_entries(target.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Notification preferences are stored per profile and replaced on save.
pub async fn test_notification_preferences_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::notification::NotificationPreferences;

    let profile = create_test_profile("notify_prefs");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_notification_preferences(profile.id)
            .await
            .unwrap()
            .is_none()
    );

    let mut prefs = NotificationPreferences::defaults(profile.id);
    backend
        .save_notification_preferences(&prefs, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .get_notification_preferences(profile.id)
            .await
            .unwrap()
            .expect("stored")
            .categories,
        prefs.categories
    );

    prefs.categories.retain(|c| c.category.is_mandatory());
    backend
        .save_notification_preferences(&prefs, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .get_notification_preferences(profile.id)
            .await
            .unwrap()
            .unwrap()
            .categories,
        prefs.categories
    );
}

/// Of concurrent registrations on a single-use invite exactly one gets it.
pub async fn test_invite_single_use_under_concurrency(backend: &dyn StorageBackend) {
    let admin = create_test_profile("inviter_race");
    backend.create_profile(&admin, test_audit()).await.unwrap();
    let once = test_invite(admin.id, 1);
    backend.create_invite(&once, test_audit()).await.unwrap();

    let (a, b, c, d) = tokio::join!(
        backend.try_use_invite(once.id, test_audit()),
        backend.try_use_invite(once.id, test_audit()),
        backend.try_use_invite(once.id, test_audit()),
        backend.try_use_invite(once.id, test_audit()),
    );
    let winners = [a, b, c, d]
        .into_iter()
        .map(|r| r.unwrap())
        .filter(Option::is_some)
        .count();

    assert_eq!(winners, 1);
    let stored = backend.get_invite(once.id).await.unwrap().unwrap();
    assert_eq!(stored.use_count, 1);
}

pub async fn test_session_delete(backend: &dyn StorageBackend) {
    let profile = create_test_profile("session_del");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    backend
        .delete_session(session.id, &test_session_end(), test_audit())
        .await
        .unwrap();

    assert!(backend.get_session(session.id).await.unwrap().is_none());
}

pub async fn test_session_delete_by_profile(backend: &dyn StorageBackend) {
    let profile = create_test_profile("session_bulk");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let s1 = create_test_session(profile.id);
    let s2 = create_test_session(profile.id);
    backend.create_session(&s1, test_audit()).await.unwrap();
    backend.create_session(&s2, test_audit()).await.unwrap();

    let deleted = backend
        .delete_sessions_by_profile(profile.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    let mut deleted: Vec<_> = deleted.iter().map(|s| s.id).collect();
    deleted.sort();
    let mut expected = vec![s1.id, s2.id];
    expected.sort();
    assert_eq!(deleted, expected, "the deleted sessions are returned");
    assert!(
        backend
            .list_sessions_by_profile(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
}

pub async fn test_session_list_by_profile(backend: &dyn StorageBackend) {
    let profile = create_test_profile("session_list");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let s1 = create_test_session(profile.id);
    let s2 = create_test_session(profile.id);
    backend.create_session(&s1, test_audit()).await.unwrap();
    backend.create_session(&s2, test_audit()).await.unwrap();

    let sessions = backend.list_sessions_by_profile(profile.id).await.unwrap();
    assert_eq!(sessions.len(), 2);
}

pub async fn test_session_get_nonexistent(backend: &dyn StorageBackend) {
    use sid_core::models::SessionId;
    let result = backend.get_session(SessionId::generate()).await.unwrap();
    assert!(result.is_none());
}

// ─── Project CRUD ───

pub async fn test_ensure_system_project(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();

    let project = backend.get_project(ProjectId::system()).await.unwrap();
    assert!(project.is_some());
    assert!(project.unwrap().is_system);
}

pub async fn test_cannot_delete_system_project(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();

    let result = backend
        .delete_project(ProjectId::system(), test_audit())
        .await;
    assert!(result.is_err());
}

// ─── OAuth2 Client CRUD ───

pub async fn test_oauth2_client_save_and_get(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();

    let cid = format!("test-client-{}", Uuid::now_v7().simple());
    let client = create_test_oauth2_client(&cid);
    application::store_client(backend, &client, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_oauth2_client(&cid).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.client_id, cid);
    assert_eq!(retrieved.client_name, "Test Client");
    assert!(retrieved.active);
}

/// A stored client of the system project, as read back from the store.
async fn stored_oauth2_client(backend: &dyn StorageBackend, prefix: &str) -> OAuth2Client {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let cid = format!("{prefix}-{}", Uuid::now_v7().simple());
    application::store_client(backend, &create_test_oauth2_client(&cid), test_audit())
        .await
        .unwrap();
    backend.get_oauth2_client(&cid).await.unwrap().unwrap()
}

/// An update over the revision it read is stored and moves the revision on.
pub async fn test_oauth2_client_update(backend: &dyn StorageBackend) {
    let mut client = stored_oauth2_client(backend, "test-client-upd").await;
    let read = client.revision;

    client.active = false;
    client.client_name = "Updated Client".to_string();
    assert!(
        backend
            .update_oauth2_client(&client, test_audit())
            .await
            .unwrap()
    );

    let retrieved = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!retrieved.active);
    assert_eq!(retrieved.client_name, "Updated Client");
    assert_eq!(retrieved.revision, read + 1);
}

/// Every policy setting of a client reads back as stored: a `recognized`
/// device requirement is not read as `unknown`, a pairwise client stays
/// pairwise, a hard mode stays hard.
pub async fn test_oauth2_client_settings_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::device::DeviceAssurance;
    use sid_core::models::session::AuthLevel;
    use sid_core::models::{EnforcementMode, SubjectType, TokenEndpointAuthMethod};
    backend.ensure_system_project(test_audit()).await.unwrap();
    let mut client =
        create_test_oauth2_client(&format!("test-client-settings-{}", Uuid::now_v7().simple()));
    client.subject_type = SubjectType::Pairwise;
    client.enforcement_mode = EnforcementMode::Hard;
    client.min_device_assurance = Some(DeviceAssurance::Recognized);
    client.required_acr = Some(AuthLevel::Standard);
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    client.login_strategy = sid_core::models::LoginStrategy::FederationOnly;
    application::store_client(backend, &client, test_audit())
        .await
        .unwrap();

    let stored = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.subject_type, SubjectType::Pairwise);
    assert_eq!(stored.enforcement_mode, EnforcementMode::Hard);
    assert_eq!(
        stored.min_device_assurance,
        Some(DeviceAssurance::Recognized)
    );
    assert_eq!(stored.required_acr, Some(AuthLevel::Standard));
    assert_eq!(
        stored.token_endpoint_auth_method,
        TokenEndpointAuthMethod::PrivateKeyJwt
    );
    assert_eq!(
        stored.login_strategy,
        sid_core::models::LoginStrategy::FederationOnly
    );
    assert_eq!(stored.revision, 0);
}

/// A client's registered keys are replaced by an update, as a rotation adds
/// the next key and later drops the old one.
pub async fn test_oauth2_client_keys_rotate(backend: &dyn StorageBackend) {
    use sid_core::models::{ClientKeySet, TokenEndpointAuthMethod};
    let key = |kid: &str| {
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"{kid}"}}"#
        )
    };
    let set = |kids: &[&str]| {
        let keys: Vec<String> = kids.iter().map(|k| key(k)).collect();
        ClientKeySet::from_json(&format!(r#"{{"keys":[{}]}}"#, keys.join(","))).unwrap()
    };
    let mut client = stored_oauth2_client(backend, "test-client-keys").await;
    client.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    client.jwks = Some(set(&["old", "next"]));
    assert!(
        backend
            .update_oauth2_client(&client, test_audit())
            .await
            .unwrap()
    );
    let stored = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.jwks, client.jwks);

    let mut rotated = stored.clone();
    rotated.jwks = Some(set(&["next"]));
    assert!(
        backend
            .update_oauth2_client(&rotated, test_audit())
            .await
            .unwrap()
    );
    let stored = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.jwks, rotated.jwks);
}

/// An update of a client deleted meanwhile does not bring it back.
pub async fn test_oauth2_client_update_keeps_deleted_deleted(backend: &dyn StorageBackend) {
    let mut client = stored_oauth2_client(backend, "test-client-del").await;
    backend
        .delete_oauth2_client(&client.client_id, test_audit())
        .await
        .unwrap();

    client.client_name = "Renamed".to_string();
    assert!(
        !backend
            .update_oauth2_client(&client, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .get_oauth2_client(&client.client_id)
            .await
            .unwrap()
            .is_none(),
        "a deleted client was recreated"
    );
}

/// Of two updates from the same read one applies, and the other does not undo
/// it: a deactivation racing a registration-management update stays.
pub async fn test_oauth2_client_update_is_compare_and_swap(backend: &dyn StorageBackend) {
    let client = stored_oauth2_client(backend, "test-client-cas").await;
    let mut deactivated = client.clone();
    deactivated.active = false;
    let mut renamed = client.clone();
    renamed.client_name = "Renamed".to_string();

    let (a, b) = tokio::join!(
        backend.update_oauth2_client(&deactivated, test_audit()),
        backend.update_oauth2_client(&renamed, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one update must apply: {a} {b}");

    let stored = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.active, !a, "the applied update decides activity");
    assert_eq!(stored.revision, client.revision + 1);
}

/// Creating a client whose id is taken is refused and leaves the owner intact:
/// a registration must never take over an existing client.
pub async fn test_oauth2_client_create_never_replaces(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();

    let cid = format!("test-client-new-{}", Uuid::now_v7().simple());
    let owner = create_test_oauth2_client(&cid);
    application::store_client(backend, &owner, test_audit())
        .await
        .unwrap();

    let mut intruder = create_test_oauth2_client(&cid);
    intruder.client_name = "Intruder".to_string();
    intruder.redirect_uris = vec!["https://attacker.example.com/cb".to_string()];
    let err = application::store_client(backend, &intruder, test_audit())
        .await
        .unwrap_err();
    assert!(
        matches!(err, sid_core::Error::Conflict(_)),
        "second create must be a conflict, got {err:?}"
    );

    let stored = backend.get_oauth2_client(&cid).await.unwrap().unwrap();
    assert_eq!(stored.client_name, owner.client_name);
    assert_eq!(stored.redirect_uris, owner.redirect_uris);
    // The refused registration's application was not stored either.
    assert!(
        backend
            .get_application(intruder.application_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Two registrations racing for one id: exactly one wins, the other conflicts.
pub async fn test_oauth2_client_concurrent_create(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();

    let cid = format!("test-client-race-{}", Uuid::now_v7().simple());
    let mut a = create_test_oauth2_client(&cid);
    a.client_name = "A".to_string();
    let mut b = create_test_oauth2_client(&cid);
    b.client_name = "B".to_string();

    let (ra, rb) = tokio::join!(
        application::store_client(backend, &a, test_audit()),
        application::store_client(backend, &b, test_audit()),
    );
    let winner = match (&ra, &rb) {
        (Ok(()), Err(sid_core::Error::Conflict(_))) => "A",
        (Err(sid_core::Error::Conflict(_)), Ok(())) => "B",
        other => panic!("expected one winner and one conflict, got {other:?}"),
    };
    let stored = backend.get_oauth2_client(&cid).await.unwrap().unwrap();
    assert_eq!(stored.client_name, winner);
}

/// Every client field survives a save and a load. A backend that drops one
/// changes behaviour silently: a lost `subject_type` turns a public client
/// pairwise, a lost registration token hash disables RFC 7592 management.
/// A list keeps its items as given: a comma is valid inside a URI (RFC 3986
/// §2.2) and a quoted e-mail local part (RFC 5322 §3.4.1), and splitting on
/// it would register URIs nobody validated.
pub async fn test_oauth2_client_full_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{
        ApplicationType, AuthLevel, ClaimMapping, DeviceAssurance, EnforcementMode,
        InitialAccessTokenId, SubjectType, TokenEndpointAuthMethod,
    };
    backend.ensure_system_project(test_audit()).await.unwrap();

    let at = |days: i64| {
        chrono::DateTime::from_timestamp_millis(
            (Utc::now() - Duration::days(days)).timestamp_millis(),
        )
        .unwrap()
    };
    let client = OAuth2Client {
        client_id: format!("test-full-{}", Uuid::now_v7().simple()),
        project_id: ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: ApplicationType::Spa,
        client_secret_hash: Some(vec![1, 2, 3]),
        jwks: Some(
            sid_core::models::ClientKeySet::from_json(
                r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1","use":"sig"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k2"}]}"#,
            )
            .unwrap(),
        ),
        redirect_uris: vec![
            "https://app.sid.example.com/cb".to_string(),
            "https://app.sid.example.com/cb2?a=1,http://evil.sid.example.com/cb".to_string(),
        ],
        allowed_scopes: vec!["openid".into(), "email".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: "Full".to_string(),
        logo_uri: Some("https://app.sid.example.com/logo.png".to_string()),
        active: false,
        token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: Some("https://app.sid.example.com/sector.json".to_string()),
        contacts: vec![
            "a@sid.example.com".to_string(),
            "\"b,c\"@sid.example.com".to_string(),
        ],
        client_id_issued_at: at(3),
        client_secret_expires_at: Some(at(-30)),
        registration_iat: Some(InitialAccessTokenId(Uuid::now_v7())),
        registration_access_token_hash: Some(vec![9, 8, 7]),
        required_acr: Some(AuthLevel::Elevated),
        required_amr: vec!["hwk".into(), "pin".into()],
        enforcement_mode: EnforcementMode::Hard,
        min_device_assurance: Some(DeviceAssurance::Managed),
        require_verified_email: Some(true),
        require_verified_phone: Some(false),
        backchannel_logout_uri: Some("https://app.sid.example.com/logout".to_string()),
        backchannel_logout_session_required: true,
        post_logout_redirect_uris: vec![
            "https://app.sid.example.com/bye?a=1,2".to_string(),
            "https://app.sid.example.com/bye2".to_string(),
        ],
        claim_mappings: vec![ClaimMapping {
            source: "profile.email".to_string(),
            target: "mail".to_string(),
            transform: None,
            condition: Some("scope:email".to_string()),
        }],
        login_strategy: LoginStrategy::FederationFirst,
        show_federation_button: false,
        federation_timeout_ms: 1500,
        unified_input: true,
        org_id: Some(instance_org(backend).await),
        revision: 0,
        created_at: at(3),
    };
    application::store_client(backend, &client, test_audit())
        .await
        .unwrap();

    let got = backend
        .get_oauth2_client(&client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.project_id, client.project_id);
    assert_eq!(got.application_id, client.application_id);
    assert_eq!(got.default_resource, client.default_resource);
    assert_eq!(got.application_type, client.application_type);
    assert_eq!(got.client_secret_hash, client.client_secret_hash);
    assert_eq!(got.jwks, client.jwks);
    assert_eq!(got.redirect_uris, client.redirect_uris);
    assert_eq!(got.allowed_scopes, client.allowed_scopes);
    assert_eq!(got.grant_types, client.grant_types);
    assert_eq!(got.client_name, client.client_name);
    assert_eq!(got.logo_uri, client.logo_uri);
    assert_eq!(got.active, client.active);
    assert_eq!(
        got.token_endpoint_auth_method,
        client.token_endpoint_auth_method
    );
    assert_eq!(got.response_types, client.response_types);
    assert_eq!(got.subject_type, client.subject_type);
    assert_eq!(got.sector_identifier_uri, client.sector_identifier_uri);
    assert_eq!(got.contacts, client.contacts);
    assert_eq!(got.client_id_issued_at, client.client_id_issued_at);
    assert_eq!(
        got.client_secret_expires_at,
        client.client_secret_expires_at
    );
    assert_eq!(got.registration_iat, client.registration_iat);
    assert_eq!(
        got.registration_access_token_hash,
        client.registration_access_token_hash
    );
    assert_eq!(got.required_acr, client.required_acr);
    assert_eq!(got.required_amr, client.required_amr);
    assert_eq!(got.enforcement_mode, client.enforcement_mode);
    assert_eq!(got.min_device_assurance, client.min_device_assurance);
    assert_eq!(got.require_verified_email, client.require_verified_email);
    assert_eq!(got.require_verified_phone, client.require_verified_phone);
    assert_eq!(got.backchannel_logout_uri, client.backchannel_logout_uri);
    assert_eq!(
        got.backchannel_logout_session_required,
        client.backchannel_logout_session_required
    );
    assert_eq!(
        got.post_logout_redirect_uris,
        client.post_logout_redirect_uris
    );
    assert_eq!(got.claim_mappings.len(), 1);
    assert_eq!(got.claim_mappings[0].target, "mail");
    assert_eq!(got.login_strategy, client.login_strategy);
    assert_eq!(got.show_federation_button, client.show_federation_button);
    assert_eq!(got.federation_timeout_ms, client.federation_timeout_ms);
    assert_eq!(got.unified_input, client.unified_input);
    assert_eq!(got.org_id, client.org_id);
}

pub fn create_test_iat(max_clients: u32) -> sid_core::models::InitialAccessToken {
    let now = Utc::now();
    sid_core::models::InitialAccessToken {
        id: sid_core::models::InitialAccessTokenId(Uuid::now_v7()),
        token_hash: Uuid::now_v7().as_bytes().to_vec(),
        project_id: ProjectId::system(),
        max_clients,
        clients_registered: 0,
        allowed_scopes: vec!["openid".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        allowed_redirect_patterns: vec!["https://*.sid.example.com/*".into()],
        expires_at: now + Duration::hours(1),
        created_at: now,
        created_by: "admin".to_string(),
        revoked: false,
    }
}

/// An initial access token is stored and found by id, by hash and by project;
/// revoking an unknown token is `NotFound`.
pub async fn test_iat_save_get_list_revoke(backend: &dyn StorageBackend) {
    use sid_core::models::InitialAccessTokenId;
    backend.ensure_system_project(test_audit()).await.unwrap();
    let iat = create_test_iat(3);
    backend
        .create_initial_access_token(&iat, test_audit())
        .await
        .unwrap();

    let by_id = backend
        .get_initial_access_token(iat.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_id.token_hash, iat.token_hash);
    assert_eq!(by_id.max_clients, 3);
    assert_eq!(by_id.allowed_scopes, iat.allowed_scopes);
    assert_eq!(by_id.allowed_grant_types, iat.allowed_grant_types);
    assert_eq!(
        by_id.allowed_redirect_patterns,
        iat.allowed_redirect_patterns
    );
    assert_eq!(by_id.created_by, "admin");
    let by_hash = backend
        .get_initial_access_token_by_hash(&iat.token_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_hash.id, iat.id);
    let listed = backend
        .list_initial_access_tokens_by_project(ProjectId::system())
        .await
        .unwrap();
    assert!(listed.iter().any(|t| t.id == iat.id));

    backend
        .revoke_initial_access_token(iat.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_initial_access_token(iat.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    // Sending the token again never lifts its revocation.
    let err = backend
        .create_initial_access_token(&iat, test_audit())
        .await
        .expect_err("a create over a revoked token");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert!(
        backend
            .get_initial_access_token(iat.id)
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "a revoked token was reactivated"
    );
    let unknown = backend
        .revoke_initial_access_token(InitialAccessTokenId(Uuid::now_v7()), test_audit())
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, sid_core::Error::NotFound(_)),
        "{unknown:?}"
    );
}

fn dcr_client(iat: &sid_core::models::InitialAccessToken) -> OAuth2Client {
    let mut client = create_test_oauth2_client(&format!("dyn_{}", Uuid::now_v7().simple()));
    client.registration_iat = Some(iat.id);
    client
}

/// Register `client` with an application of its own against `iat`.
async fn register(
    backend: &dyn StorageBackend,
    client: &OAuth2Client,
    iat: sid_core::models::InitialAccessTokenId,
) -> sid_core::Result<()> {
    backend
        .register_dynamic_client(
            &application::application_of(client),
            client,
            iat,
            test_audit(),
        )
        .await
}

async fn iat_count(
    backend: &dyn StorageBackend,
    iat: &sid_core::models::InitialAccessToken,
) -> u32 {
    backend
        .get_initial_access_token(iat.id)
        .await
        .unwrap()
        .unwrap()
        .clients_registered
}

/// A registration counts one use of its token and stores the client with the
/// token it came from; past the limit, or with a revoked or expired token,
/// nothing is stored.
pub async fn test_register_dynamic_client(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let iat = create_test_iat(1);
    backend
        .create_initial_access_token(&iat, test_audit())
        .await
        .unwrap();

    let first = dcr_client(&iat);
    register(backend, &first, iat.id).await.unwrap();
    assert!(
        backend
            .get_application(first.application_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(iat_count(backend, &iat).await, 1);
    let stored = backend
        .get_oauth2_client(&first.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.registration_iat, Some(iat.id));

    let second = dcr_client(&iat);
    let err = register(backend, &second, iat.id).await.unwrap_err();
    assert!(
        backend
            .get_application(second.application_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(err, sid_core::Error::InvalidState(_)), "{err:?}");
    assert!(
        backend
            .get_oauth2_client(&second.client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(iat_count(backend, &iat).await, 1);

    let revoked = create_test_iat(0);
    backend
        .create_initial_access_token(&revoked, test_audit())
        .await
        .unwrap();
    backend
        .revoke_initial_access_token(revoked.id, test_audit())
        .await
        .unwrap();
    let err = register(backend, &dcr_client(&revoked), revoked.id)
        .await
        .unwrap_err();
    assert!(matches!(err, sid_core::Error::Revoked(_)), "{err:?}");

    let mut expired = create_test_iat(0);
    expired.expires_at = Utc::now() - Duration::minutes(1);
    backend
        .create_initial_access_token(&expired, test_audit())
        .await
        .unwrap();
    let err = register(backend, &dcr_client(&expired), expired.id)
        .await
        .unwrap_err();
    assert!(matches!(err, sid_core::Error::Expired(_)), "{err:?}");
    assert_eq!(iat_count(backend, &expired).await, 0);
}

/// A registration whose `client_id` exists is refused whole: the existing
/// client is untouched and the token use is not counted.
pub async fn test_register_dynamic_client_conflict_counts_nothing(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let iat = create_test_iat(0);
    backend
        .create_initial_access_token(&iat, test_audit())
        .await
        .unwrap();
    let owner = create_test_oauth2_client(&format!("dyn_{}", Uuid::now_v7().simple()));
    application::store_client(backend, &owner, test_audit())
        .await
        .unwrap();

    let mut taker = dcr_client(&iat);
    taker.client_id = owner.client_id.clone();
    taker.client_name = "Intruder".to_string();
    let err = register(backend, &taker, iat.id).await.unwrap_err();
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert_eq!(iat_count(backend, &iat).await, 0);
    let stored = backend
        .get_oauth2_client(&owner.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_name, owner.client_name);
    assert_eq!(stored.registration_iat, None);
}

/// Concurrent registrations against a single-use token: exactly one succeeds.
pub async fn test_register_dynamic_client_concurrent_limit(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let iat = create_test_iat(1);
    backend
        .create_initial_access_token(&iat, test_audit())
        .await
        .unwrap();
    let (a, b) = (dcr_client(&iat), dcr_client(&iat));
    let (ra, rb) = tokio::join!(register(backend, &a, iat.id), register(backend, &b, iat.id),);
    let registered = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    assert_eq!(registered, 1, "results: {ra:?} {rb:?}");
    assert!(
        [&ra, &rb]
            .iter()
            .any(|r| matches!(r, Err(sid_core::Error::InvalidState(_))))
    );
    assert_eq!(iat_count(backend, &iat).await, 1);
}

/// A version number no other test run uses (the table is shared).
fn unique_key_version() -> u32 {
    let n = u32::from_le_bytes(Uuid::new_v4().as_bytes()[..4].try_into().unwrap());
    1_000_000 + n % 1_000_000_000
}

/// Concurrent appends to one audit chain serialize: each record gets its own
/// sequence number and links to the record before it, from the first on.
pub async fn test_audit_chain_concurrent_appends(log: std::sync::Arc<dyn sid_plugin::AuditLog>) {
    const WRITERS: u64 = 16;
    let chain = format!("conformance:{}", Uuid::now_v7());
    let tasks: Vec<_> = (0..WRITERS)
        .map(|i| {
            let log = log.clone();
            let chain = chain.clone();
            tokio::spawn(async move {
                log.log(&chain, AuditEntry::system("append", format!("writer-{i}")))
                    .await
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().expect("every append succeeds");
    }

    let records = log.query(&chain, None, None).await.unwrap();
    let sequences: Vec<u64> = records.iter().map(|r| r.sequence).collect();
    assert_eq!(sequences, (1..=WRITERS).collect::<Vec<_>>());
    let verify = log.verify_chain(&chain).await.unwrap();
    assert!(
        verify.valid,
        "chain forked: {:?}",
        verify.first_broken_record
    );
    assert_eq!(verify.records_verified, WRITERS);
}

/// Every field of a closure request survives a create and a reload, including
/// the legal hold that freezes the closure; a second create never replaces it.
pub async fn test_closure_request_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{ClosureMode, ClosureRequest, ExportStatus, LegalHold, ProfileStatus};
    let profile = create_test_profile("closure");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    // Whole seconds: SQLite keeps timestamps at millisecond precision.
    let at = |secs| chrono::DateTime::from_timestamp(secs, 0).unwrap();
    let hold = LegalHold {
        court_reference: "case-7".into(),
        reason: Some("litigation".into()),
        placed_at: at(1_800_000_000),
        expected_end: Some(at(1_900_000_000)),
        placed_by: profile.id,
        reviewing_counsel: Some("counsel@sid.example.com".into()),
        previous_status: ProfileStatus::GracePeriod,
    };
    let mut request = ClosureRequest {
        profile_id: profile.id,
        mode: ClosureMode::GdprErasure,
        closure_reason: Some("user asked".into()),
        requested_by: profile.id,
        requested_at: at(1_700_000_000),
        grace_period_end: Some(at(1_700_100_000)),
        export_status: ExportStatus::Ready,
        legal_hold: Some(hold),
        cancel_count: 2,
    };
    backend
        .create_closure_request(&request, test_audit())
        .await
        .unwrap();

    let stored = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .expect("closure request stored");
    assert_eq!(stored.mode, ClosureMode::GdprErasure);
    assert_eq!(stored.closure_reason.as_deref(), Some("user asked"));
    assert_eq!(stored.requested_by, profile.id);
    assert_eq!(stored.requested_at, request.requested_at);
    assert_eq!(stored.grace_period_end, request.grace_period_end);
    assert_eq!(stored.export_status, ExportStatus::Ready);
    assert_eq!(stored.cancel_count, 2);
    let stored_hold = stored.legal_hold.expect("legal hold stored");
    assert_eq!(stored_hold.court_reference, "case-7");
    assert_eq!(stored_hold.reason.as_deref(), Some("litigation"));
    assert_eq!(stored_hold.placed_at, at(1_800_000_000));
    assert_eq!(stored_hold.expected_end, Some(at(1_900_000_000)));
    assert_eq!(stored_hold.placed_by, profile.id);
    assert_eq!(
        stored_hold.reviewing_counsel.as_deref(),
        Some("counsel@sid.example.com")
    );
    assert_eq!(stored_hold.previous_status, ProfileStatus::GracePeriod);

    request.legal_hold = None;
    assert!(matches!(
        backend.create_closure_request(&request, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    let kept = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .expect("closure request stored");
    assert!(
        kept.legal_hold.is_some(),
        "a second create replaced the request"
    );
}

/// The closing status and the closure request are one write over the profile
/// revision: a stale copy stores neither; a cancellation is counted with the
/// status it restores; a new request keeps the count and the legal hold of
/// the one before; a profile without a request cannot be cancelled.
pub async fn test_closure_request_moves_with_profile(backend: &dyn StorageBackend) {
    use sid_core::models::{ClosureMode, ClosureRequest, LegalHold, ProfileStatus};
    let profile = create_test_profile("closing");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let reload = || async {
        backend
            .get_profile(profile.id)
            .await
            .unwrap()
            .expect("profile")
    };
    let request = |hold: Option<LegalHold>| {
        let mut r = ClosureRequest::new(profile.id, ClosureMode::Voluntary, profile.id)
            .with_grace_period_days(30);
        r.legal_hold = hold;
        r
    };
    let closing = |mut p: sid_core::models::Profile| {
        p.transition_status(ProfileStatus::ClosureRequested)
            .unwrap();
        p
    };
    let restored = |mut p: sid_core::models::Profile| {
        p.as_closing().expect("closing").cancel();
        p
    };
    let hold = LegalHold {
        court_reference: "case-9".into(),
        reason: None,
        placed_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        expected_end: None,
        placed_by: profile.id,
        reviewing_counsel: None,
        previous_status: ProfileStatus::ClosureRequested,
    };

    assert!(matches!(
        backend.cancel_profile_closure(&profile, test_audit()).await,
        Err(sid_core::Error::NotFound(_))
    ));
    assert_eq!(reload().await.status, ProfileStatus::Active);

    let stale = profile.clone();
    assert!(
        backend
            .request_profile_closure(
                &closing(profile.clone()),
                &request(Some(hold)),
                test_audit()
            )
            .await
            .unwrap()
    );
    assert_eq!(reload().await.status, ProfileStatus::ClosureRequested);
    let first = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .expect("request stored");
    assert!(
        !backend
            .request_profile_closure(&closing(stale.clone()), &request(None), test_audit())
            .await
            .unwrap(),
        "a stale profile copy requested a closure"
    );
    let unchanged = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.requested_at, first.requested_at);
    assert!(unchanged.legal_hold.is_some());

    let before_cancel = reload().await;
    assert!(
        backend
            .cancel_profile_closure(&restored(before_cancel.clone()), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(reload().await.status, ProfileStatus::Active);
    assert!(
        !backend
            .cancel_profile_closure(&restored(before_cancel), test_audit())
            .await
            .unwrap(),
        "a stale profile copy cancelled again"
    );
    let cancelled = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cancelled.cancel_count, 1,
        "a stale cancellation was counted"
    );

    // The new request carries neither count nor hold; the stored ones stay.
    assert!(
        backend
            .request_profile_closure(&closing(reload().await), &request(None), test_audit())
            .await
            .unwrap()
    );
    let renewed = backend
        .get_closure_request(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed.cancel_count, 1,
        "a new request reset the cancel count"
    );
    assert!(
        renewed.legal_hold.is_some(),
        "a new request dropped the legal hold"
    );
    assert!(renewed.requested_at >= first.requested_at);
}

/// A key version is stored once: a second insert of the same version (another
/// replica starting with its own random salt) writes nothing, so every process
/// derives the same key for it.
pub async fn test_key_version_insert_once(backend: &dyn StorageBackend) {
    let version = unique_key_version();
    let first = sid_plugin::KeyVersionParams::new(version, vec![1u8; 16], "key-v-test");
    let second = sid_plugin::KeyVersionParams::new(version, vec![2u8; 16], "key-v-test");
    assert!(
        backend
            .insert_key_version(&first, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .insert_key_version(&second, test_audit())
            .await
            .unwrap()
    );
    let stored = backend.list_key_versions().await.unwrap();
    let ours = stored.iter().find(|v| v.version == version).unwrap();
    assert_eq!(ours.salt, first.salt);
    assert_eq!(ours.context, "key-v-test");
    assert_eq!(ours.algorithm, first.algorithm);
    assert!(stored.windows(2).all(|w| w[0].version < w[1].version));
}

/// Concurrent starters inserting the same version: exactly one wins.
pub async fn test_key_version_concurrent_insert(backend: &dyn StorageBackend) {
    let version = unique_key_version();
    let a = sid_plugin::KeyVersionParams::new(version, vec![3u8; 16], "key-v-a");
    let b = sid_plugin::KeyVersionParams::new(version, vec![4u8; 16], "key-v-b");
    let (ra, rb) = tokio::join!(
        backend.insert_key_version(&a, test_audit()),
        backend.insert_key_version(&b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "exactly one insert must win: {ra} {rb}");
    let stored = backend.list_key_versions().await.unwrap();
    let ours = stored.iter().find(|v| v.version == version).unwrap();
    let winner = if ra { &a } else { &b };
    assert_eq!(ours.salt, winner.salt);
}

/// An instance secret is written once: of concurrent starters at most one
/// insert wins (none when an earlier start already stored it), every later
/// insert writes nothing, and all of them read back the same stored value.
pub async fn test_instance_secret_insert_once(backend: &dyn StorageBackend) {
    use sid_core::models::InstanceSecret;
    let secret = InstanceSecret::OpaqueServerSetup;
    let before = backend.get_instance_secret(secret).await.unwrap();
    let (a, b) = (
        Uuid::now_v7().as_bytes().to_vec(),
        Uuid::now_v7().as_bytes().to_vec(),
    );
    let (ra, rb) = tokio::join!(
        backend.insert_instance_secret(secret, &a, test_audit()),
        backend.insert_instance_secret(secret, &b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(!(ra && rb), "two inserts of one secret both won");

    let stored = backend.get_instance_secret(secret).await.unwrap().unwrap();
    match (&before, ra, rb) {
        (Some(earlier), false, false) => assert_eq!(&stored, earlier),
        (None, true, false) => assert_eq!(stored, a),
        (None, false, true) => assert_eq!(stored, b),
        other => panic!("inconsistent insert outcome: {other:?}"),
    }
    let late = Uuid::now_v7().as_bytes().to_vec();
    assert!(
        !backend
            .insert_instance_secret(secret, &late, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.get_instance_secret(secret).await.unwrap().unwrap(),
        stored
    );
}

/// Paging credentials of one type visits each of them once, in id order,
/// and nothing of another type.
pub async fn test_list_credentials_by_type_pages(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};
    let profile = create_test_profile("cred_pages");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut ours = Vec::new();
    for n in 0..3u8 {
        let c = Credential::new(profile.id, CredentialType::Totp, vec![n; 20], None);
        backend.create_credential(&c, test_audit()).await.unwrap();
        ours.push(c.id);
    }
    let other = Credential::new(profile.id, CredentialType::Recovery, vec![9; 8], None);
    backend
        .create_credential(&other, test_audit())
        .await
        .unwrap();

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = backend
            .list_credentials_by_type(CredentialType::Totp, after, 2)
            .await
            .unwrap();
        let Some(last) = page.last() else { break };
        assert!(page.len() <= 2);
        assert!(
            page.iter()
                .all(|c| c.credential_type == CredentialType::Totp)
        );
        after = Some(last.id);
        seen.extend(page.iter().map(|c| c.id));
    }
    assert!(
        seen.windows(2).all(|w| w[0].0 < w[1].0),
        "pages must follow id order"
    );
    for id in &ours {
        assert_eq!(seen.iter().filter(|s| *s == id).count(), 1);
    }
    assert!(!seen.contains(&other.id));
}

pub async fn test_oauth2_client_not_found(backend: &dyn StorageBackend) {
    let result = backend
        .get_oauth2_client("nonexistent-client")
        .await
        .unwrap();
    assert!(result.is_none());
}

// ─── Refresh Token CRUD ───

pub async fn test_refresh_token_save_and_get(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    let token_hash: Vec<u8> = Uuid::now_v7().as_bytes().to_vec();
    let token_id = Uuid::now_v7();
    let token = RefreshToken {
        id: token_id,
        token_hash: token_hash.clone(),
        session_id: session.id,
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into(), "profile".into()],
        resource: application::grant_resource(backend).await,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: token_id,
        grace_expires_at: None,
        dpop_jkt: Some("IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA".to_string()),
    };
    backend
        .create_refresh_token(&token, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_refresh_token_by_hash(&token_hash)
        .await
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, token.id);
    assert_eq!(retrieved.family_id, token.family_id);
    assert!(!retrieved.revoked);
    assert_eq!(retrieved.dpop_jkt, token.dpop_jkt);
    assert_eq!(retrieved.resource, token.resource);
}

pub async fn test_refresh_token_revoke(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt_revoke");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    let token_hash: Vec<u8> = Uuid::now_v7().as_bytes().to_vec();
    let token_id = Uuid::now_v7();
    let token = RefreshToken {
        id: token_id,
        token_hash: token_hash.clone(),
        session_id: session.id,
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: token_id,
        grace_expires_at: None,
        dpop_jkt: None,
    };
    backend
        .create_refresh_token(&token, test_audit())
        .await
        .unwrap();

    assert_eq!(
        backend
            .revoke_refresh_tokens_by_family(token.family_id, test_audit())
            .await
            .unwrap(),
        1
    );

    let retrieved = backend
        .get_refresh_token_by_hash(&token_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(retrieved.revoked);
}

pub async fn test_refresh_token_revoke_by_session(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt_bulk");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();

    let family_id = Uuid::now_v7();
    for _ in 0..3u8 {
        let token = RefreshToken {
            id: Uuid::now_v7(),
            token_hash: Uuid::now_v7().as_bytes().to_vec(),
            session_id: session.id,
            profile_id: profile.id,
            client_id: "test-client".to_string(),
            scopes: vec!["openid".into()],
            resource: application::grant_resource(backend).await,
            expires_at: Utc::now() + Duration::days(30),
            created_at: Utc::now(),
            revoked: false,
            replaced_by: None,
            family_id,
            grace_expires_at: None,
            dpop_jkt: None,
        };
        backend
            .create_refresh_token(&token, test_audit())
            .await
            .unwrap();
    }

    let revoked = backend
        .revoke_refresh_tokens_by_session(session.id, test_audit())
        .await
        .unwrap();
    assert_eq!(revoked, 3);
}

/// A refresh token of `family_id` for `session`, stored unless `store` is false.
async fn refresh_token_in(
    backend: &dyn StorageBackend,
    session: &Session,
    family_id: Uuid,
    store: bool,
) -> RefreshToken {
    let token = RefreshToken {
        id: Uuid::now_v7(),
        token_hash: Uuid::now_v7().as_bytes().to_vec(),
        session_id: session.id,
        profile_id: session.profile_id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id,
        grace_expires_at: None,
        dpop_jkt: None,
    };
    if store {
        backend
            .create_refresh_token(&token, test_audit())
            .await
            .unwrap();
    }
    token
}

async fn stored_refresh(
    backend: &dyn StorageBackend,
    token: &RefreshToken,
) -> Option<RefreshToken> {
    backend
        .get_refresh_token_by_hash(&token.token_hash)
        .await
        .unwrap()
}

/// Rotation replaces the old token with the new one in one write: the old
/// one keeps a grace window for a client retry (a retry inside it rotates
/// again and keeps the window), and nothing is written once the old token is
/// revoked for good.
pub async fn test_rotate_refresh_token(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt_rotate");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let family = Uuid::now_v7();
    let old = refresh_token_in(backend, &session, family, true).await;
    let grace = Utc::now() + Duration::seconds(30);

    let first = refresh_token_in(backend, &session, family, false).await;
    assert!(
        backend
            .rotate_refresh_token(old.id, &first, grace, test_audit())
            .await
            .unwrap()
    );
    let old_after = stored_refresh(backend, &old).await.unwrap();
    assert!(old_after.revoked);
    assert_eq!(old_after.replaced_by, Some(first.id));
    let window = old_after.grace_expires_at.expect("grace window");
    assert!(!stored_refresh(backend, &first).await.unwrap().revoked);

    // A client retry inside the window rotates again; the window stays.
    let retry = refresh_token_in(backend, &session, family, false).await;
    assert!(
        backend
            .rotate_refresh_token(
                old.id,
                &retry,
                Utc::now() + Duration::seconds(300),
                test_audit()
            )
            .await
            .unwrap()
    );
    let kept = stored_refresh(backend, &old)
        .await
        .unwrap()
        .grace_expires_at;
    assert_eq!(
        kept.map(|t| t.timestamp_millis()),
        Some(window.timestamp_millis())
    );

    // Reuse detected: the whole family ends, including the grace window.
    backend
        .revoke_refresh_tokens_by_family(family, test_audit())
        .await
        .unwrap();
    for token in [&old, &first, &retry] {
        let stored = stored_refresh(backend, token).await.unwrap();
        assert!(stored.revoked);
        assert!(stored.grace_expires_at.is_none(), "grace window survived");
    }
    let late = refresh_token_in(backend, &session, family, false).await;
    assert!(
        !backend
            .rotate_refresh_token(old.id, &late, grace, test_audit())
            .await
            .unwrap()
    );
    assert!(
        stored_refresh(backend, &late).await.is_none(),
        "rotated after revocation"
    );
}

/// A token revoked by sign-out cannot be rotated, and signing out ends a
/// grace window too.
pub async fn test_rotate_after_sign_out_is_refused(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt_signout");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let family = Uuid::now_v7();
    let old = refresh_token_in(backend, &session, family, true).await;
    let next = refresh_token_in(backend, &session, family, false).await;
    backend
        .rotate_refresh_token(
            old.id,
            &next,
            Utc::now() + Duration::seconds(30),
            test_audit(),
        )
        .await
        .unwrap();

    backend
        .revoke_refresh_tokens_by_session(session.id, test_audit())
        .await
        .unwrap();

    let retry = refresh_token_in(backend, &session, family, false).await;
    assert!(
        !backend
            .rotate_refresh_token(
                old.id,
                &retry,
                Utc::now() + Duration::seconds(30),
                test_audit()
            )
            .await
            .unwrap(),
        "a grace window outlived sign-out"
    );
    assert!(stored_refresh(backend, &retry).await.is_none());
}

// ─── Authorization Code CRUD ───

/// Store a stepped-up MFA session of `profile` and return the authentication
/// a code it authorizes carries. Times are at millisecond precision, which
/// every store keeps.
async fn authorizing_session(
    backend: &dyn StorageBackend,
    profile: &Profile,
) -> sid_core::models::GrantAuthentication {
    let ms = |t: chrono::DateTime<Utc>| {
        chrono::DurationRound::duration_trunc(t, Duration::milliseconds(1)).unwrap()
    };
    let mut session = create_test_session(profile.id);
    session.authenticated_at = ms(Utc::now() - Duration::minutes(20));
    session.amr = vec!["pwd".into(), "otp".into(), "mfa".into()];
    session.assurance_level = sid_core::models::AuthLevel::Standard;
    session.elevation = Some(sid_core::models::session::Elevation {
        level: sid_core::models::AuthLevel::Elevated,
        until: ms(Utc::now() + Duration::minutes(10)),
    });
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    session.grant_authentication()
}

pub async fn test_auth_code_save_and_get(backend: &dyn StorageBackend) {
    let profile = create_test_profile("ac");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let code_hash: Vec<u8> = Uuid::now_v7().as_bytes().to_vec();
    let code = AuthorizationCode {
        code_hash: code_hash.clone(),
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        code_challenge: Some("challenge".to_string()),
        nonce: Some("n-0S6_WzA2Mj".to_string()),
        authentication: authorizing_session(backend, &profile).await,
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    };
    backend.create_auth_code(&code, test_audit()).await.unwrap();

    let retrieved = backend.get_auth_code_by_hash(&code_hash).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert!(!retrieved.used);
    assert_eq!(retrieved.client_id, "test-client");
    assert_eq!(retrieved.code_challenge.as_deref(), Some("challenge"));
    assert_eq!(retrieved.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(retrieved.resource, code.resource);
    // The authorizing session's authentication, step-up included.
    assert_eq!(retrieved.authentication, code.authentication);
}

/// A stored, unused authorization code for a fresh profile; returns the
/// profile and the code hash.
async fn stored_auth_code(backend: &dyn StorageBackend, name: &str) -> (Profile, Vec<u8>) {
    let profile = create_test_profile(name);
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let code_hash: Vec<u8> = Uuid::now_v7().as_bytes().to_vec();
    let code = AuthorizationCode {
        code_hash: code_hash.clone(),
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        code_challenge: None,
        nonce: None,
        authentication: authorizing_session(backend, &profile).await,
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    };
    backend.create_auth_code(&code, test_audit()).await.unwrap();
    (profile, code_hash)
}

/// Issuing an authorization code never replaces one: a second code with the
/// same hash is `Conflict`, and a redeemed code stays redeemed.
pub async fn test_auth_code_create_never_replaces(backend: &dyn StorageBackend) {
    let (profile, code_hash) = stored_auth_code(backend, "ac_replace").await;
    let (session, token) = exchange_records(backend, &profile).await;
    backend
        .redeem_auth_code(&code_hash, &session, &token, test_audit())
        .await
        .unwrap();

    let again = AuthorizationCode {
        code_hash: code_hash.clone(),
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        redirect_uri: "https://app.sid.example.com/callback".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        code_challenge: None,
        nonce: None,
        authentication: authorizing_session(backend, &profile).await,
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    };
    assert!(matches!(
        backend.create_auth_code(&again, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    let stored = backend
        .get_auth_code_by_hash(&code_hash)
        .await
        .unwrap()
        .expect("code stored");
    assert!(stored.used, "a redeemed code was made usable again");
}

/// The session and refresh token one exchange of a code would issue.
pub async fn exchange_records(
    backend: &dyn StorageBackend,
    profile: &Profile,
) -> (Session, RefreshToken) {
    let session = create_test_session(profile.id);
    let token = RefreshToken {
        id: Uuid::now_v7(),
        token_hash: Uuid::now_v7().as_bytes().to_vec(),
        session_id: session.id,
        profile_id: profile.id,
        client_id: "test-client".to_string(),
        scopes: vec!["openid".into()],
        resource: application::grant_resource(backend).await,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: Uuid::now_v7(),
        grace_expires_at: None,
        dpop_jkt: None,
    };
    (session, token)
}

/// Storing a refresh token never replaces one: a revoked token stays revoked
/// when a save of it arrives again.
pub async fn test_refresh_token_save_never_replaces(backend: &dyn StorageBackend) {
    let profile = create_test_profile("rt_replace");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let (session, mut token) = exchange_records(backend, &profile).await;
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    backend
        .create_refresh_token(&token, test_audit())
        .await
        .unwrap();
    backend
        .revoke_refresh_tokens_by_family(token.family_id, test_audit())
        .await
        .unwrap();

    token.revoked = false;
    let err = backend
        .create_refresh_token(&token, test_audit())
        .await
        .expect_err("a save over an existing refresh token");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    let stored = backend
        .get_refresh_token_by_hash(&token.token_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.revoked, "a revoked refresh token was revived");
}

/// A code is redeemed once: the redemption stores its session and refresh
/// token and marks the code; a second redemption stores nothing and reports
/// the first session so its tokens can be revoked (RFC 6749 §4.1.2).
pub async fn test_auth_code_redeem_once(backend: &dyn StorageBackend) {
    let (profile, code_hash) = stored_auth_code(backend, "ac_redeem").await;

    let (session, token) = exchange_records(backend, &profile).await;
    let first = backend
        .redeem_auth_code(&code_hash, &session, &token, test_audit())
        .await
        .unwrap();
    assert_eq!(first, AuthCodeRedemption::Redeemed);
    let code = backend
        .get_auth_code_by_hash(&code_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(code.used);
    assert_eq!(code.session_id, Some(session.id));
    assert!(backend.get_session(session.id).await.unwrap().is_some());
    assert!(
        backend
            .get_refresh_token_by_hash(&token.token_hash)
            .await
            .unwrap()
            .is_some()
    );

    let (again_session, again_token) = exchange_records(backend, &profile).await;
    let second = backend
        .redeem_auth_code(&code_hash, &again_session, &again_token, test_audit())
        .await
        .unwrap();
    assert_eq!(
        second,
        AuthCodeRedemption::AlreadyRedeemed {
            session_id: Some(session.id)
        }
    );
    assert!(
        backend
            .get_session(again_session.id)
            .await
            .unwrap()
            .is_none(),
        "a refused redemption stores no session"
    );
    assert!(
        backend
            .get_refresh_token_by_hash(&again_token.token_hash)
            .await
            .unwrap()
            .is_none(),
        "a refused redemption stores no refresh token"
    );
}

/// Two concurrent redemptions of one code: exactly one succeeds and only its
/// session exists afterwards.
pub async fn test_auth_code_concurrent_redeem(backend: &dyn StorageBackend) {
    let (profile, code_hash) = stored_auth_code(backend, "ac_race").await;
    let (a_session, a_token) = exchange_records(backend, &profile).await;
    let (b_session, b_token) = exchange_records(backend, &profile).await;

    let (a, b) = tokio::join!(
        backend.redeem_auth_code(&code_hash, &a_session, &a_token, test_audit()),
        backend.redeem_auth_code(&code_hash, &b_session, &b_token, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    let winners = [a, b]
        .iter()
        .filter(|r| **r == AuthCodeRedemption::Redeemed)
        .count();
    assert_eq!(winners, 1, "exactly one exchange gets tokens: {a:?} {b:?}");

    let (winner, loser) = if a == AuthCodeRedemption::Redeemed {
        (&a_session, &b_session)
    } else {
        (&b_session, &a_session)
    };
    assert!(backend.get_session(winner.id).await.unwrap().is_some());
    assert!(backend.get_session(loser.id).await.unwrap().is_none());
}

pub async fn test_auth_code_not_found(backend: &dyn StorageBackend) {
    let result = backend.get_auth_code_by_hash(&[0u8; 32]).await.unwrap();
    assert!(result.is_none());
}

// ─── Magic Link ───

pub async fn test_magic_link_crud(backend: &dyn StorageBackend) {
    use sid_core::models::magic_link::MagicLinkSession;

    let id = Uuid::now_v7();
    // The store is shared across runs: the address is this test's own.
    let email = format!("ml-{}@sid.example.com", id.simple());
    let session = MagicLinkSession {
        id,
        email: email.clone(),
        token_hash: format!("hash_{}", id),
        consumed: false,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
    };

    backend
        .create_magic_link_session(&session, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_magic_link_session(id).await.unwrap();
    assert!(retrieved.is_some());
    assert!(!retrieved.unwrap().consumed);

    backend
        .consume_magic_link_session(id, test_audit())
        .await
        .unwrap();

    let consumed = backend.get_magic_link_session(id).await.unwrap().unwrap();
    assert!(consumed.consumed);

    let active = backend
        .count_active_magic_links_for_email(&email)
        .await
        .unwrap();
    assert_eq!(active, 0);

    // A create over a consumed link is refused: the link stays spent.
    let err = backend
        .create_magic_link_session(&session, test_audit())
        .await
        .expect_err("a create over an existing link");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
    assert!(
        backend
            .get_magic_link_session(id)
            .await
            .unwrap()
            .unwrap()
            .consumed,
        "a consumed link became usable again"
    );
}

/// Creating a reset session never replaces one.
pub async fn test_reset_session_create_never_replaces(backend: &dyn StorageBackend) {
    use sid_core::models::PasswordResetSession;
    let profile = create_test_profile("reset_replace");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let reset = PasswordResetSession::new(profile.id, "r@sid.example.com".into(), "h".into());
    backend
        .create_reset_session(&reset, test_audit())
        .await
        .unwrap();
    let err = backend
        .create_reset_session(&reset, test_audit())
        .await
        .expect_err("a create over an existing reset session");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");
}

// ─── PAT ───

pub async fn test_pat_crud(backend: &dyn StorageBackend) {
    use sid_core::models::pat::{PatId, PatStatus, PersonalAccessToken};

    let profile = create_test_profile("pat");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let pat = PersonalAccessToken {
        id: PatId(Uuid::now_v7()),
        profile_id: profile.id,
        name: "Test PAT".to_string(),
        description: Some("A test token".to_string()),
        token_hash: format!("sha256hash_{}", Uuid::now_v7().simple()),
        token_prefix: "sid_".to_string(),
        scopes: vec!["read".into()],
        ip_allowlist: vec![],
        status: PatStatus::Active,
        expires_at: Some(Utc::now() + Duration::days(90)),
        last_used_at: None,
        last_used_ip: None,
        use_count: 0,
        revoked_at: None,
        revoked_by: None,
        created_at: Utc::now(),
    };

    backend.create_pat(&pat, None, test_audit()).await.unwrap();

    let retrieved = backend.get_pat(pat.id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Test PAT");

    let by_hash = backend
        .get_pat_by_token_hash(&pat.token_hash)
        .await
        .unwrap();
    assert!(by_hash.is_some());

    let count = backend
        .count_active_pats_by_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(count, 1);

    assert!(
        backend
            .revoke_pat(pat.id, "admin", test_audit())
            .await
            .unwrap()
    );

    let revoked = backend.get_pat(pat.id).await.unwrap().unwrap();
    assert_eq!(revoked.status, PatStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.revoked_by.as_deref(), Some("admin"));

    // A second revocation changes nothing: the first one's actor and time
    // stay on record.
    assert!(
        !backend
            .revoke_pat(pat.id, "owner", test_audit())
            .await
            .unwrap()
    );
    let again = backend.get_pat(pat.id).await.unwrap().unwrap();
    assert_eq!(again.revoked_by.as_deref(), Some("admin"));
    assert_eq!(again.revoked_at, revoked.revoked_at);
    assert!(
        !backend
            .revoke_pat(
                sid_core::models::PatId(Uuid::now_v7()),
                "admin",
                test_audit()
            )
            .await
            .unwrap()
    );
}

/// A PAT fixture of `profile` with a unique token hash.
fn test_pat(profile: &Profile) -> sid_core::models::PersonalAccessToken {
    sid_core::models::PersonalAccessToken::new(
        profile.id,
        "ci",
        format!("hash-{}", Uuid::now_v7()),
        "sid_",
        vec!["read".into()],
    )
}

/// Creating a PAT never replaces one: a second create with the same id is a
/// Conflict and a revoked token stays revoked.
pub async fn test_create_pat_never_replaces(backend: &dyn StorageBackend) {
    use sid_core::models::PatStatus;

    let profile = create_test_profile("pat_once");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut revoked = test_pat(&profile);
    revoked.status = PatStatus::Revoked;
    backend
        .create_pat(&revoked, None, test_audit())
        .await
        .unwrap();

    let mut again = revoked.clone();
    again.status = PatStatus::Active;
    let err = backend
        .create_pat(&again, None, test_audit())
        .await
        .expect_err("a create over an existing PAT");
    assert!(
        matches!(err, sid_core::Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
    let stored = backend.get_pat(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, PatStatus::Revoked);
}

/// The active limit holds under concurrent creates of one profile: of four
/// creates against a limit of two, exactly two are stored; revoked tokens do
/// not count.
pub async fn test_create_pat_active_limit_under_concurrency(backend: &dyn StorageBackend) {
    use sid_core::models::PatStatus;

    let profile = create_test_profile("pat_limit");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut revoked = test_pat(&profile);
    revoked.status = PatStatus::Revoked;
    backend
        .create_pat(&revoked, Some(2), test_audit())
        .await
        .unwrap();

    let pats: Vec<_> = (0..4).map(|_| test_pat(&profile)).collect();
    let (a, b, c, d) = tokio::join!(
        backend.create_pat(&pats[0], Some(2), test_audit()),
        backend.create_pat(&pats[1], Some(2), test_audit()),
        backend.create_pat(&pats[2], Some(2), test_audit()),
        backend.create_pat(&pats[3], Some(2), test_audit()),
    );
    let results = [a, b, c, d];
    let stored = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(stored, 2, "{results:?}");
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, sid_core::Error::ResourceExhausted(_))),
        "{results:?}"
    );
    assert_eq!(
        backend
            .count_active_pats_by_profile(profile.id)
            .await
            .unwrap(),
        2
    );
}

/// A use is recorded only on a token that is active and not expired; a
/// revoked or expired token stays as it was and an unknown id writes nothing.
pub async fn test_record_pat_use_only_when_usable(backend: &dyn StorageBackend) {
    use sid_core::models::{PatId, PatStatus};

    let profile = create_test_profile("pat_use");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let active = test_pat(&profile);
    let mut revoked = test_pat(&profile);
    revoked.status = PatStatus::Revoked;
    let mut expired = test_pat(&profile);
    expired.expires_at = Some(Utc::now() - Duration::minutes(1));
    for p in [&active, &revoked, &expired] {
        backend.create_pat(p, None, test_audit()).await.unwrap();
    }

    assert!(
        backend
            .record_pat_use(active.id, Some("192.0.2.1"), test_audit())
            .await
            .unwrap()
    );
    for id in [revoked.id, expired.id, PatId(Uuid::now_v7())] {
        assert!(
            !backend
                .record_pat_use(id, Some("192.0.2.1"), test_audit())
                .await
                .unwrap()
        );
    }

    let stored = backend.get_pat(active.id).await.unwrap().unwrap();
    assert_eq!(stored.use_count, 1);
    assert_eq!(stored.last_used_ip.as_deref(), Some("192.0.2.1"));
    assert!(stored.last_used_at.is_some());
    let stored = backend.get_pat(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, PatStatus::Revoked);
    assert_eq!(stored.use_count, 0);
    let stored = backend.get_pat(expired.id).await.unwrap().unwrap();
    assert_eq!(stored.use_count, 0);
}

/// PATs list per profile and across the store; the profile-wide revocation
/// ends only that profile's active tokens and keeps the first revocation of
/// one already revoked, also under two concurrent revocations.
pub async fn test_pat_listing_and_profile_revocation(backend: &dyn StorageBackend) {
    use sid_core::models::PatStatus;

    let owner = create_test_profile("pat_owner");
    let other = create_test_profile("pat_other");
    for p in [&owner, &other] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    let a = test_pat(&owner);
    let b = test_pat(&owner);
    let mut earlier = test_pat(&owner);
    earlier.status = PatStatus::Revoked;
    earlier.revoked_by = Some("first".into());
    earlier.revoked_at = Some(Utc::now() - Duration::days(1));
    let foreign = test_pat(&other);
    for p in [&a, &b, &earlier, &foreign] {
        backend.create_pat(p, None, test_audit()).await.unwrap();
    }

    let mut of_owner: Vec<_> = backend
        .list_pats_by_profile(owner.id)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    of_owner.sort_by_key(|id| id.0);
    let mut expected = vec![a.id, b.id, earlier.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(of_owner, expected);
    let all: Vec<_> = backend
        .list_all_pats()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    for id in [a.id, b.id, earlier.id, foreign.id] {
        assert!(all.contains(&id), "list_all_pats is missing {id:?}");
    }

    let (first, second) = tokio::join!(
        backend.revoke_active_pats_by_profile(owner.id, "cascade", test_audit()),
        backend.revoke_active_pats_by_profile(owner.id, "cascade", test_audit()),
    );
    assert_eq!(
        first.unwrap() + second.unwrap(),
        2,
        "each active token is revoked exactly once"
    );
    for id in [a.id, b.id] {
        let stored = backend.get_pat(id).await.unwrap().unwrap();
        assert_eq!(stored.status, PatStatus::Revoked);
        assert_eq!(stored.revoked_by.as_deref(), Some("cascade"));
    }
    let kept = backend.get_pat(earlier.id).await.unwrap().unwrap();
    assert_eq!(kept.revoked_by.as_deref(), Some("first"));
    let untouched = backend.get_pat(foreign.id).await.unwrap().unwrap();
    assert_eq!(
        untouched.status,
        PatStatus::Active,
        "another profile's token was revoked"
    );
}

/// Tokens unused for longer than the window are revoked: never used and
/// created before it, or last used before it. A token used within the
/// window, or created within it, stays active.
pub async fn test_revoke_unused_pats(backend: &dyn StorageBackend) {
    use sid_core::models::PatStatus;

    let profile = create_test_profile("pat_unused");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut stale = test_pat(&profile);
    stale.created_at = Utc::now() - Duration::days(40);
    let mut used_long_ago = test_pat(&profile);
    used_long_ago.created_at = Utc::now() - Duration::days(60);
    used_long_ago.last_used_at = Some(Utc::now() - Duration::days(40));
    let mut old_but_used = test_pat(&profile);
    old_but_used.created_at = Utc::now() - Duration::days(40);
    let fresh = test_pat(&profile);
    for p in [&stale, &used_long_ago, &old_but_used, &fresh] {
        backend.create_pat(p, None, test_audit()).await.unwrap();
    }
    assert!(
        backend
            .record_pat_use(old_but_used.id, None, test_audit())
            .await
            .unwrap()
    );

    let revoked = backend.revoke_unused_pats(30, test_audit()).await.unwrap();
    assert!(revoked >= 2, "{revoked}");
    for id in [stale.id, used_long_ago.id] {
        assert_eq!(
            backend.get_pat(id).await.unwrap().unwrap().status,
            PatStatus::Revoked
        );
    }
    for id in [old_but_used.id, fresh.id] {
        assert_eq!(
            backend.get_pat(id).await.unwrap().unwrap().status,
            PatStatus::Active,
            "a token used or created within the window was revoked"
        );
    }
}

/// Deleting a credential removes that one; the profile-wide delete removes
/// every credential of the profile, counts them, and leaves another
/// profile's.
pub async fn test_credential_deletion(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("cred_delete");
    let other = create_test_profile("cred_keep");
    for p in [&profile, &other] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    let totp = Credential::new(profile.id, CredentialType::Totp, vec![1], None);
    let recovery = Credential::new(profile.id, CredentialType::Recovery, vec![2], None);
    let webauthn = Credential::new(profile.id, CredentialType::WebAuthn, vec![3], None);
    let foreign = Credential::new(other.id, CredentialType::Totp, vec![4], None);
    for c in [&totp, &recovery, &webauthn, &foreign] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }

    backend
        .delete_credential(totp.id, test_audit())
        .await
        .unwrap();
    assert!(backend.get_credential(totp.id).await.unwrap().is_none());
    assert!(backend.get_credential(recovery.id).await.unwrap().is_some());

    let removed = backend
        .delete_credentials_by_profile(profile.id, test_audit())
        .await
        .unwrap();
    assert_eq!(removed, 2);
    for id in [recovery.id, webauthn.id] {
        assert!(backend.get_credential(id).await.unwrap().is_none());
    }
    assert!(
        backend.get_credential(foreign.id).await.unwrap().is_some(),
        "another profile's credential was deleted"
    );
    assert_eq!(
        backend
            .delete_credentials_by_profile(profile.id, test_audit())
            .await
            .unwrap(),
        0
    );
}

// ─── Principal CRUD ───

/// An E.164 number no other test run uses (random low digits).
fn unique_phone() -> String {
    let n = u64::from_le_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    format!("+3805{:08}", n % 100_000_000)
}

fn create_test_principal(profile_id: ProfileId, pt: PrincipalType, value: &str) -> Principal {
    let now = Utc::now();
    Principal {
        id: PrincipalId(Uuid::now_v7()),
        profile_id,
        principal_type: pt,
        value: value.to_string(),
        verified: false,
        verified_at: None,
        verification_expires: None,
        assigned_profile_id: None,
        assignment_revision: 0,
        email_policy_revision: (pt == PrincipalType::Email)
            .then_some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
        is_primary: true,
        source_field: None,
        source_email_id: None,
        source_phone_id: None,
        created_at: now,
        updated_at: now,
    }
}

pub async fn test_principal_save_and_get(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_crud");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email = unique_email("crud");
    let principal = create_test_principal(profile.id, PrincipalType::Email, &email);
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_principal(principal.id).await.unwrap();
    assert!(retrieved.is_some(), "principal not found after save");
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, principal.id);
    assert_eq!(retrieved.profile_id, profile.id);
    assert_eq!(retrieved.principal_type, PrincipalType::Email);
    assert_eq!(retrieved.value, email);
    assert!(!retrieved.verified);
    assert!(retrieved.is_primary);
}

pub async fn test_principal_list_by_profile(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_list");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email = create_test_principal(profile.id, PrincipalType::Email, &unique_email("list"));
    let phone = create_test_principal(profile.id, PrincipalType::Phone, &unique_phone());
    backend.save_principal(&email, test_audit()).await.unwrap();
    backend.save_principal(&phone, test_audit()).await.unwrap();

    let principals = backend.get_principals_by_profile(profile.id).await.unwrap();
    assert_eq!(principals.len(), 2);
    assert!(
        principals
            .iter()
            .any(|p| p.principal_type == PrincipalType::Email)
    );
    assert!(
        principals
            .iter()
            .any(|p| p.principal_type == PrincipalType::Phone)
    );
}

pub async fn test_principal_get_profile_by_principal(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_lookup");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email = unique_email("lookup");
    let principal = create_test_principal(profile.id, PrincipalType::Email, &email);
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();

    let found = backend
        .get_profile_by_principal(PrincipalType::Email, &email)
        .await
        .unwrap();
    assert!(found.is_some(), "profile not found by principal");
    assert_eq!(found.unwrap().id, profile.id);

    // Not found for wrong type
    let not_found = backend
        .get_profile_by_principal(PrincipalType::Phone, &email)
        .await
        .unwrap();
    assert!(not_found.is_none());
}

pub async fn test_principal_delete(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_delete");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let principal = create_test_principal(profile.id, PrincipalType::Phone, &unique_phone());
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();

    assert!(
        backend
            .unbind_principal(principal.id, profile.id, test_audit())
            .await
            .unwrap()
    );

    let retrieved = backend.get_principal(principal.id).await.unwrap();
    assert!(retrieved.is_none(), "principal should be deleted");
}

pub async fn test_principal_username_federated(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_federated");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let handle = format!("alice{}#acme.corp", Uuid::now_v7().simple());
    let principal = create_test_principal(profile.id, PrincipalType::Username, &handle);
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();

    let found = backend
        .get_profile_by_principal(PrincipalType::Username, &handle)
        .await
        .unwrap();
    assert!(found.is_some(), "federated username principal not found");
    assert_eq!(found.unwrap().id, profile.id);

    let principals = backend.get_principals_by_profile(profile.id).await.unwrap();
    let username = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Username);
    assert!(username.is_some());
    assert_eq!(username.unwrap().value, handle);
}

pub async fn test_principal_source_field_roundtrip(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_source_field");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    // Principal with source_field set (profile-bound)
    let now = Utc::now();
    let with_source = Principal {
        id: PrincipalId(Uuid::now_v7()),
        profile_id: profile.id,
        principal_type: PrincipalType::Email,
        value: unique_email("source_field"),
        verified: true,
        verified_at: None,
        verification_expires: None,
        assigned_profile_id: None,
        assignment_revision: 0,
        email_policy_revision: Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
        is_primary: true,
        source_field: Some("email".to_string()),
        source_email_id: None,
        source_phone_id: None,
        created_at: now,
        updated_at: now,
    };
    backend
        .save_principal(&with_source, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_principal(with_source.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retrieved.source_field,
        Some("email".to_string()),
        "source_field should roundtrip"
    );
    assert!(retrieved.verified);

    // Principal without source_field
    let without_source = Principal {
        id: PrincipalId(Uuid::now_v7()),
        profile_id: profile.id,
        principal_type: PrincipalType::Phone,
        value: unique_phone(),
        verified: false,
        verified_at: None,
        verification_expires: None,
        assigned_profile_id: None,
        assignment_revision: 0,
        email_policy_revision: None,
        is_primary: false,
        source_field: None,
        source_email_id: None,
        source_phone_id: None,
        created_at: now,
        updated_at: now,
    };
    backend
        .save_principal(&without_source, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_principal(without_source.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retrieved.source_field, None,
        "source_field should be None when not set"
    );

    // Update: set source_field on previously None
    let mut updated = without_source.clone();
    updated.source_field = Some("phone".to_string());
    updated.updated_at = Utc::now();
    backend
        .save_principal(&updated, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_principal(updated.id).await.unwrap().unwrap();
    assert_eq!(
        retrieved.source_field,
        Some("phone".to_string()),
        "source_field should update via UPSERT"
    );
}

/// Test source_email_id / source_phone_id FK roundtrip on Principal.
pub async fn test_principal_source_contact_fk_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{
        EmailLabel, PhoneLabel, ProfileEmail, ProfileEmailId, ProfilePhone, ProfilePhoneId,
    };

    let profile = create_test_profile("principal_contact_fk");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    // Create a ProfileEmail entry
    let pe = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: format!("fk-test-{}@sid.example.com", Uuid::now_v7()),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_email(&pe, test_audit())
        .await
        .unwrap();

    // Create a ProfilePhone entry
    let pp = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 380509999999,
        extension: None,
        label: PhoneLabel::Mobile,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_phone(&pp, test_audit())
        .await
        .unwrap();

    // Create Principal with source_email_id FK
    let mut email_principal = Principal::new(profile.id, PrincipalType::Email, pe.email.clone());
    email_principal.is_primary = true;
    email_principal.source_email_id = Some(pe.id);
    backend
        .save_principal(&email_principal, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_principal(email_principal.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retrieved.source_email_id,
        Some(pe.id),
        "source_email_id FK should roundtrip"
    );
    assert!(retrieved.source_phone_id.is_none());

    // Create Principal with source_phone_id FK
    let mut phone_principal = Principal::new(profile.id, PrincipalType::Phone, unique_phone());
    phone_principal.source_phone_id = Some(pp.id);
    backend
        .save_principal(&phone_principal, test_audit())
        .await
        .unwrap();

    let retrieved = backend
        .get_principal(phone_principal.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retrieved.source_phone_id,
        Some(pp.id),
        "source_phone_id FK should roundtrip"
    );
    assert!(retrieved.source_email_id.is_none());

    // Update: clear source_email_id
    let mut updated = email_principal.clone();
    updated.source_email_id = None;
    updated.updated_at = Utc::now();
    backend
        .save_principal(&updated, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_principal(updated.id).await.unwrap().unwrap();
    assert!(
        retrieved.source_email_id.is_none(),
        "source_email_id should be clearable"
    );
}

pub async fn test_principal_quarantine_roundtrip(backend: &dyn StorageBackend) {
    let hash = &format!("sha256:quarantine-{}", Uuid::now_v7().simple());
    let until = Utc::now() + chrono::Duration::hours(24);

    // Quarantine a principal hash
    backend
        .quarantine_principal(hash, "email", until, test_audit())
        .await
        .unwrap();

    // Check it's quarantined
    let is_quarantined = backend.is_principal_quarantined(hash).await.unwrap();
    assert!(is_quarantined, "principal hash should be quarantined");

    // Check non-existent hash is not quarantined
    let not_quarantined = backend
        .is_principal_quarantined("sha256:nonexistent_hash")
        .await
        .unwrap();
    assert!(
        !not_quarantined,
        "non-existent hash should not be quarantined"
    );

    // Cleanup expired (our entry is in the future, should not be removed)
    let _cleaned = backend
        .cleanup_expired_quarantine(test_audit())
        .await
        .unwrap();
    // Our entry hasn't expired yet
    let still_quarantined = backend.is_principal_quarantined(hash).await.unwrap();
    assert!(
        still_quarantined,
        "non-expired entry should survive cleanup"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Principal entity and claim tests
// ═══════════════════════════════════════════════════════════════════

/// Test: get_principal_by_value returns entity without binding context.
pub async fn test_principal_get_by_value(backend: &dyn StorageBackend) {
    let profile = create_test_profile("principal_by_value");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email = unique_email("byvalue");
    let mut p = Principal::new_email(profile.id, &email);
    p.verify(0);
    backend.save_principal(&p, test_audit()).await.unwrap();

    let entity = backend
        .get_principal_by_value(PrincipalType::Email, &email)
        .await
        .unwrap();
    assert!(entity.is_some(), "should find principal entity by value");
    let entity = entity.unwrap();
    assert_eq!(entity.id, p.id);
    assert_eq!(entity.value, email);
    assert!(entity.verified);
    assert_eq!(entity.assigned_profile_id, Some(profile.id));
}

/// Test: get_principal_bindings returns all bindings for a principal.
pub async fn test_principal_bindings_crud(backend: &dyn StorageBackend) {
    let profile = create_test_profile("bindings_crud");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let p = Principal::new_email(profile.id, unique_email("bindings_crud"));
    backend.save_principal(&p, test_audit()).await.unwrap();

    let bindings = backend.get_principal_bindings(p.id).await.unwrap();
    assert_eq!(bindings.len(), 1, "should have 1 binding after save");
    assert_eq!(bindings[0].principal_id, p.id);
    assert_eq!(bindings[0].profile_id, profile.id);
}

/// Test: count_active_principal_bindings only counts active profiles.
pub async fn test_principal_count_active_bindings(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileStatus;

    let profile = create_test_profile("count_active");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let p = Principal::new_email(profile.id, unique_email("count_active"));
    backend.save_principal(&p, test_audit()).await.unwrap();

    let count = backend.count_active_principal_bindings(p.id).await.unwrap();
    assert_eq!(count, 1, "active profile = 1 active binding");

    // Deactivate the profile → count should be 0
    let mut deactivated = profile.clone();
    deactivated.status = ProfileStatus::Closed;
    assert!(
        backend
            .update_profile(&deactivated, test_audit())
            .await
            .unwrap()
    );

    let count = backend.count_active_principal_bindings(p.id).await.unwrap();
    assert_eq!(count, 0, "closed profile = 0 active bindings");
}

/// Two profiles hold one email (contestation): removing it from one profile,
/// as SCIM and `RemovePrincipal` do, leaves the other profile's hold intact.
pub async fn test_removing_shared_principal_keeps_other_holder(backend: &dyn StorageBackend) {
    let first = create_test_profile("shared_first");
    let second = create_test_profile("shared_second");
    backend.create_profile(&first, test_audit()).await.unwrap();
    backend.create_profile(&second, test_audit()).await.unwrap();
    let email = unique_email("shared");
    let held_by_first = Principal::new_email(first.id, &email);
    backend
        .save_principal(&held_by_first, test_audit())
        .await
        .unwrap();
    backend
        .save_principal(&Principal::new_email(second.id, &email), test_audit())
        .await
        .unwrap();
    let entity = backend
        .get_principal_by_value(PrincipalType::Email, &email)
        .await
        .unwrap()
        .unwrap();

    assert!(
        backend
            .unbind_principal(entity.id, first.id, test_audit())
            .await
            .unwrap()
    );

    let second_holds: Vec<_> = backend
        .get_principals_by_profile(second.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.value == email)
        .collect();
    assert_eq!(second_holds.len(), 1, "the other holder lost the email");
    let first_holds = backend.get_principals_by_profile(first.id).await.unwrap();
    assert!(first_holds.iter().all(|p| p.value != email));

    // Unbinding again removes nothing.
    assert!(
        !backend
            .unbind_principal(entity.id, first.id, test_audit())
            .await
            .unwrap()
    );

    // The last holder's release takes the principal with it, so the value is
    // free to register again.
    assert!(
        backend
            .unbind_principal(entity.id, second.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .get_principal_by_value(PrincipalType::Email, &email)
            .await
            .unwrap()
            .is_none(),
        "a principal nobody holds was kept"
    );
}

/// Test profile_phones CRUD: save phone, read back, update, delete.
pub async fn test_profile_phone_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{PhoneLabel, ProfilePhone, ProfilePhoneId};

    let profile = create_test_profile("phone_roundtrip");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    // 1. No phones initially
    let phones = backend.list_profile_phones(profile.id).await.unwrap();
    assert!(phones.is_empty());
    assert!(
        backend
            .get_primary_profile_phone(profile.id)
            .await
            .unwrap()
            .is_none()
    );

    // 2. Add a phone
    let phone = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 380501234567,
        extension: None,
        label: PhoneLabel::Mobile,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_phone(&phone, test_audit())
        .await
        .unwrap();
    assert!(matches!(
        backend.create_profile_phone(&phone, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));

    let retrieved = backend.get_profile_phone(phone.id).await.unwrap().unwrap();
    assert_eq!(retrieved.e164, 380501234567);
    assert!(!retrieved.verified);

    let primary = backend
        .get_primary_profile_phone(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.id, phone.id);

    // 3. The owner changes a setting; nothing else changes. Another
    // profile cannot change it.
    let settings = sid_core::models::PhoneSettings {
        can_receive_fax: Some(true),
        custom_label: Some(Some("desk".into())),
        ..Default::default()
    };
    assert!(
        backend
            .update_profile_phone_settings(
                profile.id,
                phone.id,
                &settings,
                Utc::now(),
                test_audit()
            )
            .await
            .unwrap()
    );
    let stranger = ProfileId::generate();
    assert!(
        !backend
            .update_profile_phone_settings(stranger, phone.id, &settings, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    let retrieved = backend.get_profile_phone(phone.id).await.unwrap().unwrap();
    assert!(retrieved.can_receive_fax);
    assert!(retrieved.can_receive_sms, "an unset setting was changed");
    assert_eq!(retrieved.custom_label.as_deref(), Some("desk"));
    assert_eq!(retrieved.label, PhoneLabel::Mobile);
    assert!(retrieved.is_primary);

    // 4. Delete phone
    backend
        .delete_profile_phone(phone.id, test_audit())
        .await
        .unwrap();
    assert!(backend.get_profile_phone(phone.id).await.unwrap().is_none());
}

/// Test profile_emails CRUD: save email, read back, update, delete, primary lookup.
pub async fn test_profile_email_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{EmailLabel, ProfileEmail, ProfileEmailId};

    let profile = create_test_profile("email_roundtrip");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    // 1. No emails initially
    let emails = backend.list_profile_emails(profile.id).await.unwrap();
    assert!(emails.is_empty());
    assert!(
        backend
            .get_primary_profile_email(profile.id)
            .await
            .unwrap()
            .is_none()
    );

    // 2. Add a primary email
    let email = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: format!("roundtrip-{}@sid.example.com", Uuid::now_v7()),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_email(&email, test_audit())
        .await
        .unwrap();
    assert!(matches!(
        backend.create_profile_email(&email, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));

    let retrieved = backend.get_profile_email(email.id).await.unwrap().unwrap();
    assert_eq!(retrieved.email, email.email);
    assert!(!retrieved.verified);
    assert_eq!(retrieved.label, EmailLabel::Personal);

    let primary = backend
        .get_primary_profile_email(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.id, email.id);

    // 3. The owner relabels it; the address and flags stay.
    let settings = sid_core::models::EmailSettings {
        label: Some(EmailLabel::Work),
        custom_label: None,
    };
    assert!(
        backend
            .update_profile_email_settings(
                profile.id,
                email.id,
                &settings,
                Utc::now(),
                test_audit()
            )
            .await
            .unwrap()
    );
    let retrieved = backend.get_profile_email(email.id).await.unwrap().unwrap();
    assert_eq!(retrieved.label, EmailLabel::Work);
    assert_eq!(retrieved.email, email.email);
    assert!(retrieved.is_primary);

    // 4. List emails
    let list = backend.list_profile_emails(profile.id).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, email.id);

    // 5. Delete email
    backend
        .delete_profile_email(email.id, test_audit())
        .await
        .unwrap();
    assert!(backend.get_profile_email(email.id).await.unwrap().is_none());
    assert!(
        backend
            .list_profile_emails(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Test get_profile_by_email works through profile_emails JOIN.
pub async fn test_get_profile_by_email_via_join(backend: &dyn StorageBackend) {
    use sid_core::models::{EmailLabel, ProfileEmail, ProfileEmailId};

    let profile = create_test_profile("email_join");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let email_addr = format!("join-test-{}@sid.example.com", Uuid::now_v7());

    // Before adding email → not found
    assert!(
        backend
            .get_profile_by_email(&email_addr)
            .await
            .unwrap()
            .is_none()
    );

    // Add email entry
    let pe = ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: profile.id,
        email: email_addr.clone(),
        label: EmailLabel::Work,
        custom_label: None,
        is_primary: true,
        verified: true,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_email(&pe, test_audit())
        .await
        .unwrap();

    // Now found via JOIN
    let found = backend.get_profile_by_email(&email_addr).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, profile.id);
}

/// Test multiple phones per profile with ordering.
pub async fn test_multiple_phones_per_profile(backend: &dyn StorageBackend) {
    use sid_core::models::{PhoneLabel, ProfilePhone, ProfilePhoneId};

    let profile = create_test_profile("multi_phone");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    // Add primary phone
    let phone1 = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 380501111111,
        extension: None,
        label: PhoneLabel::Mobile,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: true,
        verified_at: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_phone(&phone1, test_audit())
        .await
        .unwrap();

    // Add secondary phone (work with extension)
    let phone2 = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 14185559999,
        extension: Some(102),
        label: PhoneLabel::Work,
        custom_label: None,
        is_primary: false,
        can_receive_sms: false,
        can_receive_fax: true,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_phone(&phone2, test_audit())
        .await
        .unwrap();

    // List: primary first
    let phones = backend.list_profile_phones(profile.id).await.unwrap();
    assert_eq!(phones.len(), 2);
    assert!(phones[0].is_primary, "primary phone should be first");
    assert_eq!(phones[0].e164, 380501111111);
    assert_eq!(phones[1].e164, 14185559999);
    assert_eq!(phones[1].extension, Some(102));
    assert!(phones[1].can_receive_fax);

    // Primary lookup
    let primary = backend
        .get_primary_profile_phone(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.e164, 380501111111);

    // A new primary phone takes the flag in the same write.
    let phone3 = ProfilePhone {
        id: ProfilePhoneId::new(),
        e164: 380502222222,
        is_primary: true,
        ..phone1.clone()
    };
    backend
        .create_profile_phone(&phone3, test_audit())
        .await
        .expect("a second primary phone replaces the first as primary");
    let primary = backend
        .get_primary_profile_phone(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.id, phone3.id);

    // The flag moves back in one write; another profile's phone cannot take it.
    assert!(
        backend
            .set_primary_profile_phone(profile.id, phone2.id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .set_primary_profile_phone(ProfileId::generate(), phone1.id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    let phones = backend.list_profile_phones(profile.id).await.unwrap();
    assert_eq!(
        phones.iter().filter(|p| p.is_primary).count(),
        1,
        "a profile has one primary phone"
    );
    assert!(phones.iter().any(|p| p.id == phone2.id && p.is_primary));
}

/// Test phone extension stored and retrieved correctly.
pub async fn test_phone_extension(backend: &dyn StorageBackend) {
    use sid_core::models::{PhoneLabel, ProfilePhone, ProfilePhoneId};

    let profile = create_test_profile("phone_ext");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();

    let phone = ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id: profile.id,
        e164: 12125551234,
        extension: Some(5678),
        label: PhoneLabel::Work,
        custom_label: None,
        is_primary: true,
        can_receive_sms: false,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    backend
        .create_profile_phone(&phone, test_audit())
        .await
        .unwrap();

    let retrieved = backend.get_profile_phone(phone.id).await.unwrap().unwrap();
    assert_eq!(retrieved.extension, Some(5678));
    assert_eq!(retrieved.formatted_e164(), "+12125551234;ext=5678");
}

// ─── Self-registration ───

/// A self-registration by email: new profile, unverified email principal sourced
/// from its primary contact row, and one OPAQUE credential.
pub fn new_email_registration(email: &str) -> sid_core::models::NewRegistration {
    use sid_core::models::{Credential, CredentialType, NewRegistration};

    let profile = create_test_profile("register");
    let credential = Credential::new(profile.id, CredentialType::Opaque, vec![7u8; 32], None);
    NewRegistration::new(
        profile,
        sid_core::models::SignupIdentifier::Email {
            key: email,
            address: email,
            revision: sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION,
        },
        Some(credential),
    )
    .expect("an email signup")
}

/// An email address no other test run uses: scenarios share one database.
fn unique_email(tag: &str) -> String {
    format!("{tag}_{}@sid.example.com", Uuid::now_v7().simple())
}

/// Number of OPAQUE credentials stored for `profile_id`.
async fn opaque_credentials(backend: &dyn StorageBackend, profile_id: ProfileId) -> usize {
    backend
        .get_credentials_by_profile(profile_id, Some(sid_core::models::CredentialType::Opaque))
        .await
        .unwrap()
        .len()
}

/// A registration commits the profile, its principal, contact row and credential
/// together, all resolvable from the signup identifier.
pub async fn test_register_profile_commits_all(backend: &dyn StorageBackend) {
    let email = unique_email("reg_all");
    let reg = new_email_registration(&email);
    backend
        .register_profile(&reg, test_audit())
        .await
        .expect("register");

    let held = backend
        .get_profile_by_principal(PrincipalType::Email, &email)
        .await
        .unwrap()
        .expect("profile resolvable by its email");
    assert_eq!(held.id, reg.profile.id);
    let principals = backend
        .get_principals_by_profile(reg.profile.id)
        .await
        .unwrap();
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0].value, email);
    assert!(!principals[0].verified);
    let primary = backend
        .get_primary_profile_email(reg.profile.id)
        .await
        .unwrap()
        .expect("contact row");
    assert_eq!(primary.email, email);
    assert_eq!(opaque_credentials(backend, reg.profile.id).await, 1);
}

/// An account provisioned without a credential (its owner sets one up later)
/// is stored whole: profile, principal and contact row, and no credential.
pub async fn test_register_profile_without_credential(backend: &dyn StorageBackend) {
    let email = unique_email("reg_nocred");
    let mut reg = new_email_registration(&email);
    reg.credential = None;

    backend
        .register_profile(&reg, test_audit())
        .await
        .expect("register");

    let held = backend
        .get_profile_by_principal(PrincipalType::Email, &email)
        .await
        .unwrap()
        .expect("profile resolvable by its email");
    assert_eq!(held.id, reg.profile.id);
    assert!(
        backend
            .get_primary_profile_email(reg.profile.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        backend
            .get_credentials_by_profile(reg.profile.id, None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Regression: SQLite required every profile to have a username, so an
/// account provisioned by email alone failed there while PostgreSQL stored
/// it. A username is never generated; profiles without one are stored and
/// do not collide with each other.
pub async fn test_register_profile_without_username(backend: &dyn StorageBackend) {
    for tag in ["reg_nouser_a", "reg_nouser_b"] {
        let email = unique_email(tag);
        let mut reg = new_email_registration(&email);
        reg.profile.username = None;
        backend
            .register_profile(&reg, test_audit())
            .await
            .expect("register without a username");
        let held = backend
            .get_profile_by_principal(PrincipalType::Email, &email)
            .await
            .unwrap()
            .expect("profile resolvable by its email");
        assert_eq!(held.username, None);
    }
}

/// Regression:a registration for an identifier another profile already
/// holds returns Conflict and writes nothing: no second profile, no credential on
/// either account.
pub async fn test_register_profile_conflict_writes_nothing(backend: &dyn StorageBackend) {
    let email = unique_email("reg_conflict");
    let first = new_email_registration(&email);
    backend
        .register_profile(&first, test_audit())
        .await
        .expect("first registration");

    let second = new_email_registration(&email);
    let err = backend
        .register_profile(&second, test_audit())
        .await
        .expect_err("identifier already held");
    assert!(
        matches!(err, sid_core::Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
    assert!(
        backend
            .get_profile(second.profile.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(opaque_credentials(backend, second.profile.id).await, 0);
    assert_eq!(opaque_credentials(backend, first.profile.id).await, 1);
    let held = backend
        .get_profile_by_principal(PrincipalType::Email, &email)
        .await
        .unwrap()
        .expect("still held by the first profile");
    assert_eq!(held.id, first.profile.id);
}

/// Regression:a profile has one password. A second active OPAQUE credential
/// is refused with Conflict; after the first is revoked a new one may be stored.
pub async fn test_single_active_password(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("one_password");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut first = Credential::new(profile.id, CredentialType::Opaque, vec![1u8; 32], None);
    backend
        .create_credential(&first, test_audit())
        .await
        .unwrap();

    let second = Credential::new(profile.id, CredentialType::Opaque, vec![2u8; 32], None);
    let err = backend
        .create_credential(&second, test_audit())
        .await
        .expect_err("second active password");
    assert!(
        matches!(err, sid_core::Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    // Another primary method keeps the account reachable, so the password
    // can be revoked.
    let passkey = Credential::new(profile.id, CredentialType::WebAuthn, vec![3u8; 16], None);
    backend
        .create_credential(&passkey, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .revoke_credential(first.id, test_audit())
            .await
            .unwrap(),
        sid_core::models::CredentialRevocation::Revoked
    );
    first.status = CredentialStatus::Revoked;
    assert_eq!(
        backend
            .get_credential(first.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        first.status
    );
    backend
        .create_credential(&second, test_audit())
        .await
        .expect("a new password after the old one is revoked");
}

/// Replacing credential data is a compare-and-swap: it applies only over the
/// expected data of an active credential, and of two concurrent writers
/// starting from the same data exactly one wins.
pub async fn test_replace_credential_data_is_compare_and_swap(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("cas_data");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let credential = Credential::new(profile.id, CredentialType::Recovery, b"v0".to_vec(), None);
    backend
        .create_credential(&credential, test_audit())
        .await
        .unwrap();

    assert!(
        !backend
            .replace_credential_data(credential.id, b"stale", b"lost", test_audit())
            .await
            .unwrap(),
        "a write over unexpected data applies"
    );
    assert!(
        backend
            .replace_credential_data(credential.id, b"v0", b"v1", test_audit())
            .await
            .unwrap()
    );
    let (a, b) = tokio::join!(
        backend.replace_credential_data(credential.id, b"v1", b"a", test_audit()),
        backend.replace_credential_data(credential.id, b"v1", b"b", test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent writer must win: {a} {b}");
    let stored = backend
        .get_credential(credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.data.expose(), if a { b"a" } else { b"b" });
    assert!(stored.last_used_at.is_some());

    assert_eq!(
        backend
            .revoke_credential(credential.id, test_audit())
            .await
            .unwrap(),
        sid_core::models::CredentialRevocation::Revoked
    );
    let current = stored.data.expose().to_vec();
    assert!(
        !backend
            .replace_credential_data(credential.id, &current, b"after-revoke", test_audit())
            .await
            .unwrap(),
        "a revoked credential's data changed"
    );
}

/// Marking a credential used touches only an active one: a revoked
/// credential stays revoked and unused, an unknown id writes nothing.
pub async fn test_mark_credential_used_only_when_active(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialId, CredentialType};

    let profile = create_test_profile("mark_used");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let active = Credential::new(profile.id, CredentialType::Opaque, vec![1u8; 32], None);
    backend
        .create_credential(&active, test_audit())
        .await
        .unwrap();
    let mut revoked = Credential::new(profile.id, CredentialType::Totp, vec![2u8; 32], None);
    revoked.status = CredentialStatus::Revoked;
    backend
        .create_credential(&revoked, test_audit())
        .await
        .unwrap();

    assert!(
        backend
            .mark_credential_used(active.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .mark_credential_used(revoked.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .mark_credential_used(CredentialId::new(), test_audit())
            .await
            .unwrap()
    );

    let stored = backend.get_credential(active.id).await.unwrap().unwrap();
    assert!(stored.last_used_at.is_some());
    assert_eq!(stored.status, CredentialStatus::Active);
    let stored = backend.get_credential(revoked.id).await.unwrap().unwrap();
    assert!(stored.last_used_at.is_none());
    assert_eq!(stored.status, CredentialStatus::Revoked);
}

/// Creating a credential never replaces one: a second create with the same id
/// is refused with Conflict and the stored credential keeps its data and
/// status (a create over a revoked factor would revive it).
pub async fn test_create_credential_never_replaces(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("create_once");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut revoked = Credential::new(profile.id, CredentialType::Totp, b"first".to_vec(), None);
    revoked.status = CredentialStatus::Revoked;
    backend
        .create_credential(&revoked, test_audit())
        .await
        .unwrap();

    let mut again = revoked.clone();
    again.status = CredentialStatus::Active;
    again.data = sid_core::models::CredentialData::new(b"second".to_vec());
    let err = backend
        .create_credential(&again, test_audit())
        .await
        .expect_err("a create over an existing credential");
    assert!(
        matches!(err, sid_core::Error::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
    let stored = backend.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert_eq!(stored.data.expose(), b"first");
}

/// A label changes only on an active credential; a revoked one keeps its
/// label and stays revoked.
pub async fn test_credential_label_only_on_active(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialId, CredentialType};

    let profile = create_test_profile("cred_label");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let active = Credential::new(
        profile.id,
        CredentialType::Totp,
        vec![1],
        Some("old".into()),
    );
    let mut revoked = Credential::new(
        profile.id,
        CredentialType::Totp,
        vec![2],
        Some("gone".into()),
    );
    revoked.status = CredentialStatus::Revoked;
    for c in [&active, &revoked] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }

    assert!(
        backend
            .set_credential_label(active.id, Some("new"), test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .set_credential_label(revoked.id, Some("revived"), test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .set_credential_label(CredentialId::new(), Some("x"), test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_credential(active.id).await.unwrap().unwrap();
    assert_eq!(stored.label.as_deref(), Some("new"));
    let stored = backend.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.label.as_deref(), Some("gone"));
    assert_eq!(stored.status, CredentialStatus::Revoked);
}

/// A password change is a compare-and-swap over the current password of an
/// active credential and stores the new policy evidence with it; of two
/// concurrent changes from one password exactly one applies, and a revoked
/// password is not changed back to use.
pub async fn test_change_password_is_compare_and_swap(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialData, CredentialType};

    let profile = create_test_profile("change_pw");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"p0".to_vec(), None);
    let passkey = Credential::new(profile.id, CredentialType::WebAuthn, b"k".to_vec(), None);
    for c in [&password, &passkey] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }
    let changed_to = |data: &[u8], version: u32| {
        let mut new = password.clone();
        new.data = CredentialData::new(data.to_vec());
        new.policy_evidence = PolicyEvidence::Verified {
            policy_version: version,
            artifact: [version as u8; 32],
        };
        new
    };

    assert!(
        !backend
            .change_password(
                password.id,
                b"stale",
                &changed_to(b"lost", 1),
                None,
                test_audit()
            )
            .await
            .unwrap(),
        "a change over another password applies"
    );
    assert!(
        backend
            .change_password(
                password.id,
                b"p0",
                &changed_to(b"p1", 2),
                None,
                test_audit()
            )
            .await
            .unwrap()
    );
    let stored = backend.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(stored.data.expose(), b"p1");
    assert_eq!(
        stored.policy_evidence,
        PolicyEvidence::Verified {
            policy_version: 2,
            artifact: [2; 32],
        },
        "the verdict keeps its policy and artifact"
    );
    assert!(stored.last_used_at.is_some());

    let (to_a, to_b) = (changed_to(b"a", 3), changed_to(b"b", 3));
    let (a, b) = tokio::join!(
        backend.change_password(password.id, b"p1", &to_a, None, test_audit()),
        backend.change_password(password.id, b"p1", &to_b, None, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one concurrent change must win: {a} {b}");

    let current = backend
        .get_credential(password.id)
        .await
        .unwrap()
        .unwrap()
        .data
        .expose()
        .to_vec();
    backend
        .revoke_credential(password.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .change_password(
                password.id,
                &current,
                &changed_to(b"after", 4),
                None,
                test_audit()
            )
            .await
            .unwrap(),
        "a revoked password was changed"
    );
    let stored = backend.get_credential(password.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert_eq!(stored.data.expose(), current.as_slice());
}

/// Resealing replaces data over the expected value only, whatever the status,
/// and is not a use: status and last use are untouched.
pub async fn test_reseal_credential_data_keeps_status(backend: &dyn StorageBackend) {
    use sid_core::models::credential::CredentialStatus;
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("reseal");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut revoked = Credential::new(profile.id, CredentialType::Totp, b"plain".to_vec(), None);
    revoked.status = CredentialStatus::Revoked;
    backend
        .create_credential(&revoked, test_audit())
        .await
        .unwrap();

    assert!(
        !backend
            .reseal_credential_data(revoked.id, b"other", b"sealed", test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .reseal_credential_data(revoked.id, b"plain", b"sealed", test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_credential(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.data.expose(), b"sealed");
    assert_eq!(stored.status, CredentialStatus::Revoked);
    assert!(stored.last_used_at.is_none());
}

/// A password replacement removes the profile's OPAQUE and legacy-hash credentials,
/// installs the new one, and leaves other factors alone.
pub async fn test_replace_password_swaps_only_password(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("replace_pw");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let old = Credential::new(profile.id, CredentialType::Opaque, vec![1u8; 32], None);
    let legacy = Credential::new(profile.id, CredentialType::LegacyHash, vec![3u8; 32], None);
    let totp = Credential::new(profile.id, CredentialType::Totp, vec![4u8; 20], None);
    for c in [&old, &legacy, &totp] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }

    let new = Credential::new(profile.id, CredentialType::Opaque, vec![2u8; 32], None);
    backend
        .replace_credential(&new, test_audit())
        .await
        .expect("replace");

    let opaque = backend
        .get_credentials_by_profile(profile.id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(opaque.len(), 1);
    assert_eq!(opaque[0].id, new.id);
    let legacy_left = backend
        .get_credentials_by_profile(profile.id, Some(CredentialType::LegacyHash))
        .await
        .unwrap();
    assert!(legacy_left.is_empty(), "legacy hash must be gone");
    let totp_left = backend
        .get_credentials_by_profile(profile.id, Some(CredentialType::Totp))
        .await
        .unwrap();
    assert_eq!(totp_left.len(), 1, "other factors are untouched");

    let err = backend
        .replace_credential(&totp, test_audit())
        .await
        .expect_err("a second factor is added, not replaced");
    assert!(matches!(err, sid_core::Error::Validation(_)), "{err:?}");
}

/// A password's policy evidence (the policy version and the artifact that
/// accepted its proof) reads back as stored, for a verified and for a
/// policy-unverified credential.
pub async fn test_credential_policy_evidence_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("policy_evidence");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let evidence = PolicyEvidence::Verified {
        policy_version: 3,
        artifact: [0xa5; 32],
    };
    let mut verified = Credential::new(profile.id, CredentialType::Opaque, vec![1u8; 32], None);
    verified.policy_evidence = evidence;
    backend
        .create_credential(&verified, test_audit())
        .await
        .unwrap();

    let stored = backend.get_credential(verified.id).await.unwrap().unwrap();
    assert_eq!(stored.policy_evidence, evidence);

    let unverified = Credential::new(profile.id, CredentialType::Opaque, vec![2u8; 32], None);
    backend
        .replace_credential(&unverified, test_audit())
        .await
        .unwrap();
    let stored = backend
        .get_credential(unverified.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.policy_evidence, PolicyEvidence::Unverified);

    // A policy version beyond the stored integer is refused, never truncated
    // into another policy's evidence.
    let mut out_of_range = Credential::new(profile.id, CredentialType::Opaque, vec![3u8; 32], None);
    out_of_range.policy_evidence = PolicyEvidence::Verified {
        policy_version: u32::MAX,
        artifact: [1; 32],
    };
    assert!(
        backend
            .replace_credential(&out_of_range, test_audit())
            .await
            .is_err()
    );
}

/// A new recovery-code set replaces the old one and nothing else, so the old
/// codes stop working the moment the new ones exist.
pub async fn test_replace_recovery_codes_swaps_only_the_set(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("replace_rc");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, vec![1u8; 32], None);
    let old = Credential::new(
        profile.id,
        CredentialType::Recovery,
        b"[\"a\"]".to_vec(),
        None,
    );
    for c in [&password, &old] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }

    let new = Credential::new(
        profile.id,
        CredentialType::Recovery,
        b"[\"b\"]".to_vec(),
        None,
    );
    backend
        .replace_credential(&new, test_audit())
        .await
        .expect("replace");

    let sets = backend
        .get_credentials_by_profile(profile.id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(sets.len(), 1, "{sets:?}");
    assert_eq!(sets[0].id, new.id);
    assert!(backend.get_credential(old.id).await.unwrap().is_none());
    assert!(backend.get_credential(password.id).await.unwrap().is_some());
}

/// Ending a legacy migration clears the flag and deletes the legacy hashes in
/// one write: a stale copy of the profile does neither, and the profile's
/// other credentials stay.
pub async fn test_end_legacy_migration_is_one_write(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let mut profile = create_test_profile("legacy_mig");
    profile.migration_pending = true;
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let legacy = Credential::new(profile.id, CredentialType::LegacyHash, vec![3u8; 32], None);
    let totp = Credential::new(profile.id, CredentialType::Totp, vec![4u8; 20], None);
    for c in [&legacy, &totp] {
        backend.create_credential(c, test_audit()).await.unwrap();
    }
    let read = backend.get_profile(profile.id).await.unwrap().unwrap();

    // Someone changes the profile first: the stale copy ends nothing.
    let mut renamed = read.clone();
    renamed.given_name = Some("Renamed".into());
    assert!(
        backend
            .update_profile(&renamed, test_audit())
            .await
            .unwrap()
    );
    let mut stale = read.clone();
    stale.migration_pending = false;
    assert!(
        !backend
            .end_legacy_migration(&stale, test_audit())
            .await
            .unwrap()
    );
    assert!(backend.get_credential(legacy.id).await.unwrap().is_some());
    assert!(
        backend
            .get_profile(profile.id)
            .await
            .unwrap()
            .unwrap()
            .migration_pending
    );

    let mut current = backend.get_profile(profile.id).await.unwrap().unwrap();
    current.migration_pending = false;
    assert!(
        backend
            .end_legacy_migration(&current, test_audit())
            .await
            .unwrap()
    );
    assert!(backend.get_credential(legacy.id).await.unwrap().is_none());
    assert!(backend.get_credential(totp.id).await.unwrap().is_some());
    assert!(
        !backend
            .get_profile(profile.id)
            .await
            .unwrap()
            .unwrap()
            .migration_pending
    );
}

/// A metadata entry is read back by its key, replaced by a second set of
/// the same key (one entry, also under two concurrent sets), and deleted
/// alone, leaving the profile's other keys and another profile's same key.
pub async fn test_profile_metadata_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileMetadata;

    let profile = create_test_profile("meta");
    let other = create_test_profile("meta_other");
    for p in [&profile, &other] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    assert!(
        backend
            .get_profile_metadata(profile.id, "employee_id")
            .await
            .unwrap()
            .is_none()
    );

    // Metadata of a profile that does not exist is refused as not found,
    // not as a storage fault.
    let orphan = ProfileMetadata::new(ProfileId::generate(), "employee_id", serde_json::json!(1));
    let err = backend
        .set_profile_metadata(&orphan, test_audit())
        .await
        .expect_err("no such profile");
    assert!(matches!(err, sid_core::Error::NotFound(_)), "{err:?}");

    let first = ProfileMetadata::new(profile.id, "employee_id", serde_json::json!("E-1"));
    let team = ProfileMetadata::new(profile.id, "team", serde_json::json!({"name": "core"}));
    let foreign = ProfileMetadata::new(other.id, "employee_id", serde_json::json!("E-9"));
    for m in [&first, &team, &foreign] {
        backend.set_profile_metadata(m, test_audit()).await.unwrap();
    }
    let stored = backend
        .get_profile_metadata(profile.id, "employee_id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.value, serde_json::json!("E-1"));

    let a = ProfileMetadata::new(profile.id, "employee_id", serde_json::json!("E-2"));
    let b = ProfileMetadata::new(profile.id, "employee_id", serde_json::json!("E-3"));
    let (ra, rb) = tokio::join!(
        backend.set_profile_metadata(&a, test_audit()),
        backend.set_profile_metadata(&b, test_audit()),
    );
    ra.unwrap();
    rb.unwrap();
    let entries = backend.list_profile_metadata(profile.id).await.unwrap();
    assert_eq!(entries.len(), 2, "{entries:?}");
    let value = backend
        .get_profile_metadata(profile.id, "employee_id")
        .await
        .unwrap()
        .unwrap()
        .value;
    assert!(
        value == a.value || value == b.value,
        "the entry holds neither write: {value}"
    );

    backend
        .delete_profile_metadata(profile.id, "employee_id", test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .get_profile_metadata(profile.id, "employee_id")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .get_profile_metadata(profile.id, "team")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        backend
            .get_profile_metadata(other.id, "employee_id")
            .await
            .unwrap()
            .unwrap()
            .value,
        serde_json::json!("E-9"),
        "another profile's entry changed"
    );
}

/// Deleting a profile grant removes that grant only.
pub async fn test_delete_profile_grant(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileGrant;

    backend.ensure_system_project(test_audit()).await.unwrap();
    let profile = create_test_profile("grant_delete");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let admin = ProfileGrant::new(ProjectId::system(), profile.id, vec!["admin".into()]);
    let project =
        sid_core::models::Project::new(format!("grants-{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let editor = ProfileGrant::new(project.id, profile.id, vec!["editor".into()]);
    for g in [&admin, &editor] {
        backend.create_profile_grant(g, test_audit()).await.unwrap();
    }

    backend
        .delete_profile_grant(admin.id, test_audit())
        .await
        .unwrap();
    assert!(backend.get_profile_grant(admin.id).await.unwrap().is_none());
    let left: Vec<_> = backend
        .list_profile_grants_for_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(left, vec![editor.id]);
}

/// Lifecycle scans return the profiles in the asked status, and those with
/// a pending legacy migration, never others.
pub async fn test_profile_lifecycle_scans(backend: &dyn StorageBackend) {
    use sid_core::models::ProfileStatus;

    let mut suspended = create_test_profile("scan_suspended");
    suspended.status = ProfileStatus::Suspended;
    let active = create_test_profile("scan_active");
    let mut migrating = create_test_profile("scan_migrating");
    migrating.migration_pending = true;
    for p in [&suspended, &active, &migrating] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }

    let in_status: Vec<_> = backend
        .list_profiles_with_status(ProfileStatus::Suspended)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert!(in_status.contains(&suspended.id));
    assert!(
        !in_status.contains(&active.id),
        "an active profile was listed as suspended"
    );

    let pending: Vec<_> = backend
        .list_profiles_with_pending_migration()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert!(pending.contains(&migrating.id));
    assert!(
        !pending.contains(&active.id),
        "a profile without migration was listed"
    );
}

/// Making an email primary takes the flag from the current primary in one
/// write: there is one primary after it, also when two emails are made
/// primary at once; another profile's email cannot be made primary.
pub async fn test_set_primary_profile_email(backend: &dyn StorageBackend) {
    use sid_core::models::{EmailLabel, ProfileEmail, ProfileEmailId};

    let profile = create_test_profile("primary_email");
    let other = create_test_profile("primary_email_other");
    for p in [&profile, &other] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    let email = |owner: ProfileId, primary: bool| ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id: owner,
        email: format!("primary-{}@sid.example.com", Uuid::now_v7()),
        label: EmailLabel::Personal,
        custom_label: None,
        is_primary: primary,
        verified: false,
        verified_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let first = email(profile.id, true);
    let second = email(profile.id, false);
    let third = email(profile.id, false);
    let foreign = email(other.id, true);
    for e in [&first, &second, &third, &foreign] {
        backend.create_profile_email(e, test_audit()).await.unwrap();
    }

    assert!(
        backend
            .set_primary_profile_email(profile.id, second.id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    let primary = backend
        .get_primary_profile_email(profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.id, second.id);

    let (a, b) = tokio::join!(
        backend.set_primary_profile_email(profile.id, first.id, Utc::now(), test_audit()),
        backend.set_primary_profile_email(profile.id, third.id, Utc::now(), test_audit()),
    );
    assert!(a.unwrap() && b.unwrap());
    let primaries = backend
        .list_profile_emails(profile.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.is_primary)
        .count();
    assert_eq!(
        primaries, 1,
        "two concurrent changes left {primaries} primaries"
    );

    assert!(
        !backend
            .set_primary_profile_email(profile.id, foreign.id, Utc::now(), test_audit())
            .await
            .unwrap(),
        "another profile's email was made primary"
    );
    assert_eq!(
        backend
            .get_primary_profile_email(other.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        foreign.id
    );
}

/// An enrolled factor and the recovery codes issued with it are stored
/// together: the new set replaces the old one, and when either write fails
/// neither is stored (a factor without its codes cannot be enrolled again).
pub async fn test_enroll_credential_stores_factor_with_codes(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};

    let profile = create_test_profile("enroll_mfa");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let codes =
        |data: &[u8]| Credential::new(profile.id, CredentialType::Recovery, data.to_vec(), None);
    let old = codes(b"[\"a\"]");
    backend.create_credential(&old, test_audit()).await.unwrap();

    let totp = Credential::new(profile.id, CredentialType::Totp, vec![7u8; 20], None);
    let set = codes(b"[\"b\"]");
    backend
        .enroll_credential(&totp, Some(&set), test_audit())
        .await
        .unwrap();
    assert!(backend.get_credential(totp.id).await.unwrap().is_some());
    let sets = backend
        .get_credentials_by_profile(profile.id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(sets.iter().map(|c| c.id).collect::<Vec<_>>(), vec![set.id]);

    // The codes cannot be stored (their id is taken): the factor is not stored
    // either, and the stored set stays.
    let second = Credential::new(profile.id, CredentialType::Totp, vec![8u8; 20], None);
    let mut clash = codes(b"[\"c\"]");
    clash.id = totp.id;
    assert!(
        backend
            .enroll_credential(&second, Some(&clash), test_audit())
            .await
            .is_err()
    );
    assert!(
        backend.get_credential(second.id).await.unwrap().is_none(),
        "a factor was stored without its recovery codes"
    );
    assert!(backend.get_credential(set.id).await.unwrap().is_some());

    let third = Credential::new(profile.id, CredentialType::Totp, vec![9u8; 20], None);
    let not_codes = Credential::new(profile.id, CredentialType::Totp, vec![1u8; 20], None);
    assert!(matches!(
        backend
            .enroll_credential(&third, Some(&not_codes), test_audit())
            .await,
        Err(sid_core::Error::Validation(_))
    ));
    assert!(backend.get_credential(third.id).await.unwrap().is_none());
}

/// Two registrations of the same identifier racing: exactly one commits, the other
/// gets Conflict, and only the winner's profile exists.
pub async fn test_register_profile_concurrent_single_winner(backend: &dyn StorageBackend) {
    let email = unique_email("reg_race");
    let a = new_email_registration(&email);
    let b = new_email_registration(&email);
    let (ra, rb) = tokio::join!(
        backend.register_profile(&a, test_audit()),
        backend.register_profile(&b, test_audit()),
    );

    let (winner, loser, loser_err) = match (ra, rb) {
        (Ok(()), Err(e)) => (&a, &b, e),
        (Err(e), Ok(())) => (&b, &a, e),
        other => panic!("exactly one registration must win, got {other:?}"),
    };
    assert!(
        matches!(loser_err, sid_core::Error::Conflict(_)),
        "loser must see Conflict, got {loser_err:?}"
    );
    assert!(
        backend
            .get_profile(loser.profile.id)
            .await
            .unwrap()
            .is_none()
    );
    let held = backend
        .get_profile_by_principal(PrincipalType::Email, &email)
        .await
        .unwrap()
        .expect("held by the winner");
    assert_eq!(held.id, winner.profile.id);
}
