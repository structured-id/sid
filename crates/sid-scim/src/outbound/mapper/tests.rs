use super::*;
use chrono::Utc;
use sid_core::models::{
    AttributeMappingEntry, GroupMappingEntry, PrincipalId, ProfileAssurance, ProfileId,
    ProfileType, ProfileVisibility,
};

fn test_profile() -> Profile {
    Profile {
        id: ProfileId::generate(),
        profile_type: ProfileType::Corporate,
        username: Some("alice.smith".into()),
        given_name: Some("Alice".into()),
        family_name: Some("Smith".into()),
        middle_name: None,
        honorific_prefix: None,
        honorific_suffix: None,
        roles: vec![],
        status: ProfileStatus::Provisioned,
        max_assurance: ProfileAssurance::default(),
        visibility: ProfileVisibility::Private,
        manager_id: None,
        migration_pending: false,
        migration_started_at: None,
        migration_completed_at: None,
        revision: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_principals(profile_id: ProfileId) -> Vec<Principal> {
    vec![
        Principal {
            id: PrincipalId::new(),
            profile_id,
            principal_type: PrincipalType::Username,
            value: "alice.smith#acme.corp".into(),
            is_primary: true,
            verified: false,
            verified_at: None,
            verification_expires: None,
            assigned_profile_id: None,
            assignment_revision: 0,
            email_policy_revision: None,
            source_field: None,
            source_email_id: None,
            source_phone_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Principal {
            id: PrincipalId::new(),
            profile_id,
            principal_type: PrincipalType::Email,
            value: "alice@acme.com".into(),
            is_primary: false,
            verified: false,
            verified_at: None,
            verification_expires: None,
            assigned_profile_id: None,
            assignment_revision: 0,
            email_policy_revision: Some(sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION),
            source_field: Some("email".into()),
            source_email_id: None,
            source_phone_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ]
}

fn test_metadata(profile_id: ProfileId) -> Vec<ProfileMetadata> {
    vec![
        ProfileMetadata::new(profile_id, "employee_id", serde_json::json!("EMP-001")),
        ProfileMetadata::new(profile_id, "department", serde_json::json!("Engineering")),
        // given_name/family_name are now Profile fields, not metadata
    ]
}

#[test]
fn test_default_mapping_builds_full_user() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    let metadata = test_metadata(profile.id);

    let payload = build_scim_user(
        &profile,
        &principals,
        &metadata,
        &AttributeMapping::default(),
    );

    assert_eq!(payload.user_name, "alice.smith");
    assert_eq!(payload.display_name.as_deref(), Some("Alice Smith"));
    assert!(payload.active); // Provisioned = active for downstream
    assert_eq!(payload.external_id.as_deref(), Some("EMP-001"));
    assert_eq!(payload.department.as_deref(), Some("Engineering"));
    assert_eq!(payload.emails.len(), 1);
    assert_eq!(payload.emails[0].value, "alice@acme.com");
    assert_eq!(
        payload.name.as_ref().unwrap().given_name.as_deref(),
        Some("Alice")
    );
    assert_eq!(
        payload.name.as_ref().unwrap().family_name.as_deref(),
        Some("Smith")
    );
}

#[test]
fn test_custom_mapping_overrides_username() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    let metadata = test_metadata(profile.id);

    let mapping = AttributeMapping {
        mappings: vec![
            AttributeMappingEntry {
                scim_path: "userName".into(),
                source: MappingSource::Path {
                    path: "profile.email".into(),
                },
            },
            AttributeMappingEntry {
                scim_path: "active".into(),
                source: MappingSource::StatusCheck {
                    active_value: "provisioned".into(),
                },
            },
        ],
    };

    let payload = build_scim_user(&profile, &principals, &metadata, &mapping);
    assert_eq!(payload.user_name, "alice@acme.com");
    assert!(payload.active);
}

#[test]
fn test_literal_mapping() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    let mapping = AttributeMapping {
        mappings: vec![AttributeMappingEntry {
            scim_path: "custom_field".into(),
            source: MappingSource::Literal {
                value: serde_json::json!("constant"),
            },
        }],
    };

    let payload = build_scim_user(&profile, &principals, &[], &mapping);
    assert_eq!(payload.extra.get("custom_field").unwrap(), "constant");
}

/// Every attribute the mapping writes and the user lacks is to be removed:
/// a lost sub-attribute of `name` alone while `name` stays, the whole `name`
/// once none of it is left, never `userName` or `active`.
#[test]
fn test_absent_user_paths() {
    let mut profile = test_profile();
    profile.family_name = None;
    let user = build_scim_user(&profile, &[], &[], &AttributeMapping::default());
    let absent = absent_user_paths(&user, &AttributeMapping::default()).unwrap();
    assert!(
        absent.contains(&"name.familyName".to_string()),
        "{absent:?}"
    );
    assert!(!absent.iter().any(|p| p == "name" || p == "name.givenName"));
    assert!(absent.contains(&"emails".to_string()), "{absent:?}");
    assert!(!absent.iter().any(|p| p == "userName" || p == "active"));

    profile.given_name = None;
    let user = build_scim_user(&profile, &[], &[], &AttributeMapping::default());
    let absent = absent_user_paths(&user, &AttributeMapping::default()).unwrap();
    assert!(absent.contains(&"name".to_string()), "{absent:?}");
    assert!(!absent.iter().any(|p| p.starts_with("name.")), "{absent:?}");
}

#[test]
fn test_metadata_path_resolution() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    let metadata = test_metadata(profile.id);

    let mapping = AttributeMapping {
        mappings: vec![AttributeMappingEntry {
            scim_path: "externalId".into(),
            source: MappingSource::Path {
                path: "metadata.employee_id".into(),
            },
        }],
    };

    let payload = build_scim_user(&profile, &principals, &metadata, &mapping);
    assert_eq!(payload.external_id.as_deref(), Some("EMP-001"));
}

#[test]
fn test_extract_login_strips_domain() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    assert_eq!(extract_login(&profile, &principals), "alice.smith");
}

#[test]
fn test_extract_login_fallback_to_username() {
    let profile = test_profile();
    assert_eq!(extract_login(&profile, &[]), "alice.smith");
}

#[test]
fn test_group_mapping_resolution() {
    let config = GroupPushConfig {
        enabled: true,
        mapping: vec![GroupMappingEntry {
            sid_group: "Engineering".into(),
            target_group: "S0001".into(),
        }],
    };

    assert_eq!(
        resolve_group_mapping("Engineering", &config),
        Some("S0001".into())
    );
    assert_eq!(resolve_group_mapping("Sales", &config), None);
}

#[test]
fn test_group_mapping_disabled() {
    let config = GroupPushConfig::default(); // enabled=false
    assert_eq!(resolve_group_mapping("Engineering", &config), None);
}

/// A user replacement carries every mapped attribute of the current state,
/// `active` included, so an inactive profile is pushed inactive whatever
/// event caused the push.
#[test]
fn test_replace_user_carries_the_whole_state() {
    let mut profile = test_profile();
    profile.status = ProfileStatus::Suspended;
    let principals = test_principals(profile.id);
    let payload = build_scim_user(&profile, &principals, &[], &AttributeMapping::default());

    let patch = ScimPatchPayload::replace_user(&payload).unwrap();
    assert!(patch.operations.iter().all(|op| op.op == "replace"));
    let active = patch
        .operations
        .iter()
        .find(|op| op.path.as_deref() == Some("active"))
        .expect("active is replaced");
    assert_eq!(active.value, Some(serde_json::json!(false)));
    assert!(
        patch
            .operations
            .iter()
            .any(|op| op.path.as_deref() == Some("userName"))
    );
    assert!(
        !patch
            .operations
            .iter()
            .any(|op| op.path.as_deref() == Some("schemas"))
    );
}

/// A group replacement sets the whole membership: the members given, or
/// none (a removal of every member) when it is empty.
#[test]
fn test_replace_group_sets_the_whole_membership() {
    let mut group = ScimGroupPayload {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".into()],
        display_name: "Engineering".into(),
        members: vec![ScimMemberPayload {
            value: "u1".into(),
            display: None,
        }],
    };
    let patch = ScimPatchPayload::replace_group(&group);
    let members = patch
        .operations
        .iter()
        .find(|op| op.path.as_deref() == Some("members"))
        .unwrap();
    assert_eq!(members.op, "replace");
    assert_eq!(members.value, Some(serde_json::json!([{"value": "u1"}])));

    // An empty membership is a removal sent on its own, so a provider's
    // noTarget for a group without members cannot reject the rename with it.
    group.members.clear();
    let patch = ScimPatchPayload::replace_group(&group);
    assert!(
        patch
            .operations
            .iter()
            .all(|op| op.path.as_deref() != Some("members")),
        "the membership rides with the rename"
    );
    let clear = ScimPatchPayload::remove(&["members".to_string()]);
    assert_eq!(clear.operations.len(), 1);
    assert_eq!(clear.operations[0].op, "remove");
    assert_eq!(clear.operations[0].path.as_deref(), Some("members"));
    assert_eq!(clear.operations[0].value, None);
}

#[test]
fn test_scim_user_payload_serializes() {
    let profile = test_profile();
    let principals = test_principals(profile.id);
    let metadata = test_metadata(profile.id);

    let payload = build_scim_user(
        &profile,
        &principals,
        &metadata,
        &AttributeMapping::default(),
    );
    let json = serde_json::to_string(&payload).unwrap();
    assert!(json.contains("\"userName\""));
    assert!(json.contains("\"displayName\""));
    assert!(json.contains("\"emails\""));
}

#[test]
fn test_suspended_profile_inactive() {
    let mut profile = test_profile();
    profile.status = ProfileStatus::Suspended;
    let payload = build_scim_user(&profile, &[], &[], &AttributeMapping::default());
    assert!(!payload.active);
}
