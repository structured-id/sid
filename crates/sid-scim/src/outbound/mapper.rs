// SPDX-License-Identifier: AGPL-3.0-only
//! Attribute mapping engine for SCIM outbound provisioning.
//!
//! Resolves SID profile/identifier/metadata fields into SCIM User payloads
//! using the configured AttributeMapping.

use serde_json::{Value, json};
use sid_core::models::{
    AttributeMapping, GroupPushConfig, MappingSource, Principal, PrincipalType, Profile,
    ProfileMetadata, ProfileStatus,
};

/// Resolved SCIM User payload ready to send to downstream.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimUserPayload {
    pub schemas: Vec<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimNamePayload>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimMultiValuePayload>,
    #[serde(rename = "phoneNumbers", skip_serializing_if = "Vec::is_empty")]
    pub phone_numbers: Vec<ScimMultiValuePayload>,
    pub active: bool,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// Extra mapped attributes not covered by standard fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ScimNamePayload {
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimMultiValuePayload {
    pub value: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub primary: bool,
}

/// SCIM Group payload for outbound.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimGroupPayload {
    pub schemas: Vec<String>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimMemberPayload>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimMemberPayload {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM PATCH operation payload.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimPatchPayload {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOp>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimPatchOp {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl ScimPatchPayload {
    pub fn new(operations: Vec<ScimPatchOp>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".into()],
            operations,
        }
    }

    pub fn deactivate() -> Self {
        Self::new(vec![ScimPatchOp {
            op: "replace".into(),
            path: Some("active".into()),
            value: Some(json!(false)),
        }])
    }

    pub fn reactivate() -> Self {
        Self::new(vec![ScimPatchOp {
            op: "replace".into(),
            path: Some("active".into()),
            value: Some(json!(true)),
        }])
    }

    pub fn add_members(member_ids: Vec<String>) -> Self {
        let members: Vec<Value> = member_ids
            .into_iter()
            .map(|id| json!({"value": id}))
            .collect();
        Self::new(vec![ScimPatchOp {
            op: "add".into(),
            path: Some("members".into()),
            value: Some(Value::Array(members)),
        }])
    }

    pub fn remove_members(member_ids: Vec<String>) -> Self {
        let members: Vec<Value> = member_ids
            .into_iter()
            .map(|id| json!({"value": id}))
            .collect();
        Self::new(vec![ScimPatchOp {
            op: "remove".into(),
            path: Some("members".into()),
            value: Some(Value::Array(members)),
        }])
    }
}

/// Build a SCIM User payload from SID profile data using the configured attribute mapping.
///
/// If `mapping` is empty, uses default field mapping.
pub fn build_scim_user(
    profile: &Profile,
    identifiers: &[Principal],
    metadata: &[ProfileMetadata],
    mapping: &AttributeMapping,
) -> ScimUserPayload {
    if mapping.mappings.is_empty() {
        return build_default_scim_user(profile, identifiers, metadata);
    }

    let mut payload = ScimUserPayload {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".into()],
        user_name: String::new(),
        name: None,
        display_name: None,
        emails: Vec::new(),
        phone_numbers: Vec::new(),
        active: profile.status == ProfileStatus::Active
            || profile.status == ProfileStatus::Provisioned,
        external_id: None,
        title: None,
        department: None,
        extra: serde_json::Map::new(),
    };

    for entry in &mapping.mappings {
        let value = resolve_source(profile, identifiers, metadata, &entry.source);
        apply_to_payload(&mut payload, &entry.scim_path, value);
    }

    // Ensure userName is never empty
    if payload.user_name.is_empty() {
        payload.user_name = extract_login(profile, identifiers);
    }

    payload
}

/// Default mapping when no explicit AttributeMapping is configured.
fn build_default_scim_user(
    profile: &Profile,
    identifiers: &[Principal],
    metadata: &[ProfileMetadata],
) -> ScimUserPayload {
    let login = extract_login(profile, identifiers);
    let email = find_identifier(identifiers, PrincipalType::Email);
    let phone = find_identifier(identifiers, PrincipalType::Phone);

    // Name from Profile fields (structured name), not metadata
    let given_name = profile.given_name.clone();
    let family_name = profile.family_name.clone();
    let employee_id = find_metadata(metadata, "employee_id");
    let department = find_metadata(metadata, "department");
    let title = find_metadata(metadata, "title");

    let name = if given_name.is_some() || family_name.is_some() {
        Some(ScimNamePayload {
            formatted: profile.formatted_name(),
            given_name,
            family_name,
        })
    } else {
        None
    };

    let emails = email
        .into_iter()
        .map(|e| ScimMultiValuePayload {
            value: e,
            value_type: "work".into(),
            primary: true,
        })
        .collect();

    let phone_numbers = phone
        .into_iter()
        .map(|p| ScimMultiValuePayload {
            value: p,
            value_type: "work".into(),
            primary: true,
        })
        .collect();

    ScimUserPayload {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".into()],
        user_name: login,
        name,
        display_name: profile.formatted_name(),
        emails,
        phone_numbers,
        active: profile.status == ProfileStatus::Active
            || profile.status == ProfileStatus::Provisioned,
        external_id: employee_id,
        title,
        department,
        extra: serde_json::Map::new(),
    }
}

/// Resolve a mapping source against SID profile data.
fn resolve_source(
    profile: &Profile,
    identifiers: &[Principal],
    metadata: &[ProfileMetadata],
    source: &MappingSource,
) -> Option<Value> {
    match source {
        MappingSource::Path { path } => resolve_path(profile, identifiers, metadata, path),
        MappingSource::Literal { value } => Some(value.clone()),
        MappingSource::StatusCheck { active_value } => {
            let status_str = format!("{:?}", profile.status).to_lowercase();
            Some(Value::Bool(status_str == active_value.to_lowercase()))
        }
    }
}

/// Resolve a dotted path like "profile.login", "profile.email", "metadata.employee_id".
fn resolve_path(
    profile: &Profile,
    identifiers: &[Principal],
    metadata: &[ProfileMetadata],
    path: &str,
) -> Option<Value> {
    match path {
        "profile.login" => Some(Value::String(extract_login(profile, identifiers))),
        "profile.username" => profile.username.clone().map(Value::String),
        "profile.display_name" => profile.formatted_name().map(Value::String),
        "profile.given_name" => profile.given_name.clone().map(Value::String),
        "profile.family_name" => profile.family_name.clone().map(Value::String),
        "profile.middle_name" => profile.middle_name.clone().map(Value::String),
        "profile.email" => find_identifier(identifiers, PrincipalType::Email).map(Value::String),
        "profile.phone" => find_identifier(identifiers, PrincipalType::Phone).map(Value::String),
        "profile.status" => Some(Value::String(
            format!("{:?}", profile.status).to_lowercase(),
        )),
        _ if path.starts_with("metadata.") => {
            let key = &path["metadata.".len()..];
            // ProfileMetadata.value is serde_json::Value; extract as string for SCIM
            metadata.iter().find(|m| m.key == key).map(|m| {
                if let Some(s) = m.value.as_str() {
                    Value::String(s.to_string())
                } else {
                    m.value.clone()
                }
            })
        }
        _ => None,
    }
}

/// Apply a resolved value to the SCIM payload at the given SCIM path.
fn apply_to_payload(payload: &mut ScimUserPayload, scim_path: &str, value: Option<Value>) {
    let Some(value) = value else { return };

    match scim_path {
        "userName" => {
            if let Value::String(s) = value {
                payload.user_name = s;
            }
        }
        "displayName" => {
            if let Value::String(s) = value {
                payload.display_name = Some(s);
            }
        }
        "name.givenName" => {
            let name = payload.name.get_or_insert_default();
            if let Value::String(s) = value {
                name.given_name = Some(s);
            }
        }
        "name.familyName" => {
            let name = payload.name.get_or_insert_default();
            if let Value::String(s) = value {
                name.family_name = Some(s);
            }
        }
        "name.formatted" => {
            let name = payload.name.get_or_insert_default();
            if let Value::String(s) = value {
                name.formatted = Some(s);
            }
        }
        "active" => {
            if let Value::Bool(b) = value {
                payload.active = b;
            }
        }
        "externalId" => {
            if let Value::String(s) = value {
                payload.external_id = Some(s);
            }
        }
        "title" => {
            if let Value::String(s) = value {
                payload.title = Some(s);
            }
        }
        "department" => {
            if let Value::String(s) = value {
                payload.department = Some(s);
            }
        }
        _ => {
            // Store as extra attribute
            payload.extra.insert(scim_path.to_string(), value);
        }
    }
}

/// Extract the login part from the corporate identifier (before '#').
fn extract_login(profile: &Profile, identifiers: &[Principal]) -> String {
    // Look for Custom identifier (corporate login: "user#domain")
    for id in identifiers {
        if id.principal_type == PrincipalType::Username {
            // Strip org domain suffix: "alice.smith#acme.corp" → "alice.smith"
            if let Some(pos) = id.value.find('#') {
                return id.value[..pos].to_string();
            }
            return id.value.clone();
        }
    }
    // Fallback to username, then profile ID
    profile
        .username
        .clone()
        .unwrap_or_else(|| profile.id.to_string())
}

fn find_identifier(identifiers: &[Principal], id_type: PrincipalType) -> Option<String> {
    identifiers
        .iter()
        .find(|id| id.principal_type == id_type)
        .map(|id| id.value.clone())
}

fn find_metadata(metadata: &[ProfileMetadata], key: &str) -> Option<String> {
    metadata
        .iter()
        .find(|m| m.key == key)
        .and_then(|m| m.value.as_str())
        .map(|s| s.to_string())
}

/// Resolve a SID group name to downstream group ID using the group push config.
pub fn resolve_group_mapping(sid_group_name: &str, config: &GroupPushConfig) -> Option<String> {
    if !config.enabled {
        return None;
    }
    config
        .mapping
        .iter()
        .find(|m| m.sid_group == sid_group_name)
        .map(|m| m.target_group.clone())
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn test_patch_payload_deactivate() {
        let patch = ScimPatchPayload::deactivate();
        assert_eq!(patch.operations.len(), 1);
        assert_eq!(patch.operations[0].op, "replace");
        assert_eq!(patch.operations[0].path.as_deref(), Some("active"));
        assert_eq!(patch.operations[0].value, Some(serde_json::json!(false)));
    }

    #[test]
    fn test_patch_payload_add_members() {
        let patch = ScimPatchPayload::add_members(vec!["user1".into(), "user2".into()]);
        assert_eq!(patch.operations.len(), 1);
        assert_eq!(patch.operations[0].op, "add");
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
}
