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

    /// Replace every attribute `user` carries (RFC 7644 §3.5.2.3): the
    /// resource takes the current state whatever it held, so a repeated or
    /// late push restores the same state rather than an older one.
    pub fn replace_user(user: &ScimUserPayload) -> Result<Self, super::client::ScimClientError> {
        let Value::Object(attributes) = serde_json::to_value(user)
            .map_err(|e| super::client::ScimClientError::Serialization(e.to_string()))?
        else {
            return Err(super::client::ScimClientError::Serialization(
                "a user is not an object".into(),
            ));
        };
        Ok(Self::new(
            attributes
                .into_iter()
                .filter(|(name, _)| name != "schemas")
                .map(|(name, value)| ScimPatchOp {
                    op: "replace".into(),
                    path: Some(name),
                    value: Some(value),
                })
                .collect(),
        ))
    }

    /// Replace a group's name and, when it has members, its whole
    /// membership. An empty membership is not part of this patch: it is
    /// [`Self::remove_members`], sent on its own (see there).
    pub fn replace_group(group: &ScimGroupPayload) -> Self {
        let mut operations = vec![ScimPatchOp {
            op: "replace".into(),
            path: Some("displayName".into()),
            value: Some(json!(group.display_name)),
        }];
        if !group.members.is_empty() {
            operations.push(ScimPatchOp {
                op: "replace".into(),
                path: Some("members".into()),
                value: Some(Value::Array(
                    group
                        .members
                        .iter()
                        .map(|m| json!({"value": m.value}))
                        .collect(),
                )),
            });
        }
        Self::new(operations)
    }

    /// Remove every attribute at `paths` (RFC 7644 §3.5.2.2), such as a
    /// group's `members` (a replacement with an empty value is not one every
    /// server accepts). A server may refuse a path it has nothing at as
    /// `noTarget`, and a patch is atomic, so removals go apart from other
    /// changes rather than taking them down too.
    pub fn remove(paths: &[String]) -> Self {
        Self::new(
            paths
                .iter()
                .map(|path| ScimPatchOp {
                    op: "remove".into(),
                    path: Some(path.clone()),
                    value: None,
                })
                .collect(),
        )
    }
}

/// The attributes the default mapping writes besides `userName` and
/// `active`, which every user carries.
const DEFAULT_USER_PATHS: [&str; 9] = [
    "displayName",
    "name.givenName",
    "name.familyName",
    "name.formatted",
    "emails",
    "phoneNumbers",
    "externalId",
    "title",
    "department",
];

/// The attribute paths `mapping` writes that `user` does not carry now: a
/// push removes them, so the target is left without what the user lost. A
/// `name` with none of its mapped sub-attributes left is removed as a whole;
/// otherwise each missing sub-attribute is, since a replacement of `name`
/// leaves the sub-attributes it does not name unchanged (RFC 7644 §3.5.2.3).
pub fn absent_user_paths(
    user: &ScimUserPayload,
    mapping: &AttributeMapping,
) -> Result<Vec<String>, super::client::ScimClientError> {
    let Value::Object(held) = serde_json::to_value(user)
        .map_err(|e| super::client::ScimClientError::Serialization(e.to_string()))?
    else {
        return Err(super::client::ScimClientError::Serialization(
            "a user is not an object".into(),
        ));
    };
    let written: Vec<&str> = if mapping.mappings.is_empty() {
        DEFAULT_USER_PATHS.to_vec()
    } else {
        mapping
            .mappings
            .iter()
            .map(|entry| entry.scim_path.as_str())
            .filter(|path| !matches!(*path, "userName" | "active"))
            .collect()
    };
    let name = held.get("name");
    let mut absent = Vec::new();
    for path in written {
        let missing = match path.strip_prefix("name.") {
            Some(_) if name.is_none() => "name",
            Some(sub) if name.and_then(|n| n.get(sub)).is_none() => path,
            Some(_) => continue,
            None if held.contains_key(path) => continue,
            None => path,
        };
        if !absent.iter().any(|p| p == missing) {
            absent.push(missing.to_string());
        }
    }
    Ok(absent)
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
mod tests;
