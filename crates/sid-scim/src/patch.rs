// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM PATCH operations (RFC 7644 §3.5.2).
//!
//! Applies add/remove/replace operations to SID profiles and groups.

use sid_core::models::{PrincipalType, Profile, ProfileStatus};
use sid_proto::sid::v1 as proto;

/// Error applying a SCIM PATCH operation.
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("unsupported operation: {0}")]
    UnsupportedOp(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("invalid value for {path}: {reason}")]
    InvalidValue { path: String, reason: String },
    #[error("immutable attribute: {0}")]
    ImmutableAttribute(String),
}

/// Result of applying PATCH operations to a user profile.
///
/// Contains the changes that need to be persisted.
#[derive(Default)]
pub struct UserPatchResult {
    /// Whether the Profile struct was modified.
    pub profile_changed: bool,
    /// Whether the profile needs reactivation from Suspended.
    /// The gRPC handler resolves the target state:
    /// - Provisioned (if never claimed — no verified login identifiers)
    /// - Active (if previously claimed — has verified login identifiers)
    pub needs_reactivation: bool,
    /// Identifiers to add.
    pub add_identifiers: Vec<PatchIdentifier>,
    /// Identifiers to remove (by value).
    pub remove_identifier_values: Vec<(PrincipalType, String)>,
    /// Metadata to set/update.
    pub set_metadata: Vec<(String, serde_json::Value)>,
    /// Metadata keys to remove.
    pub remove_metadata: Vec<String>,
}

/// An identifier to add via PATCH.
pub struct PatchIdentifier {
    pub id_type: PrincipalType,
    pub value: String,
    pub is_primary: bool,
}

/// Apply SCIM PATCH operations to a user profile.
///
/// Returns a description of changes to persist. Does NOT mutate storage directly.
pub fn apply_user_patch(
    profile: &mut Profile,
    ops: &[proto::ScimPatchOp],
) -> Result<UserPatchResult, PatchError> {
    let mut result = UserPatchResult::default();

    for op in ops {
        let op_type = op.op.to_lowercase();
        match op_type.as_str() {
            "replace" => apply_replace(profile, &op.path, &op.value, &mut result)?,
            "add" => apply_add(&op.path, &op.value, &mut result)?,
            "remove" => apply_remove(&op.path, &mut result)?,
            _ => return Err(PatchError::UnsupportedOp(op.op.clone())),
        }
    }

    Ok(result)
}

fn apply_replace(
    profile: &mut Profile,
    path: &str,
    value: &str,
    result: &mut UserPatchResult,
) -> Result<(), PatchError> {
    match path {
        "displayName" => {
            // SCIM displayName → given_name (unstructured fallback).
            // Clears family_name/middle_name since displayName is unstructured.
            // Full SCIM name.* mapping is via name.givenName/name.familyName paths.
            profile.given_name = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            profile.family_name = None;
            profile.middle_name = None;
            result.profile_changed = true;
        }
        "active" => {
            let active = value
                .parse::<bool>()
                .map_err(|_| PatchError::InvalidValue {
                    path: path.into(),
                    reason: "expected boolean".into(),
                })?;
            if !active {
                profile.status = ProfileStatus::Suspended;
                result.profile_changed = true;
            } else if profile.status == ProfileStatus::Suspended {
                // Mark for reactivation — grpc handler resolves the target state
                // (Provisioned if never claimed, Active if previously claimed).
                result.needs_reactivation = true;
                result.profile_changed = true;
            }
        }
        "title" => {
            result
                .set_metadata
                .push(("title".into(), serde_json::Value::String(value.to_string())));
        }
        "department" => {
            result.set_metadata.push((
                "department".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        "name.givenName" => {
            profile.given_name = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            result.profile_changed = true;
        }
        "name.familyName" => {
            profile.family_name = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            result.profile_changed = true;
        }
        "name.middleName" => {
            profile.middle_name = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            result.profile_changed = true;
        }
        "externalId" => {
            result.set_metadata.push((
                "employee_id".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        // SCIM Enterprise Extension (RFC 7643 §4.3)
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
        | "employeeNumber" => {
            result.set_metadata.push((
                "employee_number".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter" | "costCenter" => {
            result.set_metadata.push((
                "cost_center".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization"
        | "organization" => {
            result.set_metadata.push((
                "organization".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division" | "division" => {
            result.set_metadata.push((
                "division".into(),
                serde_json::Value::String(value.to_string()),
            ));
        }
        "id" | "userName" => {
            return Err(PatchError::ImmutableAttribute(path.into()));
        }
        _ => {
            return Err(PatchError::InvalidPath(path.into()));
        }
    }
    Ok(())
}

fn apply_add(path: &str, value: &str, result: &mut UserPatchResult) -> Result<(), PatchError> {
    match path {
        "emails" => {
            // Parse value as JSON email object
            let email: serde_json::Value =
                serde_json::from_str(value).map_err(|_| PatchError::InvalidValue {
                    path: path.into(),
                    reason: "expected JSON email object".into(),
                })?;
            if let Some(val) = email.get("value").and_then(|v| v.as_str()) {
                let primary = email
                    .get("primary")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                result.add_identifiers.push(PatchIdentifier {
                    id_type: PrincipalType::Email,
                    value: val.to_string(),
                    is_primary: primary,
                });
            }
        }
        "phoneNumbers" => {
            let phone: serde_json::Value =
                serde_json::from_str(value).map_err(|_| PatchError::InvalidValue {
                    path: path.into(),
                    reason: "expected JSON phone object".into(),
                })?;
            if let Some(val) = phone.get("value").and_then(|v| v.as_str()) {
                let primary = phone
                    .get("primary")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                result.add_identifiers.push(PatchIdentifier {
                    id_type: PrincipalType::Phone,
                    value: val.to_string(),
                    is_primary: primary,
                });
            }
        }
        _ => {
            return Err(PatchError::InvalidPath(path.into()));
        }
    }
    Ok(())
}

fn apply_remove(path: &str, result: &mut UserPatchResult) -> Result<(), PatchError> {
    match path {
        "title" => {
            result.remove_metadata.push("title".into());
        }
        "department" => {
            result.remove_metadata.push("department".into());
        }
        "id" | "userName" => {
            return Err(PatchError::ImmutableAttribute(path.into()));
        }
        _ if path.starts_with("emails[") => {
            // Parse emails[value eq "x@y.com"] pattern
            if let Some(value) = extract_filter_value(path) {
                result
                    .remove_identifier_values
                    .push((PrincipalType::Email, value));
            } else {
                return Err(PatchError::InvalidPath(path.into()));
            }
        }
        _ if path.starts_with("phoneNumbers[") => {
            if let Some(value) = extract_filter_value(path) {
                result
                    .remove_identifier_values
                    .push((PrincipalType::Phone, value));
            } else {
                return Err(PatchError::InvalidPath(path.into()));
            }
        }
        _ => {
            return Err(PatchError::InvalidPath(path.into()));
        }
    }
    Ok(())
}

/// Extract value from filter path like `emails[value eq "alice@acme.com"]`.
fn extract_filter_value(path: &str) -> Option<String> {
    let start = path.find('"')? + 1;
    let end = path.rfind('"')?;
    if start < end {
        Some(path[start..end].to_string())
    } else {
        None
    }
}

/// Result of applying PATCH operations to a group.
pub struct GroupPatchResult {
    /// Display name changed.
    pub display_name: Option<String>,
    /// Members to add (profile IDs).
    pub add_members: Vec<String>,
    /// Members to remove (profile IDs).
    pub remove_members: Vec<String>,
}

/// Apply SCIM PATCH operations to a group.
pub fn apply_group_patch(ops: &[proto::ScimPatchOp]) -> Result<GroupPatchResult, PatchError> {
    let mut result = GroupPatchResult {
        display_name: None,
        add_members: vec![],
        remove_members: vec![],
    };

    for op in ops {
        let op_type = op.op.to_lowercase();
        match (op_type.as_str(), op.path.as_str()) {
            ("replace", "displayName") => {
                result.display_name = Some(op.value.clone());
            }
            ("add", "members") => {
                // Value is JSON array or single member ref
                if let Ok(members) = serde_json::from_str::<Vec<serde_json::Value>>(&op.value) {
                    for m in members {
                        if let Some(val) = m.get("value").and_then(|v| v.as_str()) {
                            result.add_members.push(val.to_string());
                        }
                    }
                } else if let Ok(m) = serde_json::from_str::<serde_json::Value>(&op.value)
                    && let Some(val) = m.get("value").and_then(|v| v.as_str())
                {
                    result.add_members.push(val.to_string());
                }
            }
            ("remove", path) if path.starts_with("members[") => {
                if let Some(value) = extract_filter_value(path) {
                    result.remove_members.push(value);
                }
            }
            _ => {
                return Err(PatchError::InvalidPath(op.path.clone()));
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::ProfileType;

    fn test_profile() -> Profile {
        let mut p = Profile::new(Some("test"));
        p.profile_type = ProfileType::Corporate;
        p.status = ProfileStatus::Active;
        p.given_name = Some("Alice".into());
        p.family_name = Some("Smith".into());
        p
    }

    #[test]
    fn test_replace_display_name() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "displayName".into(),
            value: "Alice Jones".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert!(result.profile_changed);
        // SCIM displayName patch maps to given_name (unstructured fallback)
        assert_eq!(profile.given_name.as_deref(), Some("Alice Jones"));
    }

    #[test]
    fn test_replace_active_false_suspends() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "active".into(),
            value: "false".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert!(result.profile_changed);
        assert_eq!(profile.status, ProfileStatus::Suspended);
    }

    #[test]
    fn test_replace_active_true_reactivates() {
        let mut profile = test_profile();
        profile.status = ProfileStatus::Suspended;
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "active".into(),
            value: "true".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        // patch.rs doesn't resolve target state — it sets needs_reactivation.
        // gRPC handler decides Provisioned vs Active based on verified identifiers.
        assert!(result.needs_reactivation);
        assert!(result.profile_changed);
        // Profile status stays Suspended — grpc handler will change it.
        assert_eq!(profile.status, ProfileStatus::Suspended);
    }

    #[test]
    fn test_replace_metadata() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "department".into(),
            value: "Product".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata.len(), 1);
        assert_eq!(result.set_metadata[0].0, "department");
    }

    #[test]
    fn test_immutable_id_rejected() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "id".into(),
            value: "new-id".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops);
        assert!(matches!(result, Err(PatchError::ImmutableAttribute(_))));
    }

    #[test]
    fn test_add_email() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "add".into(),
            path: "emails".into(),
            value: r#"{"value":"new@acme.com","type":"work","primary":false}"#.into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.add_identifiers.len(), 1);
        assert_eq!(result.add_identifiers[0].value, "new@acme.com");
        assert_eq!(result.add_identifiers[0].id_type, PrincipalType::Email);
    }

    #[test]
    fn test_remove_email_by_filter() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "remove".into(),
            path: r#"emails[value eq "old@acme.com"]"#.into(),
            value: String::new(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.remove_identifier_values.len(), 1);
        assert_eq!(result.remove_identifier_values[0].1, "old@acme.com");
    }

    #[test]
    fn test_group_patch_add_members() {
        let ops = vec![proto::ScimPatchOp {
            op: "add".into(),
            path: "members".into(),
            value: r#"[{"value":"user-id-1"},{"value":"user-id-2"}]"#.into(),
        }];
        let result = apply_group_patch(&ops).unwrap();
        assert_eq!(result.add_members.len(), 2);
        assert_eq!(result.add_members[0], "user-id-1");
    }

    #[test]
    fn test_group_patch_remove_member() {
        let ops = vec![proto::ScimPatchOp {
            op: "remove".into(),
            path: r#"members[value eq "user-id-1"]"#.into(),
            value: String::new(),
        }];
        let result = apply_group_patch(&ops).unwrap();
        assert_eq!(result.remove_members.len(), 1);
        assert_eq!(result.remove_members[0], "user-id-1");
    }

    // ── Enterprise Extension (RFC 7643 §4.3) ──

    #[test]
    fn test_replace_employee_number() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "employeeNumber".into(),
            value: "E-12345".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata.len(), 1);
        assert_eq!(result.set_metadata[0].0, "employee_number");
    }

    #[test]
    fn test_replace_employee_number_full_urn() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
                .into(),
            value: "E-12345".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata[0].0, "employee_number");
    }

    #[test]
    fn test_replace_cost_center() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "costCenter".into(),
            value: "CC-100".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata[0].0, "cost_center");
    }

    #[test]
    fn test_replace_organization() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "organization".into(),
            value: "Acme Corp".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata[0].0, "organization");
    }

    #[test]
    fn test_replace_division() {
        let mut profile = test_profile();
        let ops = vec![proto::ScimPatchOp {
            op: "replace".into(),
            path: "division".into(),
            value: "West Region".into(),
        }];
        let result = apply_user_patch(&mut profile, &ops).unwrap();
        assert_eq!(result.set_metadata[0].0, "division");
    }
}
