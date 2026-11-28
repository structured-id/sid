// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM PATCH operations (RFC 7644 §3.5.2).
//!
//! Applies add/remove/replace operations to SID profiles and groups.

use sid_core::models::{PrincipalType, Profile};
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
    /// The `active` the request asks the user to show, when it names it;
    /// the last operation stands. What that changes depends on what the
    /// resource stands for, which the caller of this module decides.
    pub active: Option<bool>,
    /// The `userName` the request gives the user, when it names it; the
    /// last operation stands.
    pub user_name: Option<String>,
    /// Identifiers to add.
    pub add_identifiers: Vec<PatchIdentifier>,
    /// Identifiers to remove (by value).
    pub remove_identifier_values: Vec<(PrincipalType, String)>,
    /// Metadata to set/update.
    pub set_metadata: Vec<(String, serde_json::Value)>,
    /// Metadata keys to remove.
    pub remove_metadata: Vec<String>,
    /// The identifier the asking provisioning source gives the user, when
    /// the request sets it: `Some(None)` drops it (RFC 7643 3.1, the
    /// client's own `externalId`, never an attribute of the account).
    pub external_id: Option<Option<String>>,
}

impl UserPatchResult {
    /// The request leaves metadata `key` with `value`: operations apply in
    /// order (RFC 7644 §3.5.2), so this one stands over any before it.
    fn set(&mut self, key: &str, value: &str) {
        self.unset_pending(key);
        self.set_metadata
            .push((key.into(), serde_json::Value::String(value.into())));
    }

    /// The request leaves metadata `key` absent, likewise.
    fn remove(&mut self, key: &str) {
        self.unset_pending(key);
        self.remove_metadata.push(key.into());
    }

    fn unset_pending(&mut self, key: &str) {
        self.set_metadata.retain(|(held, _)| held != key);
        self.remove_metadata.retain(|held| held != key);
    }
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
            result.active = Some(active);
        }
        "title" => result.set("title", value),
        "department" => result.set("department", value),
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
            result.external_id = Some((!value.is_empty()).then(|| value.to_string()));
        }
        // SCIM Enterprise Extension (RFC 7643 §4.3). The employee number is
        // the account's, one value whichever source writes it.
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
        | "employeeNumber" => result.set("employee_id", value),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter" | "costCenter" => {
            result.set("cost_center", value)
        }
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization"
        | "organization" => result.set("organization", value),
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:division" | "division" => {
            result.set("division", value)
        }
        // The organization's login: whether the caller may rename it is the
        // caller of this module's to decide.
        "userName" => result.user_name = Some(value.to_string()),
        "id" => {
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
        "title" => result.remove("title"),
        "department" => result.remove("department"),
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
    /// Whether the request set the caller's whole member list (a
    /// replacement of `members`, or their removal with no value): the
    /// caller's assignments not in [`Self::add_members`] are withdrawn.
    pub replaces_members: bool,
    /// The members the request leaves assigned, by the identifiers it
    /// named them with, in request order.
    pub add_members: Vec<String>,
    /// The members the request leaves withdrawn, likewise.
    pub remove_members: Vec<String>,
}

/// Apply SCIM PATCH operations to a group.
pub fn apply_group_patch(ops: &[proto::ScimPatchOp]) -> Result<GroupPatchResult, PatchError> {
    let mut result = GroupPatchResult {
        display_name: None,
        replaces_members: false,
        add_members: vec![],
        remove_members: vec![],
    };

    // Operations apply in request order, each on the result of the one
    // before (RFC 7644 §3.5.2): what is kept is where each member ends.
    for op in ops {
        let op_type = op.op.to_lowercase();
        match (op_type.as_str(), op.path.as_str()) {
            ("replace", "displayName") => {
                result.display_name = Some(op.value.clone());
            }
            ("add", "members") => {
                for id in member_values(&op.value)? {
                    result.assign(id);
                }
            }
            ("replace", "members") => {
                let members = member_values(&op.value)?;
                result.clear_members();
                for id in members {
                    result.assign(id);
                }
            }
            // No value: the caller's whole list. A value that is present
            // and malformed is refused by `member_values`, never read as
            // this.
            ("remove", "members") if op.value.is_empty() => result.clear_members(),
            // A value array names the members to remove, an empty one
            // nobody.
            ("remove", "members") => {
                for id in member_values(&op.value)? {
                    result.withdraw(id);
                }
            }
            ("remove", path) if path.starts_with("members[") => {
                let id = extract_filter_value(path)
                    .ok_or_else(|| PatchError::InvalidPath(op.path.clone()))?;
                result.withdraw(id);
            }
            _ => {
                return Err(PatchError::InvalidPath(op.path.clone()));
            }
        }
    }

    Ok(result)
}

impl GroupPatchResult {
    fn assign(&mut self, id: String) {
        self.remove_members.retain(|held| *held != id);
        if !self.add_members.contains(&id) {
            self.add_members.push(id);
        }
    }

    fn withdraw(&mut self, id: String) {
        self.add_members.retain(|held| *held != id);
        if !self.remove_members.contains(&id) {
            self.remove_members.push(id);
        }
    }

    fn clear_members(&mut self) {
        self.replaces_members = true;
        self.add_members.clear();
        self.remove_members.clear();
    }
}

/// The member identifiers a `members` value names: an array of member
/// objects, or one object, each with a string `value` (other keys, a `$ref`
/// of null among them, are not read). Anything else is a refused value.
fn member_values(value: &str) -> Result<Vec<String>, PatchError> {
    let invalid = |reason: &str| PatchError::InvalidValue {
        path: "members".into(),
        reason: reason.into(),
    };
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| invalid("expected JSON member objects"))?;
    let members = match parsed {
        serde_json::Value::Array(members) => members,
        member @ serde_json::Value::Object(_) => vec![member],
        _ => return Err(invalid("expected JSON member objects")),
    };
    members
        .iter()
        .map(|member| {
            member
                .get("value")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid("a member has no value"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::{ProfileStatus, ProfileType};

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

    /// `active` is only recorded: whether it suspends an account or ends a
    /// relationship is not this module's to decide, so the account's state
    /// is left as it was. The last operation of a request stands.
    #[test]
    fn test_replace_active_is_recorded_not_applied() {
        let op = |value: &str| proto::ScimPatchOp {
            op: "replace".into(),
            path: "active".into(),
            value: value.into(),
        };
        let mut profile = test_profile();
        let result = apply_user_patch(&mut profile, &[op("false")]).unwrap();
        assert_eq!(result.active, Some(false));
        assert_eq!(profile.status, ProfileStatus::Active);

        let result = apply_user_patch(&mut profile, &[op("false"), op("true")]).unwrap();
        assert_eq!(result.active, Some(true));
        assert_eq!(profile.status, ProfileStatus::Active);

        let result = apply_user_patch(&mut profile, &[]).unwrap();
        assert_eq!(result.active, None);
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

    /// RFC 7644 3.5.2: operations apply in request order, each on the result
    /// of the one before. An attribute replaced and then removed ends
    /// absent; removed and then replaced it ends with the value; of two
    /// replacements the later stands.
    #[test]
    fn test_metadata_operations_keep_request_order() {
        let op = |op: &str, value: &str| proto::ScimPatchOp {
            op: op.into(),
            path: "title".into(),
            value: value.into(),
        };
        let run = |ops: &[proto::ScimPatchOp]| {
            let result = apply_user_patch(&mut test_profile(), ops).unwrap();
            (result.set_metadata, result.remove_metadata)
        };
        let title = |value: &str| ("title".to_string(), serde_json::Value::String(value.into()));

        let (set, removed) = run(&[op("replace", "Y"), op("remove", "")]);
        assert!(set.is_empty(), "{set:?}");
        assert_eq!(removed, vec!["title"]);

        let (set, removed) = run(&[op("remove", ""), op("replace", "Y")]);
        assert_eq!(set, vec![title("Y")]);
        assert!(removed.is_empty(), "{removed:?}");

        let (set, removed) = run(&[op("replace", "Y"), op("replace", "Z")]);
        assert_eq!(set, vec![title("Z")]);
        assert!(removed.is_empty());
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

    /// One PATCH applies in request order, each operation on the result of
    /// the one before (RFC 7644 3.5.2): the same member added and then
    /// removed is removed, removed and then added is added.
    #[test]
    fn test_group_patch_member_operations_keep_request_order() {
        let op = |op: &str, path: &str, value: &str| proto::ScimPatchOp {
            op: op.into(),
            path: path.into(),
            value: value.into(),
        };
        let add = |id: &str| op("add", "members", &format!(r#"[{{"value":"{id}"}}]"#));
        let remove = |id: &str| op("remove", &format!(r#"members[value eq "{id}"]"#), "");

        let result = apply_group_patch(&[add("a"), add("b"), remove("a")]).unwrap();
        assert_eq!(result.add_members, vec!["b"]);
        assert_eq!(result.remove_members, vec!["a"]);
        assert!(!result.replaces_members);

        let result = apply_group_patch(&[remove("a"), add("a")]).unwrap();
        assert_eq!(result.add_members, vec!["a"]);
        assert!(result.remove_members.is_empty());
    }

    /// The other member operations directory clients send: a removal that
    /// lists members in a value array (a `$ref` of null included) removes
    /// those and nobody else, an empty array nobody; a removal of `members`
    /// with no value, and a replacement of `members`, set the caller's whole
    /// list, later operations building on it.
    #[test]
    fn test_group_patch_lists_and_whole_set() {
        let op = |op: &str, path: &str, value: &str| proto::ScimPatchOp {
            op: op.into(),
            path: path.into(),
            value: value.into(),
        };
        let listed = apply_group_patch(&[op(
            "remove",
            "members",
            r#"[{"value":"a","$ref":null},{"value":"b"}]"#,
        )])
        .unwrap();
        assert_eq!(listed.remove_members, vec!["a", "b"]);
        assert!(!listed.replaces_members);

        let nobody = apply_group_patch(&[op("remove", "members", "[]")]).unwrap();
        assert!(nobody.remove_members.is_empty());
        assert!(!nobody.replaces_members);

        let cleared = apply_group_patch(&[
            op("add", "members", r#"[{"value":"a"}]"#),
            op("remove", "members", ""),
            op("add", "members", r#"[{"value":"b"}]"#),
        ])
        .unwrap();
        assert!(cleared.replaces_members);
        assert_eq!(cleared.add_members, vec!["b"]);

        let replaced =
            apply_group_patch(&[op("replace", "members", r#"[{"value":"a"},{"value":"b"}]"#)])
                .unwrap();
        assert!(replaced.replaces_members);
        assert_eq!(replaced.add_members, vec!["a", "b"]);
    }

    /// A malformed member value is the client's mistake and fails the
    /// request: it is never read as an omitted value, which for a removal
    /// would clear the whole list.
    #[test]
    fn test_group_patch_malformed_members_are_refused() {
        let op = |op: &str, path: &str, value: &str| proto::ScimPatchOp {
            op: op.into(),
            path: path.into(),
            value: value.into(),
        };
        for bad in [
            op("add", "members", "not json"),
            op("add", "members", r#"[{"display":"no value"}]"#),
            op("remove", "members", "{"),
            op("remove", "members", r#"[{"value":7}]"#),
            op("replace", "members", r#""a string""#),
        ] {
            assert!(
                matches!(
                    apply_group_patch(std::slice::from_ref(&bad)),
                    Err(PatchError::InvalidValue { .. })
                ),
                "{} {}",
                bad.op,
                bad.value
            );
        }
        assert!(matches!(
            apply_group_patch(&[op("remove", "members[value eq ]", "")]),
            Err(PatchError::InvalidPath(_))
        ));
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
        assert_eq!(result.set_metadata[0].0, "employee_id");
        assert_eq!(result.external_id, None, "not the source's identifier");
    }

    /// `externalId` is the asking source's identifier of the user, never an
    /// attribute of the account: it sets no metadata, and an empty value
    /// drops it.
    #[test]
    fn test_replace_external_id_is_the_sources() {
        let mut profile = test_profile();
        let op = |value: &str| proto::ScimPatchOp {
            op: "replace".into(),
            path: "externalId".into(),
            value: value.into(),
        };
        let result = apply_user_patch(&mut profile, &[op("HR-7")]).unwrap();
        assert_eq!(result.external_id, Some(Some("HR-7".into())));
        assert!(result.set_metadata.is_empty());
        let result = apply_user_patch(&mut profile, &[op("")]).unwrap();
        assert_eq!(result.external_id, Some(None));
        let untouched = apply_user_patch(&mut profile, &[]).unwrap();
        assert_eq!(untouched.external_id, None);
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
        assert_eq!(result.set_metadata[0].0, "employee_id");
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
