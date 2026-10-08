// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 (RFC 7643/7644) user resource parser.
//!
//! Parses SCIM User Resource JSON exports (ListResponse or direct JSON array).
//! SCIM does not export password hashes — all users require password-first login
//! (lazy migration via OPAQUE enrollment).

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// SCIM 2.0 JSON export adapter.
pub struct ScimAdapter;

impl MigrationAdapter for ScimAdapter {
    fn provider_name(&self) -> &'static str {
        "scim"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        // Try SCIM ListResponse first (standard paginated response).
        if let Ok(list_response) = serde_json::from_slice::<ScimListResponse>(data)
            && list_response
                .schemas
                .iter()
                .any(|s| s.contains("ListResponse"))
        {
            let users = list_response
                .resources
                .iter()
                .map(convert_scim_user)
                .collect();
            return Ok(users);
        }

        // Fallback: plain JSON array of SCIM User resources.
        let scim_users: Vec<ScimUser> = serde_json::from_slice(data)?;
        let users = scim_users.iter().map(convert_scim_user).collect();
        Ok(users)
    }
}

fn convert_scim_user(scim: &ScimUser) -> ImportedUser {
    let (email, email_verified) = extract_primary_email(scim);
    let phone = extract_primary_phone(scim);
    let display_name = scim
        .display_name
        .clone()
        .or_else(|| scim.name.as_ref().and_then(|n| n.formatted.clone()));
    let (first_name, last_name) = scim
        .name
        .as_ref()
        .map(|n| (n.given_name.clone(), n.family_name.clone()))
        .unwrap_or((None, None));

    let groups = scim
        .groups
        .as_ref()
        .map(|gs| gs.iter().filter_map(|g| g.display.clone()).collect())
        .unwrap_or_default();

    let mut attributes = HashMap::new();
    if let Some(ref ext) = scim.enterprise_extension {
        if let Some(ref dept) = ext.department {
            attributes.insert("department".to_string(), dept.clone());
        }
        if let Some(ref org) = ext.organization {
            attributes.insert("organization".to_string(), org.clone());
        }
        if let Some(ref mgr) = ext.manager {
            if let Some(ref v) = mgr.value {
                attributes.insert("manager_id".to_string(), v.clone());
            }
            if let Some(ref dn) = mgr.display_name {
                attributes.insert("manager_name".to_string(), dn.clone());
            }
        }
    }

    ImportedUser {
        username: scim.user_name.clone(),
        email,
        email_verified,
        display_name,
        first_name,
        last_name,
        phone,
        enabled: scim.active.unwrap_or(true),
        password_hash: None,  // SCIM does not export password hashes
        hash_algorithm: None, // All users require password-first login
        totp_seed: None,      // SCIM does not export TOTP seeds
        roles: Vec::new(),    // SCIM roles are provider-specific extensions
        groups,
        external_id: scim
            .external_id
            .clone()
            .unwrap_or_else(|| scim.id.clone().unwrap_or_default()),
        attributes,
    }
}

fn extract_primary_email(scim: &ScimUser) -> (String, bool) {
    if let Some(ref emails) = scim.emails {
        // Prefer primary email.
        if let Some(primary) = emails.iter().find(|e| e.primary.unwrap_or(false)) {
            return (
                primary.value.clone().unwrap_or_default(),
                primary.verified.unwrap_or(false),
            );
        }
        // Fallback to first email.
        if let Some(first) = emails.first() {
            return (
                first.value.clone().unwrap_or_default(),
                first.verified.unwrap_or(false),
            );
        }
    }
    (String::new(), false)
}

fn extract_primary_phone(scim: &ScimUser) -> Option<String> {
    scim.phone_numbers.as_ref().and_then(|phones| {
        phones
            .iter()
            .find(|p| p.primary.unwrap_or(false))
            .or(phones.first())
            .and_then(|p| p.value.clone())
    })
}

// ── SCIM 2.0 JSON schema (RFC 7643) ─────────────────────────────

/// SCIM ListResponse (paginated result set).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimListResponse {
    schemas: Vec<String>,
    #[serde(alias = "Resources")]
    resources: Vec<ScimUser>,
}

/// SCIM User Resource (core schema).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUser {
    id: Option<String>,
    external_id: Option<String>,
    user_name: String,
    display_name: Option<String>,
    name: Option<ScimName>,
    emails: Option<Vec<ScimMultiValue>>,
    phone_numbers: Option<Vec<ScimMultiValue>>,
    groups: Option<Vec<ScimGroupRef>>,
    active: Option<bool>,
    /// Enterprise User extension (RFC 7643 §4.3).
    #[serde(
        alias = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        default
    )]
    enterprise_extension: Option<ScimEnterpriseExtension>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimName {
    formatted: Option<String>,
    family_name: Option<String>,
    given_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimMultiValue {
    value: Option<String>,
    primary: Option<bool>,
    /// Non-standard but used by some providers for email verification.
    #[serde(default)]
    verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupRef {
    display: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimEnterpriseExtension {
    department: Option<String>,
    organization: Option<String>,
    manager: Option<ScimManager>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimManager {
    value: Option<String>,
    #[serde(alias = "displayName")]
    display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scim_list_response() -> &'static str {
        r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
                {
                    "id": "2819c223-7f76-453a-919d-413861904646",
                    "userName": "alice",
                    "displayName": "Alice Smith",
                    "name": {
                        "formatted": "Alice Smith",
                        "familyName": "Smith",
                        "givenName": "Alice"
                    },
                    "emails": [
                        {"value": "alice@sid.example.com", "primary": true, "verified": true},
                        {"value": "alice.work@sid.example.com", "primary": false}
                    ],
                    "phoneNumbers": [
                        {"value": "+12125551234", "primary": true}
                    ],
                    "groups": [
                        {"display": "Engineering"},
                        {"display": "DevOps"}
                    ],
                    "active": true,
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "department": "Engineering",
                        "organization": "StructuredID",
                        "manager": {
                            "value": "manager-uuid-123",
                            "displayName": "Bob Manager"
                        }
                    }
                },
                {
                    "id": "2819c223-7f76-453a-919d-413861904647",
                    "userName": "charlie",
                    "emails": [
                        {"value": "charlie@sid.example.com"}
                    ],
                    "active": false
                }
            ]
        }"#
    }

    fn sample_scim_array() -> &'static str {
        r#"[
            {
                "id": "user-001",
                "externalId": "ext-001",
                "userName": "dave",
                "displayName": "Dave Jones",
                "emails": [{"value": "dave@sid.example.com", "primary": true}],
                "active": true
            }
        ]"#
    }

    #[test]
    fn test_scim_parse_list_response() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_scim_parse_array() {
        let adapter = ScimAdapter;
        let users = adapter.parse(sample_scim_array().as_bytes()).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "dave");
        assert_eq!(users[0].external_id, "ext-001");
    }

    #[test]
    fn test_scim_user_alice() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.email_verified);
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(alice.first_name.as_deref(), Some("Alice"));
        assert_eq!(alice.last_name.as_deref(), Some("Smith"));
        assert_eq!(alice.phone.as_deref(), Some("+12125551234"));
        assert!(alice.enabled);
        assert_eq!(alice.external_id, "2819c223-7f76-453a-919d-413861904646");
        assert_eq!(alice.groups, vec!["Engineering", "DevOps"]);
    }

    #[test]
    fn test_scim_no_password_hash() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        let alice = &users[0];

        assert!(alice.password_hash.is_none());
        assert!(alice.hash_algorithm.is_none());
        assert!(alice.totp_seed.is_none());
    }

    #[test]
    fn test_scim_enterprise_extension() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        let alice = &users[0];

        assert_eq!(alice.attributes.get("department").unwrap(), "Engineering");
        assert_eq!(
            alice.attributes.get("organization").unwrap(),
            "StructuredID"
        );
        assert_eq!(
            alice.attributes.get("manager_id").unwrap(),
            "manager-uuid-123"
        );
        assert_eq!(alice.attributes.get("manager_name").unwrap(), "Bob Manager");
    }

    #[test]
    fn test_scim_inactive_user() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        let charlie = &users[1];

        assert_eq!(charlie.username, "charlie");
        assert!(!charlie.enabled);
        assert_eq!(charlie.email, "charlie@sid.example.com");
        assert!(!charlie.email_verified); // no verified field
    }

    #[test]
    fn test_scim_empty_array() {
        let adapter = ScimAdapter;
        let users = adapter.parse(b"[]").unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn test_scim_external_id_fallback_to_id() {
        let adapter = ScimAdapter;
        let users = adapter
            .parse(sample_scim_list_response().as_bytes())
            .unwrap();
        // Alice has no externalId → falls back to id
        assert_eq!(users[0].external_id, "2819c223-7f76-453a-919d-413861904646");
    }
}
