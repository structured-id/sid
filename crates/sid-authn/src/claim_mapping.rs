// SPDX-License-Identifier: AGPL-3.0-only
//! Claim mapping resolution engine.
//!
//! Resolves static YAML claim mappings against profile data,
//! applying built-in transforms and scope-based conditions.

use sid_core::models::claim_mapping::{ClaimMapping, ClaimTransform};
use sid_core::models::profile::Profile;
use sid_core::models::profile_email::ProfileEmail;
use sid_core::models::profile_metadata::ProfileMetadata;
use sid_core::models::profile_phone::ProfilePhone;
use std::collections::HashMap;

/// Resolve all claim mappings into a map of claim name → JSON value.
///
/// Mappings that fail to resolve (unknown source, transform error) are
/// silently skipped — never fail token issuance due to mapping config.
pub fn resolve_claims(
    mappings: &[ClaimMapping],
    profile: &Profile,
    metadata: &[ProfileMetadata],
    scopes: &[String],
    primary_email: Option<&ProfileEmail>,
    primary_phone: Option<&ProfilePhone>,
) -> HashMap<String, serde_json::Value> {
    let mut claims = HashMap::new();

    for mapping in mappings {
        // Check condition
        if let Some(ref condition) = mapping.condition
            && !evaluate_condition(condition, scopes)
        {
            continue;
        }

        // Resolve source value
        if let Some(value) = resolve_source(
            &mapping.source,
            profile,
            metadata,
            primary_email,
            primary_phone,
        ) {
            // Apply transform
            let transformed = match &mapping.transform {
                Some(t) => apply_transform(t, value),
                None => value,
            };
            claims.insert(mapping.target.clone(), transformed);
        }
    }

    claims
}

/// Evaluate a condition string against current scopes.
///
/// Supported conditions:
/// - `scope:NAME` — true if NAME is in the scopes list
fn evaluate_condition(condition: &str, scopes: &[String]) -> bool {
    if let Some(scope_name) = condition.strip_prefix("scope:") {
        scopes.iter().any(|s| s == scope_name)
    } else {
        // Unknown condition format → skip (fail closed)
        false
    }
}

/// Resolve a source path to a JSON value.
///
/// Supported paths:
/// - `profile.email` → profile email
/// - `profile.username` → profile username
/// - `profile.display_name` → computed formatted name (from given/family/middle name components)
/// - `profile.roles` → profile roles as JSON array
/// - `profile.status` → profile status as string
/// - `profile.metadata.KEY` → ProfileMetadata lookup by key
/// - `literal(VALUE)` → static string value
fn resolve_source(
    source: &str,
    profile: &Profile,
    metadata: &[ProfileMetadata],
    primary_email: Option<&ProfileEmail>,
    primary_phone: Option<&ProfilePhone>,
) -> Option<serde_json::Value> {
    // literal(VALUE)
    if let Some(value) = source
        .strip_prefix("literal(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return Some(serde_json::Value::String(value.to_string()));
    }

    // profile.metadata.KEY
    if let Some(key) = source.strip_prefix("profile.metadata.") {
        return metadata
            .iter()
            .find(|m| m.key == key)
            .map(|m| m.value.clone());
    }

    // profile.FIELD
    if let Some(field) = source.strip_prefix("profile.") {
        return match field {
            // Contact fields (from profile_emails / profile_phones)
            "email" => primary_email.map(|e| serde_json::json!(&e.email)),
            "email_verified" => primary_email.map(|e| serde_json::json!(e.verified)),
            "phone" | "phone_number" => {
                primary_phone.map(|p| serde_json::json!(p.formatted_e164()))
            }
            "phone_verified" | "phone_number_verified" => {
                primary_phone.map(|p| serde_json::json!(p.verified))
            }
            // Identity fields
            "username" => Some(serde_json::json!(&profile.username)),
            "display_name" | "name" => profile.formatted_name().map(|d| serde_json::json!(d)),
            "given_name" => profile.given_name.as_ref().map(|v| serde_json::json!(v)),
            "family_name" => profile.family_name.as_ref().map(|v| serde_json::json!(v)),
            "middle_name" => profile.middle_name.as_ref().map(|v| serde_json::json!(v)),
            // Authorization fields
            "roles" => Some(serde_json::json!(&profile.roles)),
            "status" => Some(serde_json::json!(profile.status.as_str())),
            // Temporal fields
            "updated_at" => Some(serde_json::json!(profile.updated_at.timestamp())),
            _ => None, // Unknown field → skip
        };
    }

    None
}

/// Apply a built-in transform to a JSON value.
fn apply_transform(transform: &ClaimTransform, value: serde_json::Value) -> serde_json::Value {
    match transform {
        ClaimTransform::Uppercase => match value {
            serde_json::Value::String(s) => serde_json::Value::String(s.to_uppercase()),
            other => other,
        },
        ClaimTransform::Lowercase => match value {
            serde_json::Value::String(s) => serde_json::Value::String(s.to_lowercase()),
            other => other,
        },
        ClaimTransform::Prefix(prefix) => match value {
            serde_json::Value::String(s) => serde_json::Value::String(format!("{}{}", prefix, s)),
            other => other,
        },
        ClaimTransform::Join(separator) => match value {
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                serde_json::Value::String(parts.join(separator))
            }
            other => other,
        },
        ClaimTransform::NamesOnly => match value {
            serde_json::Value::Array(arr) => {
                let names: Vec<serde_json::Value> =
                    arr.iter().filter_map(|v| v.get("name").cloned()).collect();
                serde_json::Value::Array(names)
            }
            other => other,
        },
        ClaimTransform::IdsOnly => match value {
            serde_json::Value::Array(arr) => {
                let ids: Vec<serde_json::Value> =
                    arr.iter().filter_map(|v| v.get("id").cloned()).collect();
                serde_json::Value::Array(ids)
            }
            other => other,
        },
        ClaimTransform::Flatten => match value {
            serde_json::Value::Array(arr) => {
                let mut flat = Vec::new();
                for item in arr {
                    if let serde_json::Value::Array(inner) = item {
                        flat.extend(inner);
                    } else {
                        flat.push(item);
                    }
                }
                serde_json::Value::Array(flat)
            }
            other => other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::ProfileId;

    fn test_profile() -> Profile {
        let mut p = Profile::new(Some("alice@sid.example.com"));
        p.given_name = Some("Alice".to_string());
        p.family_name = Some("Smith".to_string());
        p.roles = vec!["admin".to_string(), "user".to_string()];
        p
    }

    /// Test helper — wraps resolve_claims with default primary contacts
    fn resolve_test(
        mappings: &[ClaimMapping],
        profile: &Profile,
        metadata: &[ProfileMetadata],
        scopes: &[String],
    ) -> std::collections::HashMap<String, serde_json::Value> {
        let email = test_primary_email();
        resolve_claims(mappings, profile, metadata, scopes, Some(&email), None)
    }

    fn test_primary_email() -> ProfileEmail {
        ProfileEmail {
            id: sid_core::models::ProfileEmailId::new(),
            profile_id: ProfileId::generate(),
            email: "alice@sid.example.com".to_string(),
            label: sid_core::models::EmailLabel::Personal,
            custom_label: None,
            is_primary: true,
            verified: true,
            verified_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn test_metadata() -> Vec<ProfileMetadata> {
        vec![
            ProfileMetadata::new(
                ProfileId::generate(),
                "department",
                serde_json::json!("engineering"),
            ),
            ProfileMetadata::new(
                ProfileId::generate(),
                "employee_id",
                serde_json::json!("EMP-42"),
            ),
            ProfileMetadata::new(
                ProfileId::generate(),
                "groups",
                serde_json::json!([
                    {"id": "g1", "name": "engineering"},
                    {"id": "g2", "name": "devops"}
                ]),
            ),
        ]
    }

    // ── Source resolution ──

    #[test]
    fn test_resolve_profile_email() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.email".to_string(),
                target: "email".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("email").unwrap(), "alice@sid.example.com");
    }

    #[test]
    fn test_resolve_profile_username() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.username".to_string(),
                target: "preferred_username".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert!(claims.contains_key("preferred_username"));
    }

    #[test]
    fn test_resolve_profile_roles() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.roles".to_string(),
                target: "roles".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        let roles = claims.get("roles").unwrap().as_array().unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0], "admin");
    }

    #[test]
    fn test_resolve_profile_metadata() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.department".to_string(),
                target: "dept".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &test_metadata(),
            &[],
        );
        assert_eq!(claims.get("dept").unwrap(), "engineering");
    }

    #[test]
    fn test_resolve_literal() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "literal(acme-corp)".to_string(),
                target: "org_name".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("org_name").unwrap(), "acme-corp");
    }

    #[test]
    fn test_unknown_source_skipped() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.nonexistent_field".to_string(),
                target: "x".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert!(claims.is_empty());
    }

    // ── Transforms ──

    #[test]
    fn test_transform_uppercase() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.department".to_string(),
                target: "dept".to_string(),
                transform: Some(ClaimTransform::Uppercase),
                condition: None,
            }],
            &test_profile(),
            &test_metadata(),
            &[],
        );
        assert_eq!(claims.get("dept").unwrap(), "ENGINEERING");
    }

    #[test]
    fn test_transform_lowercase() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "literal(ENGINEERING)".to_string(),
                target: "dept".to_string(),
                transform: Some(ClaimTransform::Lowercase),
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("dept").unwrap(), "engineering");
    }

    #[test]
    fn test_transform_prefix() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "literal(admin)".to_string(),
                target: "role".to_string(),
                transform: Some(ClaimTransform::Prefix("ROLE_".to_string())),
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("role").unwrap(), "ROLE_admin");
    }

    #[test]
    fn test_transform_join() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.roles".to_string(),
                target: "roles_str".to_string(),
                transform: Some(ClaimTransform::Join(",".to_string())),
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("roles_str").unwrap(), "admin,user");
    }

    #[test]
    fn test_transform_names_only() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.groups".to_string(),
                target: "group_names".to_string(),
                transform: Some(ClaimTransform::NamesOnly),
                condition: None,
            }],
            &test_profile(),
            &test_metadata(),
            &[],
        );
        let names = claims.get("group_names").unwrap().as_array().unwrap();
        assert_eq!(
            names,
            &[
                serde_json::json!("engineering"),
                serde_json::json!("devops")
            ]
        );
    }

    #[test]
    fn test_transform_ids_only() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.groups".to_string(),
                target: "group_ids".to_string(),
                transform: Some(ClaimTransform::IdsOnly),
                condition: None,
            }],
            &test_profile(),
            &test_metadata(),
            &[],
        );
        let ids = claims.get("group_ids").unwrap().as_array().unwrap();
        assert_eq!(ids, &[serde_json::json!("g1"), serde_json::json!("g2")]);
    }

    #[test]
    fn test_transform_flatten() {
        let meta = vec![ProfileMetadata::new(
            ProfileId::generate(),
            "nested",
            serde_json::json!([["a", "b"], ["c"]]),
        )];
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.nested".to_string(),
                target: "flat".to_string(),
                transform: Some(ClaimTransform::Flatten),
                condition: None,
            }],
            &test_profile(),
            &meta,
            &[],
        );
        let flat = claims.get("flat").unwrap().as_array().unwrap();
        assert_eq!(
            flat,
            &[
                serde_json::json!("a"),
                serde_json::json!("b"),
                serde_json::json!("c")
            ]
        );
    }

    // ── Conditions ──

    #[test]
    fn test_condition_scope_match() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.department".to_string(),
                target: "dept".to_string(),
                transform: None,
                condition: Some("scope:hr".to_string()),
            }],
            &test_profile(),
            &test_metadata(),
            &["hr".to_string(), "openid".to_string()],
        );
        assert_eq!(claims.get("dept").unwrap(), "engineering");
    }

    #[test]
    fn test_condition_scope_miss() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.metadata.department".to_string(),
                target: "dept".to_string(),
                transform: None,
                condition: Some("scope:hr".to_string()),
            }],
            &test_profile(),
            &test_metadata(),
            &["openid".to_string()],
        );
        assert!(claims.is_empty());
    }

    // ── Multiple mappings ──

    #[test]
    fn test_multiple_mappings() {
        let mappings = vec![
            ClaimMapping {
                source: "profile.email".to_string(),
                target: "email".to_string(),
                transform: None,
                condition: None,
            },
            ClaimMapping {
                source: "profile.metadata.department".to_string(),
                target: "dept".to_string(),
                transform: Some(ClaimTransform::Uppercase),
                condition: None,
            },
            ClaimMapping {
                source: "literal(acme-corp)".to_string(),
                target: "org".to_string(),
                transform: None,
                condition: None,
            },
        ];
        let claims = resolve_test(&mappings, &test_profile(), &test_metadata(), &[]);
        assert_eq!(claims.len(), 3);
        assert_eq!(claims.get("email").unwrap(), "alice@sid.example.com");
        assert_eq!(claims.get("dept").unwrap(), "ENGINEERING");
        assert_eq!(claims.get("org").unwrap(), "acme-corp");
    }

    #[test]
    fn test_empty_mappings() {
        let claims = resolve_test(&[], &test_profile(), &[], &[]);
        assert!(claims.is_empty());
    }

    // ── Profile Fields: structured name + email_verified + updated_at ──

    #[test]
    fn test_resolve_profile_given_name() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.given_name".to_string(),
                target: "given_name".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("given_name").unwrap(), "Alice");
    }

    #[test]
    fn test_resolve_profile_family_name() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.family_name".to_string(),
                target: "family_name".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("family_name").unwrap(), "Smith");
    }

    #[test]
    fn test_resolve_profile_middle_name_absent() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.middle_name".to_string(),
                target: "middle_name".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        // test_profile() has no middle_name → claim absent
        assert!(claims.is_empty());
    }

    #[test]
    fn test_resolve_profile_email_verified() {
        let email = test_primary_email(); // verified = true
        let claims = resolve_claims(
            &[ClaimMapping {
                source: "profile.email_verified".to_string(),
                target: "email_verified".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
            Some(&email),
            None,
        );
        assert_eq!(claims.get("email_verified").unwrap(), true);
    }

    #[test]
    fn test_resolve_profile_email_verified_absent_without_email() {
        // No primary email → email_verified absent
        let claims = resolve_claims(
            &[ClaimMapping {
                source: "profile.email_verified".to_string(),
                target: "email_verified".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
            None,
            None,
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn test_resolve_profile_phone() {
        use sid_core::models::{PhoneLabel, ProfilePhoneId};
        let phone = ProfilePhone {
            id: ProfilePhoneId::new(),
            profile_id: ProfileId::generate(),
            e164: 380501234567,
            extension: None,
            label: PhoneLabel::Mobile,
            custom_label: None,
            is_primary: true,
            can_receive_sms: true,
            can_receive_fax: false,
            can_receive_voice: true,
            verified: true,
            verified_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let claims = resolve_claims(
            &[
                ClaimMapping {
                    source: "profile.phone_number".to_string(),
                    target: "phone_number".to_string(),
                    transform: None,
                    condition: None,
                },
                ClaimMapping {
                    source: "profile.phone_number_verified".to_string(),
                    target: "phone_number_verified".to_string(),
                    transform: None,
                    condition: None,
                },
            ],
            &test_profile(),
            &[],
            &[],
            None,
            Some(&phone),
        );
        assert_eq!(claims.get("phone_number").unwrap(), "+380501234567");
        assert_eq!(claims.get("phone_number_verified").unwrap(), true);
    }

    #[test]
    fn test_resolve_profile_phone_verified_absent_without_phone() {
        // No primary phone → phone_number_verified absent
        let claims = resolve_claims(
            &[ClaimMapping {
                source: "profile.phone_verified".to_string(),
                target: "phone_number_verified".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
            None,
            None,
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn test_resolve_profile_name_alias() {
        // "profile.name" should work as alias for "profile.display_name"
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.name".to_string(),
                target: "name".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("name").unwrap(), "Alice Smith");
    }

    #[test]
    fn test_resolve_profile_updated_at() {
        let profile = test_profile();
        let expected = profile.updated_at.timestamp();
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.updated_at".to_string(),
                target: "updated_at".to_string(),
                transform: None,
                condition: None,
            }],
            &profile,
            &[],
            &[],
        );
        assert_eq!(claims.get("updated_at").unwrap(), expected);
    }
}
