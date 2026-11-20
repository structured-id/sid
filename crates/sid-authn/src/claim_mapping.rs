// SPDX-License-Identifier: AGPL-3.0-only
//! Claim mapping resolution engine.
//!
//! Resolves static YAML claim mappings against profile data,
//! applying built-in transforms and scope-based conditions.

use sid_core::models::claim_mapping::{ClaimMapping, ClaimTransform};
use sid_core::models::consent::{ClaimGrant, ClaimType};
use sid_core::models::profile::Profile;
use sid_core::models::profile_metadata::ProfileMetadata;
use std::collections::HashMap;

/// Resolve all claim mappings into a map of claim name → JSON value.
///
/// A holder-disclosed field (names, username, email, phone) comes only from
/// `disclosed`, the active grants of the holder's consent to this client
/// with their approved values: a mapping, whatever its target name or
/// transform, cannot take it from the current Profile after a refusal or an
/// edit (token-claims-hooks.md, additive enrichment and protected token
/// fields). Organization attributes and literals map as configured.
///
/// Mappings that fail to resolve (unknown source, transform error) are
/// silently skipped — never fail token issuance due to mapping config.
pub fn resolve_claims(
    mappings: &[ClaimMapping],
    profile: &Profile,
    metadata: &[ProfileMetadata],
    scopes: &[String],
    disclosed: &[ClaimGrant],
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
        if let Some(value) = resolve_source(&mapping.source, profile, metadata, disclosed) {
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
    disclosed: &[ClaimGrant],
) -> Option<serde_json::Value> {
    // The approved disclosure of claim `name`: its value only for a data
    // grant, its verification for any.
    let grant = |name: &str| {
        disclosed
            .iter()
            .find(|g| g.is_active() && g.claim_name == name)
            .and_then(|g| g.disclosed.as_ref().map(|d| (g.claim_type, d)))
    };
    let value = |name: &str| {
        grant(name)
            .filter(|(kind, _)| *kind == ClaimType::Data)
            .map(|(_, d)| serde_json::json!(&d.value))
    };
    let verified =
        |name: &str| grant(name).and_then(|(_, d)| d.verified.map(|v| serde_json::json!(v)));
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
            // Holder-disclosed fields: the approved values only.
            "email" => value("email"),
            "email_verified" => verified("email"),
            "phone" | "phone_number" => value("phone_number"),
            "phone_verified" | "phone_number_verified" => verified("phone_number"),
            "username" => value("preferred_username"),
            "display_name" | "name" => value("name"),
            "given_name" => value("given_name"),
            "family_name" => value("family_name"),
            "middle_name" => value("middle_name"),
            // Authorization fields of this installation.
            "roles" => Some(serde_json::json!(&profile.roles)),
            "status" => Some(serde_json::json!(profile.status.as_str())),
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

    /// Test helper: resolve_claims with the holder's approved disclosure of
    /// [`approved`].
    fn resolve_test(
        mappings: &[ClaimMapping],
        profile: &Profile,
        metadata: &[ProfileMetadata],
        scopes: &[String],
    ) -> std::collections::HashMap<String, serde_json::Value> {
        resolve_claims(mappings, profile, metadata, scopes, &approved())
    }

    /// A grant of `name` with its approved `value`.
    fn grant(name: &str, value: &str, verified: Option<bool>) -> ClaimGrant {
        let mut grant = ClaimGrant::new(
            sid_core::models::ConsentId::new(),
            name,
            ClaimType::Data,
            sid_core::models::ConsentMode::Static,
        );
        grant.disclosed = Some(sid_core::models::DisclosedValue {
            value: value.into(),
            verified,
        });
        grant
    }

    /// The holder shared these values with the client: a verified email,
    /// the username and the names.
    fn approved() -> Vec<ClaimGrant> {
        vec![
            grant("email", "alice@sid.example.com", Some(true)),
            grant("preferred_username", "alice@sid.example.com", None),
            grant("name", "Alice Smith", None),
            grant("given_name", "Alice", None),
            grant("family_name", "Smith", None),
        ]
    }

    /// A holder-disclosed field mapped under any name or transform comes
    /// only from the approved disclosure: not shared, or shared with an
    /// older value, the mapping yields nothing or the approved value, never
    /// the current Profile (token-claims-hooks.md, additive enrichment).
    #[test]
    fn a_mapping_cannot_take_a_holder_field_from_the_profile() {
        let mapping = |source: &str, target: &str| ClaimMapping {
            source: source.to_string(),
            target: target.to_string(),
            transform: Some(ClaimTransform::Uppercase),
            condition: None,
        };
        let mappings = [
            mapping("profile.email", "mail"),
            mapping("profile.given_name", "first"),
        ];
        let mut profile = test_profile();
        profile.given_name = Some("Alicia".into());

        let refused = resolve_claims(&mappings, &profile, &[], &[], &[]);
        assert!(refused.is_empty(), "{refused:?}");

        let approved = resolve_claims(&mappings, &profile, &[], &[], &approved());
        assert_eq!(approved.get("mail").unwrap(), "ALICE@SID.EXAMPLE.COM");
        assert_eq!(approved.get("first").unwrap(), "ALICE");
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
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.email_verified".to_string(),
                target: "email_verified".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert_eq!(claims.get("email_verified").unwrap(), true);
    }

    #[test]
    fn test_resolve_profile_email_verified_absent_without_email() {
        // The email not shared → email_verified absent
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
            &[],
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn test_resolve_profile_phone() {
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
            &[grant("phone_number", "+380501234567", Some(true))],
        );
        assert_eq!(claims.get("phone_number").unwrap(), "+380501234567");
        assert_eq!(claims.get("phone_number_verified").unwrap(), true);
    }

    #[test]
    fn test_resolve_profile_phone_verified_absent_without_phone() {
        // The phone not shared → phone_number_verified absent
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
            &[],
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

    /// The live Profile's update time is not mapped: it is no approved value
    /// and would reveal an edit the holder did not disclose.
    #[test]
    fn test_resolve_profile_updated_at_is_not_mapped() {
        let claims = resolve_test(
            &[ClaimMapping {
                source: "profile.updated_at".to_string(),
                target: "updated_at".to_string(),
                transform: None,
                condition: None,
            }],
            &test_profile(),
            &[],
            &[],
        );
        assert!(claims.is_empty());
    }
}
