// SPDX-License-Identifier: AGPL-3.0-only
//! Claim mapping model for static JWT claim configuration.
//!
//! Per-client mapping rules: profile field → JWT claim name,
//! with optional built-in transforms and scope-based conditions.

use serde::{Deserialize, Serialize};

/// A single claim mapping rule: profile field → JWT claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimMapping {
    /// Source path: "profile.email", "profile.metadata.department", "literal(acme-corp)".
    pub source: String,
    /// Target claim name in JWT: "department", "emp_id", "org_name".
    pub target: String,
    /// Optional built-in transform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<ClaimTransform>,
    /// Optional condition: "scope:hr" — only include when scope present.
    #[serde(rename = "when", skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// Built-in transforms for claim values (CE: hardcoded, not pluggable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTransform {
    /// Convert string to UPPERCASE.
    Uppercase,
    /// Convert string to lowercase.
    Lowercase,
    /// Prepend a prefix string (e.g., "ROLE_" + "admin" → "ROLE_admin").
    Prefix(String),
    /// Join array elements with separator (e.g., ["a","b"] + "," → "a,b").
    Join(String),
    /// Extract "name" field from array of objects: [{id,name},...] → [name,...].
    NamesOnly,
    /// Extract "id" field from array of objects: [{id,name},...] → [id,...].
    IdsOnly,
    /// Flatten nested arrays into a single flat list.
    Flatten,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_mapping_serde_roundtrip() {
        let mapping = ClaimMapping {
            source: "profile.email".to_string(),
            target: "email".to_string(),
            transform: None,
            condition: None,
        };
        let json = serde_json::to_string(&mapping).unwrap();
        let parsed: ClaimMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(mapping, parsed);
    }

    #[test]
    fn test_claim_mapping_with_transform() {
        let mapping = ClaimMapping {
            source: "profile.metadata.department".to_string(),
            target: "department".to_string(),
            transform: Some(ClaimTransform::Uppercase),
            condition: Some("scope:hr".to_string()),
        };
        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"when\":\"scope:hr\""));
        let parsed: ClaimMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(mapping, parsed);
    }

    #[test]
    fn test_claim_transform_prefix_serde() {
        let t = ClaimTransform::Prefix("ROLE_".to_string());
        let json = serde_json::to_string(&t).unwrap();
        let parsed: ClaimTransform = serde_json::from_str(&json).unwrap();
        assert_eq!(t, parsed);
    }

    #[test]
    fn test_claim_transform_join_serde() {
        let t = ClaimTransform::Join(",".to_string());
        let json = serde_json::to_string(&t).unwrap();
        let parsed: ClaimTransform = serde_json::from_str(&json).unwrap();
        assert_eq!(t, parsed);
    }

    #[test]
    fn test_skip_none_fields() {
        let mapping = ClaimMapping {
            source: "profile.email".to_string(),
            target: "email".to_string(),
            transform: None,
            condition: None,
        };
        let json = serde_json::to_string(&mapping).unwrap();
        assert!(!json.contains("transform"));
        assert!(!json.contains("when"));
    }

    #[test]
    fn test_vec_claim_mappings_serde() {
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
                condition: Some("scope:hr".to_string()),
            },
            ClaimMapping {
                source: "literal(acme-corp)".to_string(),
                target: "org_name".to_string(),
                transform: None,
                condition: None,
            },
        ];
        let json = serde_json::to_string(&mappings).unwrap();
        let parsed: Vec<ClaimMapping> = serde_json::from_str(&json).unwrap();
        assert_eq!(mappings, parsed);
    }
}
