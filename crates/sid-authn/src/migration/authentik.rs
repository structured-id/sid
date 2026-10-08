// SPDX-License-Identifier: AGPL-3.0-only
//! Authentik API export parser.
//!
//! Parses Authentik user export JSON (Core API → GET /api/v3/core/users/).
//! Authentik uses argon2id or pbkdf2-sha256 (Django-based).

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// Authentik JSON export adapter.
pub struct AuthentikAdapter;

impl MigrationAdapter for AuthentikAdapter {
    fn provider_name(&self) -> &'static str {
        "authentik"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        // Try paginated response first, then plain array
        if let Ok(paginated) = serde_json::from_slice::<AuthentikPaginatedResponse>(data) {
            return Ok(paginated
                .results
                .iter()
                .map(convert_authentik_user)
                .collect());
        }

        let users: Vec<AuthentikUser> = serde_json::from_slice(data)?;
        Ok(users.iter().map(convert_authentik_user).collect())
    }
}

fn convert_authentik_user(ak: &AuthentikUser) -> ImportedUser {
    let (password_hash, hash_algorithm) = ak
        .password
        .as_ref()
        .filter(|p| !p.starts_with("!")) // Authentik uses "!" prefix for unusable passwords
        .map(|p| {
            let algo = detect_django_hash_algorithm(p);
            (Some(p.clone()), algo)
        })
        .unwrap_or((None, None));

    let mut attributes = HashMap::new();
    if let Some(ref attrs) = ak.attributes {
        for (k, v) in attrs {
            if let Some(s) = v.as_str() {
                attributes.insert(k.clone(), s.to_string());
            }
        }
    }

    let groups = ak
        .groups_obj
        .as_ref()
        .map(|gs| gs.iter().filter_map(|g| g.name.clone()).collect())
        .unwrap_or_default();

    ImportedUser {
        username: ak.username.clone(),
        email: ak.email.clone().unwrap_or_default(),
        email_verified: true, // Authentik doesn't expose this in standard API
        display_name: ak.name.clone(),
        first_name: None,
        last_name: None,
        phone: attributes.get("phone").cloned(),
        enabled: ak.is_active.unwrap_or(true),
        password_hash,
        hash_algorithm,
        totp_seed: None, // TOTP via separate authenticator API
        roles: Vec::new(),
        groups,
        external_id: ak.pk.map(|pk| pk.to_string()).unwrap_or_default(),
        attributes,
    }
}

fn detect_django_hash_algorithm(hash: &str) -> Option<String> {
    // Django/Authentik format: algorithm$iterations$salt$hash
    // or PHC format: $argon2id$...
    if hash.starts_with("$argon2") {
        Some("argon2id".to_string())
    } else if hash.starts_with("pbkdf2_sha256$") {
        Some("pbkdf2-sha256".to_string())
    } else if hash.starts_with("pbkdf2_sha1$") {
        Some("pbkdf2-sha1".to_string())
    } else if hash.starts_with("bcrypt") || hash.starts_with("$2") {
        Some("bcrypt".to_string())
    } else {
        None
    }
}

// ── Authentik JSON schema (subset) ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct AuthentikPaginatedResponse {
    results: Vec<AuthentikUser>,
}

#[derive(Debug, Deserialize)]
struct AuthentikUser {
    pk: Option<u64>,
    username: String,
    name: Option<String>,
    email: Option<String>,
    is_active: Option<bool>,
    password: Option<String>,
    groups_obj: Option<Vec<AuthentikGroup>>,
    attributes: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct AuthentikGroup {
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_authentik_json() -> &'static str {
        r#"{
            "pagination": {"count": 2},
            "results": [
                {
                    "pk": 1,
                    "username": "alice",
                    "name": "Alice Smith",
                    "email": "alice@sid.example.com",
                    "is_active": true,
                    "password": "$argon2id$v=19$m=65536,t=3,p=4$abc123$defghijklmnopqrs",
                    "groups_obj": [
                        {"name": "engineering"},
                        {"name": "admins"}
                    ]
                },
                {
                    "pk": 2,
                    "username": "bob",
                    "email": "bob@sid.example.com",
                    "is_active": false,
                    "password": "!unusable"
                }
            ]
        }"#
    }

    #[test]
    fn test_authentik_parse_paginated() {
        let adapter = AuthentikAdapter;
        let users = adapter.parse(sample_authentik_json().as_bytes()).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_authentik_user_alice() {
        let adapter = AuthentikAdapter;
        let users = adapter.parse(sample_authentik_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.enabled);
        assert_eq!(alice.hash_algorithm.as_deref(), Some("argon2id"));
        assert_eq!(alice.groups, vec!["engineering", "admins"]);
    }

    #[test]
    fn test_authentik_unusable_password() {
        let adapter = AuthentikAdapter;
        let users = adapter.parse(sample_authentik_json().as_bytes()).unwrap();
        let bob = &users[1];

        assert!(bob.password_hash.is_none()); // "!" prefix = unusable
        assert!(!bob.enabled);
    }

    #[test]
    fn test_authentik_plain_array() {
        let json = r#"[{"pk": 1, "username": "test"}]"#;
        let adapter = AuthentikAdapter;
        let users = adapter.parse(json.as_bytes()).unwrap();
        assert_eq!(users.len(), 1);
    }
}
