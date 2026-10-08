// SPDX-License-Identifier: AGPL-3.0-only
//! Auth0 Management API export parser.
//!
//! Parses Auth0 user export JSON (Management API → GET /api/v2/users or bulk export job).
//! Auth0 stores bcrypt hashes. TOTP enrolled via Guardian (not directly exportable).

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// Auth0 JSON export adapter.
pub struct Auth0Adapter;

impl MigrationAdapter for Auth0Adapter {
    fn provider_name(&self) -> &'static str {
        "auth0"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        // Auth0 exports as JSON array of users
        let auth0_users: Vec<Auth0User> = serde_json::from_slice(data)?;
        let users = auth0_users.iter().map(convert_auth0_user).collect();
        Ok(users)
    }
}

fn convert_auth0_user(a0: &Auth0User) -> ImportedUser {
    let (password_hash, hash_algorithm) = extract_password(a0);

    let mut attributes = HashMap::new();
    if let Some(ref meta) = a0.user_metadata {
        for (k, v) in meta {
            if let Some(s) = v.as_str() {
                attributes.insert(k.clone(), s.to_string());
            }
        }
    }

    // Auth0 uses connection-based identities
    let username = a0
        .username
        .clone()
        .or_else(|| a0.nickname.clone())
        .unwrap_or_else(|| a0.email.clone().unwrap_or_default());

    ImportedUser {
        username,
        email: a0.email.clone().unwrap_or_default(),
        email_verified: a0.email_verified.unwrap_or(false),
        display_name: a0.name.clone(),
        first_name: a0.given_name.clone(),
        last_name: a0.family_name.clone(),
        phone: a0.phone_number.clone(),
        enabled: !a0.blocked.unwrap_or(false),
        password_hash,
        hash_algorithm,
        totp_seed: None,   // Auth0 Guardian TOTP not in standard export
        roles: Vec::new(), // Roles come from separate API endpoint
        groups: Vec::new(),
        external_id: a0.user_id.clone(),
        attributes,
    }
}

fn extract_password(a0: &Auth0User) -> (Option<String>, Option<String>) {
    // Auth0 bulk import/export uses identities[].connection = "Username-Password-Authentication"
    // Password hash in custom_password_hash field (if included)
    if let Some(ref identities) = a0.identities {
        for identity in identities {
            if identity.connection.as_deref() == Some("Username-Password-Authentication")
                && let Some(ref profile_data) = identity.profile_data
                && let Some(ref hash) = profile_data.password_hash
            {
                let algo = sid_auth_legacy_detect(hash);
                return (Some(hash.clone()), algo);
            }
        }
    }

    // Direct password_hash field (custom export)
    if let Some(ref hash) = a0.password_hash {
        let algo = sid_auth_legacy_detect(hash);
        return (Some(hash.clone()), algo);
    }

    (None, None)
}

fn sid_auth_legacy_detect(hash: &str) -> Option<String> {
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
        Some("bcrypt".to_string())
    } else if hash.starts_with("$argon2") {
        Some("argon2id".to_string())
    } else if hash.starts_with("$pbkdf2") {
        Some("pbkdf2-sha256".to_string())
    } else {
        None
    }
}

// ── Auth0 JSON schema (subset) ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct Auth0User {
    user_id: String,
    email: Option<String>,
    email_verified: Option<bool>,
    username: Option<String>,
    nickname: Option<String>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    phone_number: Option<String>,
    blocked: Option<bool>,
    identities: Option<Vec<Auth0Identity>>,
    user_metadata: Option<HashMap<String, serde_json::Value>>,
    password_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Auth0Identity {
    connection: Option<String>,
    profile_data: Option<Auth0ProfileData>,
}

#[derive(Debug, Deserialize)]
struct Auth0ProfileData {
    password_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_auth0_json() -> &'static str {
        r#"[
            {
                "user_id": "auth0|abc123",
                "email": "alice@sid.example.com",
                "email_verified": true,
                "username": "alice",
                "name": "Alice Smith",
                "given_name": "Alice",
                "family_name": "Smith",
                "phone_number": "+1234567890",
                "blocked": false,
                "password_hash": "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
            },
            {
                "user_id": "auth0|def456",
                "email": "bob@sid.example.com",
                "email_verified": false,
                "nickname": "bob_the_builder",
                "blocked": true
            }
        ]"#
    }

    #[test]
    fn test_auth0_parse_basic() {
        let adapter = Auth0Adapter;
        let users = adapter.parse(sample_auth0_json().as_bytes()).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_auth0_user_alice() {
        let adapter = Auth0Adapter;
        let users = adapter.parse(sample_auth0_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.email_verified);
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert!(alice.enabled);
        assert_eq!(alice.external_id, "auth0|abc123");
    }

    #[test]
    fn test_auth0_password_hash() {
        let adapter = Auth0Adapter;
        let users = adapter.parse(sample_auth0_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert!(alice.password_hash.is_some());
        assert!(alice.password_hash.as_ref().unwrap().starts_with("$2b$"));
        assert_eq!(alice.hash_algorithm.as_deref(), Some("bcrypt"));
    }

    #[test]
    fn test_auth0_blocked_user() {
        let adapter = Auth0Adapter;
        let users = adapter.parse(sample_auth0_json().as_bytes()).unwrap();
        let bob = &users[1];

        assert_eq!(bob.username, "bob_the_builder"); // falls back to nickname
        assert!(!bob.enabled); // blocked = true → enabled = false
    }

    #[test]
    fn test_auth0_empty_array() {
        let adapter = Auth0Adapter;
        let users = adapter.parse(b"[]").unwrap();
        assert!(users.is_empty());
    }
}
