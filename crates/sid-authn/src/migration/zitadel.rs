// SPDX-License-Identifier: AGPL-3.0-only
//! Zitadel gRPC export parser.
//!
//! Parses Zitadel user export JSON (exported via Management API or Admin API).
//! Zitadel uses bcrypt or argon2id for password hashes.

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// Zitadel JSON export adapter.
pub struct ZitadelAdapter;

impl MigrationAdapter for ZitadelAdapter {
    fn provider_name(&self) -> &'static str {
        "zitadel"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        // Try array format first, then single-result wrapper
        if let Ok(users) = serde_json::from_slice::<Vec<ZitadelUser>>(data) {
            return Ok(users.iter().map(convert_zitadel_user).collect());
        }

        let wrapper: ZitadelListResponse = serde_json::from_slice(data)?;
        let users = wrapper
            .result
            .unwrap_or_default()
            .iter()
            .map(convert_zitadel_user)
            .collect();
        Ok(users)
    }
}

fn convert_zitadel_user(z: &ZitadelUser) -> ImportedUser {
    let human = z.human.as_ref();

    let (first_name, last_name) = human
        .and_then(|h| h.profile.as_ref())
        .map(|p| (p.first_name.clone(), p.last_name.clone()))
        .unwrap_or((None, None));

    let email = human
        .and_then(|h| h.email.as_ref())
        .and_then(|e| e.email.clone())
        .unwrap_or_default();

    let email_verified = human
        .and_then(|h| h.email.as_ref())
        .and_then(|e| e.is_email_verified)
        .unwrap_or(false);

    let phone = human
        .and_then(|h| h.phone.as_ref())
        .and_then(|p| p.phone.clone());

    let display_name = human
        .and_then(|h| h.profile.as_ref())
        .and_then(|p| p.display_name.clone())
        .or_else(|| build_display_name(first_name.as_deref(), last_name.as_deref()));

    let (password_hash, hash_algorithm) = human
        .and_then(|h| h.hashed_password.as_ref())
        .map(|hp| {
            let algo = detect_hash_algorithm(&hp.value);
            (Some(hp.value.clone()), algo)
        })
        .unwrap_or((None, None));

    ImportedUser {
        username: z
            .user_name
            .clone()
            .unwrap_or_else(|| z.preferred_login_name.clone().unwrap_or_default()),
        email,
        email_verified,
        display_name,
        first_name,
        last_name,
        phone,
        enabled: z.state.as_deref() == Some("USER_STATE_ACTIVE"),
        password_hash,
        hash_algorithm,
        totp_seed: None, // Zitadel TOTP via separate API
        roles: Vec::new(),
        groups: Vec::new(),
        external_id: z.id.clone().unwrap_or_default(),
        attributes: HashMap::new(),
    }
}

fn detect_hash_algorithm(hash: &str) -> Option<String> {
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

fn build_display_name(first: Option<&str>, last: Option<&str>) -> Option<String> {
    match (first, last) {
        (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
        (Some(f), None) => Some(f.to_string()),
        (None, Some(l)) => Some(l.to_string()),
        (None, None) => None,
    }
}

// ── Zitadel JSON schema (subset) ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZitadelListResponse {
    result: Option<Vec<ZitadelUser>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZitadelUser {
    id: Option<String>,
    state: Option<String>,
    user_name: Option<String>,
    preferred_login_name: Option<String>,
    human: Option<ZitadelHuman>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZitadelHuman {
    profile: Option<ZitadelProfile>,
    email: Option<ZitadelEmail>,
    phone: Option<ZitadelPhone>,
    hashed_password: Option<ZitadelHashedPassword>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZitadelProfile {
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZitadelEmail {
    email: Option<String>,
    is_email_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ZitadelPhone {
    phone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZitadelHashedPassword {
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zitadel_json() -> &'static str {
        r#"{
            "result": [
                {
                    "id": "z-user-001",
                    "state": "USER_STATE_ACTIVE",
                    "userName": "alice",
                    "human": {
                        "profile": {
                            "firstName": "Alice",
                            "lastName": "Smith",
                            "displayName": "Alice Smith"
                        },
                        "email": {
                            "email": "alice@sid.example.com",
                            "isEmailVerified": true
                        },
                        "phone": {
                            "phone": "+1234567890"
                        },
                        "hashedPassword": {
                            "value": "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
                        }
                    }
                }
            ]
        }"#
    }

    #[test]
    fn test_zitadel_parse_wrapper() {
        let adapter = ZitadelAdapter;
        let users = adapter.parse(sample_zitadel_json().as_bytes()).unwrap();
        assert_eq!(users.len(), 1);
    }

    #[test]
    fn test_zitadel_user_alice() {
        let adapter = ZitadelAdapter;
        let users = adapter.parse(sample_zitadel_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.email_verified);
        assert!(alice.enabled);
        assert_eq!(alice.hash_algorithm.as_deref(), Some("bcrypt"));
    }

    #[test]
    fn test_zitadel_parse_array() {
        let json = r#"[{"id": "z-1", "state": "USER_STATE_ACTIVE", "userName": "test"}]"#;
        let adapter = ZitadelAdapter;
        let users = adapter.parse(json.as_bytes()).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "test");
    }
}
