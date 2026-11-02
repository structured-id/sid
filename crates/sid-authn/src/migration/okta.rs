// SPDX-License-Identifier: AGPL-3.0-only
//! Okta Users API export parser.
//!
//! Parses Okta user export JSON (Users API → GET /api/v1/users).
//! Okta uses bcrypt for password hashes. TOTP factors from Factors API.

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// Okta JSON export adapter.
pub struct OktaAdapter;

impl MigrationAdapter for OktaAdapter {
    fn provider_name(&self) -> &'static str {
        "okta"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        let okta_users: Vec<OktaUser> = serde_json::from_slice(data)?;
        let users = okta_users.iter().map(convert_okta_user).collect();
        Ok(users)
    }
}

fn convert_okta_user(okta: &OktaUser) -> ImportedUser {
    let profile = &okta.profile;

    let (password_hash, hash_algorithm) = okta
        .credentials
        .as_ref()
        .and_then(|c| c.password.as_ref())
        .and_then(|p| p.hash.as_ref())
        .map(|h| {
            let algo = h.algorithm.clone().unwrap_or_default().to_lowercase();
            let hash_str = format_okta_hash(&algo, &h.value, h.salt.as_deref(), h.work_factor);
            let normalized_algo = normalize_okta_algo(&algo);
            (Some(hash_str), Some(normalized_algo))
        })
        .unwrap_or((None, None));

    let mut attributes = HashMap::new();
    if let Some(ref dept) = profile.department {
        attributes.insert("department".to_string(), dept.clone());
    }
    if let Some(ref title) = profile.title {
        attributes.insert("title".to_string(), title.clone());
    }

    // Okta uses login as primary identifier
    let username = profile
        .login
        .clone()
        .unwrap_or_else(|| profile.email.clone().unwrap_or_default());

    ImportedUser {
        username,
        email: profile.email.clone().unwrap_or_default(),
        email_verified: true, // Okta requires email verification by default
        display_name: build_display_name(
            profile.first_name.as_deref(),
            profile.last_name.as_deref(),
        ),
        first_name: profile.first_name.clone(),
        last_name: profile.last_name.clone(),
        phone: profile
            .mobile_phone
            .clone()
            .or(profile.primary_phone.clone()),
        enabled: okta.status.as_deref() == Some("ACTIVE"),
        password_hash,
        hash_algorithm,
        totp_seed: None,   // TOTP comes from separate Factors API export
        roles: Vec::new(), // Roles come from separate Groups API
        groups: Vec::new(),
        external_id: okta.id.clone(),
        attributes,
    }
}

fn format_okta_hash(
    algo: &str,
    value: &str,
    salt: Option<&str>,
    _work_factor: Option<u32>,
) -> String {
    // Okta exports hashes in their own format; we reconstruct PHC when possible
    match algo {
        "bcrypt" => {
            // Okta bcrypt: value is the full bcrypt hash string
            value.to_string()
        }
        _ => {
            // For other algorithms, store as-is with metadata
            if let Some(s) = salt {
                format!("okta:{}:{}:{}", algo, s, value)
            } else {
                format!("okta:{}:{}", algo, value)
            }
        }
    }
}

fn normalize_okta_algo(algo: &str) -> String {
    match algo {
        "bcrypt" => "bcrypt".to_string(),
        "sha-256" | "sha256" => "sha-256".to_string(),
        "sha-512" | "sha512" => "sha-512".to_string(),
        "sha-1" | "sha1" => "sha-1".to_string(),
        "md5" => "md5".to_string(),
        other => other.to_string(),
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

// ── Okta JSON schema (subset) ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct OktaUser {
    id: String,
    status: Option<String>,
    profile: OktaProfile,
    credentials: Option<OktaCredentials>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaProfile {
    login: Option<String>,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    mobile_phone: Option<String>,
    primary_phone: Option<String>,
    department: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaCredentials {
    password: Option<OktaPassword>,
}

#[derive(Debug, Deserialize)]
struct OktaPassword {
    hash: Option<OktaHash>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaHash {
    algorithm: Option<String>,
    value: String,
    salt: Option<String>,
    work_factor: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_okta_json() -> &'static str {
        r#"[
            {
                "id": "00u1abcdef",
                "status": "ACTIVE",
                "profile": {
                    "login": "alice@sid.example.com",
                    "email": "alice@sid.example.com",
                    "firstName": "Alice",
                    "lastName": "Smith",
                    "mobilePhone": "+1234567890",
                    "department": "Engineering"
                },
                "credentials": {
                    "password": {
                        "hash": {
                            "algorithm": "BCRYPT",
                            "value": "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
                        }
                    }
                }
            },
            {
                "id": "00u2ghijkl",
                "status": "SUSPENDED",
                "profile": {
                    "login": "bob@sid.example.com",
                    "email": "bob@sid.example.com",
                    "firstName": "Bob",
                    "lastName": "Jones"
                }
            }
        ]"#
    }

    #[test]
    fn test_okta_parse_basic() {
        let adapter = OktaAdapter;
        let users = adapter.parse(sample_okta_json().as_bytes()).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_okta_user_alice() {
        let adapter = OktaAdapter;
        let users = adapter.parse(sample_okta_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice@sid.example.com");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.enabled);
        assert_eq!(alice.phone.as_deref(), Some("+1234567890"));
        assert_eq!(alice.hash_algorithm.as_deref(), Some("bcrypt"));
    }

    #[test]
    fn test_okta_suspended_user() {
        let adapter = OktaAdapter;
        let users = adapter.parse(sample_okta_json().as_bytes()).unwrap();
        let bob = &users[1];

        assert!(!bob.enabled); // SUSPENDED ≠ ACTIVE
        assert!(bob.password_hash.is_none());
    }
}
