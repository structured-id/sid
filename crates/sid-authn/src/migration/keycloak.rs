// SPDX-License-Identifier: AGPL-3.0-only
//! Keycloak realm JSON export parser.
//!
//! Parses Keycloak's realm export format (Admin Console → Export → Include users).
//! Handles user profiles, credentials (bcrypt hashes), TOTP, roles, and groups.

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use serde::Deserialize;
use std::collections::HashMap;

/// Keycloak realm JSON adapter.
pub struct KeycloakAdapter;

impl MigrationAdapter for KeycloakAdapter {
    fn provider_name(&self) -> &'static str {
        "keycloak"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        let realm: KeycloakRealm = serde_json::from_slice(data)?;
        let mut users = Vec::new();

        for kc_user in realm.users.unwrap_or_default() {
            let user = convert_keycloak_user(&kc_user, &realm.roles);
            users.push(user);
        }

        Ok(users)
    }
}

fn convert_keycloak_user(kc: &KeycloakUser, _realm_roles: &Option<KeycloakRoles>) -> ImportedUser {
    // Extract password hash from credentials
    let (password_hash, hash_algorithm) = extract_password_hash(&kc.credentials);

    // Extract TOTP seed from credentials
    let totp_seed = extract_totp_seed(&kc.credentials);

    // Extract roles
    let mut roles = Vec::new();
    if let Some(ref realm_mappings) = kc.realm_roles {
        roles.extend(realm_mappings.clone());
    }

    // Extract groups
    let groups = kc.groups.clone().unwrap_or_default();

    // Build attributes map
    let mut attributes = HashMap::new();
    if let Some(ref attrs) = kc.attributes {
        for (key, values) in attrs {
            if let Some(first) = values.first() {
                attributes.insert(key.clone(), first.clone());
            }
        }
    }

    ImportedUser {
        username: kc.username.clone(),
        email: kc.email.clone().unwrap_or_default(),
        email_verified: kc.email_verified.unwrap_or(false),
        display_name: build_display_name(kc.first_name.as_deref(), kc.last_name.as_deref()),
        first_name: kc.first_name.clone(),
        last_name: kc.last_name.clone(),
        phone: attributes.get("phoneNumber").cloned(),
        enabled: kc.enabled.unwrap_or(true),
        password_hash,
        hash_algorithm,
        totp_seed,
        roles,
        groups,
        external_id: kc.id.clone(),
        attributes,
    }
}

fn extract_password_hash(
    credentials: &Option<Vec<KeycloakCredential>>,
) -> (Option<String>, Option<String>) {
    let creds = match credentials {
        Some(c) => c,
        None => return (None, None),
    };

    for cred in creds {
        // Keycloak stores password in JSON: {"value":"$hash","salt":"..."}
        if cred.credential_type == "password"
            && let Some(ref secret_data) = cred.secret_data
            && let Ok(secret) = serde_json::from_str::<KeycloakSecretData>(secret_data)
        {
            let algorithm = cred.credential_data.as_ref().and_then(|cd| {
                serde_json::from_str::<KeycloakCredentialData>(cd)
                    .ok()
                    .and_then(|d| d.algorithm.map(|a| normalize_algorithm(&a)))
            });

            return (Some(secret.value), algorithm);
        }
    }

    (None, None)
}

fn extract_totp_seed(credentials: &Option<Vec<KeycloakCredential>>) -> Option<String> {
    let creds = credentials.as_ref()?;

    for cred in creds {
        if (cred.credential_type == "otp" || cred.credential_type == "totp")
            && let Some(ref secret_data) = cred.secret_data
            && let Ok(secret) = serde_json::from_str::<KeycloakSecretData>(secret_data)
        {
            return Some(secret.value);
        }
    }

    None
}

fn normalize_algorithm(alg: &str) -> String {
    match alg.to_lowercase().as_str() {
        "bcrypt" | "bcrypt-sha256" => "bcrypt".to_string(),
        "argon2" | "argon2id" => "argon2id".to_string(),
        "pbkdf2-sha256" | "pbkdf2" => "pbkdf2-sha256".to_string(),
        "pbkdf2-sha512" => "pbkdf2-sha512".to_string(),
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

// ── Keycloak JSON schema (subset) ──────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeycloakRealm {
    #[allow(dead_code)]
    realm: Option<String>,
    users: Option<Vec<KeycloakUser>>,
    roles: Option<KeycloakRoles>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeycloakUser {
    id: String,
    username: String,
    email: Option<String>,
    email_verified: Option<bool>,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: Option<bool>,
    credentials: Option<Vec<KeycloakCredential>>,
    realm_roles: Option<Vec<String>>,
    groups: Option<Vec<String>>,
    attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeycloakCredential {
    #[serde(rename = "type")]
    credential_type: String,
    secret_data: Option<String>,
    credential_data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeycloakSecretData {
    value: String,
}

#[derive(Debug, Deserialize)]
struct KeycloakCredentialData {
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeycloakRoles {
    #[allow(dead_code)]
    realm: Option<Vec<KeycloakRole>>,
}

#[derive(Debug, Deserialize)]
struct KeycloakRole {
    #[allow(dead_code)]
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_realm_json() -> &'static str {
        r#"{
            "realm": "myrealm",
            "users": [
                {
                    "id": "user-001",
                    "username": "alice",
                    "email": "alice@sid.example.com",
                    "emailVerified": true,
                    "firstName": "Alice",
                    "lastName": "Smith",
                    "enabled": true,
                    "credentials": [
                        {
                            "type": "password",
                            "secretData": "{\"value\":\"$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234\",\"salt\":\"abc\"}",
                            "credentialData": "{\"algorithm\":\"bcrypt\"}"
                        },
                        {
                            "type": "otp",
                            "secretData": "{\"value\":\"JBSWY3DPEHPK3PXP\"}"
                        }
                    ],
                    "realmRoles": ["user", "admin"],
                    "groups": ["/engineering", "/admins"],
                    "attributes": {
                        "phoneNumber": ["+1234567890"]
                    }
                },
                {
                    "id": "user-002",
                    "username": "bob",
                    "email": "bob@sid.example.com",
                    "emailVerified": false,
                    "enabled": false,
                    "credentials": []
                }
            ]
        }"#
    }

    #[test]
    fn test_keycloak_parse_basic() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_keycloak_user_alice() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert!(alice.email_verified);
        assert_eq!(alice.first_name.as_deref(), Some("Alice"));
        assert_eq!(alice.last_name.as_deref(), Some("Smith"));
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert!(alice.enabled);
        assert_eq!(alice.external_id, "user-001");
    }

    #[test]
    fn test_keycloak_password_extraction() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert!(alice.password_hash.is_some());
        assert!(alice.password_hash.as_ref().unwrap().starts_with("$2a$"));
        assert_eq!(alice.hash_algorithm.as_deref(), Some("bcrypt"));
    }

    #[test]
    fn test_keycloak_totp_extraction() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.totp_seed.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_keycloak_roles_and_groups() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.roles, vec!["user", "admin"]);
        assert_eq!(alice.groups, vec!["/engineering", "/admins"]);
    }

    #[test]
    fn test_keycloak_phone_from_attributes() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.phone.as_deref(), Some("+1234567890"));
    }

    #[test]
    fn test_keycloak_disabled_user() {
        let adapter = KeycloakAdapter;
        let users = adapter.parse(sample_realm_json().as_bytes()).unwrap();
        let bob = &users[1];

        assert_eq!(bob.username, "bob");
        assert!(!bob.enabled);
        assert!(bob.password_hash.is_none());
        assert!(bob.totp_seed.is_none());
    }

    #[test]
    fn test_keycloak_empty_realm() {
        let json = r#"{"realm": "empty"}"#;
        let adapter = KeycloakAdapter;
        let users = adapter.parse(json.as_bytes()).unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn test_keycloak_invalid_json() {
        let adapter = KeycloakAdapter;
        let result = adapter.parse(b"not json");
        assert!(result.is_err());
    }
}
