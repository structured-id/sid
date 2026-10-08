// SPDX-License-Identifier: AGPL-3.0-only
//! LDAP/AD LDIF export parser.
//!
//! Parses LDIF (LDAP Data Interchange Format, RFC 2849) files
//! exported from Active Directory, OpenLDAP, FreeIPA, etc.
//! Password hashes vary: SSHA, MD5, bcrypt (FreeIPA), or none (AD uses NTLM).

use super::{ImportedUser, MigrationAdapter, MigrationImportError};
use std::collections::HashMap;

/// LDIF file adapter.
pub struct LdifAdapter;

impl MigrationAdapter for LdifAdapter {
    fn provider_name(&self) -> &'static str {
        "ldif"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<ImportedUser>, MigrationImportError> {
        let text = std::str::from_utf8(data)
            .map_err(|e| MigrationImportError::InvalidFormat(format!("invalid UTF-8: {}", e)))?;

        let entries = parse_ldif_entries(text);
        let users = entries
            .into_iter()
            .filter(is_user_entry)
            .map(|e| convert_ldif_entry(&e))
            .collect();

        Ok(users)
    }
}

type LdifEntry = HashMap<String, Vec<String>>;

fn parse_ldif_entries(text: &str) -> Vec<LdifEntry> {
    let mut entries = Vec::new();
    let mut current: LdifEntry = HashMap::new();

    for line in text.lines() {
        // Empty line = entry separator
        if line.trim().is_empty() {
            if !current.is_empty() {
                entries.push(std::mem::take(&mut current));
            }
            continue;
        }

        // Comment lines
        if line.starts_with('#') {
            continue;
        }

        // Continuation line (starts with space)
        if line.starts_with(' ') || line.starts_with('\t') {
            // Append to previous attribute's last value
            // (simplified — full LDIF supports base64 continuation)
            continue;
        }

        // attribute: value
        if let Some((attr, value)) = line.split_once(':') {
            let attr = attr.trim().to_lowercase();
            let value = value.trim().to_string();
            current.entry(attr).or_default().push(value);
        }
    }

    // Don't forget last entry
    if !current.is_empty() {
        entries.push(current);
    }

    entries
}

fn is_user_entry(entry: &LdifEntry) -> bool {
    let objectclasses = entry.get("objectclass").cloned().unwrap_or_default();
    let lower: Vec<String> = objectclasses.iter().map(|s| s.to_lowercase()).collect();

    // Common user objectClasses
    lower.contains(&"person".to_string())
        || lower.contains(&"inetorgperson".to_string())
        || lower.contains(&"user".to_string())
        || lower.contains(&"posixaccount".to_string())
}

fn convert_ldif_entry(entry: &LdifEntry) -> ImportedUser {
    let get = |key: &str| -> Option<String> { entry.get(key).and_then(|v| v.first().cloned()) };

    let get_all = |key: &str| -> Vec<String> { entry.get(key).cloned().unwrap_or_default() };

    // Username: uid > sAMAccountName > cn
    let username = get("uid")
        .or_else(|| get("samaccountname"))
        .or_else(|| get("cn"))
        .unwrap_or_default();

    let email = get("mail").unwrap_or_default();

    // DN as external_id
    let external_id = get("dn").unwrap_or_default();

    // Password hash (userPassword attribute, may be prefixed: {SSHA}, {BCRYPT}, etc.)
    let (password_hash, hash_algorithm) = get("userpassword")
        .map(|p| detect_ldap_password(&p))
        .unwrap_or((None, None));

    // Groups from memberOf
    let groups = get_all("memberof")
        .into_iter()
        .filter_map(|dn| extract_cn_from_dn(&dn))
        .collect();

    let mut attributes = HashMap::new();
    if let Some(title) = get("title") {
        attributes.insert("title".to_string(), title);
    }
    if let Some(dept) = get("departmentnumber").or_else(|| get("department")) {
        attributes.insert("department".to_string(), dept);
    }

    ImportedUser {
        username,
        email,
        email_verified: false, // LDAP doesn't track email verification
        display_name: get("displayname").or_else(|| get("cn")),
        first_name: get("givenname"),
        last_name: get("sn"),
        phone: get("telephonenumber").or_else(|| get("mobile")),
        enabled: true, // LDAP account status requires checking userAccountControl (AD)
        password_hash,
        hash_algorithm,
        totp_seed: None,
        roles: Vec::new(),
        groups,
        external_id,
        attributes,
    }
}

fn detect_ldap_password(password: &str) -> (Option<String>, Option<String>) {
    // LDAP passwords are prefixed: {SSHA}base64hash, {BCRYPT}$2b$..., {CRYPT}$hash, etc.
    if let Some(rest) = password.strip_prefix("{SSHA}") {
        (Some(format!("{{SSHA}}{}", rest)), Some("ssha".to_string()))
    } else if let Some(rest) = password.strip_prefix("{SHA}") {
        (Some(format!("{{SHA}}{}", rest)), Some("sha".to_string()))
    } else if let Some(rest) = password.strip_prefix("{BCRYPT}") {
        (Some(rest.to_string()), Some("bcrypt".to_string()))
    } else if let Some(rest) = password.strip_prefix("{CRYPT}") {
        let algo = if rest.starts_with("$2") {
            "bcrypt"
        } else if rest.starts_with("$6$") {
            "sha-512-crypt"
        } else if rest.starts_with("$5$") {
            "sha-256-crypt"
        } else {
            "crypt"
        };
        (Some(rest.to_string()), Some(algo.to_string()))
    } else if password.starts_with("$2") {
        (Some(password.to_string()), Some("bcrypt".to_string()))
    } else if password.starts_with("$argon2") {
        (Some(password.to_string()), Some("argon2id".to_string()))
    } else {
        (None, None) // Unrecognized format (possibly base64 or AD NTLM)
    }
}

fn extract_cn_from_dn(dn: &str) -> Option<String> {
    // "cn=GroupName,ou=Groups,dc=example,dc=com" → "GroupName"
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part
            .strip_prefix("cn=")
            .or_else(|| part.strip_prefix("CN="))
        {
            return Some(cn.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ldif() -> &'static str {
        "dn: uid=alice,ou=People,dc=sid,dc=example,dc=com\n\
         objectClass: inetOrgPerson\n\
         objectClass: posixAccount\n\
         uid: alice\n\
         cn: Alice Smith\n\
         givenName: Alice\n\
         sn: Smith\n\
         mail: alice@sid.example.com\n\
         displayName: Alice Smith\n\
         telephoneNumber: +1234567890\n\
         userPassword: {BCRYPT}$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234\n\
         memberOf: cn=engineering,ou=Groups,dc=sid,dc=example,dc=com\n\
         memberOf: cn=admins,ou=Groups,dc=sid,dc=example,dc=com\n\
         \n\
         dn: uid=bob,ou=People,dc=sid,dc=example,dc=com\n\
         objectClass: inetOrgPerson\n\
         uid: bob\n\
         cn: Bob Jones\n\
         sn: Jones\n\
         mail: bob@sid.example.com\n"
    }

    #[test]
    fn test_ldif_parse_basic() {
        let adapter = LdifAdapter;
        let users = adapter.parse(sample_ldif().as_bytes()).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_ldif_user_alice() {
        let adapter = LdifAdapter;
        let users = adapter.parse(sample_ldif().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.username, "alice");
        assert_eq!(alice.email, "alice@sid.example.com");
        assert_eq!(alice.first_name.as_deref(), Some("Alice"));
        assert_eq!(alice.last_name.as_deref(), Some("Smith"));
        assert_eq!(alice.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(alice.phone.as_deref(), Some("+1234567890"));
    }

    #[test]
    fn test_ldif_password_bcrypt() {
        let adapter = LdifAdapter;
        let users = adapter.parse(sample_ldif().as_bytes()).unwrap();
        let alice = &users[0];

        assert!(alice.password_hash.is_some());
        assert!(alice.password_hash.as_ref().unwrap().starts_with("$2b$"));
        assert_eq!(alice.hash_algorithm.as_deref(), Some("bcrypt"));
    }

    #[test]
    fn test_ldif_groups() {
        let adapter = LdifAdapter;
        let users = adapter.parse(sample_ldif().as_bytes()).unwrap();
        let alice = &users[0];

        assert_eq!(alice.groups, vec!["engineering", "admins"]);
    }

    #[test]
    fn test_ldif_no_password() {
        let adapter = LdifAdapter;
        let users = adapter.parse(sample_ldif().as_bytes()).unwrap();
        let bob = &users[1];

        assert!(bob.password_hash.is_none());
    }

    #[test]
    fn test_ldif_empty() {
        let adapter = LdifAdapter;
        let users = adapter.parse(b"# empty file\n").unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn test_extract_cn_from_dn() {
        assert_eq!(
            extract_cn_from_dn("cn=admins,ou=Groups,dc=example,dc=com"),
            Some("admins".to_string())
        );
        assert_eq!(
            extract_cn_from_dn("CN=Users,DC=ad,DC=example,DC=com"),
            Some("Users".to_string())
        );
        assert_eq!(extract_cn_from_dn("ou=People,dc=example"), None);
    }

    #[test]
    fn test_detect_ldap_passwords() {
        let (hash, algo) = detect_ldap_password("{SSHA}base64data");
        assert!(hash.is_some());
        assert_eq!(algo.as_deref(), Some("ssha"));

        let (hash, algo) = detect_ldap_password("{CRYPT}$6$salt$hash");
        assert!(hash.is_some());
        assert_eq!(algo.as_deref(), Some("sha-512-crypt"));

        let (hash, _) = detect_ldap_password("randomjunk");
        assert!(hash.is_none());
    }
}
