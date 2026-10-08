// SPDX-License-Identifier: AGPL-3.0-only
//! Login principal normalization.
//!
//! Converts any login principal (email, phone, username) to a canonical form
//! suitable for deterministic database lookup.
//!
//! # Anti-homoglyph protection
//!
//! Two-layer approach:
//! 1. **Normalization** (this module): NFC + lowercase + IDNA. Non-ASCII local
//!    parts in emails and usernames are converted via Unicode skeleton to prevent
//!    confusable principals from being stored.
//! 2. **Confusable check** (`confusable_skeleton()`): During registration, compare
//!    skeleton of new principal against skeletons of existing ones to reject
//!    lookalikes (e.g., Cyrillic "аlice" vs Latin "alice").
//!
//! # Supported principal types
//!
//! Detection is based on input format:
//! - Contains `@` → **Email**: the installation's resolution key from
//!   [`crate::email`] (case, local-part dots and `+tag` folded)
//! - Starts with `+` → **Phone**: strip non-digits, E.164 format
//! - Otherwise → **Username**: NFC + lowercase + ASCII filter (handles both
//!   global `alice` and federated `alice#acme.corp`)

use sid_core::models::PrincipalType;
use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

/// Normalization error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizeError {
    /// Username too short after normalization (min 3 chars).
    #[error("username too short (min 3 characters, got {0})")]
    UsernameTooShort(usize),
    /// Username too long after normalization (max 32 chars).
    #[error("username too long (max 32 characters, got {0})")]
    UsernameTooLong(usize),
    /// Empty principal after trimming.
    #[error("empty principal")]
    Empty,
    /// Phone number failed E.164 validation (invalid country code, wrong length).
    #[error("invalid phone number: {0}")]
    InvalidPhone(String),
    /// Not an admissible email login handle.
    #[error(transparent)]
    Email(#[from] crate::email::EmailError),
}

/// Result of principal normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPrincipal {
    /// Detected principal type.
    pub principal_type: LoginPrincipalType,
    /// Canonical normalized value for database lookup.
    pub normalized: String,
    /// For an email, the whole handle: the validated mailbox in the spelling
    /// given (what a new contact stores and mail goes to, never `normalized`)
    /// and the policy revision the key was derived under.
    pub email: Option<crate::email::EmailHandle>,
}

impl NormalizedPrincipal {
    /// The email policy revision a lookup by this key uses; `None` for a
    /// phone or username.
    pub fn key_revision(&self) -> Option<i64> {
        self.email.as_ref().map(|e| e.revision)
    }
}

/// Username length constraints.
pub const USERNAME_MIN_LENGTH: usize = 3;
pub const USERNAME_MAX_LENGTH: usize = 32;

/// Login principal type (subset of PrincipalType used for text-based authentication).
///
/// FaceEmbedding and NfcTag are device-initiated, not text-typed, so excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginPrincipalType {
    Email,
    Phone,
    Username,
}

impl LoginPrincipalType {
    /// Convert to storage PrincipalType (for Principal entity lookup).
    pub fn to_principal_type(self) -> PrincipalType {
        match self {
            Self::Email => PrincipalType::Email,
            Self::Phone => PrincipalType::Phone,
            Self::Username => PrincipalType::Username,
        }
    }
}

/// Normalize a login principal to canonical form.
///
/// Auto-detects type based on format and applies type-specific normalization.
/// Returns error for invalid usernames (too short/long after normalization).
pub fn normalize_principal(input: &str) -> Result<NormalizedPrincipal, NormalizeError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(NormalizeError::Empty);
    }

    if trimmed.contains('@') {
        // An installation's own login handles: the fixed Personal equality.
        let handle = crate::email::parse(trimmed, &crate::email::EmailPolicy::LOCAL)?;
        Ok(NormalizedPrincipal {
            principal_type: LoginPrincipalType::Email,
            normalized: handle.key.clone(),
            email: Some(handle),
        })
    } else if trimmed.starts_with('+') {
        let normalized = normalize_phone(trimmed)?;
        Ok(NormalizedPrincipal {
            principal_type: LoginPrincipalType::Phone,
            normalized,
            email: None,
        })
    } else {
        // Username: global ("alice") or federated ("alice#acme.corp")
        let normalized = normalize_username(trimmed);
        let is_federated = normalized.contains('#');
        let login_part = normalized.split('#').next().unwrap_or(&normalized);
        let len = login_part.len();

        if is_federated {
            // Federated: org admin decides login part length, only check non-empty + max
            if len == 0 {
                return Err(NormalizeError::UsernameTooShort(0));
            }
        } else {
            // Global: SaaS-curated namespace, enforce min length
            if len < USERNAME_MIN_LENGTH {
                return Err(NormalizeError::UsernameTooShort(len));
            }
        }
        if len > USERNAME_MAX_LENGTH {
            return Err(NormalizeError::UsernameTooLong(len));
        }
        Ok(NormalizedPrincipal {
            principal_type: LoginPrincipalType::Username,
            normalized,
            email: None,
        })
    }
}

/// Compute skeleton form for confusable detection.
///
/// Use during **registration** to check if a new principal is visually
/// confusable with any existing principal. Compare skeletons: if equal,
/// reject to prevent homoglyph attacks.
///
/// Example: `confusable_skeleton("аlice") == confusable_skeleton("alice")`
pub fn confusable_skeleton(input: &str) -> String {
    let nfc: String = input.nfc().collect();
    skeleton(&nfc).collect::<String>().to_lowercase()
}

/// Normalize phone number to E.164 format.
///
/// Strips non-digit chars except leading `+`, validates basic structure.
fn normalize_phone(phone: &str) -> Result<String, NormalizeError> {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() < 7 || digits.len() > 15 {
        return Err(NormalizeError::InvalidPhone(format!(
            "invalid length: {} digits (expected 7-15)",
            digits.len()
        )));
    }

    Ok(format!("+{}", digits))
}

/// Normalize username.
///
/// Handles both global ("alice") and federated ("alice#acme.corp").
/// - NFC normalization
/// - Lowercase
/// - Non-ASCII: skeleton approximation (anti-homoglyph)
/// - ASCII filter on login part (alphanumeric + underscore + dash)
/// - Domain part (after #) normalized via IDNA (same as email domain)
fn normalize_username(username: &str) -> String {
    let nfc: String = username.nfc().collect();

    if let Some(hash_pos) = nfc.find('#') {
        // Federated: login_part#domain
        let login_part = &nfc[..hash_pos];
        let domain_part = &nfc[hash_pos + 1..];

        let normalized_login = normalize_username_part(login_part);
        let normalized_domain =
            idna::domain_to_ascii(domain_part).unwrap_or_else(|_| domain_part.to_lowercase());

        format!("{}#{}", normalized_login, normalized_domain)
    } else {
        // Global username
        normalize_username_part(&nfc)
    }
}

/// Normalize the login part of a username (before # or the whole string).
fn normalize_username_part(input: &str) -> String {
    let lowered = input.to_lowercase();

    // Non-ASCII: use skeleton for ASCII approximation (anti-homoglyph)
    let ascii_form = if lowered.is_ascii() {
        lowered
    } else {
        skeleton(&lowered).collect::<String>().to_lowercase()
    };

    ascii_form
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Email normalization ────────────────────────────────────

    #[test]
    fn test_email_basic() {
        let result = normalize_principal("Alice@Example.COM").unwrap();
        assert_eq!(result.principal_type, LoginPrincipalType::Email);
        assert_eq!(result.normalized, "alice@example.com");
    }

    #[test]
    fn test_email_plus_tag_stripped() {
        let result = normalize_principal("user+tag@example.com").unwrap();
        assert_eq!(result.normalized, "user@example.com");
    }

    #[test]
    fn test_email_unicode_domain_idna() {
        let result = normalize_principal("user@münchen.de").unwrap();
        assert_eq!(result.normalized, "user@xn--mnchen-3ya.de");
    }

    #[test]
    fn test_email_nfc_normalization() {
        // é as combining e + acute vs precomposed é
        let combining = "caf\u{0065}\u{0301}@example.com"; // e + combining acute
        let precomposed = "caf\u{00e9}@example.com"; // precomposed é
        let r1 = normalize_principal(combining).unwrap();
        let r2 = normalize_principal(precomposed).unwrap();
        assert_eq!(r1.normalized, r2.normalized);
    }

    // ── Phone normalization ────────────────────────────────────

    #[test]
    fn test_phone_basic() {
        let result = normalize_principal("+1 (212) 555-1234").unwrap();
        assert_eq!(result.principal_type, LoginPrincipalType::Phone);
        assert_eq!(result.normalized, "+12125551234");
    }

    #[test]
    fn test_phone_too_short() {
        let result = normalize_principal("+123");
        assert!(matches!(result, Err(NormalizeError::InvalidPhone(_))));
    }

    #[test]
    fn test_phone_strips_formatting() {
        let result = normalize_principal("+380-50-123-4567").unwrap();
        assert_eq!(result.normalized, "+380501234567");
    }

    // ── Username normalization ─────────────────────────────────

    #[test]
    fn test_username_basic() {
        let result = normalize_principal("Alice_Smith").unwrap();
        assert_eq!(result.principal_type, LoginPrincipalType::Username);
        assert_eq!(result.normalized, "alice_smith");
    }

    #[test]
    fn test_username_too_short() {
        let result = normalize_principal("ab");
        assert!(matches!(result, Err(NormalizeError::UsernameTooShort(2))));
    }

    #[test]
    fn test_username_special_chars_stripped() {
        let result = normalize_principal("alice.smith!").unwrap();
        assert_eq!(result.normalized, "alicesmith");
    }

    #[test]
    fn test_username_federated() {
        let result = normalize_principal("Alice#Acme.Corp").unwrap();
        assert_eq!(result.principal_type, LoginPrincipalType::Username);
        assert_eq!(result.normalized, "alice#acme.corp");
    }

    #[test]
    fn test_username_federated_short_login_part_allowed() {
        // Federated: org admin decides login part length, no min length check
        let result = normalize_principal("ab#acme.corp").unwrap();
        assert_eq!(result.normalized, "ab#acme.corp");

        let result = normalize_principal("a#acme.corp").unwrap();
        assert_eq!(result.normalized, "a#acme.corp");
    }

    #[test]
    fn test_username_federated_empty_login_part_rejected() {
        let result = normalize_principal("#acme.corp");
        assert!(matches!(result, Err(NormalizeError::UsernameTooShort(0))));
    }

    #[test]
    fn test_username_federated_idna_domain() {
        let result = normalize_principal("alice#münchen.de").unwrap();
        assert_eq!(result.normalized, "alice#xn--mnchen-3ya.de");
    }

    // ── Edge cases ─────────────────────────────────────────────

    #[test]
    fn test_empty_input() {
        let result = normalize_principal("");
        assert!(matches!(result, Err(NormalizeError::Empty)));
    }

    #[test]
    fn test_whitespace_only() {
        let result = normalize_principal("   ");
        assert!(matches!(result, Err(NormalizeError::Empty)));
    }

    #[test]
    fn test_leading_trailing_whitespace() {
        let result = normalize_principal("  alice@example.com  ").unwrap();
        assert_eq!(result.normalized, "alice@example.com");
    }

    // ── Confusable skeleton ────────────────────────────────────

    #[test]
    fn test_confusable_cyrillic_a() {
        // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
        let latin = confusable_skeleton("alice");
        let cyrillic = confusable_skeleton("\u{0430}lice");
        assert_eq!(latin, cyrillic);
    }

    // ── LoginPrincipalType → PrincipalType ─────────────────────

    #[test]
    fn test_login_principal_type_to_principal_type() {
        assert_eq!(
            LoginPrincipalType::Email.to_principal_type(),
            PrincipalType::Email
        );
        assert_eq!(
            LoginPrincipalType::Phone.to_principal_type(),
            PrincipalType::Phone
        );
        assert_eq!(
            LoginPrincipalType::Username.to_principal_type(),
            PrincipalType::Username
        );
    }
}
