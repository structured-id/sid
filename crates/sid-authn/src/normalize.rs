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

/// Normalize a login principal of this installation's own namespace to
/// canonical form ([`normalize_principal_in`] under
/// [`EmailPolicy::LOCAL`](crate::email::EmailPolicy::LOCAL)).
pub fn normalize_principal(input: &str) -> Result<NormalizedPrincipal, NormalizeError> {
    normalize_principal_in(input, &crate::email::EmailPolicy::LOCAL)
}

/// Normalize a login principal to canonical form, an email handle under the
/// namespace `email` governs: what it does not admit is refused, and the key
/// carries its revision.
///
/// Auto-detects type based on format and applies type-specific normalization.
/// Returns error for invalid usernames (too short/long after normalization).
pub fn normalize_principal_in(
    input: &str,
    email: &crate::email::EmailPolicy,
) -> Result<NormalizedPrincipal, NormalizeError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(NormalizeError::Empty);
    }

    if trimmed.contains('@') {
        let handle = crate::email::parse(trimmed, email)?;
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
mod tests;
