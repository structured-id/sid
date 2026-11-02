// SPDX-License-Identifier: AGPL-3.0-only
//! Username domain model.
//!
//! Global usernames (SaaS-issued, federation-wide unique) and
//! corporate logins (`login#domain`).
//!
//! Validation rules enforce anti-phishing and anti-squatting properties.

use serde::{Deserialize, Serialize};

/// Minimum username length.
pub const USERNAME_MIN_LEN: usize = 3;
/// Maximum username length.
pub const USERNAME_MAX_LEN: usize = 32;

/// Quarantine period for released usernames (days).
pub const USERNAME_QUARANTINE_DAYS: u32 = 180;

/// Cooldown between username changes (days).
pub const USERNAME_CHANGE_COOLDOWN_DAYS: u32 = 30;

/// Username lifecycle states.
///
/// ```text
/// Active → Suspended → Released → Available
///   │         │                       ↑
///   │         └─ appeal → Active      │
///   │                                 │
///   ├─ DisputePending ──► Suspended (if TRANSFER) or Active (if REJECT)
///   │   (username still works during dispute)
///   │
///   └─ Quarantined (voluntary release / closure) → Available (180 days)
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameStatus {
    /// Normal operating state.
    #[default]
    Active,
    /// Trademark dispute filed — username functions normally during investigation.
    /// Visible to holder only. Transitions to Suspended (TRANSFER) or Active (REJECT).
    DisputePending,
    /// Suspended (trademark dispute, policy violation, court order).
    Suspended,
    /// Voluntarily released or post-closure, in quarantine period.
    Quarantined,
    /// Available for re-registration (after quarantine).
    Released,
}

/// Reason for username suspension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspensionReason {
    /// Trademark dispute resolved in favor of complainant.
    TrademarkDispute,
    /// Court order requiring suspension.
    CourtOrder,
    /// Policy violation (hate speech, impersonation).
    PolicyViolation,
    /// Inactivity reclaim (future feature).
    InactivityReclaim,
}

impl SuspensionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TrademarkDispute => "trademark_dispute",
            Self::CourtOrder => "court_order",
            Self::PolicyViolation => "policy_violation",
            Self::InactivityReclaim => "inactivity_reclaim",
        }
    }

    /// Whether the suspension is reversible via appeal.
    pub fn is_reversible(&self) -> bool {
        match self {
            Self::TrademarkDispute => true,
            Self::CourtOrder => false, // Per court order
            Self::PolicyViolation => true,
            Self::InactivityReclaim => true,
        }
    }
}

impl UsernameStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DisputePending => "dispute_pending",
            Self::Suspended => "suspended",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
        }
    }

    /// Whether the username can be used for login.
    /// DisputePending still allows login (no pre-judgment suspension).
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::DisputePending)
    }
}

impl std::fmt::Display for UsernameStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Username validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameError {
    TooShort,
    TooLong,
    InvalidCharacter(char),
    StartsWithUnderscore,
    EndsWithUnderscore,
    ConsecutiveUnderscores,
    Reserved,
}

impl std::fmt::Display for UsernameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(
                f,
                "username must be at least {} characters",
                USERNAME_MIN_LEN
            ),
            Self::TooLong => write!(
                f,
                "username must be at most {} characters",
                USERNAME_MAX_LEN
            ),
            Self::InvalidCharacter(c) => {
                write!(f, "invalid character: '{c}' (only a-z, 0-9, _ allowed)")
            }
            Self::StartsWithUnderscore => write!(f, "username cannot start with underscore"),
            Self::EndsWithUnderscore => write!(f, "username cannot end with underscore"),
            Self::ConsecutiveUnderscores => {
                write!(f, "username cannot contain consecutive underscores")
            }
            Self::Reserved => write!(f, "this username is reserved"),
        }
    }
}

impl std::error::Error for UsernameError {}

/// Reserved system names that cannot be registered as usernames.
const RESERVED_NAMES: &[&str] = &[
    "admin",
    "administrator",
    "abuse",
    "help",
    "info",
    "noreply",
    "operator",
    "postmaster",
    "root",
    "security",
    "support",
    "system",
    "webmaster",
];

/// Validate a global username against format rules.
///
/// Rules: `^[a-z0-9_]{3,32}$`, no leading/trailing underscore,
/// no consecutive underscores, not a reserved name.
pub fn validate_username(username: &str) -> Result<(), UsernameError> {
    if username.len() < USERNAME_MIN_LEN {
        return Err(UsernameError::TooShort);
    }
    if username.len() > USERNAME_MAX_LEN {
        return Err(UsernameError::TooLong);
    }
    if username.starts_with('_') {
        return Err(UsernameError::StartsWithUnderscore);
    }
    if username.ends_with('_') {
        return Err(UsernameError::EndsWithUnderscore);
    }
    if username.contains("__") {
        return Err(UsernameError::ConsecutiveUnderscores);
    }

    for c in username.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_') {
            return Err(UsernameError::InvalidCharacter(c));
        }
    }

    if RESERVED_NAMES.contains(&username) {
        return Err(UsernameError::Reserved);
    }

    Ok(())
}

/// Validate a corporate login in `login#domain` format.
///
/// Login part follows same rules as global username.
/// Domain part must be a valid DNS hostname.
pub fn validate_corporate_login(login: &str) -> Result<(&str, &str), UsernameError> {
    let (user, domain) = login
        .split_once('#')
        .ok_or(UsernameError::InvalidCharacter('@'))?;

    // Validate login part (same rules as global username, except not reserved).
    if user.len() < USERNAME_MIN_LEN {
        return Err(UsernameError::TooShort);
    }
    if user.len() > USERNAME_MAX_LEN {
        return Err(UsernameError::TooLong);
    }
    if user.starts_with('_') {
        return Err(UsernameError::StartsWithUnderscore);
    }
    if user.ends_with('_') {
        return Err(UsernameError::EndsWithUnderscore);
    }
    if user.contains("__") {
        return Err(UsernameError::ConsecutiveUnderscores);
    }
    for c in user.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_') {
            return Err(UsernameError::InvalidCharacter(c));
        }
    }

    // Domain part: basic validation (non-empty, contains dot, ASCII only).
    if domain.is_empty() || !domain.contains('.') {
        return Err(UsernameError::InvalidCharacter('#'));
    }
    for c in domain.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '-' | '.') {
            return Err(UsernameError::InvalidCharacter(c));
        }
    }

    Ok((user, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Global username validation ──────────────────────────────

    #[test]
    fn test_valid_usernames() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice_wonder").is_ok());
        assert!(validate_username("dev42").is_ok());
        assert!(validate_username("a_b_c").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("sid").is_ok());
        assert!(validate_username("abc").is_ok()); // Minimum length.
    }

    #[test]
    fn test_too_short() {
        assert_eq!(validate_username("al"), Err(UsernameError::TooShort));
        assert_eq!(validate_username("a"), Err(UsernameError::TooShort));
        assert_eq!(validate_username(""), Err(UsernameError::TooShort));
    }

    #[test]
    fn test_too_long() {
        let long = "a".repeat(33);
        assert_eq!(validate_username(&long), Err(UsernameError::TooLong));
    }

    #[test]
    fn test_max_length_ok() {
        let max = "a".repeat(32);
        assert!(validate_username(&max).is_ok());
    }

    #[test]
    fn test_invalid_characters() {
        assert_eq!(
            validate_username("Alice"),
            Err(UsernameError::InvalidCharacter('A'))
        );
        assert_eq!(
            validate_username("alice.wonder"),
            Err(UsernameError::InvalidCharacter('.'))
        );
        assert_eq!(
            validate_username("alice-wonder"),
            Err(UsernameError::InvalidCharacter('-'))
        );
        assert!(matches!(
            validate_username("алиса"),
            Err(UsernameError::InvalidCharacter(_))
        ));
    }

    #[test]
    fn test_underscore_rules() {
        assert_eq!(
            validate_username("_alice"),
            Err(UsernameError::StartsWithUnderscore)
        );
        assert_eq!(
            validate_username("alice_"),
            Err(UsernameError::EndsWithUnderscore)
        );
        assert_eq!(
            validate_username("alice__wonder"),
            Err(UsernameError::ConsecutiveUnderscores)
        );
    }

    #[test]
    fn test_reserved_names() {
        assert_eq!(validate_username("admin"), Err(UsernameError::Reserved));
        assert_eq!(validate_username("root"), Err(UsernameError::Reserved));
        assert_eq!(validate_username("support"), Err(UsernameError::Reserved));
        assert_eq!(validate_username("system"), Err(UsernameError::Reserved));

        // Not reserved.
        assert!(validate_username("alice").is_ok());
    }

    // ── Corporate login validation ──────────────────────────────

    #[test]
    fn test_valid_corporate_logins() {
        let (user, domain) = validate_corporate_login("alice#acme.corp").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "acme.corp");

        let (user, domain) = validate_corporate_login("dev_ops#internal.bank.com").unwrap();
        assert_eq!(user, "dev_ops");
        assert_eq!(domain, "internal.bank.com");
    }

    #[test]
    fn test_corporate_login_no_separator() {
        assert!(validate_corporate_login("alice").is_err());
    }

    #[test]
    fn test_corporate_login_at_not_hash() {
        assert!(validate_corporate_login("alice@acme.corp").is_err());
    }

    #[test]
    fn test_corporate_login_invalid_user() {
        assert!(validate_corporate_login("Al#acme.corp").is_err());
        assert!(validate_corporate_login("_a#acme.corp").is_err());
        assert!(validate_corporate_login("ab#acme.corp").is_err()); // Too short.
    }

    #[test]
    fn test_corporate_login_invalid_domain() {
        assert!(validate_corporate_login("alice#").is_err());
        assert!(validate_corporate_login("alice#nodot").is_err());
    }

    // ── Username status ─────────────────────────────────────────

    #[test]
    fn test_username_status_usable() {
        assert!(UsernameStatus::Active.is_usable());
        assert!(UsernameStatus::DisputePending.is_usable()); // No pre-judgment suspension.
        assert!(!UsernameStatus::Suspended.is_usable());
        assert!(!UsernameStatus::Quarantined.is_usable());
        assert!(!UsernameStatus::Released.is_usable());
    }

    #[test]
    fn test_username_status_serde() {
        let s = UsernameStatus::Quarantined;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"quarantined\"");
        let parsed: UsernameStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UsernameStatus::Quarantined);
    }

    #[test]
    fn test_dispute_pending_serde() {
        let s = UsernameStatus::DisputePending;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"dispute_pending\"");
        let parsed: UsernameStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, UsernameStatus::DisputePending);
    }

    // ── Suspension reason ───────────────────────────────────────

    #[test]
    fn test_suspension_reason_reversible() {
        assert!(SuspensionReason::TrademarkDispute.is_reversible());
        assert!(!SuspensionReason::CourtOrder.is_reversible());
        assert!(SuspensionReason::PolicyViolation.is_reversible());
        assert!(SuspensionReason::InactivityReclaim.is_reversible());
    }

    #[test]
    fn test_suspension_reason_serde() {
        let r = SuspensionReason::TrademarkDispute;
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"trademark_dispute\"");
        let parsed: SuspensionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SuspensionReason::TrademarkDispute);
    }

    #[test]
    fn test_constants() {
        assert_eq!(USERNAME_MIN_LEN, 3);
        assert_eq!(USERNAME_MAX_LEN, 32);
        assert_eq!(USERNAME_QUARANTINE_DAYS, 180);
        assert_eq!(USERNAME_CHANGE_COOLDOWN_DAYS, 30);
    }
}
