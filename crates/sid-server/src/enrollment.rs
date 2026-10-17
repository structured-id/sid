// SPDX-License-Identifier: AGPL-3.0-only
//! The enrollment policy in force (auth/enrollment-policy.md): the one an
//! administrator stored, else the defaults, with the mode the deployment
//! pins, if it pins one. Read from the store on every use, so every replica
//! applies a change at once.

use sid_core::models::{EnrollmentMode, EnrollmentPolicy, SecurityPolicy};
use sid_plugin::storage::StorageBackend;

/// The variable that pins the enrollment mode.
pub const PIN_VARIABLE: &str = "SID_ENROLLMENT_MODE";

/// The stored policy, or the defaults while none is stored.
pub async fn stored_or_default(storage: &dyn StorageBackend) -> sid_core::Result<EnrollmentPolicy> {
    Ok(storage
        .enrollment_policy()
        .await?
        .unwrap_or_else(|| SecurityPolicy::ce_default().enrollment))
}

/// The policy in force: the stored one with the pinned mode over its own.
pub async fn effective(
    storage: &dyn StorageBackend,
    pinned: Option<EnrollmentMode>,
) -> sid_core::Result<EnrollmentPolicy> {
    let mut policy = stored_or_default(storage).await?;
    if let Some(mode) = pinned {
        policy.mode = mode;
    }
    Ok(policy)
}

/// `SID_ENROLLMENT_MODE` as read: unset pins nothing; a value that is not a
/// mode's name stops the start, never read as unset.
pub fn pinned_mode_setting(
    read: Result<String, std::env::VarError>,
) -> anyhow::Result<Option<EnrollmentMode>> {
    crate::init::setting(PIN_VARIABLE, read)?
        .map(|value| {
            value
                .parse()
                .map_err(|e| anyhow::anyhow!("{PIN_VARIABLE}: {e}"))
        })
        .transpose()
}

/// Why an administrator's policy is not stored.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The deployment pins another mode.
    #[error("the deployment pins the enrollment mode to {0}")]
    Pinned(EnrollmentMode),
    /// Domain-restricted enrollment without any domain would admit no one
    /// while looking configured.
    #[error("a domain-restricted policy needs at least one allowed domain")]
    NoDomain,
    /// An allowed domain that is not a domain name.
    #[error("{0:?} is not a domain name")]
    BadDomain(String),
    /// A default use limit above what an invite can store.
    #[error("the default invite use limit is at most {MAX_INVITE_USES}")]
    TooManyUses,
    /// A default expiry later than any representable time.
    #[error("the default invite expiry is too far in the future")]
    ExpiryTooFar,
}

/// When an invite created at `now` expires under a default of `hours`
/// (0: never); `None` when that time cannot be represented.
pub fn default_expiry(
    now: chrono::DateTime<chrono::Utc>,
    hours: u32,
) -> Option<Option<chrono::DateTime<chrono::Utc>>> {
    if hours == 0 {
        return Some(None);
    }
    chrono::TimeDelta::try_hours(i64::from(hours))
        .and_then(|delta| now.checked_add_signed(delta))
        .map(Some)
}

/// The largest use limit an invite stores (a signed 32-bit column).
pub const MAX_INVITE_USES: u32 = i32::MAX as u32;

/// `policy` as it is stored: allowed domains trimmed, lowercased and without
/// repeats (registration compares them case-insensitively). While a mode is
/// pinned the request carries that mode, as the API reports it, and the
/// `stored_mode` is kept, so removing the pin restores it. Refused when it
/// changes a pinned mode, leaves a domain-restricted mode (stored or pinned)
/// without a usable domain, or sets a default use limit no invite can hold.
pub fn validated(
    mut policy: EnrollmentPolicy,
    pinned: Option<EnrollmentMode>,
    stored_mode: EnrollmentMode,
) -> Result<EnrollmentPolicy, Refusal> {
    if let Some(mode) = pinned {
        if policy.mode != mode {
            return Err(Refusal::Pinned(mode));
        }
        policy.mode = stored_mode;
    }
    if policy.invite.default_max_uses > MAX_INVITE_USES {
        return Err(Refusal::TooManyUses);
    }
    if default_expiry(chrono::Utc::now(), policy.invite.default_expiry_hours).is_none() {
        return Err(Refusal::ExpiryTooFar);
    }
    let mut domains = Vec::with_capacity(policy.allowed_domains.len());
    for domain in &policy.allowed_domains {
        let domain = domain.trim().to_ascii_lowercase();
        // Host name syntax, RFC 1035 §2.3.1 as relaxed by RFC 1123 §2.1
        // (labels may start with a digit); an IDN appears in its A-label form.
        let valid = !domain.is_empty()
            && domain.len() <= 253
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !valid {
            return Err(Refusal::BadDomain(domain));
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    // The domains apply under the mode in force (a pinned one) and under the
    // stored one once the pin is removed.
    let restricted = |mode: Option<EnrollmentMode>| mode == Some(EnrollmentMode::DomainRestricted);
    if (restricted(Some(policy.mode)) || restricted(pinned)) && domains.is_empty() {
        return Err(Refusal::NoDomain);
    }
    policy.allowed_domains = domains;
    Ok(policy)
}

#[cfg(test)]
mod tests;
