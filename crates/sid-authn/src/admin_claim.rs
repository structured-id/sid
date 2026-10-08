// SPDX-License-Identifier: AGPL-3.0-only
//! Claiming the first administrator of an instance.
//!
//! While the instance has no administrator it holds one claim token, shared
//! by every replica and written to the log at start. A signed-in profile that
//! presents it becomes the first administrator, and the token is removed in
//! the same transaction. Knowing a username or restarting the server grants
//! nothing.

use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use sid_core::models::{AuditEntry, InstanceSecret, ProfileId};
use sid_keys::KeyManager;
use sid_plugin::StorageBackend;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::instance_secret::{self, InstanceSecretError};
use crate::sealed_secret::{self, SealedSecretError};

/// Leads every claim token, so an operator recognises it in the log.
const TOKEN_PREFIX: &str = "sidclaim_";

/// Why a claim was refused or could not be checked.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// The instance already has an administrator (or its claim was just taken).
    #[error("the instance has no open administrator claim")]
    NotOpen,
    #[error("administrator claim token does not match")]
    Mismatch,
    #[error("profile {0} not found")]
    UnknownProfile(ProfileId),
    /// The profile changed between read and write; the claim is still open.
    #[error("profile changed concurrently")]
    Changed,
    #[error(transparent)]
    Sealed(#[from] SealedSecretError),
    #[error(transparent)]
    Storage(#[from] sid_core::Error),
}

/// The open claim token, created when the instance has no administrator yet;
/// `None` once an administrator exists.
pub async fn open_claim(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
) -> Result<Option<SecretString>, InstanceSecretError<core::convert::Infallible>> {
    if storage.admin_exists().await? {
        return Ok(None);
    }
    let token = instance_secret::load_or_create(storage, keys, InstanceSecret::AdminClaim, || {
        let random = Zeroizing::new(rand::random::<[u8; 32]>());
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random.as_slice());
        Ok(Zeroizing::new(
            format!("{TOKEN_PREFIX}{encoded}").into_bytes(),
        ))
    })
    .await?;
    let token = String::from_utf8(token.to_vec()).map_err(|_| InstanceSecretError::Malformed)?;
    Ok(Some(SecretString::from(token)))
}

/// Whether the installation still waits for its first administrator.
pub async fn is_open(storage: &dyn StorageBackend) -> Result<bool, ClaimError> {
    Ok(!storage.admin_exists().await?)
}

/// Check `presented` against the open claim. `Some(sealed)` is the stored claim
/// the caller then consumes in its own write (a registration or the role
/// grant); `None` means the installation has an administrator or no claim.
pub async fn verify(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
    presented: &SecretString,
) -> Result<Option<Vec<u8>>, ClaimError> {
    if storage.admin_exists().await? {
        return Ok(None);
    }
    let Some(stored) = storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await?
    else {
        return Ok(None);
    };
    require_match(keys, &stored, presented).await?;
    Ok(Some(stored))
}

/// `Mismatch` unless `presented` is the token sealed in `stored`; compared in
/// constant time.
async fn require_match(
    keys: &dyn KeyManager,
    stored: &[u8],
    presented: &SecretString,
) -> Result<(), ClaimError> {
    let context = instance_secret::context(InstanceSecret::AdminClaim);
    let opened = sealed_secret::open(keys, &context, stored).await?;
    let matches: bool = opened
        .secret
        .as_slice()
        .ct_eq(presented.expose_secret().as_bytes())
        .into();
    if matches {
        Ok(())
    } else {
        Err(ClaimError::Mismatch)
    }
}

/// Make `profile_id` the first administrator if `presented` is the open claim.
pub async fn claim(
    storage: &dyn StorageBackend,
    keys: &dyn KeyManager,
    profile_id: ProfileId,
    presented: &SecretString,
) -> Result<(), ClaimError> {
    let Some(stored) = storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await?
    else {
        return Err(ClaimError::NotOpen);
    };
    require_match(keys, &stored, presented).await?;
    let mut profile = storage
        .get_profile(profile_id)
        .await?
        .ok_or(ClaimError::UnknownProfile(profile_id))?;
    if !profile.is_admin() {
        profile.roles.push("admin".to_string());
    }
    let claimed = storage
        .claim_first_admin(
            &stored,
            &profile,
            AuditEntry::user(
                profile_id.to_string(),
                "profile.admin_claimed",
                profile_id.to_string(),
            )
            .into(),
        )
        .await?;
    if claimed {
        return Ok(());
    }
    // Still stored: only the profile write lost a race. Gone: someone claimed it.
    if storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await?
        .is_some_and(|now| now == stored)
    {
        Err(ClaimError::Changed)
    } else {
        Err(ClaimError::NotOpen)
    }
}

#[cfg(test)]
mod tests;
