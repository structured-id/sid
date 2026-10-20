// SPDX-License-Identifier: AGPL-3.0-only
//! Password sign-in (OPAQUE, RFC 9807 §6) for any authenticated account type.
//! The host resolves the principal, keeps the lockout, opens the stored
//! password and reads the account; this module keeps the two-step ceremony,
//! its answers for accounts that cannot sign in and the credential checks.

use std::fmt::Display;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialFence, CredentialId, CredentialType,
};
use sid_plugin::{CredentialStore, LoginState, StoredCredential};
use tracing::warn;

use crate::challenge_store::{ChallengeStore, ChallengeStoreError};
use crate::opaque::OpaqueRouter;

/// Server state between sign-in start and finish.
#[derive(Serialize, Deserialize)]
#[serde(bound = "O: Serialize + DeserializeOwned")]
pub enum PendingSignIn<O> {
    /// A sign-in against the account's password. Its tag is new so that a
    /// build which does not fence the session cannot read it and finish it
    /// unfenced: such a finish fails instead.
    #[serde(rename = "PasswordFenced")]
    Password {
        state: LoginState,
        // The stored name of the field states in flight already carry.
        #[serde(rename = "profile_id")]
        owner: O,
        credential_id: CredentialId,
        /// The stored password as the start read it: the session must still
        /// find it so (a reset replaces it in place).
        credential_data: CredentialData,
    },
    /// A sign-in that cannot succeed: no account holds the principal, or its
    /// account has no password. Stored and consumed like a real state and
    /// refused like a wrong password, so neither the timing of either step nor
    /// the answer tells whether the account exists. `identity` is the key its
    /// failed attempts count against.
    Decoy { identity: String },
}

/// Why a sign-in step gave no result.
#[derive(Debug, thiserror::Error)]
pub enum PasswordSignInError {
    /// Wrong password, unknown account or no usable password: one answer for
    /// all of them.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The account has only a password hash imported from another system; it
    /// signs in through the migration ceremony.
    #[error("the password must be migrated before signing in")]
    MigrationRequired,
    /// The started sign-in is unknown or expired.
    #[error("the sign-in expired")]
    Expired,
    #[error("credential storage failed: {0}")]
    Storage(sid_core::Error),
    #[error(transparent)]
    State(#[from] ChallengeStoreError),
}

/// What a password sign-in host supplies. One value serves one request: it
/// knows the request's client.
#[async_trait]
pub trait PasswordSignInHost: Send + Sync {
    /// The account a password belongs to.
    type Owner: Clone + Display + Serialize + DeserializeOwned + Send + Sync + 'static;
    /// The account the host reads for a verified owner.
    type Account: Send;
    /// A refusal or failure of the host, returned as is.
    type Error: Send + From<PasswordSignInError>;

    fn credentials(&self) -> &dyn CredentialStore<Owner = Self::Owner>;
    fn opaque(&self) -> &OpaqueRouter;
    fn pending(&self) -> &ChallengeStore<PendingSignIn<Self::Owner>>;

    /// The account `principal` signs in to now; `None` when none may.
    async fn resolve(&self, principal: &str) -> Result<Option<Self::Owner>, Self::Error>;

    /// Refuse while failed attempts against `identity` hold a lockout.
    async fn refuse_if_locked(&self, identity: &str) -> Result<(), Self::Error>;

    /// Count a failed attempt against `identity`.
    async fn record_failure(&self, identity: &str) -> Result<(), Self::Error>;

    /// The OPAQUE record of `credential`, opened from its sealed form, and
    /// the form the store holds for it now (opening may write it back
    /// resealed).
    async fn stored_password(
        &self,
        credential: &Credential<Self::Owner>,
    ) -> Result<OpenedPassword, Self::Error>;

    /// The OPAQUE credential identifier sign-ins of `credential` evaluate
    /// under (RFC 9807 §5).
    fn opaque_credential_identifier(&self, credential: &Credential<Self::Owner>) -> [u8; 16];

    /// The account `owner` names; `None` when it can no longer sign in.
    async fn account(&self, owner: &Self::Owner) -> Result<Option<Self::Account>, Self::Error>;
}

/// A stored password opened for a sign-in.
pub struct OpenedPassword {
    /// The OPAQUE record the sign-in runs against.
    pub record: StoredCredential,
    /// The credential's data as the store holds it now: the session the
    /// sign-in creates is fenced on it.
    pub stored: CredentialData,
}

/// The answer to a sign-in start.
pub struct Started {
    pub credential_response: Vec<u8>,
    /// The key the finish names its state by.
    pub state_key: String,
}

/// An account whose password the sign-in verified.
pub struct Verified<A> {
    pub account: A,
    /// The password the sign-in proved, for the session it creates
    /// (`GrantStore::create_session_atomic`): a reset committed meanwhile
    /// refuses that session.
    pub proved_by: CredentialFence,
}

fn storage<E: From<PasswordSignInError>>(e: sid_core::Error) -> E {
    PasswordSignInError::Storage(e).into()
}

/// The identifier a decoy answers under: stable per principal, so a repeated
/// start for an unknown principal looks like one for a known one.
fn decoy_credential_id(principal: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"sid-fake-credential-id:");
    hasher.update(principal.as_bytes());
    hasher.finalize().to_vec()
}

/// Answer a start that cannot succeed exactly like a real one: a decoy
/// OPAQUE response and a stored state that finish refuses like a wrong
/// password (RFC 9807 §10.9).
async fn decoy_start<H: PasswordSignInHost>(
    host: &H,
    principal: &str,
    credential_request: &[u8],
    identity: String,
) -> Result<Started, H::Error> {
    let credential_response = host
        .opaque()
        .fake_login_start(credential_request, &decoy_credential_id(principal))
        .map_err(|e| {
            // A malformed request fails here as it would on a real account:
            // the same answer either way.
            warn!("OPAQUE fake login start failed: {}", e);
            PasswordSignInError::AuthenticationFailed
        })?;
    let state_key = uuid::Uuid::now_v7().to_string();
    host.pending()
        .insert(&state_key, &PendingSignIn::Decoy { identity })
        .await
        .map_err(PasswordSignInError::from)?;
    Ok(Started {
        credential_response,
        state_key,
    })
}

/// Start a sign-in of `principal`. A start that cannot succeed is answered
/// like a real one (a decoy), never refused early; failed attempts count
/// against the account when one holds the principal, else the principal.
pub async fn start<H: PasswordSignInHost>(
    host: &H,
    principal: &str,
    credential_request: &[u8],
) -> Result<Started, H::Error> {
    let owner = host.resolve(principal).await?;
    let identity = owner
        .as_ref()
        .map_or_else(|| principal.to_string(), ToString::to_string);
    host.refuse_if_locked(&identity).await?;

    let Some(owner) = owner else {
        return decoy_start(host, principal, credential_request, identity).await;
    };

    let passwords = host
        .credentials()
        .get_credentials_by_profile(owner.clone(), Some(CredentialType::Opaque))
        .await
        .map_err(storage)?;
    // The store keeps at most one active password per account; revoked rows
    // stay for history and never authenticate.
    let Some(password) = passwords.iter().find(|c| c.status.is_active()) else {
        let imported = host
            .credentials()
            .get_credentials_by_profile(owner, Some(CredentialType::LegacyHash))
            .await
            .map_err(storage)?;
        if !imported.is_empty() {
            return Err(PasswordSignInError::MigrationRequired.into());
        }
        // An account without a password (passkey-only, provisioned) is
        // answered like an unknown principal.
        return decoy_start(host, principal, credential_request, identity).await;
    };

    let credential_id = host.opaque_credential_identifier(password);
    let opened = host.stored_password(password).await?;
    let (credential_response, state) = host
        .opaque()
        // An ordinary sign-in has the empty context.
        .login_start(&opened.record, credential_request, &credential_id, &[])
        .map_err(|e| {
            warn!("OPAQUE login start failed for {}: {}", principal, e);
            PasswordSignInError::AuthenticationFailed
        })?;

    let state_key = uuid::Uuid::now_v7().to_string();
    host.pending()
        .insert(
            &state_key,
            &PendingSignIn::Password {
                state,
                owner,
                credential_id: password.id,
                credential_data: opened.stored,
            },
        )
        .await
        .map_err(PasswordSignInError::from)?;
    Ok(Started {
        credential_response,
        state_key,
    })
}

/// Finish the sign-in stored under `state_key`: the account whose password
/// `finalization` proves, after its password is marked used. A lockout is
/// checked before the password, so during one a right and a wrong password
/// get the same answer.
pub async fn finish<H: PasswordSignInHost>(
    host: &H,
    state_key: &str,
    finalization: &[u8],
) -> Result<Verified<H::Account>, H::Error> {
    let pending = match host.pending().take(state_key).await {
        Ok(pending) => pending.ok_or(PasswordSignInError::Expired)?,
        // A state this build cannot read (an earlier build's, without the
        // password's stored form to fence on) is spent: the client starts
        // again, as after an expiry.
        Err(ChallengeStoreError::Encoding(_)) => return Err(PasswordSignInError::Expired.into()),
        Err(e) => return Err(PasswordSignInError::from(e).into()),
    };
    let (state, owner, credential_id, credential_data) = match pending {
        PendingSignIn::Password {
            state,
            owner,
            credential_id,
            credential_data,
        } => (state, owner, credential_id, credential_data),
        PendingSignIn::Decoy { identity } => {
            // A lockout reached while this attempt was in flight answers the
            // same here as for a real account.
            host.refuse_if_locked(&identity).await?;
            host.record_failure(&identity).await?;
            return Err(PasswordSignInError::AuthenticationFailed.into());
        }
    };
    let identity = owner.to_string();
    host.refuse_if_locked(&identity).await?;

    if let Err(e) = host.opaque().login_finish(&state, finalization, &[]) {
        warn!("OPAQUE login finish failed: {}", e);
        host.record_failure(&identity).await?;
        return Err(PasswordSignInError::AuthenticationFailed.into());
    }

    // An account removed while the sign-in was in flight signs nobody in.
    let account = host
        .account(&owner)
        .await?
        .ok_or(PasswordSignInError::AuthenticationFailed)?;

    // The password this sign-in used must still be active: one revoked while
    // the sign-in was in flight neither signs in nor comes back to active.
    let still_active = host
        .credentials()
        .mark_credential_used(
            credential_id,
            AuditEntry::user(identity, "credential.used", credential_id.0.to_string()).into(),
        )
        .await
        .map_err(storage)?;
    if !still_active {
        return Err(PasswordSignInError::AuthenticationFailed.into());
    }
    Ok(Verified {
        account,
        proved_by: CredentialFence {
            id: credential_id,
            data: credential_data,
        },
    })
}

#[cfg(test)]
mod tests;
