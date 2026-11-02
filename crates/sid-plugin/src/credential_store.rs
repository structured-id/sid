// SPDX-License-Identifier: AGPL-3.0-only
//! Credential store capability: the authentication factors of an
//! authority's accounts, their password history and their atomic
//! transitions. `Owner` is the account type the authority authenticates;
//! CE's is the local Profile.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{
    Credential, CredentialId, CredentialType, HistoryCommit, MutationContext, PasswordHistory,
};

#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// The account a credential and its password history belong to.
    type Owner: Send + Sync;

    /// Get a credential by ID.
    async fn get_credential(&self, id: CredentialId) -> Result<Option<Credential<Self::Owner>>>;

    /// Get credentials by profile ID and type.
    async fn get_credentials_by_profile(
        &self,
        profile_id: Self::Owner,
        credential_type: Option<CredentialType>,
    ) -> Result<Vec<Credential<Self::Owner>>>;

    /// Store a new credential. An existing id is refused with
    /// `Error::Conflict` and nothing is written: a create never replaces a
    /// credential, so it cannot revive a revoked one.
    async fn create_credential(
        &self,
        credential: &Credential<Self::Owner>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Set the label of an active credential. Returns `false`, writing
    /// nothing, when it is no longer active.
    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Replace an active password credential's data and its policy evidence
    /// (policy version, verification) with those of `new` and mark it used,
    /// only if its data is still `expected`, and with it apply `history` (the
    /// accepted password's entries) to its owner's history. Returns `false`,
    /// writing nothing, when another change came first, the credential is no
    /// longer active or the history moved past `history.expected_revision`.
    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential<Self::Owner>,
        history: Option<&HistoryCommit<Self::Owner>>,
        ctx: MutationContext,
    ) -> Result<bool>;

    // === PASSWORD HISTORY ===
    //
    // The credential service's side: epoch descriptors and retained entries,
    // never key material. The evaluator's keys and lifecycle live in its own
    // store ([`crate::history_keys::HistoryKeyStore`]).

    /// `owner`'s history: its revision, every recorded epoch descriptor and
    /// every retained entry. An owner with no history reads as revision 0,
    /// empty.
    async fn get_password_history(
        &self,
        owner: Self::Owner,
    ) -> Result<PasswordHistory<Self::Owner>>;

    /// The history write cutoff this store records; `None` when none was set.
    async fn history_write_cutoff(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>>;

    /// Raise the history write cutoff to `not_before`: from its commit no
    /// history commit writes an entry under an epoch created before it
    /// (`Error::Fenced`), serialized with those commits. Monotonic: an equal
    /// or earlier value changes nothing. Returns the cutoff in force.
    async fn raise_history_write_cutoff(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> Result<chrono::DateTime<chrono::Utc>>;

    /// Replace a credential's data with the same secret sealed differently,
    /// only if its data is still `expected`. Its status and last use are left
    /// as they are (a revoked secret is sealed too, and stays revoked).
    /// Returns `false`, writing nothing, otherwise.
    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Record that an active credential was just used. Returns `false`,
    /// writing nothing, when the credential is no longer active (revoked
    /// meanwhile), so a sign-in in flight cannot complete on it or revive it.
    async fn mark_credential_used(&self, id: CredentialId, ctx: MutationContext) -> Result<bool>;

    /// Replace an active credential's data with `data` and mark it used, only
    /// if its data is still `expected`. Returns `false`, writing nothing, when
    /// another writer changed it first or it is no longer active: consuming one
    /// of several one-time secrets is a compare-and-swap, so a secret is spent
    /// once even under concurrent use.
    async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Install `credential` in place of its profile's credentials of the types
    /// it replaces (`CredentialType::replaces`: a password, a recovery-code
    /// set) in one transaction: those are deleted and the new one inserted. A
    /// crash leaves either the old ones or the new one, never none and never
    /// both. A type that replaces nothing is refused with `Error::Validation`.
    async fn replace_credential(
        &self,
        credential: &Credential<Self::Owner>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Insert a newly enrolled `credential` (an existing id is `Conflict`)
    /// and, with `recovery`, replace the profile's recovery codes by that set,
    /// in one transaction: a factor is never stored without the codes issued
    /// for it. A `recovery` that is not a recovery-code set is refused with
    /// `Error::Validation`.
    async fn enroll_credential(
        &self,
        credential: &Credential<Self::Owner>,
        recovery: Option<&Credential<Self::Owner>>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Delete a credential by ID.
    async fn delete_credential(&self, id: CredentialId, ctx: MutationContext) -> Result<()>;

    /// Revoke a credential, keeping the record. A profile's last active
    /// primary credential ([`CredentialType::is_primary`]) is not revoked
    /// (`LastPrimary`, nothing written); the check and the revocation are one
    /// step for concurrent revocations of the same profile, so two requests
    /// cannot each remove one of its last two sign-in methods.
    async fn revoke_credential(
        &self,
        id: CredentialId,
        ctx: MutationContext,
    ) -> Result<sid_core::models::CredentialRevocation>;

    /// Delete all credentials for a profile (cascade revocation).
    /// Returns the number of credentials deleted.
    async fn delete_credentials_by_profile(
        &self,
        profile_id: Self::Owner,
        ctx: MutationContext,
    ) -> Result<u64>;

    // === WEBAUTHN USER HANDLES ===
    //
    // One opaque handle per
    // Profile and relying party, created once and kept for all its passkeys.

    /// `profile_id`'s user handle at `rp_id`, storing `candidate` when it has
    /// none. Concurrent calls agree on one stored handle; an existing one is
    /// never replaced. `Error::NotFound` when the profile does not exist,
    /// `Error::Conflict` when `candidate` is another profile's handle there.
    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: Self::Owner,
        rp_id: &str,
        candidate: sid_core::models::WebAuthnUserHandle,
        ctx: MutationContext,
    ) -> Result<sid_core::models::WebAuthnUserHandle>;

    /// The profile whose user handle at `rp_id` is `handle`, if any.
    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: sid_core::models::WebAuthnUserHandle,
    ) -> Result<Option<Self::Owner>>;
}
