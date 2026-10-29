// SPDX-License-Identifier: AGPL-3.0-only
//! Grant store capability: the state an authorization server keeps for its
//! authenticated accounts: sessions, authorization codes and refresh token
//! families, with their atomic transitions. `Owner` is the account type the
//! host authenticates; CE's is the local Profile.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::Result;
use sid_core::models::{
    AuthCodeRedemption, AuthorizationCode, BrowserSecretHash, MutationContext, RefreshToken,
    Session, SessionEnd, SessionId, SignInProof,
};
use uuid::Uuid;

#[async_trait]
pub trait GrantStore: Send + Sync {
    /// The authenticated account a session, code and refresh token belong to.
    type Owner: Send + Sync;

    /// Atomic session creation with concurrent limit enforcement.
    ///
    /// Session creation is serialized per owner, so two concurrent logins
    /// cannot both pass the limit check; an existing id is a `Conflict`.
    ///
    /// If `max_sessions` is 0, no limit is enforced.
    /// If the owner has `max_sessions` or more active sessions, the oldest are
    /// evicted (FIFO) to make room for the new one, with the sessions they
    /// authenticated; each evicted session owes what its end owes, with
    /// reason `SessionLimit`.
    ///
    /// With `proved_by`, the session commits only while what the sign-in
    /// proved still holds, checked in the same transaction and serialized
    /// against its change: a credential still active with the fence's data
    /// (a sign-in whose credential a reset replaced meanwhile gets
    /// `Error::Fenced` and stores nothing; a reset committing after the
    /// session ends it through its own revocation), or a principal still
    /// assigned to the session's owner at the fence's revision. A store that
    /// keeps no principals of its owners refuses an assignment proof with
    /// `Error::Fenced`, never ignores it.
    ///
    /// Returns the list of evicted session IDs (empty if under limit or unlimited).
    async fn create_session_atomic(
        &self,
        session: &Session<Self::Owner>,
        max_sessions: u32,
        proved_by: Option<SignInProof<'_>>,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>>;

    /// Complete a sign-in's pending second-factor context `pending` into
    /// `session`, stored as [`Self::create_session_atomic`] stores one, in
    /// the same transaction that ends `pending` (owing what `end` names):
    /// the session commits only while `pending` exists. Of concurrent
    /// completions one commits; when something ended `pending` first (its
    /// completion, a reset ending the owner's sessions), `Error::Fenced` and
    /// nothing is stored.
    ///
    /// A pending context takes no place under the limit, here or in
    /// [`Self::create_session_atomic`]: it is neither counted nor evicted.
    async fn complete_pending_session(
        &self,
        pending: SessionId,
        end: &SessionEnd,
        session: &Session<Self::Owner>,
        max_sessions: u32,
        proved_by: Option<SignInProof<'_>>,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>>;

    /// Get a session by ID.
    async fn get_session(&self, id: SessionId) -> Result<Option<Session<Self::Owner>>>;

    /// The session a browser signed in with, by the hash of its cookie's
    /// secret; expiry and revocation are the caller's to check.
    async fn get_session_by_browser_secret(
        &self,
        hash: &BrowserSecretHash,
    ) -> Result<Option<Session<Self::Owner>>>;

    /// Every session `owner` holds, expired ones included (what is current
    /// is the caller's to check), newest first.
    async fn list_sessions(&self, owner: &Self::Owner) -> Result<Vec<Session<Self::Owner>>>;

    /// Record activity on session `id` at `at`; last activity only moves
    /// forward. An unknown session is left alone.
    async fn touch_session(&self, id: SessionId, at: DateTime<Utc>) -> Result<()>;

    /// Delete a session by ID and the sessions it authenticated
    /// (`authenticated_by`), returning the ids of every session ended. In
    /// one transaction: their refresh tokens end with them and what each
    /// ended session owes under `end` commits with the deletion; on failure
    /// nothing changes. Deleting a session that is already gone ends and
    /// owes nothing.
    async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> Result<Vec<SessionId>>;

    /// Get a refresh token by its hash.
    async fn get_refresh_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<RefreshToken<Self::Owner>>>;

    /// Revoke all refresh tokens for a session. Returns count revoked.
    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Revoke every refresh token of a rotation family, including those still
    /// inside a grace window, so none of them can be used again. Returns the
    /// count changed. Used when a rotated token is reused (theft).
    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        ctx: MutationContext,
    ) -> Result<u64>;

    /// Rotate a refresh token in one transaction: `old_id` is marked replaced
    /// by `new` (revoked, usable until `grace_expires_at` for a client retry,
    /// an existing grace window is kept) and `new` is stored. Returns `false`,
    /// writing nothing, when `old_id` is neither active nor inside its grace
    /// window (expired, or revoked by sign-out or theft meanwhile).
    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken<Self::Owner>,
        grace_expires_at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Insert an authorization code; an existing code hash is `Conflict`.
    async fn create_auth_code(
        &self,
        code: &AuthorizationCode<Self::Owner>,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Get an authorization code by its hash.
    async fn get_auth_code_by_hash(
        &self,
        code_hash: &[u8],
    ) -> Result<Option<AuthorizationCode<Self::Owner>>>;

    /// Redeem an authorization code exactly once (RFC 6749 §4.1.2).
    ///
    /// In one transaction: mark the code used only if it is not used yet, bind
    /// it to `session`, and store `session` and `refresh_token`. Of any number
    /// of concurrent redemptions exactly one gets `Redeemed`; the others get
    /// `AlreadyRedeemed` with the first redemption's session and store nothing.
    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &Session<Self::Owner>,
        refresh_token: &RefreshToken<Self::Owner>,
        ctx: MutationContext,
    ) -> Result<AuthCodeRedemption>;
}
