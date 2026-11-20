// SPDX-License-Identifier: AGPL-3.0-only
//! The store of browser authorization operations awaiting or carrying the
//! user's consent decision (authz/consent-flow.md, decision, persistence and
//! continuation).
//!
//! Every transition is written over the state it was read in, so replicas
//! racing on one operation agree on one decision and at most one code. A
//! decision commits together with the consent it grants and its audit entry;
//! the code commits together with the operation's completion.

use async_trait::async_trait;
use jiff::Timestamp;
use sid_core::Result;
use sid_core::models::{
    AuthorizationCode, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    CompletionOutcome, DecisionOutcome, MutationContext, SessionId,
};

/// The authorization operations of one installation.
#[async_trait]
pub trait AuthorizationOperationStore: Send + Sync {
    /// Hold a new operation awaiting consent. An existing id is `Conflict`:
    /// nothing is replaced.
    async fn create_authorization_operation(
        &self,
        operation: &AuthorizationOperation,
        ctx: MutationContext,
    ) -> Result<()>;

    /// The operation `id` names, in whatever state it is.
    async fn authorization_operation(
        &self,
        id: AuthorizationOperationId,
    ) -> Result<Option<AuthorizationOperation>>;

    /// Record `decision` for the operation at `revision`, decided through
    /// `session`, at `now`.
    ///
    /// Only an operation of that session, awaiting consent, unexpired and at
    /// that revision takes a decision; it then moves to approved or denied
    /// and its revision moves on. An approval, in the same commit, makes the
    /// consent of the operation's Profile to its client active and grants the
    /// operation's scopes for its resource and the chosen claims; a denial
    /// grants nothing and changes no earlier consent. `ctx` commits only with
    /// a recorded decision.
    ///
    /// An approval commits only while the selected Profile and its primary
    /// contacts, read in the same commit and held unchanged until it ends,
    /// still give `shown`, the values the holder reviewed
    /// ([`AuthorizationOperation::shown`]); otherwise it is
    /// [`DecisionOutcome::Stale`] and nothing is written.
    ///
    /// The same decision repeated for the revision it was recorded at answers
    /// [`DecisionOutcome::Replayed`] and writes nothing, without reading the
    /// Profile again; another decision, or another revision, is
    /// [`DecisionOutcome::Conflict`]; an operation that is gone, expired or
    /// another session's is [`DecisionOutcome::NotFound`].
    #[allow(clippy::too_many_arguments)]
    async fn decide_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        session: SessionId,
        revision: u64,
        decision: &AuthorizationDecision,
        shown: &[(String, Option<sid_core::models::DisclosedValue>)],
        now: Timestamp,
        ctx: MutationContext,
    ) -> Result<DecisionOutcome>;

    /// Complete the decided operation `id` at the issuer, at `now`: an
    /// approved one stores `code` in the same commit (which must be given),
    /// a denied one stores nothing. Completes at most once: an operation
    /// already completed, expired, or never decided is
    /// [`CompletionOutcome::NotDecided`] and nothing is written. `ctx`
    /// commits only with the completion.
    async fn complete_authorization_operation(
        &self,
        id: AuthorizationOperationId,
        code: Option<&AuthorizationCode>,
        now: Timestamp,
        ctx: MutationContext,
    ) -> Result<CompletionOutcome>;
}
