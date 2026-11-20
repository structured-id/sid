// SPDX-License-Identifier: AGPL-3.0-only
//! A browser authorization that needs the user's consent, kept in the owning
//! store from the review to the issuer's one code issuance
//! (authz/consent-flow.md, browser consent transaction).
//!
//! The operation pins everything the issuer validated: issuer, client,
//! redirect and response parameters, resource, scopes, the IdP session and
//! the Profile it authenticated. A decision only ever names the operation,
//! its revision and its CSRF value; it cannot nominate any of these. The
//! CSRF value is derived from session, operation and revision under an
//! installation key, so nothing about it is stored.

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

pub use sid_ids::AuthorizationOperationId;

use super::consent::{ClaimType, ConsentMode, ConsentRecord};
use super::{IssuerId, ProfileId, ResourceId, SessionId};

/// How long an operation waits for a decision and, once decided, for the
/// browser to continue at the issuer.
pub const AUTHORIZATION_OPERATION_LIFETIME_SECS: i64 = 600;

/// Where an authorization operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    /// Waiting for the user's decision.
    AwaitingConsent,
    /// Approved; the issuer issues the code when the browser continues.
    Approved,
    /// Denied; the issuer returns `access_denied` when the browser continues.
    Denied,
    /// The issuer issued the one code or delivered the denial.
    Completed,
    /// Expired or superseded before completing.
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwaitingConsent => "awaiting_consent",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }
}

parse_stored!(
    AuthorizationStatus,
    "authorization status",
    [AwaitingConsent, Approved, Denied, Completed, Expired]
);

impl std::fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a claim is shared with the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSharing {
    /// Not shared.
    None,
    /// The current value only.
    Static,
    /// The current value and its later changes.
    Subscribed,
}

impl ClaimSharing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Static => "static",
            Self::Subscribed => "subscribed",
        }
    }
}

parse_stored!(ClaimSharing, "claim sharing", [None, Static, Subscribed]);

/// The user's choice for one reviewed claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimChoice {
    pub name: String,
    /// Data or attestation, as the client registered the claim: resolved by
    /// the issuer from the registration, never taken from the browser.
    pub claim_type: ClaimType,
    pub sharing: ClaimSharing,
}

impl ClaimChoice {
    /// The consent mode this choice grants, or `None` when it shares nothing.
    pub fn mode(&self) -> Option<ConsentMode> {
        match self.sharing {
            ClaimSharing::None => None,
            ClaimSharing::Static => Some(ConsentMode::Static),
            ClaimSharing::Subscribed => Some(ConsentMode::Subscribed),
        }
    }
}

/// The user's decision on an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationDecision {
    /// Grant the reviewed scopes with these claim choices.
    Approve { choices: Vec<ClaimChoice> },
    /// Refuse this request; earlier grants are not affected.
    Deny,
}

/// One browser authorization operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationOperation {
    pub id: AuthorizationOperationId,
    /// The issuer whose endpoint validated the request.
    pub issuer_id: IssuerId,
    /// The registered client (RFC 6749 §2.2).
    pub client_id: String,
    /// The validated, registered redirect URI, exactly as requested.
    pub redirect_uri: String,
    pub response_type: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    /// The resource the code's tokens will be for (RFC 8707).
    pub resource_id: ResourceId,
    /// The scopes granted on approval, in the requested order.
    pub scopes: Vec<String>,
    /// The IdP session that authenticated the review; only it reads and
    /// decides the operation.
    pub session_id: SessionId,
    /// The Profile that session authenticated: the selected identity.
    pub profile_id: ProfileId,
    pub status: AuthorizationStatus,
    /// Moves on with every decision; a decision names the revision reviewed.
    pub revision: u64,
    /// The recorded decision, once made.
    pub decision: Option<AuthorizationDecision>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub decided_at: Option<Timestamp>,
}

impl AuthorizationOperation {
    /// Whether it has outlived its lifetime at `now`.
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// The lifetime of an operation created at `now`.
    pub fn expiry_from(now: Timestamp) -> Timestamp {
        now + SignedDuration::from_secs(AUTHORIZATION_OPERATION_LIFETIME_SECS)
    }

    /// What recording `decision` through `session` for `revision` at `now`
    /// does to this operation as stored. Every store applies this one rule
    /// over the state it holds locked.
    pub fn decide(
        &self,
        session: SessionId,
        revision: u64,
        decision: &AuthorizationDecision,
        now: Timestamp,
    ) -> DecisionStep {
        if self.session_id != session || self.is_expired_at(now) {
            return DecisionStep::NotFound;
        }
        match self.status {
            AuthorizationStatus::AwaitingConsent if self.revision == revision => {
                let mut decided = self.clone();
                decided.status = match decision {
                    AuthorizationDecision::Approve { .. } => AuthorizationStatus::Approved,
                    AuthorizationDecision::Deny => AuthorizationStatus::Denied,
                };
                decided.revision = self.revision + 1;
                decided.decision = Some(decision.clone());
                decided.decided_at = Some(now);
                DecisionStep::Apply(Box::new(decided))
            }
            // The decision recorded for the revision reviewed, repeated: the
            // committed outcome, nothing written again.
            AuthorizationStatus::Approved
            | AuthorizationStatus::Denied
            | AuthorizationStatus::Completed
                if self.revision == revision + 1 && self.decision.as_ref() == Some(decision) =>
            {
                DecisionStep::Replayed
            }
            AuthorizationStatus::Expired => DecisionStep::NotFound,
            _ => DecisionStep::Conflict,
        }
    }

    /// Whether the issuer may complete this operation at `now`: decided,
    /// not completed, not expired.
    pub fn completable_at(&self, now: Timestamp) -> bool {
        matches!(
            self.status,
            AuthorizationStatus::Approved | AuthorizationStatus::Denied
        ) && !self.is_expired_at(now)
    }

    /// The consent an approval with `choices` leaves for this operation's
    /// Profile and client, from `held`, the consent stored for that pair if
    /// any: active, with the operation's scopes for its resource and every
    /// shared claim granted in its chosen mode. Earlier grants stay; their
    /// revocation is a separate account operation (consent-flow.md, commit
    /// the decision).
    pub fn approved_consent(
        &self,
        held: Option<ConsentRecord>,
        choices: &[ClaimChoice],
    ) -> ConsentRecord {
        let mut consent =
            held.unwrap_or_else(|| ConsentRecord::new(self.profile_id, self.client_id.clone()));
        if !consent.status.is_active() {
            consent.status = super::consent::ConsentStatus::Active;
            consent.revoked_at = None;
        }
        consent.grant_scopes(self.resource_id, &self.scopes);
        for choice in choices {
            if let Some(mode) = choice.mode() {
                consent.grant_claim(choice.name.clone(), choice.claim_type, mode);
            }
        }
        consent
    }
}

/// What [`AuthorizationOperation::decide`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionStep {
    /// Store this operation, the decision recorded.
    Apply(Box<AuthorizationOperation>),
    /// Already recorded as asked: write nothing.
    Replayed,
    /// Another decision, or another revision: write nothing.
    Conflict,
    /// Not this session's, expired: write nothing.
    NotFound,
}

/// What recording a decision did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// This call recorded the decision; the operation as now stored.
    Recorded(AuthorizationOperation),
    /// The same decision was already recorded for that revision: nothing was
    /// written again.
    Replayed(AuthorizationOperation),
    /// Another decision was recorded for that revision, or the revision is
    /// not the current one: nothing written.
    Conflict,
    /// The operation is gone, expired, or not this session's.
    NotFound,
}

/// What completing an operation at the issuer did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// This call completed it (and, for an approval, stored the code).
    Completed,
    /// It was already completed, expired, or never decided: nothing written.
    NotDecided,
}

#[cfg(test)]
mod tests;
