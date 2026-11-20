// SPDX-License-Identifier: AGPL-3.0-only
//! The browser authorization consent interaction (authz/consent-flow.md,
//! narrow interaction API authority; ux/branding-theming.md, authorization
//! consent API): the review of one operation, the user's decision on the
//! revision reviewed, and the operation's durable state. Every call is the
//! browser's own IdP session; the operation is read only by the session it is
//! bound to, at the issuer it belongs to. Recording a decision issues no
//! code: the issuer's authorization endpoint does, on the continuation.

use jiff::Timestamp;
use sid_authn::browser_session::BrowserCsrf;
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    AuthorizationStatus, ClaimChoice, ClaimLevel, ClaimRequest, ClaimSharing, ClaimSubscription,
    ClaimType, DecisionOutcome, MutationContext, OAuth2Client, OidcIssuer, Session,
};
use sid_proto::sid::v1::common;

use super::OAuth;
use super::authorization::operation_continuation;
use crate::sign_in::SignIn;

/// Why a consent interaction call is refused.
#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    /// No operation this session may read: another session's or issuer's,
    /// gone, expired, or no longer under review. The same for every cause.
    #[error("no such authorization operation")]
    NotFound,
    /// The CSRF value is not this session's for this operation and revision.
    #[error("the CSRF value is not this review's")]
    Csrf,
    /// The revision reviewed is not the operation's current one, or another
    /// decision was recorded for it.
    #[error("the operation changed since it was reviewed")]
    Stale,
    /// A claim choice the review did not offer, or one missing.
    #[error("claim {0}: not a choice the review offered")]
    Choice(String),
    #[error(transparent)]
    Store(#[from] SidError),
}

/// What the user reviews for one operation.
pub struct ConsentReview {
    pub operation: AuthorizationOperation,
    pub issuer: String,
    pub client: OAuth2Client,
    /// The resource indicator the tokens will be for (RFC 8707 §2).
    pub resource: String,
    /// How the selected identity is shown to the user.
    pub identity: String,
    /// The value a decision on this revision carries.
    pub csrf: [u8; 32],
}

/// An operation's durable state, with the issuer continuation while its
/// outcome is yet to be delivered.
pub struct FlowView {
    pub operation: AuthorizationOperation,
    pub continuation: Option<url::Url>,
}

/// The user's decision as submitted: per claim, the sharing chosen.
pub enum SubmittedDecision {
    Approve(Vec<(String, ClaimSharing)>),
    Deny,
}

/// A decision submitted on one reviewed revision of an operation, with the
/// CSRF value that review returned.
pub struct Submission {
    pub operation: AuthorizationOperationId,
    pub revision: u64,
    pub csrf: Vec<u8>,
    pub decision: SubmittedDecision,
}

/// The wire form of a claim's request level.
pub fn level_to_wire(level: ClaimLevel) -> common::ClaimRequestLevel {
    match level {
        ClaimLevel::Required => common::ClaimRequestLevel::Required,
        ClaimLevel::Demanded => common::ClaimRequestLevel::Demanded,
        ClaimLevel::Optional => common::ClaimRequestLevel::Optional,
    }
}

/// The wire form of a client's claim request.
pub fn claim_request_to_wire(request: &ClaimRequest) -> common::ClaimRequest {
    common::ClaimRequest {
        name: request.claim_name.clone(),
        level: level_to_wire(request.level).into(),
        subscription: match request.subscription {
            ClaimSubscription::Required => common::ClaimSubscription::Required,
            ClaimSubscription::Preferred => common::ClaimSubscription::Preferred,
            ClaimSubscription::None => common::ClaimSubscription::None,
        }
        .into(),
        r#type: match request.claim_type {
            ClaimType::Data => common::ClaimType::Data,
            ClaimType::Attestation => common::ClaimType::Attestation,
        }
        .into(),
        justification: request.justification.clone(),
    }
}

/// A client's claim requests as registered: each named once, with a known
/// level, subscription and type, a demanded one with its justification.
/// The refusal says which request and why.
pub fn claim_requests_from_wire(
    wire: Vec<common::ClaimRequest>,
) -> Result<Vec<ClaimRequest>, String> {
    let mut requests: Vec<ClaimRequest> = Vec::with_capacity(wire.len());
    for request in wire {
        let name = request.name.trim().to_owned();
        if name.is_empty() {
            return Err("a claim request names no claim".into());
        }
        if requests.iter().any(|r| r.claim_name == name) {
            return Err(format!("claim {name} is requested twice"));
        }
        let level = match common::ClaimRequestLevel::try_from(request.level) {
            Ok(common::ClaimRequestLevel::Required) => ClaimLevel::Required,
            Ok(common::ClaimRequestLevel::Demanded) => ClaimLevel::Demanded,
            Ok(common::ClaimRequestLevel::Optional) => ClaimLevel::Optional,
            _ => return Err(format!("claim {name}: a request level")),
        };
        let subscription = match common::ClaimSubscription::try_from(request.subscription) {
            Ok(common::ClaimSubscription::Required) => ClaimSubscription::Required,
            Ok(common::ClaimSubscription::Preferred) => ClaimSubscription::Preferred,
            Ok(common::ClaimSubscription::None) => ClaimSubscription::None,
            _ => return Err(format!("claim {name}: a subscription")),
        };
        let claim_type = match common::ClaimType::try_from(request.r#type) {
            Ok(common::ClaimType::Data) => ClaimType::Data,
            Ok(common::ClaimType::Attestation) => ClaimType::Attestation,
            _ => return Err(format!("claim {name}: a claim type")),
        };
        let justification = request
            .justification
            .map(|j| j.trim().to_owned())
            .filter(|j| !j.is_empty());
        if level == ClaimLevel::Demanded && justification.is_none() {
            return Err(format!("claim {name}: a demanded claim states why"));
        }
        requests.push(ClaimRequest {
            claim_name: name,
            level,
            subscription,
            claim_type,
            justification,
        });
    }
    Ok(requests)
}

/// The CSRF context of `id` at `revision`.
fn csrf_context(id: AuthorizationOperationId, revision: u64) -> Vec<u8> {
    format!("authorization-operation:{id}:{revision}").into_bytes()
}

/// The sharing choices a claim request admits, in the order shown.
pub fn allowed_sharing(request: &ClaimRequest) -> Vec<ClaimSharing> {
    [
        ClaimSharing::None,
        ClaimSharing::Static,
        ClaimSharing::Subscribed,
    ]
    .into_iter()
    .filter(|sharing| request.admits(*sharing))
    .collect()
}

impl OAuth {
    /// The operation `id` at `issuer`, for `session`, the browser's IdP
    /// session: live, and the one the operation is bound to.
    async fn session_operation(
        &self,
        sign_in: &SignIn,
        issuer: &OidcIssuer,
        session: Option<&Session>,
        id: AuthorizationOperationId,
        now: Timestamp,
    ) -> Result<(AuthorizationOperation, Session), ConsentError> {
        let session = session
            .filter(|s| sign_in.authorizes(s, now))
            .ok_or(ConsentError::NotFound)?;
        let operation = self
            .storage
            .authorization_operation(id)
            .await?
            .filter(|op| op.issuer_id == issuer.id)
            .filter(|op| op.session_id == session.id && op.profile_id == session.profile_id)
            .ok_or(ConsentError::NotFound)?;
        Ok((operation, session.clone()))
    }

    /// The review of operation `id` for `session` at `issuer`: what the
    /// client asks for and the CSRF value bound to this session, operation
    /// and revision. Only an operation awaiting a decision is reviewed;
    /// reading approves nothing.
    pub async fn review_consent(
        &self,
        sign_in: &SignIn,
        issuer: &OidcIssuer,
        session: Option<&Session>,
        id: AuthorizationOperationId,
    ) -> Result<ConsentReview, ConsentError> {
        let now = Timestamp::now();
        let (operation, session) = self
            .session_operation(sign_in, issuer, session, id, now)
            .await?;
        if operation.status != AuthorizationStatus::AwaitingConsent || operation.is_expired_at(now)
        {
            return Err(ConsentError::NotFound);
        }
        let token = session.browser_csrf.ok_or(ConsentError::NotFound)?;
        let client = self
            .storage
            .get_oauth2_client(&operation.client_id)
            .await?
            .filter(|c| c.active)
            .ok_or(ConsentError::NotFound)?;
        let resource = self
            .storage
            .get_protected_resource(operation.resource_id)
            .await?
            .ok_or(ConsentError::NotFound)?;
        let identity = self
            .storage
            .get_profile(operation.profile_id)
            .await?
            .and_then(|p| p.formatted_name().or(p.username.clone()))
            .unwrap_or_default();
        Ok(ConsentReview {
            csrf: BrowserCsrf::bound(&token, &csrf_context(operation.id, operation.revision)),
            issuer: issuer.canonical_url.clone(),
            client,
            resource: resource.indicator.to_string(),
            identity,
            operation,
        })
    }

    /// Record the `submission`'s decision on its operation for the revision
    /// reviewed, with the CSRF value that review returned. The client's
    /// registered claim requests decide what each claim is and which sharing
    /// is allowed; the request names only the choices. The same decision
    /// again answers the committed state.
    pub async fn submit_consent(
        &self,
        sign_in: &SignIn,
        issuer: &OidcIssuer,
        session: Option<&Session>,
        submission: Submission,
    ) -> Result<FlowView, ConsentError> {
        let Submission {
            operation: id,
            revision,
            csrf,
            decision,
        } = submission;
        let now = Timestamp::now();
        let (operation, session) = self
            .session_operation(sign_in, issuer, session, id, now)
            .await?;
        let token = session.browser_csrf.ok_or(ConsentError::Csrf)?;
        if !BrowserCsrf::bound_matches(&csrf, &token, &csrf_context(id, revision)) {
            return Err(ConsentError::Csrf);
        }
        let decision = match decision {
            SubmittedDecision::Deny => AuthorizationDecision::Deny,
            // Read against the claim requests pinned on the operation, the
            // ones the review showed: a registration changed meanwhile never
            // turns this approval into a grant of another disclosure.
            SubmittedDecision::Approve(choices) => AuthorizationDecision::Approve {
                choices: reviewed_choices(&operation.claim_requests, choices)?,
            },
        };
        let ctx: MutationContext = AuditEntry::user(
            session.profile_id.to_string(),
            "authorization_operation.decide",
            operation.client_id.clone(),
        )
        .into();
        let decided = match self
            .storage
            .decide_authorization_operation(id, session.id, revision, &decision, now, ctx)
            .await?
        {
            DecisionOutcome::Recorded(op) | DecisionOutcome::Replayed(op) => op,
            DecisionOutcome::Conflict => return Err(ConsentError::Stale),
            DecisionOutcome::NotFound => return Err(ConsentError::NotFound),
        };
        Ok(self.view(issuer, decided, now))
    }

    /// The durable state of operation `id` for `session` at `issuer`.
    pub async fn flow_state(
        &self,
        sign_in: &SignIn,
        issuer: &OidcIssuer,
        session: Option<&Session>,
        id: AuthorizationOperationId,
    ) -> Result<FlowView, ConsentError> {
        let now = Timestamp::now();
        let (operation, _) = self
            .session_operation(sign_in, issuer, session, id, now)
            .await?;
        Ok(self.view(issuer, operation, now))
    }

    /// `operation` with its continuation, present while it is decided and
    /// its outcome not yet delivered.
    fn view(
        &self,
        issuer: &OidcIssuer,
        operation: AuthorizationOperation,
        now: Timestamp,
    ) -> FlowView {
        let continuation = operation
            .completable_at(now)
            .then(|| {
                operation_continuation(&issuer.canonical_url, &operation.client_id, operation.id)
            })
            .flatten();
        FlowView {
            operation,
            continuation,
        }
    }
}

/// The approval's choices against `requests`, the client's registered claim
/// requests: one choice per request, each one the request admits; nothing
/// else.
fn reviewed_choices(
    requests: &[ClaimRequest],
    mut submitted: Vec<(String, ClaimSharing)>,
) -> Result<Vec<ClaimChoice>, ConsentError> {
    let mut choices = Vec::with_capacity(requests.len());
    for request in requests {
        let at = submitted
            .iter()
            .position(|(name, _)| *name == request.claim_name)
            .ok_or_else(|| ConsentError::Choice(request.claim_name.clone()))?;
        let (name, sharing) = submitted.swap_remove(at);
        if !request.admits(sharing) {
            return Err(ConsentError::Choice(name));
        }
        choices.push(ClaimChoice {
            name,
            claim_type: request.claim_type,
            sharing,
        });
    }
    if let Some((name, _)) = submitted.into_iter().next() {
        return Err(ConsentError::Choice(name));
    }
    Ok(choices)
}

#[cfg(test)]
mod tests;
