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
    ClaimType, DecisionOutcome, DisclosedValue, MutationContext, OAuth2Client, OidcIssuer, Session,
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
    /// Each reviewed claim, in the operation's order, with the value
    /// approving discloses; none when the Profile holds no value.
    pub shown: Vec<(String, Option<DisclosedValue>)>,
    /// The value a decision on this revision and these shown values carries.
    pub csrf: [u8; 64],
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

/// The context binding a review's CSRF value to the values it showed: the
/// operation and revision, then each reviewed claim with its value, in the
/// operation's order. A value changed after the review no longer matches.
fn shown_context(
    id: AuthorizationOperationId,
    revision: u64,
    shown: &[(String, Option<DisclosedValue>)],
) -> Vec<u8> {
    let mut context = csrf_context(id, revision);
    for (name, value) in shown {
        context.push(0);
        context.extend_from_slice(name.as_bytes());
        context.push(0);
        match value {
            None => context.push(0),
            Some(value) => {
                context.push(1);
                context.extend_from_slice(value.value.as_bytes());
                context.push(0);
                context.push(match value.verified {
                    None => 0,
                    Some(false) => 1,
                    Some(true) => 2,
                });
            }
        }
    }
    context
}

/// The claims an OIDC request asks for through its scopes, OIDC Core 1.0
/// §5.4: the ones of the admitted `profile`, `email` and `phone` scopes this
/// issuer holds values for. `openid` alone asks for none.
pub fn scope_claims(scopes: &[String]) -> Vec<&'static str> {
    let mut claims = Vec::new();
    for scope in scopes {
        claims.extend_from_slice(match scope.as_str() {
            "profile" => &[
                "name",
                "given_name",
                "family_name",
                "middle_name",
                "preferred_username",
            ][..],
            "email" => &["email"][..],
            "phone" => &["phone_number"][..],
            _ => &[][..],
        });
    }
    claims
}

/// The claims a review covers for a client that registered `registered` and
/// asks for `scopes`, with `held`, the holder's current consent: the
/// registered requests, then each
/// claim the scopes ask for that it did not register, as voluntary and
/// without updates (consent-flow.md, OIDC scope requests), then every claim
/// disclosed before, so the whole disclosure is reviewed (identity-model.md,
/// recipient disclosure). Each claim once.
pub fn review_requests(
    registered: &[ClaimRequest],
    scopes: &[String],
    held: Option<&sid_core::models::ConsentRecord>,
) -> Vec<ClaimRequest> {
    let mut requests = registered.to_vec();
    let mut add = |request: ClaimRequest| {
        if !requests.iter().any(|r| r.claim_name == request.claim_name) {
            requests.push(request);
        }
    };
    for name in scope_claims(scopes) {
        add(ClaimRequest::optional(name, ClaimType::Data));
    }
    for grant in held
        .filter(|c| c.status.is_active())
        .map(|c| c.grants.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|g| g.is_active())
    {
        add(ClaimRequest::optional(
            grant.claim_name.clone(),
            grant.claim_type,
        ));
    }
    requests
}

use sid_core::models::consent::disclosed_for;

/// The sharing choices a claim request admits, in the order shown, when the
/// Profile holds a value for it; without one, only not sharing.
pub fn allowed_sharing(request: &ClaimRequest, has_value: bool) -> Vec<ClaimSharing> {
    [
        ClaimSharing::None,
        ClaimSharing::Static,
        ClaimSharing::Subscribed,
    ]
    .into_iter()
    .filter(|sharing| request.admits(*sharing))
    .filter(|sharing| has_value || *sharing == ClaimSharing::None)
    .collect()
}

impl OAuth {
    /// The value each claim this issuer discloses has in Profile `profile`
    /// now, from one version of it: its names, username and primary
    /// contacts are read from one consistent state of the store, so a review
    /// and its commit each see a whole version, never a mix.
    pub(crate) async fn current_values(
        &self,
        profile: sid_core::models::ProfileId,
    ) -> Result<Vec<(&'static str, DisclosedValue)>, SidError> {
        Ok(self
            .storage
            .get_profile_with_primary_contacts(profile)
            .await?
            .map(|found| {
                sid_core::models::consent::claim_values(
                    &found.profile,
                    found.email.as_ref(),
                    found.phone.as_ref(),
                )
            })
            .unwrap_or_default())
    }

    /// The disclosure Profile `profile` holds for client `client_id` now, as
    /// committed: its consent, with the subscriptions' pull delivery of a
    /// later Profile edit committed first when every changed value is
    /// subscribed, so UserInfo and the tokens read a committed snapshot and
    /// never the live Profile (consent-flow.md, claim update propagation).
    /// A delivery lost to a decision committed meanwhile is retried from
    /// what that one committed. When the Profile values cannot be read, no
    /// delivery is attempted and the consent as read is answered. A failed
    /// delivery write has an unknown outcome (its commit may have landed),
    /// so the consent is read again and that committed state is answered;
    /// when even that read fails, the call fails rather than disclose from
    /// a copy that may no longer be in force.
    pub(crate) async fn held_disclosure(
        &self,
        profile: sid_core::models::ProfileId,
        client_id: &str,
    ) -> Result<Option<sid_core::models::ConsentRecord>, SidError> {
        let mut held = self
            .storage
            .get_consent_by_client(profile, client_id)
            .await?;
        for _ in 0..3 {
            let Some(current) = held.as_ref() else {
                return Ok(None);
            };
            let subscribed = current.status.is_active()
                && current
                    .grants
                    .iter()
                    .any(|g| g.is_active() && g.mode == sid_core::models::ConsentMode::Subscribed);
            if !subscribed {
                return Ok(held);
            }
            let values = match self.current_values(profile).await {
                Ok(values) => values,
                Err(e) => {
                    tracing::warn!(error = %e, "subscribed delivery: Profile values unreadable");
                    return Ok(held);
                }
            };
            let Some(updates) = current.subscribed_delivery(|grant| {
                disclosed_for(
                    &ClaimRequest::optional(grant.claim_name.clone(), grant.claim_type),
                    &values,
                )
            }) else {
                return Ok(held);
            };
            let ctx: MutationContext =
                AuditEntry::system("consent.deliver", current.id.0.to_string()).into();
            match self
                .storage
                .deliver_subscribed(current, &updates, ctx)
                .await
            {
                Ok(Some(delivered)) => return Ok(Some(delivered)),
                Ok(None) => {
                    held = self
                        .storage
                        .get_consent_by_client(profile, client_id)
                        .await?;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "subscribed delivery outcome unknown");
                    return self.storage.get_consent_by_client(profile, client_id).await;
                }
            }
        }
        Ok(held)
    }

    /// What `operation`'s review shows: each reviewed claim with the value
    /// it discloses from the Profile now.
    async fn shown(
        &self,
        operation: &AuthorizationOperation,
    ) -> Result<Vec<(String, Option<DisclosedValue>)>, SidError> {
        let values = self.current_values(operation.profile_id).await?;
        Ok(operation.shown(&values))
    }

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
        let shown = self.shown(&operation).await?;
        // Two values: one authenticates this session, operation and
        // revision; the other also binds what this review showed, so a value
        // changed before the decision makes it stale rather than approve
        // another disclosure.
        let mut csrf = [0u8; 64];
        csrf[..32].copy_from_slice(&BrowserCsrf::bound(
            &token,
            &csrf_context(operation.id, operation.revision),
        ));
        csrf[32..].copy_from_slice(&BrowserCsrf::bound(
            &token,
            &shown_context(operation.id, operation.revision, &shown),
        ));
        Ok(ConsentReview {
            csrf,
            issuer: issuer.canonical_url.clone(),
            client,
            resource: resource.indicator.to_string(),
            identity,
            shown,
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
        let (authentic, content) = csrf.split_at(csrf.len().min(32));
        if !BrowserCsrf::bound_matches(authentic, &token, &csrf_context(id, revision)) {
            return Err(ConsentError::Csrf);
        }
        // A decision already recorded for this revision, submitted again
        // after a lost reply, answers the committed outcome, even if the
        // Profile changed since: the recorded values stand.
        if operation.revision == revision + 1
            && let Some(recorded) = &operation.decision
            && same_choices(&operation.claim_requests, recorded, &decision)
        {
            return Ok(self.view(issuer, operation, now));
        }
        let (decision, shown) = match decision {
            SubmittedDecision::Deny => (AuthorizationDecision::Deny, Vec::new()),
            // Read against the claim requests pinned on the operation and the
            // values the review showed: a registration or a value changed
            // meanwhile never turns this approval into another disclosure.
            // The store checks the same values again inside the commit, so
            // a change landing after this check is caught there too.
            SubmittedDecision::Approve(choices) => {
                let shown = self.shown(&operation).await?;
                if !BrowserCsrf::bound_matches(
                    content,
                    &token,
                    &shown_context(id, revision, &shown),
                ) {
                    return Err(ConsentError::Stale);
                }
                let choices = reviewed_choices(&operation.claim_requests, &shown, choices)?;
                (AuthorizationDecision::Approve { choices }, shown)
            }
        };
        let ctx: MutationContext = AuditEntry::user(
            session.profile_id.to_string(),
            "authorization_operation.decide",
            operation.client_id.clone(),
        )
        .into();
        let decided = match self
            .storage
            .decide_authorization_operation(id, session.id, revision, &decision, &shown, now, ctx)
            .await?
        {
            DecisionOutcome::Recorded(op) | DecisionOutcome::Replayed(op) => op,
            DecisionOutcome::Conflict | DecisionOutcome::Stale => return Err(ConsentError::Stale),
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

/// Whether `submitted` is the holder's `recorded` decision on `requests`,
/// the operation's pinned claim requests: both denials, or an approval with
/// exactly one choice per requested claim, the recorded sharing for a claim
/// recorded, and not sharing for one the review showed without a value
/// (which records no choice). Read from the recorded decision alone, never
/// the Profile now.
fn same_choices(
    requests: &[ClaimRequest],
    recorded: &AuthorizationDecision,
    submitted: &SubmittedDecision,
) -> bool {
    match (recorded, submitted) {
        (AuthorizationDecision::Deny, SubmittedDecision::Deny) => true,
        (AuthorizationDecision::Approve { choices }, SubmittedDecision::Approve(submitted)) => {
            submitted.len() == requests.len()
                && requests.iter().all(|request| {
                    let mut given = submitted
                        .iter()
                        .filter(|(name, _)| *name == request.claim_name);
                    let (Some((_, sharing)), None) = (given.next(), given.next()) else {
                        return false;
                    };
                    match choices.iter().find(|c| c.name == request.claim_name) {
                        Some(choice) => choice.sharing == *sharing,
                        None => *sharing == ClaimSharing::None,
                    }
                })
        }
        _ => false,
    }
}

/// The approval's choices against `requests`, the reviewed claim requests,
/// and `shown`, the values the review showed for them in the same order: one
/// choice per request, each one the request admits, sharing only a claim
/// with a value; nothing else. Each shared choice carries its shown value.
fn reviewed_choices(
    requests: &[ClaimRequest],
    shown: &[(String, Option<DisclosedValue>)],
    mut submitted: Vec<(String, ClaimSharing)>,
) -> Result<Vec<ClaimChoice>, ConsentError> {
    let mut choices = Vec::with_capacity(requests.len());
    for (request, (_, value)) in requests.iter().zip(shown) {
        let at = submitted
            .iter()
            .position(|(name, _)| *name == request.claim_name)
            .ok_or_else(|| ConsentError::Choice(request.claim_name.clone()))?;
        let (name, sharing) = submitted.swap_remove(at);
        if !allowed_sharing(request, value.is_some()).contains(&sharing) {
            return Err(ConsentError::Choice(name));
        }
        // A claim the Profile has no value for offered no choice: not
        // sharing it is no refusal, so it records nothing and is reviewed
        // once a value exists (consent-flow.md, OIDC scope requests).
        if value.is_none() {
            continue;
        }
        choices.push(ClaimChoice {
            name,
            claim_type: request.claim_type,
            sharing,
            disclosed: (sharing != ClaimSharing::None)
                .then(|| value.clone())
                .flatten(),
        });
    }
    if let Some((name, _)) = submitted.into_iter().next() {
        return Err(ConsentError::Choice(name));
    }
    Ok(choices)
}

#[cfg(test)]
mod tests;
