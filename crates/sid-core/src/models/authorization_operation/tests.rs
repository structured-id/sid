// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::models::consent::{ClaimRequest, ClaimType, ConsentMode, ConsentRecord, ConsentStatus};

/// A stored status reads back as itself; anything else is refused, never a
/// default state.
#[test]
fn statuses_read_back_exactly() {
    for status in [
        AuthorizationStatus::AwaitingConsent,
        AuthorizationStatus::Approved,
        AuthorizationStatus::Denied,
        AuthorizationStatus::Completed,
        AuthorizationStatus::Expired,
    ] {
        assert_eq!(status.as_str().parse::<AuthorizationStatus>(), Ok(status));
    }
    assert!("approve".parse::<AuthorizationStatus>().is_err());
}

/// A stored sharing mode reads back as itself; anything else is refused.
#[test]
fn sharing_modes_read_back_exactly() {
    for sharing in [
        ClaimSharing::None,
        ClaimSharing::Static,
        ClaimSharing::Subscribed,
    ] {
        assert_eq!(sharing.as_str().parse::<ClaimSharing>(), Ok(sharing));
    }
    assert!("STATIC".parse::<ClaimSharing>().is_err());
}

/// An operation expires exactly at its lifetime's end, not before.
#[test]
fn an_operation_expires_at_the_end_of_its_lifetime() {
    let now = Timestamp::now();
    let expires_at = AuthorizationOperation::expiry_from(now);
    assert_eq!(
        expires_at.duration_since(now),
        SignedDuration::from_secs(AUTHORIZATION_OPERATION_LIFETIME_SECS)
    );
}

fn operation(now: Timestamp) -> AuthorizationOperation {
    AuthorizationOperation {
        id: AuthorizationOperationId::generate(),
        issuer_id: IssuerId::generate(),
        client_id: "rp".into(),
        redirect_uri: "https://rp.sid.example.com/cb".into(),
        response_type: "code".into(),
        state: Some("s".into()),
        code_challenge: Some("c".into()),
        code_challenge_method: Some("S256".into()),
        nonce: None,
        resource_id: ResourceId::generate(),
        scopes: vec!["openid".into(), "read".into()],
        acr_values: None,
        claim_requests: vec![],
        session_id: SessionId::generate(),
        profile_id: ProfileId::generate(),
        status: AuthorizationStatus::AwaitingConsent,
        revision: 0,
        decision: None,
        created_at: now,
        expires_at: AuthorizationOperation::expiry_from(now),
        decided_at: None,
    }
}

fn choice(name: &str, sharing: ClaimSharing) -> ClaimChoice {
    ClaimChoice {
        name: name.into(),
        claim_type: ClaimType::Data,
        sharing,
        disclosed: (sharing != ClaimSharing::None).then(|| DisclosedValue {
            value: format!("{name}-value"),
            verified: None,
        }),
    }
}

fn approve() -> AuthorizationDecision {
    AuthorizationDecision::Approve {
        choices: vec![choice("email", ClaimSharing::Static)],
    }
}

fn applied(step: DecisionStep) -> AuthorizationOperation {
    match step {
        DecisionStep::Apply(op) => *op,
        other => panic!("expected a recorded decision, got {other:?}"),
    }
}

/// A decision through the reviewing session at the reviewed revision moves
/// the operation to approved or denied and its revision on.
#[test]
fn a_decision_at_the_reviewed_revision_is_recorded() {
    let now = Timestamp::now();
    let op = operation(now);

    let approved = applied(op.decide(op.session_id, 0, &approve(), now));
    assert_eq!(approved.status, AuthorizationStatus::Approved);
    assert_eq!(approved.revision, 1);
    assert_eq!(approved.decision, Some(approve()));
    assert_eq!(approved.decided_at, Some(now));

    let denied = applied(op.decide(op.session_id, 0, &AuthorizationDecision::Deny, now));
    assert_eq!(denied.status, AuthorizationStatus::Denied);
    assert_eq!(denied.revision, 1);
}

/// The same decision repeated after a lost reply is the committed outcome,
/// also once the issuer completed it; another decision, or a stale revision,
/// is a conflict and never re-decides (consent-flow.md, response loss).
#[test]
fn a_repeat_replays_and_another_decision_conflicts() {
    let now = Timestamp::now();
    let op = operation(now);
    let mut approved = applied(op.decide(op.session_id, 0, &approve(), now));

    assert_eq!(
        approved.decide(op.session_id, 0, &approve(), now),
        DecisionStep::Replayed
    );
    assert_eq!(
        approved.decide(op.session_id, 0, &AuthorizationDecision::Deny, now),
        DecisionStep::Conflict
    );
    assert_eq!(
        approved.decide(op.session_id, 1, &approve(), now),
        DecisionStep::Conflict
    );
    assert_eq!(
        op.decide(op.session_id, 5, &approve(), now),
        DecisionStep::Conflict
    );

    approved.status = AuthorizationStatus::Completed;
    assert_eq!(
        approved.decide(op.session_id, 0, &approve(), now),
        DecisionStep::Replayed
    );
}

/// Another session, an expired operation, or one marked expired takes no
/// decision and learns nothing of it.
#[test]
fn another_session_or_expiry_is_not_found() {
    let now = Timestamp::now();
    let op = operation(now);
    assert_eq!(
        op.decide(SessionId::generate(), 0, &approve(), now),
        DecisionStep::NotFound
    );
    assert_eq!(
        op.decide(op.session_id, 0, &approve(), op.expires_at),
        DecisionStep::NotFound
    );
    let mut expired = op.clone();
    expired.status = AuthorizationStatus::Expired;
    assert_eq!(
        expired.decide(op.session_id, 0, &approve(), now),
        DecisionStep::NotFound
    );
}

/// Only a decided, uncompleted, unexpired operation completes.
#[test]
fn only_a_live_decided_operation_completes() {
    let now = Timestamp::now();
    let op = operation(now);
    assert!(!op.completable_at(now));
    let approved = applied(op.decide(op.session_id, 0, &approve(), now));
    assert!(approved.completable_at(now));
    assert!(!approved.completable_at(op.expires_at));
    let denied = applied(op.decide(op.session_id, 0, &AuthorizationDecision::Deny, now));
    assert!(denied.completable_at(now));
    let mut completed = approved;
    completed.status = AuthorizationStatus::Completed;
    assert!(!completed.completable_at(now));
}

/// An approval creates the consent when there is none: active, with the
/// operation's scopes for its resource and only the claims chosen to share,
/// each in its mode.
#[test]
fn an_approval_creates_the_consent_it_grants() {
    let now = Timestamp::now();
    let op = operation(now);
    let consent = op.approved_consent(
        None,
        &[
            choice("email", ClaimSharing::Subscribed),
            choice("phone", ClaimSharing::None),
        ],
    );
    assert_eq!(consent.profile_id, op.profile_id);
    assert_eq!(consent.client_id, op.client_id);
    assert_eq!(consent.status, ConsentStatus::Active);
    let email = ClaimRequest {
        subscription: crate::models::consent::ClaimSubscription::Preferred,
        ..ClaimRequest::required("email", ClaimType::Data)
    };
    let phone = ClaimRequest::required("phone", ClaimType::Data);
    assert!(consent.covers(op.resource_id, &op.scopes, &[&email]));
    assert!(!consent.covers(op.resource_id, &op.scopes, &[&phone]));
    assert_eq!(consent.grants[0].mode, ConsentMode::Subscribed);
}

/// An approval replaces an active consent's disclosure as a whole, under the
/// same consent: the claims shared now with their reviewed values; a claim
/// shared before and left out of this review is no longer disclosed
/// (identity-model.md, recipient disclosure). Its scopes only add.
#[test]
fn an_approval_replaces_the_disclosure() {
    let now = Timestamp::now();
    let op = operation(now);
    let mut held = ConsentRecord::new(op.profile_id, op.client_id.clone());
    held.grant_claim("name", ClaimType::Data, ConsentMode::Static);
    held.grant_scopes(op.resource_id, &["other".into()]);
    held.as_requested().unwrap().grant();
    let id = held.id;

    let consent = op.approved_consent(
        Some(held),
        &[
            choice("email", ClaimSharing::Static),
            choice("name", ClaimSharing::None),
        ],
    );
    assert_eq!(consent.id, id);
    let email = ClaimRequest::required("email", ClaimType::Data);
    let name = ClaimRequest::required("name", ClaimType::Data);
    assert!(consent.covers(op.resource_id, &op.scopes, &[&email]));
    assert!(!consent.covers(op.resource_id, &[], &[&name]));
    assert!(consent.covers(op.resource_id, &["other".into()], &[]));
    assert_eq!(consent.grants.len(), 1);
    assert_eq!(
        consent.grants[0]
            .disclosed
            .as_ref()
            .map(|d| d.value.as_str()),
        Some("email-value")
    );
}

/// A revoked consent approved again grants what this approval grants and
/// nothing it held before: approving `read` after revoking `read write`
/// does not bring `write` back, nor a revoked claim.
#[test]
fn a_revoked_consent_approved_again_starts_from_the_approval() {
    let now = Timestamp::now();
    let op = operation(now);
    let mut held = ConsentRecord::new(op.profile_id, op.client_id.clone());
    held.grant_claim("name", ClaimType::Data, ConsentMode::Static);
    held.grant_scopes(
        op.resource_id,
        &["openid".into(), "read".into(), "write".into()],
    );
    held.as_requested().unwrap().grant();
    held.as_active().unwrap().revoke_all();
    let id = held.id;

    let consent = op.approved_consent(Some(held), &[choice("email", ClaimSharing::Static)]);
    assert_eq!(consent.id, id);
    assert_eq!(consent.status, ConsentStatus::Active);
    assert!(consent.revoked_at.is_none());
    assert!(consent.covers(op.resource_id, &op.scopes, &[]));
    assert!(!consent.covers(op.resource_id, &["write".into()], &[]));
    let name = ClaimRequest::required("name", ClaimType::Data);
    assert!(!consent.covers(op.resource_id, &[], &[&name]));
    assert_eq!(consent.grants.len(), 1);
}
