// SPDX-License-Identifier: AGPL-3.0-only
//! Browser authorization operations (authz/consent-flow.md, decision,
//! persistence and continuation): one decision per reviewed revision, the
//! consent it grants committed with it, at most one code per operation, and
//! the same outcome on every replica racing on it.

use jiff::{SignedDuration as Duration, Timestamp};
use sid_core::Error;
use sid_core::models::consent::{
    ClaimRequest, ClaimType, ConsentMode, ConsentRecord, ConsentStatus, DisclosedValue,
};
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    AuthorizationCode, AuthorizationDecision, AuthorizationOperation, AuthorizationOperationId,
    AuthorizationStatus, ClaimChoice, ClaimSharing, CompletionOutcome, DecisionOutcome, Session,
    SessionId,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::application::{grant_resource, instance_issuer};
use super::{create_test_profile, create_test_session, test_audit};

/// A stored operation awaiting consent, through a stored session of a new
/// profile, with that session.
async fn awaiting(backend: &dyn StorageBackend) -> (AuthorizationOperation, Session) {
    let profile = create_test_profile("authorization");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut session = create_test_session(profile.id);
    session.amr = vec!["pwd".into()];
    session.assurance_level = AuthLevel::Basic;
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let now = Timestamp::now();
    let operation = AuthorizationOperation {
        id: AuthorizationOperationId::generate(),
        issuer_id: instance_issuer(backend).await,
        client_id: format!("rp-{}", Uuid::now_v7().simple()),
        redirect_uri: "https://rp.sid.example.com/callback".into(),
        response_type: "code".into(),
        state: Some("state-1".into()),
        code_challenge: Some("challenge".into()),
        code_challenge_method: Some("S256".into()),
        nonce: Some("nonce-1".into()),
        resource_id: grant_resource(backend).await,
        scopes: vec!["openid".into(), "read".into()],
        acr_values: Some("urn:sid:acr:mfa".into()),
        claim_requests: vec![
            ClaimRequest::demanded("email", ClaimType::Data, "Receipts are sent there."),
            ClaimRequest::optional("phone", ClaimType::Data),
        ],
        session_id: session.id,
        profile_id: profile.id,
        status: AuthorizationStatus::AwaitingConsent,
        revision: 0,
        decision: None,
        created_at: now,
        expires_at: AuthorizationOperation::expiry_from(now),
        decided_at: None,
    };
    backend
        .create_authorization_operation(&operation, test_audit())
        .await
        .unwrap();
    (operation, session)
}

fn approve() -> AuthorizationDecision {
    AuthorizationDecision::Approve {
        choices: vec![
            ClaimChoice {
                name: "email".into(),
                claim_type: ClaimType::Data,
                sharing: ClaimSharing::Subscribed,
                disclosed: Some(DisclosedValue {
                    value: "alice@sid.example.com".into(),
                    verified: Some(true),
                }),
            },
            ClaimChoice {
                name: "phone".into(),
                claim_type: ClaimType::Data,
                sharing: ClaimSharing::None,
                disclosed: None,
            },
        ],
    }
}

/// The code the issuer issues on completing `operation`, authorized by
/// `session`.
fn code(operation: &AuthorizationOperation, session: &Session) -> AuthorizationCode {
    AuthorizationCode {
        code_hash: Uuid::now_v7().as_bytes().to_vec(),
        profile_id: operation.profile_id,
        client_id: operation.client_id.clone(),
        redirect_uri: operation.redirect_uri.clone(),
        scopes: operation.scopes.clone(),
        resource: operation.resource_id,
        code_challenge: operation.code_challenge.clone(),
        nonce: operation.nonce.clone(),
        authentication: session.grant_authentication(),
        expires_at: Timestamp::now() + Duration::from_mins(5),
        created_at: Timestamp::now(),
        used: false,
        session_id: None,
        presentation: None,
    }
}

/// An operation reads back as stored, and a create never replaces one.
pub async fn test_authorization_operation_roundtrip(backend: &dyn StorageBackend) {
    let (operation, _) = awaiting(backend).await;
    let stored = backend
        .authorization_operation(operation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, operation.id);
    assert_eq!(stored.client_id, operation.client_id);
    assert_eq!(stored.redirect_uri, operation.redirect_uri);
    assert_eq!(stored.state, operation.state);
    assert_eq!(stored.code_challenge, operation.code_challenge);
    assert_eq!(
        stored.code_challenge_method,
        operation.code_challenge_method
    );
    assert_eq!(stored.nonce, operation.nonce);
    assert_eq!(stored.resource_id, operation.resource_id);
    assert_eq!(stored.scopes, operation.scopes);
    assert_eq!(stored.acr_values, operation.acr_values);
    assert_eq!(stored.claim_requests, operation.claim_requests);
    assert_eq!(stored.session_id, operation.session_id);
    assert_eq!(stored.profile_id, operation.profile_id);
    assert_eq!(stored.status, AuthorizationStatus::AwaitingConsent);
    assert_eq!(stored.revision, 0);
    assert!(stored.decision.is_none());

    let mut again = operation.clone();
    again.scopes = vec!["admin".into()];
    let err = backend
        .create_authorization_operation(&again, test_audit())
        .await
        .expect_err("a create over an existing operation");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert!(
        backend
            .authorization_operation(AuthorizationOperationId::generate())
            .await
            .unwrap()
            .is_none()
    );
}

/// An approval commits with the consent it grants: the operation's scopes
/// for its resource and only the claims shared, in their modes. A repeat
/// replays without granting again; another decision or revision conflicts.
pub async fn test_approval_commits_its_consent(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    let now = Timestamp::now();

    let recorded = backend
        .decide_authorization_operation(operation.id, session.id, 0, &approve(), now, test_audit())
        .await
        .unwrap();
    let DecisionOutcome::Recorded(decided) = recorded else {
        panic!("expected a recorded decision, got {recorded:?}");
    };
    assert_eq!(decided.status, AuthorizationStatus::Approved);
    assert_eq!(decided.revision, 1);
    assert_eq!(decided.decision, Some(approve()));

    let consent = backend
        .get_consent_by_client(operation.profile_id, &operation.client_id)
        .await
        .unwrap()
        .expect("the approval's consent");
    assert_eq!(consent.status, ConsentStatus::Active);
    // The approval shares email with its updates, which a request preferring
    // updates admits.
    let email = ClaimRequest {
        subscription: sid_core::models::ClaimSubscription::Preferred,
        ..ClaimRequest::required("email", ClaimType::Data)
    };
    let phone = ClaimRequest::required("phone", ClaimType::Data);
    assert!(consent.covers(operation.resource_id, &operation.scopes, &[&email]));
    assert!(!consent.covers(operation.resource_id, &operation.scopes, &[&phone]));
    // The disclosure is the reviewed value, read back exactly as approved.
    assert_eq!(consent.grants.len(), 1);
    assert_eq!(
        consent.grants[0].disclosed,
        Some(DisclosedValue {
            value: "alice@sid.example.com".into(),
            verified: Some(true),
        })
    );

    let replay = backend
        .decide_authorization_operation(operation.id, session.id, 0, &approve(), now, test_audit())
        .await
        .unwrap();
    assert!(
        matches!(replay, DecisionOutcome::Replayed(ref op) if op.revision == 1),
        "{replay:?}"
    );
    let after = backend
        .get_consent_by_client(operation.profile_id, &operation.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.grants, consent.grants);
    assert_eq!(after.scope_grants, consent.scope_grants);

    for (revision, decision) in [(0, AuthorizationDecision::Deny), (1, approve())] {
        assert_eq!(
            backend
                .decide_authorization_operation(
                    operation.id,
                    session.id,
                    revision,
                    &decision,
                    now,
                    test_audit()
                )
                .await
                .unwrap(),
            DecisionOutcome::Conflict
        );
    }
}

/// A consent revoked and then approved again holds only what the new
/// approval grants, as stored: a scope and a claim revoked with it are not
/// restored by approving a narrower request.
pub async fn test_reapproval_after_revocation_grants_only_the_approval(
    backend: &dyn StorageBackend,
) {
    let (operation, session) = awaiting(backend).await;
    let mut revoked = ConsentRecord::new(operation.profile_id, operation.client_id.clone());
    revoked.grant_scopes(
        operation.resource_id,
        &["openid".into(), "read".into(), "write".into()],
    );
    revoked.grant_claim("name", ClaimType::Data, ConsentMode::Static);
    revoked.as_requested().unwrap().grant();
    revoked.as_active().unwrap().revoke_all();
    backend
        .create_consent(&revoked, test_audit())
        .await
        .unwrap();

    let recorded = backend
        .decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &approve(),
            Timestamp::now(),
            test_audit(),
        )
        .await
        .unwrap();
    assert!(
        matches!(recorded, DecisionOutcome::Recorded(_)),
        "{recorded:?}"
    );
    let consent = backend
        .get_consent_by_client(operation.profile_id, &operation.client_id)
        .await
        .unwrap()
        .expect("the approval's consent");
    assert_eq!(consent.id, revoked.id);
    assert_eq!(consent.status, ConsentStatus::Active);
    assert!(consent.covers(operation.resource_id, &operation.scopes, &[]));
    assert!(!consent.covers(operation.resource_id, &["write".into()], &[]));
    let name = ClaimRequest::required("name", ClaimType::Data);
    assert!(!consent.covers(operation.resource_id, &[], &[&name]));
    assert!(consent.grants.iter().all(|g| g.claim_name == "email"));
}

/// A denial grants nothing: no consent appears for the pair.
pub async fn test_denial_grants_nothing(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    let outcome = backend
        .decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &AuthorizationDecision::Deny,
            Timestamp::now(),
            test_audit(),
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, DecisionOutcome::Recorded(ref op) if op.status == AuthorizationStatus::Denied),
        "{outcome:?}"
    );
    assert!(
        backend
            .get_consent_by_client(operation.profile_id, &operation.client_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Another session, or an expired operation, takes no decision.
pub async fn test_decision_needs_its_session_and_lifetime(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    for (by, at) in [
        (SessionId::generate(), Timestamp::now()),
        (session.id, operation.expires_at),
    ] {
        assert_eq!(
            backend
                .decide_authorization_operation(operation.id, by, 0, &approve(), at, test_audit())
                .await
                .unwrap(),
            DecisionOutcome::NotFound
        );
    }
    assert_eq!(
        backend
            .decide_authorization_operation(
                AuthorizationOperationId::generate(),
                session.id,
                0,
                &approve(),
                Timestamp::now(),
                test_audit()
            )
            .await
            .unwrap(),
        DecisionOutcome::NotFound
    );
    let stored = backend
        .authorization_operation(operation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, AuthorizationStatus::AwaitingConsent);
}

/// Concurrent decisions on one revision record exactly one; the other sees
/// it as its own replay when it asked the same, else a conflict.
pub async fn test_concurrent_decisions_record_one(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    let now = Timestamp::now();
    let approval = approve();
    let (a, b) = tokio::join!(
        backend.decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &approval,
            now,
            test_audit()
        ),
        backend.decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &AuthorizationDecision::Deny,
            now,
            test_audit()
        ),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    let recorded = outcomes
        .iter()
        .filter(|o| matches!(o, DecisionOutcome::Recorded(_)))
        .count();
    assert_eq!(recorded, 1, "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, DecisionOutcome::Conflict)),
        "{outcomes:?}"
    );

    let (operation, session) = awaiting(backend).await;
    let (a, b) = tokio::join!(
        backend.decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &approval,
            now,
            test_audit()
        ),
        backend.decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &approval,
            now,
            test_audit()
        ),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| matches!(o, DecisionOutcome::Replayed(_)));
    assert!(
        matches!(
            outcomes,
            [DecisionOutcome::Recorded(_), DecisionOutcome::Replayed(_)]
        ),
        "{outcomes:?}"
    );
    let consent = backend
        .get_consent_by_client(operation.profile_id, &operation.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(consent.grants.len(), 1);
}

/// The issuer completes an approval once, storing its code in the same
/// commit; a second completion, also a concurrent one, stores nothing.
pub async fn test_completion_issues_one_code(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    let now = Timestamp::now();
    assert_eq!(
        backend
            .complete_authorization_operation(
                operation.id,
                Some(&code(&operation, &session)),
                now,
                test_audit()
            )
            .await
            .unwrap(),
        CompletionOutcome::NotDecided,
        "an undecided operation completed"
    );
    backend
        .decide_authorization_operation(operation.id, session.id, 0, &approve(), now, test_audit())
        .await
        .unwrap();

    let (first, second) = (code(&operation, &session), code(&operation, &session));
    let (a, b) = tokio::join!(
        backend.complete_authorization_operation(operation.id, Some(&first), now, test_audit()),
        backend.complete_authorization_operation(operation.id, Some(&second), now, test_audit()),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == CompletionOutcome::Completed)
            .count(),
        1,
        "{outcomes:?}"
    );
    let stored = [
        backend
            .get_auth_code_by_hash(&first.code_hash)
            .await
            .unwrap(),
        backend
            .get_auth_code_by_hash(&second.code_hash)
            .await
            .unwrap(),
    ];
    assert_eq!(
        stored.iter().filter(|c| c.is_some()).count(),
        1,
        "not exactly one code stored"
    );
    let completed = backend
        .authorization_operation(operation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, AuthorizationStatus::Completed);
    // A decision repeated after completion still reads as its own replay.
    assert!(matches!(
        backend
            .decide_authorization_operation(
                operation.id,
                session.id,
                0,
                &approve(),
                now,
                test_audit()
            )
            .await
            .unwrap(),
        DecisionOutcome::Replayed(_)
    ));
}

/// A denial completes with no code; an expired decision does not complete.
pub async fn test_denial_and_expiry_at_completion(backend: &dyn StorageBackend) {
    let (operation, session) = awaiting(backend).await;
    let now = Timestamp::now();
    backend
        .decide_authorization_operation(
            operation.id,
            session.id,
            0,
            &AuthorizationDecision::Deny,
            now,
            test_audit(),
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .complete_authorization_operation(operation.id, None, now, test_audit())
            .await
            .unwrap(),
        CompletionOutcome::Completed
    );

    let (operation, session) = awaiting(backend).await;
    backend
        .decide_authorization_operation(operation.id, session.id, 0, &approve(), now, test_audit())
        .await
        .unwrap();
    let late = code(&operation, &session);
    assert_eq!(
        backend
            .complete_authorization_operation(
                operation.id,
                Some(&late),
                operation.expires_at,
                test_audit()
            )
            .await
            .unwrap(),
        CompletionOutcome::NotDecided
    );
    assert!(
        backend
            .get_auth_code_by_hash(&late.code_hash)
            .await
            .unwrap()
            .is_none()
    );
}
