// SPDX-License-Identifier: AGPL-3.0-only
//! Consents: a create never replaces one, a claim decision never brings back
//! a revoked or disconnected consent, and concurrent decisions keep one
//! active grant per claim.

use sid_core::Error;
use sid_core::models::consent::{
    ClaimDecision, ClaimGrantChange, ClaimType, ConsentMode, ConsentRecord, ConsentStatus,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::application::grant_resource;
use super::{create_test_profile, test_audit};

/// A stored active consent of a new profile.
async fn active_consent(backend: &dyn StorageBackend) -> ConsentRecord {
    let profile = create_test_profile("consent");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, format!("rp-{}", Uuid::now_v7().simple()));
    consent.grant_claim("email", ClaimType::Data, ConsentMode::Subscribed);
    consent.grant_scopes(
        grant_resource(backend).await,
        &["openid".to_owned(), "read".to_owned()],
    );
    consent.as_requested().unwrap().grant();
    backend
        .create_consent(&consent, test_audit())
        .await
        .unwrap();
    consent
}

fn active_claims(consent: &ConsentRecord, claim: &str) -> usize {
    consent
        .grants
        .iter()
        .filter(|g| g.claim_name == claim && g.is_active())
        .count()
}

/// A stored consent reads back whole: its claim grants with their update
/// modes and its scope grants per resource, which the consent gate compares
/// a request against.
pub async fn test_consent_reads_back_grants_and_scopes(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(stored.grants.len(), 1);
    assert_eq!(stored.grants[0].mode, ConsentMode::Subscribed);
    assert_eq!(stored.scope_grants.len(), 1);
    let granted = &consent.scope_grants[0];
    assert_eq!(stored.scope_grants[0].resource_id, granted.resource_id);
    assert_eq!(stored.scope_grants[0].scopes, granted.scopes);
    let email = sid_core::models::ClaimRequest {
        subscription: sid_core::models::ClaimSubscription::Preferred,
        ..sid_core::models::ClaimRequest::required("email", stored.grants[0].claim_type)
    };
    assert!(stored.covers(granted.resource_id, &granted.scopes, &[&email]));

    let by_client = backend
        .get_consent_by_client(consent.profile_id, &consent.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_client.scope_grants, stored.scope_grants);
}

/// Creating a consent never replaces one: not over its id, not for the same
/// profile and client.
pub async fn test_create_consent_never_replaces(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;

    let mut same_id = consent.clone();
    same_id.status = ConsentStatus::Revoked;
    let err = backend
        .create_consent(&same_id, test_audit())
        .await
        .expect_err("a create over an existing consent");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let same_pair = ConsentRecord::new(consent.profile_id, consent.client_id.clone());
    let err = backend
        .create_consent(&same_pair, test_audit())
        .await
        .expect_err("a second consent for one profile and client");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ConsentStatus::Active);
}

/// Granting and revoking a claim change only that claim, and repeating a
/// decision changes nothing.
pub async fn test_change_claim_grant(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let grant = ClaimDecision::Grant(ClaimType::Attestation);

    assert_eq!(
        backend
            .change_claim_grant(consent.id, "age_over_18", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "age_over_18", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Unchanged
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "email", ClaimDecision::Revoke, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    assert_eq!(
        backend
            .change_claim_grant(consent.id, "email", ClaimDecision::Revoke, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::Unchanged
    );

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "age_over_18"), 1);
    assert_eq!(active_claims(&stored, "email"), 0);
    assert_eq!(stored.status, ConsentStatus::Active);

    // A revoked claim can be granted again, as the one grant of that claim.
    assert_eq!(
        backend
            .change_claim_grant(
                consent.id,
                "email",
                ClaimDecision::Grant(ClaimType::Data),
                test_audit()
            )
            .await
            .unwrap(),
        ClaimGrantChange::Changed
    );
    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "email"), 1);
    assert_eq!(
        stored
            .grants
            .iter()
            .filter(|g| g.claim_name == "email")
            .count(),
        1
    );
    // A claim granted from account management is a snapshot until the user
    // chooses updates; the renewed claim keeps its earlier mode.
    let mode = |name: &str| {
        stored
            .grants
            .iter()
            .find(|g| g.claim_name == name)
            .unwrap()
            .mode
    };
    assert_eq!(mode("age_over_18"), ConsentMode::Static);
    assert_eq!(mode("email"), ConsentMode::Subscribed);
}

/// A decision on a disconnected consent does not bring it back, and one on
/// a consent revoked with its profile's consents grants nothing: the revoked
/// consent keeps no active grant.
pub async fn test_claim_grant_keeps_ended_consent_ended(backend: &dyn StorageBackend) {
    let grant = ClaimDecision::Grant(ClaimType::Data);

    let disconnected = active_consent(backend).await;
    assert!(
        backend
            .delete_consent(disconnected.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .delete_consent(disconnected.id, test_audit())
            .await
            .unwrap(),
        "a repeated disconnect reported a deletion"
    );
    assert_eq!(
        backend
            .change_claim_grant(disconnected.id, "phone", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::ConsentNotActive
    );
    assert!(
        backend
            .get_consent(disconnected.id)
            .await
            .unwrap()
            .is_none(),
        "a disconnected consent was recreated"
    );

    let revoked = active_consent(backend).await;
    backend
        .revoke_consents_by_profile(revoked.profile_id, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .change_claim_grant(revoked.id, "phone", grant, test_audit())
            .await
            .unwrap(),
        ClaimGrantChange::ConsentNotActive
    );
    let stored = backend.get_consent(revoked.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ConsentStatus::Revoked);
    assert!(
        !stored.has_active_grants(),
        "a revoked consent kept an active grant"
    );
}

/// Concurrent decisions: two grants of one claim leave one active grant, and
/// grants of two claims both apply.
pub async fn test_claim_grants_under_concurrency(backend: &dyn StorageBackend) {
    let consent = active_consent(backend).await;
    let grant = ClaimDecision::Grant(ClaimType::Data);

    let (a, b) = tokio::join!(
        backend.change_claim_grant(consent.id, "phone", grant, test_audit()),
        backend.change_claim_grant(consent.id, "phone", grant, test_audit()),
    );
    let mut outcomes = [a.unwrap(), b.unwrap()];
    outcomes.sort_by_key(|o| *o == ClaimGrantChange::Unchanged);
    assert_eq!(
        outcomes,
        [ClaimGrantChange::Changed, ClaimGrantChange::Unchanged]
    );

    let (a, b) = tokio::join!(
        backend.change_claim_grant(consent.id, "name", grant, test_audit()),
        backend.change_claim_grant(consent.id, "address", grant, test_audit()),
    );
    assert_eq!(a.unwrap(), ClaimGrantChange::Changed);
    assert_eq!(b.unwrap(), ClaimGrantChange::Changed);

    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert_eq!(active_claims(&stored, "phone"), 1);
    assert_eq!(active_claims(&stored, "name"), 1);
    assert_eq!(active_claims(&stored, "address"), 1);
}
