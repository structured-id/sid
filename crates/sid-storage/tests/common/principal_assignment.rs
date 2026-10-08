// SPDX-License-Identifier: AGPL-3.0-only
//! Principal assignment: one explicit assignment routes an email/phone
//! principal; other holders' claims never change it.

use chrono::{Duration, Utc};
use sid_core::models::{Principal, PrincipalType, Profile};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

fn address() -> String {
    format!("assign{}@sid.example.com", Uuid::now_v7().simple())
}

async fn profile(backend: &dyn StorageBackend, tag: &str) -> Profile {
    let profile = create_test_profile(tag);
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile
}

async fn entity(backend: &dyn StorageBackend, value: &str) -> sid_core::models::PrincipalEntity {
    backend
        .get_principal_by_value(PrincipalType::Email, value)
        .await
        .unwrap()
        .expect("principal exists")
}

async fn claim(backend: &dyn StorageBackend, claimant: &Profile, value: &str) {
    backend
        .save_principal(&Principal::new_email(claimant.id, value), test_audit())
        .await
        .unwrap();
}

/// A holder whose address was confirmed when it first used it.
async fn verified_holder(backend: &dyn StorageBackend, value: &str) -> Profile {
    let holder = profile(backend, "holder").await;
    let mut principal = Principal::new_email(holder.id, value);
    principal.verify(0);
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();
    holder
}

/// Another account adding the same address makes a pending claim: the
/// current holder keeps the assignment and its proof.
pub async fn test_claim_does_not_change_assignment(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    let before = entity(backend, &value).await;
    let claimant = profile(backend, "claimant").await;
    claim(backend, &claimant, &value).await;

    let state = entity(backend, &value).await;
    assert_eq!(
        state.assigned_profile_id,
        Some(holder.id),
        "a claim took the route"
    );
    assert!(state.verified, "a claim stripped the holder's proof");
    assert_eq!(state.assignment_revision, before.assignment_revision);
}

/// A claim that arrives carrying proof is still only a claim: proof for an
/// existing principal travels through a transfer, not through a bind.
pub async fn test_claim_with_proof_does_not_transfer(backend: &dyn StorageBackend) {
    let value = address();
    let holder = profile(backend, "holder").await;
    claim(backend, &holder, &value).await;
    let claimant = profile(backend, "claimant").await;
    let mut forged = Principal::new_email(claimant.id, &value);
    forged.verify(0);
    backend.save_principal(&forged, test_audit()).await.unwrap();

    let state = entity(backend, &value).await;
    assert_eq!(state.assigned_profile_id, Some(holder.id));
    assert!(!state.verified, "the claimant's proof was taken over");
}

/// A claimant's own view of the principal carries no proof: the proof is the
/// holder's, and a claimant's account must not count as verified by it.
pub async fn test_claimant_view_carries_no_proof(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    let claimant = profile(backend, "claimant").await;
    claim(backend, &claimant, &value).await;

    let claimed = backend
        .get_principals_by_profile(claimant.id)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.value == value)
        .expect("the claim is listed");
    assert!(!claimed.verified, "the claimant sees the holder's proof");
    assert!(claimed.verified_at.is_none());
    let held = backend
        .get_principals_by_profile(holder.id)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.value == value)
        .expect("the holding is listed");
    assert!(held.verified, "the holder lost sight of its proof");
}

/// A user name is a login handle, never shared: another account claiming it
/// is refused and the holder's entity stays as it was.
pub async fn test_login_handle_claim_is_conflict(backend: &dyn StorageBackend) {
    let handle = format!("handle{}", Uuid::now_v7().simple());
    let holder = profile(backend, "handle-holder").await;
    backend
        .save_principal(&Principal::new_username(holder.id, &handle), test_audit())
        .await
        .unwrap();
    let other = profile(backend, "handle-taker").await;
    let err = backend
        .save_principal(&Principal::new_username(other.id, &handle), test_audit())
        .await
        .expect_err("a second holder of a login handle");
    assert!(matches!(err, sid_core::Error::Conflict(_)), "{err:?}");

    let state = backend
        .get_principal_by_value(PrincipalType::Username, &handle)
        .await
        .unwrap()
        .expect("handle exists");
    assert_eq!(state.assigned_profile_id, Some(holder.id));
    let bindings = backend.get_principal_bindings(state.id).await.unwrap();
    assert_eq!(bindings.len(), 1, "the refused claim was stored");
    // The holder re-saving its own handle is fine.
    backend
        .save_principal(&Principal::new_username(holder.id, &handle), test_audit())
        .await
        .unwrap();
}

/// A never-used address is assigned to its first claimant (routing only).
pub async fn test_first_use_assigns_sole_claimant(backend: &dyn StorageBackend) {
    let value = address();
    let first = profile(backend, "first").await;
    claim(backend, &first, &value).await;
    let state = entity(backend, &value).await;
    assert_eq!(state.assigned_profile_id, Some(first.id));
    assert_eq!(state.assignment_revision, 1);
    assert!(!state.verified, "first use proves nothing");
}

/// Proof expiry keeps the assignment: the holder still signs in by it.
pub async fn test_proof_expiry_keeps_assignment(backend: &dyn StorageBackend) {
    let value = address();
    let holder = profile(backend, "expiring").await;
    let mut principal = Principal::new_email(holder.id, &value);
    principal.verified = true;
    principal.verified_at = Some(Utc::now() - Duration::days(200));
    principal.verification_expires = Some(Utc::now() - Duration::days(20));
    backend
        .save_principal(&principal, test_audit())
        .await
        .unwrap();

    let expired = backend.expire_principal_verifications().await.unwrap();
    assert!(expired >= 1, "the lapsed proof was not counted");

    let state = entity(backend, &value).await;
    assert_eq!(
        state.assigned_profile_id,
        Some(holder.id),
        "expiry removed the route"
    );
    assert!(!state.verified);
    assert_eq!(state.assignment_revision, 1);
}

/// The holder releasing its claim clears the route and the proof; the
/// remaining claimant is not elected, and the revision moves on.
pub async fn test_release_elects_nobody(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    let claimant = profile(backend, "claimant").await;
    claim(backend, &claimant, &value).await;
    let principal_id = entity(backend, &value).await.id;

    assert!(
        backend
            .unbind_principal(principal_id, holder.id, test_audit())
            .await
            .unwrap()
    );

    let state = entity(backend, &value).await;
    assert_eq!(state.assigned_profile_id, None, "a successor was elected");
    assert!(!state.verified, "the released proof stayed");
    assert_eq!(state.assignment_revision, 2);
    assert!(
        backend
            .get_profile_by_principal(PrincipalType::Email, &value)
            .await
            .unwrap()
            .is_none(),
        "the remaining claim resolves a profile"
    );
}

/// A claimant leaving changes nothing about the holder's assignment.
pub async fn test_claimant_leaving_keeps_assignment(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    let claimant = profile(backend, "claimant").await;
    claim(backend, &claimant, &value).await;
    let principal_id = entity(backend, &value).await.id;

    backend
        .unbind_principal(principal_id, claimant.id, test_audit())
        .await
        .unwrap();

    let state = entity(backend, &value).await;
    assert_eq!(state.assigned_profile_id, Some(holder.id));
    assert!(state.verified);
    assert_eq!(state.assignment_revision, 1);
}

/// Resolution by value returns the holder, never a claimant, whichever
/// claim the storage happens to read first.
pub async fn test_profile_by_principal_is_assigned_holder(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    for tag in ["claimant-a", "claimant-b", "claimant-c"] {
        let claimant = profile(backend, tag).await;
        claim(backend, &claimant, &value).await;
    }
    let resolved = backend
        .get_profile_by_principal(PrincipalType::Email, &value)
        .await
        .unwrap()
        .expect("the holder resolves");
    assert_eq!(resolved.id, holder.id);
}
