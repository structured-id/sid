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

/// Sign-in routes the holder, never a claimant, and nobody once the holder
/// releases the address: the remaining claim is not elected.
pub async fn test_sign_in_routes_only_the_holder(backend: &dyn StorageBackend) {
    let value = address();
    let holder = verified_holder(backend, &value).await;
    let claimant = profile(backend, "claimant").await;
    claim(backend, &claimant, &value).await;
    let state = entity(backend, &value).await;
    let route = || {
        backend.resolve_sign_in_principal(PrincipalType::Email, &value, state.email_policy_revision)
    };
    assert_eq!(route().await.unwrap(), Some(holder.id));

    assert!(
        backend
            .unbind_principal(state.id, holder.id, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(route().await.unwrap(), None, "the claimant was elected");
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

/// The registration of a federated reference: a record with no login name,
/// contact or credential, reached by the subject a trusted issuer names.
fn reference(issuer: &str, subject: Uuid) -> sid_core::models::NewRegistration {
    let mut profile = Profile::new(None::<&str>);
    profile.profile_type = sid_core::models::ProfileType::Federated;
    let principal = Principal::new_federated_subject(profile.id, issuer, &subject.to_string());
    sid_core::models::NewRegistration {
        profile,
        principal,
        email: None,
        phone: None,
        credential: None,
        source: None,
        instance_claim: None,
        history: None,
        enrollment: None,
        source_recording: sid_core::models::SourceRecording::AsGiven,
    }
}

/// A federated reference authenticates at its issuer and is reached only by
/// the subject that issuer names: the store refuses it a password, a
/// passkey, a second factor, an email and a user name, and stores none of
/// them, whichever caller asks. A registration that would create a
/// reference together with a credential is refused whole. Bug prevented: an
/// outside identity gaining a way to sign in here without its issuer.
pub async fn test_federated_reference_holds_nothing_local(backend: &dyn StorageBackend) {
    use sid_core::models::{Credential, CredentialType};
    let issuer = format!(
        "https://issuer{}.sid.example.com/i/r",
        Uuid::now_v7().simple()
    );
    let visitor = reference(&issuer, Uuid::now_v7());
    backend
        .register_profile(&visitor, test_audit())
        .await
        .unwrap();
    let id = visitor.profile.id;

    for kind in [
        CredentialType::Opaque,
        CredentialType::WebAuthn,
        CredentialType::Totp,
    ] {
        let refused = backend
            .create_credential(
                &Credential::new(id, kind, vec![7u8; 32], None),
                test_audit(),
            )
            .await;
        assert!(
            matches!(refused, Err(sid_core::Error::InvalidState(_))),
            "{kind:?}: {refused:?}"
        );
    }
    assert!(
        backend
            .get_credentials_by_profile(id, None)
            .await
            .unwrap()
            .is_empty()
    );

    let name = format!("visitor{}", Uuid::now_v7().simple());
    for claim in [
        Principal::new_email(id, address()),
        Principal::new_username(id, &name),
    ] {
        let refused = backend.save_principal(&claim, test_audit()).await;
        assert!(
            matches!(refused, Err(sid_core::Error::InvalidState(_))),
            "{:?}: {refused:?}",
            claim.principal_type
        );
    }
    let held = backend.get_principals_by_profile(id).await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].principal_type, PrincipalType::FederatedSubject);

    // Nor through a directory write to it.
    let mut write = sid_core::models::DirectoryUserWrite::new(
        sid_core::models::DirectoryWriteMode::Update,
        backend.get_profile(id).await.unwrap().expect("the record"),
    );
    write.bind = vec![Principal::new_username(
        id,
        format!("directory{}", Uuid::now_v7().simple()),
    )];
    let refused = backend.write_directory_user(&write, test_audit()).await;
    assert!(
        matches!(refused, Err(sid_core::Error::InvalidState(_))),
        "{refused:?}"
    );
    let held = backend.get_principals_by_profile(id).await.unwrap();
    assert_eq!(held.len(), 1);

    // A reference never registers under a local name: not as the principal
    // it is reached by, and not as a user name of its own.
    let mut named = reference(&issuer, Uuid::now_v7());
    named.principal = Principal::new_email(named.profile.id, address());
    let mut titled = reference(&issuer, Uuid::now_v7());
    titled.profile.username = Some(format!("titled{}", Uuid::now_v7().simple()));
    for refused in [named, titled] {
        let outcome = backend.register_profile(&refused, test_audit()).await;
        assert!(
            matches!(outcome, Err(sid_core::Error::InvalidState(_))),
            "{outcome:?}"
        );
        assert_eq!(backend.get_profile(refused.profile.id).await.unwrap(), None);
    }

    // A reference never arrives with a credential of its own.
    let mut armed = reference(&issuer, Uuid::now_v7());
    armed.credential = Some(Credential::new(
        armed.profile.id,
        CredentialType::Opaque,
        vec![9u8; 32],
        None,
    ));
    assert!(matches!(
        backend.register_profile(&armed, test_audit()).await,
        Err(sid_core::Error::InvalidState(_))
    ));
    assert_eq!(backend.get_profile(armed.profile.id).await.unwrap(), None);
}

/// An identity admitted through federation gets one local record: it is
/// stored as a federated reference without a login name and assigned its
/// issuer's subject, and a second registration of that subject, alone or at
/// the same moment, is a conflict that writes nothing. Bug prevented: two
/// records for one outside identity, each gathering its own permissions.
pub async fn test_federated_reference_is_registered_once(backend: &dyn StorageBackend) {
    let issuer = format!(
        "https://issuer{}.sid.example.com/i/r",
        Uuid::now_v7().simple()
    );
    let subject = Uuid::now_v7();
    let value = sid_core::models::federated_subject_value(&issuer, &subject.to_string());

    let first = reference(&issuer, subject);
    backend
        .register_profile(&first, test_audit())
        .await
        .expect("a reference registers without a login name or credential");
    let stored = backend
        .get_profile(first.profile.id)
        .await
        .unwrap()
        .expect("the record");
    assert_eq!(
        stored.profile_type,
        sid_core::models::ProfileType::Federated
    );
    assert_eq!(stored.username, None);
    let assigned = backend
        .get_principal_by_value(PrincipalType::FederatedSubject, &value)
        .await
        .unwrap()
        .expect("the assignment");
    assert_eq!(assigned.assigned_profile_id, Some(first.profile.id));

    let second = reference(&issuer, subject);
    assert!(matches!(
        backend.register_profile(&second, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));
    assert_eq!(
        backend.get_profile(second.profile.id).await.unwrap(),
        None,
        "a refused registration left a record"
    );

    // Two first entries of another identity at once: one record.
    let other = Uuid::now_v7();
    let (a, b) = (reference(&issuer, other), reference(&issuer, other));
    let (ra, rb) = tokio::join!(
        backend.register_profile(&a, test_audit()),
        backend.register_profile(&b, test_audit())
    );
    assert_eq!(
        [&ra, &rb].iter().filter(|r| r.is_ok()).count(),
        1,
        "{ra:?} {rb:?}"
    );
    let winner = if ra.is_ok() { &a } else { &b };
    let assigned = backend
        .get_principal_by_value(
            PrincipalType::FederatedSubject,
            &sid_core::models::federated_subject_value(&issuer, &other.to_string()),
        )
        .await
        .unwrap()
        .expect("the assignment");
    assert_eq!(assigned.assigned_profile_id, Some(winner.profile.id));
}
