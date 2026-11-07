// SPDX-License-Identifier: AGPL-3.0-only
//! Moving records between stores: what a snapshot exports is stored as it
//! is, an import writes it exactly as exported, a repeat writes nothing and a
//! different record under a stored key is a conflict that writes nothing.

use chrono::{Duration, DurationRound, Utc};
use sid_core::Error;
use sid_core::models::{
    PrincipalBindingId, PrincipalId, PrincipalType, QuarantinedPrincipal, StoredPrincipal,
    StoredUserHandle, WebAuthnUserHandle,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, new_email_registration, test_audit};

fn address(tag: &str) -> String {
    format!("{tag}{}@sid.example.com", Uuid::now_v7().simple())
}

/// `principal` as exported, found among every principal the store holds.
async fn exported(backend: &dyn StorageBackend, id: PrincipalId) -> Option<StoredPrincipal> {
    let mut after = None;
    loop {
        let batch = backend.export_principals(after, 50).await.unwrap();
        let last = batch.last()?.entity.id;
        if let Some(found) = batch.into_iter().find(|p| p.entity.id == id) {
            return Some(found);
        }
        after = Some(last);
    }
}

/// A registered principal is exported with its assignment and claim, and
/// restores exactly: a repeat writes nothing, the same id with another
/// assignment is a conflict, and the same principal under a new id and
/// value, claimed by the same Profile, is written as given.
pub async fn test_principals_move_as_stored(backend: &dyn StorageBackend) {
    let registration = new_email_registration(&address("move"));
    backend
        .register_profile(&registration, test_audit())
        .await
        .unwrap();
    let held = exported(backend, registration.principal.id)
        .await
        .expect("the registered principal is exported");
    assert_eq!(held.entity.principal_type, PrincipalType::Email);
    assert_eq!(held.claims.len(), 1);
    assert_eq!(held.claims[0].profile_id, registration.profile.id);
    assert!(
        held.claims[0].source_email_id.is_some(),
        "the claim names its contact"
    );

    assert!(
        !backend.import_principal(&held, test_audit()).await.unwrap(),
        "a repeat writes nothing"
    );
    let mut differing = held.clone();
    differing.entity.assignment_revision += 1;
    let refused = backend.import_principal(&differing, test_audit()).await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(
        exported(backend, held.entity.id).await.as_ref(),
        Some(&held)
    );

    let mut moved = held.clone();
    moved.entity.id = PrincipalId::new();
    moved.entity.value = address("moved");
    for claim in &mut moved.claims {
        claim.id = PrincipalBindingId::new();
        claim.principal_id = moved.entity.id;
    }
    assert!(
        backend
            .import_principal(&moved, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        exported(backend, moved.entity.id).await.as_ref(),
        Some(&moved)
    );

    let mut foreign = moved.clone();
    foreign.entity.id = PrincipalId::new();
    for claim in &mut foreign.claims {
        claim.id = PrincipalBindingId::new();
        claim.principal_id = foreign.entity.id;
    }
    let refused = backend.import_principal(&foreign, test_audit()).await;
    assert!(
        matches!(refused, Err(Error::Conflict(_))),
        "another principal holds the value: {refused:?}"
    );
}

/// The active revision is exported; importing it again writes nothing, and
/// another revision is refused once an email key is stored.
pub async fn test_email_policy_activation_moves(backend: &dyn StorageBackend) {
    let activation = backend.email_policy_activation().await.unwrap();
    assert!(
        !backend
            .import_email_policy_activation(&activation, test_audit())
            .await
            .unwrap()
    );
    backend
        .register_profile(&new_email_registration(&address("keyed")), test_audit())
        .await
        .unwrap();
    let mut other = activation;
    other.revision += 1;
    let refused = backend
        .import_email_policy_activation(&other, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(backend.email_policy_activation().await.unwrap(), activation);
}

/// A quarantine entry is exported as stored and restores exactly.
pub async fn test_quarantine_moves_as_stored(backend: &dyn StorageBackend) {
    let hash = format!("hash-{}", Uuid::now_v7());
    let until = (Utc::now() + Duration::days(30))
        .duration_trunc(Duration::milliseconds(1))
        .unwrap();
    backend
        .quarantine_principal(&hash, "email", until, test_audit())
        .await
        .unwrap();
    let held = backend
        .export_principal_quarantine()
        .await
        .unwrap()
        .into_iter()
        .find(|q| q.principal_hash == hash)
        .expect("exported");
    assert_eq!(held.until, until);
    assert!(
        !backend
            .import_principal_quarantine(&held, test_audit())
            .await
            .unwrap()
    );
    let mut differing = held.clone();
    differing.until += Duration::days(1);
    let refused = backend
        .import_principal_quarantine(&differing, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");

    let moved = QuarantinedPrincipal {
        principal_hash: format!("hash-{}", Uuid::now_v7()),
        ..held
    };
    assert!(
        backend
            .import_principal_quarantine(&moved, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .is_principal_quarantined(&moved.principal_hash)
            .await
            .unwrap()
    );
    assert!(
        backend
            .export_principal_quarantine()
            .await
            .unwrap()
            .contains(&moved)
    );
}

/// A restored profile keeps the revision it was exported at: a copy read
/// before the move still writes only at that revision.
pub async fn test_profile_restores_at_its_revision(backend: &dyn StorageBackend) {
    let mut profile = create_test_profile("revision_move");
    profile.revision = 3;
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let stored = backend.get_profile(profile.id).await.unwrap().unwrap();
    assert_eq!(stored.revision, 3);
    let mut stale = stored.clone();
    stale.revision = 2;
    assert!(!backend.update_profile(&stale, test_audit()).await.unwrap());
    assert!(backend.update_profile(&stored, test_audit()).await.unwrap());
}

/// A user handle is exported as stored and restores exactly, for its own
/// Profile only.
pub async fn test_user_handles_move_as_stored(backend: &dyn StorageBackend) {
    let profile = create_test_profile("handle_move");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let handle = WebAuthnUserHandle(*Uuid::new_v4().as_bytes());
    backend
        .ensure_webauthn_user_handle(profile.id, "sid.example.com", handle, test_audit())
        .await
        .unwrap();
    let held = backend
        .export_webauthn_user_handles(profile.id)
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].handle, handle);
    assert!(
        !backend
            .import_webauthn_user_handle(&held[0], test_audit())
            .await
            .unwrap()
    );

    let other = create_test_profile("handle_other");
    backend.create_profile(&other, test_audit()).await.unwrap();
    let taken = StoredUserHandle {
        profile_id: other.id,
        ..held[0].clone()
    };
    let refused = backend
        .import_webauthn_user_handle(&taken, test_audit())
        .await;
    assert!(
        matches!(refused, Err(Error::Conflict(_))),
        "the handle is another Profile's: {refused:?}"
    );
    let moved = StoredUserHandle {
        handle: WebAuthnUserHandle(*Uuid::new_v4().as_bytes()),
        ..taken
    };
    assert!(
        backend
            .import_webauthn_user_handle(&moved, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend
            .export_webauthn_user_handles(other.id)
            .await
            .unwrap(),
        vec![moved]
    );
}
