// SPDX-License-Identifier: AGPL-3.0-only
use sid_core::models::{AuditEntry, ProfileStatus};
use sid_plugin::CredentialStore;

use super::*;
use crate::test_support::{storage, stored_profile};

const ISSUER: &str = "https://central.sid.example.com/i/recipient";

fn ctx() -> MutationContext {
    AuditEntry::system("federated_entry", "federated_record").into()
}

fn subject(n: u128) -> Uuid {
    Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_0000 + n)
}

// The first admitted entry creates the record with its assignment, and every
// later entry of the same identity gets that same record: no local login
// name, no credential, no role. Bug prevented: an account per sign-in, or a
// record that looks like one of the installation's own accounts.
#[tokio::test]
async fn the_first_entry_creates_the_record_and_later_ones_reuse_it() {
    let storage = storage().await;
    let first = record_of(storage.as_ref(), ISSUER, subject(1), ctx())
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.profile.profile_type, ProfileType::Federated);
    assert!(!first.profile.profile_type.is_local());
    assert_eq!(first.profile.status, ProfileStatus::Active);
    assert_eq!(first.profile.username, None);
    assert_eq!(first.assignment.profile, first.profile.id);

    let again = record_of(storage.as_ref(), ISSUER, subject(1), ctx())
        .await
        .unwrap();
    assert!(!again.created);
    assert_eq!(again.profile.id, first.profile.id);
    assert_eq!(again.assignment, first.assignment);

    // Its only login handle is the issuer's subject; it holds no credential
    // and no role.
    let principals = storage
        .get_principals_by_profile(first.profile.id)
        .await
        .unwrap();
    assert_eq!(principals.len(), 1);
    assert_eq!(
        principals[0].principal_type,
        PrincipalType::FederatedSubject
    );
    assert!(
        storage
            .get_credentials_by_profile(first.profile.id, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(first.profile.roles.is_empty());
}

// A subject is an identity only together with its issuer, and each identity
// has its own record. Bug prevented: two issuers' equal subjects, or two
// subjects of one issuer, sharing an account here.
#[tokio::test]
async fn each_issuer_and_subject_has_its_own_record() {
    let storage = storage().await;
    let a = record_of(storage.as_ref(), ISSUER, subject(1), ctx())
        .await
        .unwrap();
    let other_subject = record_of(storage.as_ref(), ISSUER, subject(2), ctx())
        .await
        .unwrap();
    let other_issuer = record_of(
        storage.as_ref(),
        "https://other.sid.example.com/i/recipient",
        subject(1),
        ctx(),
    )
    .await
    .unwrap();
    assert_ne!(a.profile.id, other_subject.profile.id);
    assert_ne!(a.profile.id, other_issuer.profile.id);
    assert!(other_subject.created && other_issuer.created);
}

// Entries of one new identity arriving together end at one record. Bug
// prevented: a duplicate account per concurrent first sign-in, each with its
// own permissions later.
#[tokio::test]
async fn concurrent_first_entries_end_at_one_record() {
    let storage = storage().await;
    let mut entries = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let storage = storage.clone();
        entries.spawn(async move { record_of(storage.as_ref(), ISSUER, subject(1), ctx()).await });
    }
    let mut records = Vec::new();
    while let Some(entry) = entries.join_next().await {
        records.push(entry.unwrap().unwrap());
    }
    let id = records[0].profile.id;
    assert!(records.iter().all(|r| r.profile.id == id));
    assert_eq!(records.iter().filter(|r| r.created).count(), 1);
}

// A subject the installation's organization assigned to one of its own
// Profiles is not an outside identity: it gets no reference record. A
// record the installation suspended stays that same suspended record, so a
// ban is not escaped by signing in again; only a record that was deleted
// outright is forgotten, and its identity then starts anew with nothing.
// Bug prevented: an own account shadowed by a reference, or a banned
// visitor given a fresh active record.
#[tokio::test]
async fn an_own_identity_gets_no_record_and_a_ban_stays() {
    let storage = storage().await;
    let own = stored_profile(storage.as_ref(), "alice").await;
    storage
        .save_principal(
            &Principal::new_federated_subject(own, ISSUER, &subject(1).to_string()),
            ctx(),
        )
        .await
        .unwrap();
    assert!(matches!(
        record_of(storage.as_ref(), ISSUER, subject(1), ctx()).await,
        Err(RecordError::OwnProfile)
    ));

    let visitor = record_of(storage.as_ref(), ISSUER, subject(2), ctx())
        .await
        .unwrap();
    let mut banned = visitor.profile.clone();
    banned.status = ProfileStatus::Suspended;
    assert!(storage.update_profile(&banned, ctx()).await.unwrap());
    let returned = record_of(storage.as_ref(), ISSUER, subject(2), ctx())
        .await
        .unwrap();
    assert!(!returned.created);
    assert_eq!(returned.profile.id, visitor.profile.id);
    assert_eq!(returned.profile.status, ProfileStatus::Suspended);
    assert!(!returned.profile.status.can_authenticate());

    // Deleting the record's only assignment forgets the identity.
    assert!(
        storage
            .unbind_principal(visitor.assignment.principal, visitor.profile.id, ctx())
            .await
            .unwrap()
    );
    let anew = record_of(storage.as_ref(), ISSUER, subject(2), ctx())
        .await
        .unwrap();
    assert!(anew.created);
    assert_ne!(anew.profile.id, visitor.profile.id);
    assert!(anew.profile.roles.is_empty());
}
