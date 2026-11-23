// SPDX-License-Identifier: AGPL-3.0-only
//! A host's own transaction on the CoordiNode database SID's records live
//! in: the host's record and the SID registration it asks for commit
//! together or not at all, and of two competing claims exactly one leaves a
//! credential-bearing account.
//!
//! Run with: cargo nextest run -p sid-storage --features storage-coordinode --test coordinode_host_registration
#![cfg(feature = "storage-coordinode")]

use std::collections::HashMap;
use std::sync::Arc;

use coordinode_core::graph::types::Value;
use coordinode_embed::Database;
use sid_core::Error;
use sid_core::models::{AuditEntry, CredentialType, MutationContext, NewRegistration};
use sid_plugin::conformance::backend::new_email_registration;
use sid_plugin::{CredentialStore, StorageBackend};
use sid_storage::coordinode::{CoordinodeBackend, HostTransaction, HostWriteError};

async fn store() -> (CoordinodeBackend, Arc<Database>) {
    let db = Arc::new(Database::open_in_memory().expect("CoordiNode in memory"));
    let backend = CoordinodeBackend::new(db.clone())
        .await
        .expect("SID's schema in CoordiNode");
    (backend, db)
}

fn audit() -> MutationContext {
    AuditEntry::system("host", "first-owner claim").into()
}

/// The host's own record of a claim, written in its transaction.
fn write_claim(db: &Database, tx: &HostTransaction<'_>, claim: &str) {
    let params = HashMap::from([("claim".to_owned(), Value::String(claim.to_owned()))]);
    db.execute_in_transaction(
        tx.id(),
        "CREATE (c:HostClaim {claim: $claim})",
        Some(params),
    )
    .expect("the host's own write");
}

fn claims(db: &Database, claim: &str) -> usize {
    let params = HashMap::from([("claim".to_owned(), Value::String(claim.to_owned()))]);
    let id = db.begin_transaction().unwrap();
    let rows = db
        .execute_in_transaction(
            id,
            "MATCH (c:HostClaim) WHERE c.claim = $claim RETURN c.claim AS claim",
            Some(params),
        )
        .expect("read the host's records");
    db.rollback_transaction(id).unwrap();
    rows.len()
}

async fn opaque_credentials(backend: &CoordinodeBackend, registration: &NewRegistration) -> usize {
    backend
        .get_credentials_by_profile(registration.profile.id, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .len()
}

/// The host's record and the registration commit as one.
#[tokio::test]
async fn the_host_record_and_the_registration_commit_together() {
    let (backend, db) = store().await;
    let registration = new_email_registration(&format!("{}@sid.example.com", uuid::Uuid::now_v7()));
    let (claim, registration) = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            let tx = HostTransaction::begin(&db).unwrap();
            write_claim(&db, &tx, "together");
            tx.register_profile(&registration, audit()).unwrap();
            tx.commit().unwrap();
            ("together", registration)
        }
    })
    .await
    .unwrap();
    assert_eq!(claims(&db, claim), 1);
    assert!(
        backend
            .get_profile(registration.profile.id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(opaque_credentials(&backend, &registration).await, 1);
}

/// A host rolling its attempt back keeps neither its record nor the account.
#[tokio::test]
async fn a_rolled_back_attempt_leaves_nothing() {
    let (backend, db) = store().await;
    let registration = new_email_registration(&format!("{}@sid.example.com", uuid::Uuid::now_v7()));
    let registration = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            let tx = HostTransaction::begin(&db).unwrap();
            write_claim(&db, &tx, "rolled-back");
            tx.register_profile(&registration, audit()).unwrap();
            tx.rollback().unwrap();
            registration
        }
    })
    .await
    .unwrap();
    assert_eq!(claims(&db, "rolled-back"), 0);
    assert!(
        backend
            .get_profile(registration.profile.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(opaque_credentials(&backend, &registration).await, 0);
}

/// Two claims for one identifier, interleaved: the first commits; the second
/// is told to run again, and its run again is refused as a taken identifier,
/// leaving no credential and no host record.
#[tokio::test]
async fn of_two_competing_claims_one_commits_and_the_other_leaves_nothing() {
    let (backend, db) = store().await;
    let email = format!("{}@sid.example.com", uuid::Uuid::now_v7());
    let winner = new_email_registration(&email);
    let loser = new_email_registration(&email);
    let (winner, loser) = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            let first = HostTransaction::begin(&db).unwrap();
            let second = HostTransaction::begin(&db).unwrap();
            write_claim(&db, &first, "winner");
            write_claim(&db, &second, "loser");
            first.register_profile(&winner, audit()).unwrap();
            let lost = match second.register_profile(&loser, audit()) {
                // Refused at the write: the host rolls back.
                Err(HostWriteError::Contended) => {
                    second.rollback().ok();
                    first.commit().unwrap();
                    true
                }
                Err(HostWriteError::Refused(e)) => panic!("refused at the write: {e:?}"),
                Ok(()) => {
                    first.commit().unwrap();
                    matches!(second.commit(), Err(HostWriteError::Contended))
                }
            };
            assert!(lost, "the second claim is told to run again");

            // Its run again sees the first and is refused.
            let again = HostTransaction::begin(&db).unwrap();
            write_claim(&db, &again, "loser");
            let refused = again.register_profile(&loser, audit());
            assert!(
                matches!(refused, Err(HostWriteError::Refused(Error::Conflict(_)))),
                "{refused:?}"
            );
            again.rollback().ok();
            (winner, loser)
        }
    })
    .await
    .unwrap();
    assert_eq!(claims(&db, "winner"), 1);
    assert_eq!(
        claims(&db, "loser"),
        0,
        "the losing host record rolled back"
    );
    assert_eq!(opaque_credentials(&backend, &winner).await, 1);
    assert_eq!(
        opaque_credentials(&backend, &loser).await,
        0,
        "no credential is left behind"
    );
    assert!(
        backend
            .get_profile(loser.profile.id)
            .await
            .unwrap()
            .is_none()
    );
}
