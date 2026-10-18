// SPDX-License-Identifier: AGPL-3.0-only
use std::sync::Arc;

use sid_authn::password_operation::OperationPurpose as _;
use sid_core::models::{CredentialId, ProfileId, ResetSessionId};
use sid_storage::sqlite::SqliteBackend;

use super::OperationPurpose;

fn change() -> OperationPurpose {
    OperationPurpose::Change {
        profile_id: ProfileId::generate(),
        credential_id: CredentialId(uuid::Uuid::now_v7()),
        password: [5; 16],
    }
}

async fn sqlite() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

/// Deleting a profile owes its history keys' purge in the deletion's
/// transaction, under the profile's domain in this installation.
#[tokio::test]
async fn a_profile_deletion_owes_its_purge() {
    use sid_core::models::{
        AuditEntry, MutationContext, Organization, OwnerPurge, Profile, WorkState,
    };
    use sid_plugin::WorkStore;
    use sid_plugin::storage::StorageBackend;
    let storage = sqlite().await;
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, AuditEntry::system("test", "org").into())
        .await
        .unwrap();
    let profile = Profile::new(Some("purged-owner"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();

    let purge = super::owner_purge(storage.as_ref(), profile.id)
        .await
        .unwrap()
        .expect("an installation with an authority owes the purge");
    let expected = OwnerPurge {
        owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile.id),
    }
    .work();
    assert_eq!(purge.id, expected.id);
    storage
        .delete_profile(
            profile.id,
            MutationContext::from(AuditEntry::system("test", "delete")).with_work(purge.clone()),
        )
        .await
        .unwrap();
    let owed = storage.get_work(purge.id).await.unwrap().unwrap();
    assert_eq!(owed.state, WorkState::Pending);
}

/// Before the installation has an authority there is no history domain, so
/// no key, and nothing is owed.
#[tokio::test]
async fn nothing_is_owed_without_an_authority() {
    let storage = sqlite().await;
    assert!(
        super::owner_purge(storage.as_ref(), ProfileId::generate())
            .await
            .unwrap()
            .is_none()
    );
}

/// Every purpose names the method of its durable result: a registration, a
/// change and a reset are different commands under one operation key.
#[test]
fn every_purpose_names_its_method() {
    assert_eq!(change().method(), "change");
    assert_eq!(
        OperationPurpose::Reset {
            session: ResetSessionId(uuid::Uuid::now_v7()),
        }
        .method(),
        "reset"
    );
}
