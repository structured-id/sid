// SPDX-License-Identifier: AGPL-3.0-only
//! Directory (SCIM) writes: one request's changes to a user or a group are
//! applied in one transaction with its audit entry and owed work.

use chrono::Utc;
use sid_core::Error;
use sid_core::models::{
    DirectoryGroupWrite, DirectoryUserWrite, DirectoryWriteMode, EmailLabel, Event, Group,
    GroupMember, NewWork, PatStatus, PersonalAccessToken, PhoneLabel, Principal, PrincipalType,
    Profile, ProfileEmail, ProfileEmailId, ProfileId, ProfileMetadata, ProfilePhone,
    ProfilePhoneId, ProjectId, RevocationReason, SessionEnd, WorkState,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, create_test_session, test_audit};

fn tag() -> String {
    Uuid::now_v7().simple().to_string()
}

fn email(profile_id: ProfileId, address: &str) -> ProfileEmail {
    let now = Utc::now();
    ProfileEmail {
        id: ProfileEmailId::new(),
        profile_id,
        email: address.to_string(),
        label: EmailLabel::Work,
        custom_label: None,
        is_primary: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn phone(profile_id: ProfileId) -> ProfilePhone {
    let now = Utc::now();
    ProfilePhone {
        id: ProfilePhoneId::new(),
        profile_id,
        e164: 380_500_000_000 + u64::from(Uuid::now_v7().as_bytes()[15]),
        extension: None,
        label: PhoneLabel::Work,
        custom_label: None,
        is_primary: true,
        can_receive_sms: true,
        can_receive_fax: false,
        can_receive_voice: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    }
}

/// The event a write owes, and its work id.
fn owed_event() -> NewWork {
    Event::new("sid-scim", "sid.scim.user.provisioned.v1").relay()
}

/// A new account with its login handle, contact email, phone, metadata and
/// owed event is stored whole.
async fn provision(backend: &dyn StorageBackend) -> (Profile, Principal, NewWork) {
    let profile = create_test_profile("dir_user");
    let login = Principal::new_username(profile.id, format!("dir{}#acme.example.com", tag()));
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Create, profile.clone());
    write.bind.push(login.clone());
    write.bind.push(Principal::new_email(
        profile.id,
        format!("dir{}@sid.example.com", tag()),
    ));
    write
        .add_emails
        .push(email(profile.id, "work@sid.example.com"));
    write.add_phones.push(phone(profile.id));
    write.set_metadata.push(ProfileMetadata::new(
        profile.id,
        "department",
        serde_json::json!("R&D"),
    ));
    let event = owed_event();
    backend
        .write_directory_user(&write, test_audit().with_work(event.clone()))
        .await
        .unwrap();
    (profile, login, event)
}

pub async fn test_directory_user_create_stores_everything(backend: &dyn StorageBackend) {
    let (profile, login, event) = provision(backend).await;

    assert!(backend.get_profile(profile.id).await.unwrap().is_some());
    let principals = backend.get_principals_by_profile(profile.id).await.unwrap();
    assert_eq!(principals.len(), 2);
    assert!(principals.iter().any(|p| p.value == login.value));
    assert_eq!(
        backend.list_profile_emails(profile.id).await.unwrap().len(),
        1
    );
    assert_eq!(
        backend.list_profile_phones(profile.id).await.unwrap().len(),
        1
    );
    assert_eq!(
        backend
            .list_profile_metadata(profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        backend.get_work(event.id).await.unwrap().unwrap().state,
        WorkState::Pending
    );
}

/// A login handle another account already holds refuses the whole create:
/// no account, no contacts, no event.
pub async fn test_directory_user_create_taken_login_writes_nothing(backend: &dyn StorageBackend) {
    let (_, taken, _) = provision(backend).await;

    let second = create_test_profile("dir_second");
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Create, second.clone());
    write
        .bind
        .push(Principal::new_username(second.id, taken.value.clone()));
    write
        .add_emails
        .push(email(second.id, "second@sid.example.com"));
    let event = owed_event();
    let err = backend
        .write_directory_user(&write, test_audit().with_work(event.clone()))
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert!(backend.get_profile(second.id).await.unwrap().is_none());
    assert!(
        backend
            .list_profile_emails(second.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(backend.get_work(event.id).await.unwrap().is_none());
}

/// Two directories creating the same user name at once: one account exists
/// afterwards, the other create is refused.
pub async fn test_directory_user_concurrent_create_single_winner(backend: &dyn StorageBackend) {
    let handle = format!("race{}#acme.example.com", tag());
    let write = |profile: Profile| {
        let mut w = DirectoryUserWrite::new(DirectoryWriteMode::Create, profile.clone());
        w.bind
            .push(Principal::new_username(profile.id, handle.clone()));
        w
    };
    let a = write(create_test_profile("race_a"));
    let b = write(create_test_profile("race_b"));
    let (ra, rb) = tokio::join!(
        backend.write_directory_user(&a, test_audit()),
        backend.write_directory_user(&b, test_audit()),
    );
    assert_eq!(
        usize::from(ra.is_ok()) + usize::from(rb.is_ok()),
        1,
        "{ra:?} {rb:?}"
    );
    let loser = if ra.is_ok() { &b } else { &a };
    assert!(
        backend
            .get_profile(loser.profile_id())
            .await
            .unwrap()
            .is_none()
    );
}

/// An update replaces contacts and metadata and moves principals in one step.
pub async fn test_directory_user_update_applies_every_change(backend: &dyn StorageBackend) {
    let (mut profile, login, _) = provision(backend).await;
    let principals = backend.get_principals_by_profile(profile.id).await.unwrap();
    let old_contact = principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .unwrap()
        .clone();
    let old_email = backend.list_profile_emails(profile.id).await.unwrap()[0].id;
    let old_phone = backend.list_profile_phones(profile.id).await.unwrap()[0].id;

    profile.given_name = Some("Renamed".to_string());
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone());
    write.unbind.push(old_contact.id);
    let new_contact = Principal::new_email(profile.id, format!("new{}@sid.example.com", tag()));
    write.bind.push(new_contact.clone());
    write.remove_emails.push(old_email);
    write
        .add_emails
        .push(email(profile.id, "new@sid.example.com"));
    write.remove_phones.push(old_phone);
    write.remove_metadata.push("department".to_string());
    write.set_metadata.push(ProfileMetadata::new(
        profile.id,
        "title",
        serde_json::json!("Lead"),
    ));
    backend
        .write_directory_user(&write, test_audit())
        .await
        .unwrap();

    let stored = backend.get_profile(profile.id).await.unwrap().unwrap();
    assert_eq!(stored.given_name.as_deref(), Some("Renamed"));
    let values: Vec<String> = backend
        .get_principals_by_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.value)
        .collect();
    assert!(values.contains(&login.value));
    assert!(values.contains(&new_contact.value));
    assert!(!values.contains(&old_contact.value));
    let emails = backend.list_profile_emails(profile.id).await.unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].email, "new@sid.example.com");
    assert!(
        backend
            .list_profile_phones(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
    let metadata = backend.list_profile_metadata(profile.id).await.unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].key, "title");
}

/// An update of an account that does not exist writes nothing.
pub async fn test_directory_user_update_missing_writes_nothing(backend: &dyn StorageBackend) {
    let ghost = create_test_profile("dir_ghost");
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, ghost.clone());
    write.set_metadata.push(ProfileMetadata::new(
        ghost.id,
        "title",
        serde_json::json!("x"),
    ));
    let event = owed_event();
    let err = backend
        .write_directory_user(&write, test_audit().with_work(event.clone()))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert!(backend.get_profile(ghost.id).await.unwrap().is_none());
    assert!(backend.get_work(event.id).await.unwrap().is_none());
}

/// Deprovisioning ends every session (each owing its logout work) and
/// revokes every active PAT in the same write that suspends the account.
pub async fn test_directory_user_deprovision_ends_access(backend: &dyn StorageBackend) {
    let (mut profile, _, _) = provision(backend).await;
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    let pat = PersonalAccessToken::new(
        profile.id,
        "ci",
        format!("hash{}", tag()),
        format!("sid_{}", &tag()[..8]),
        vec!["openid".to_string()],
    );
    backend.create_pat(&pat, None, test_audit()).await.unwrap();

    profile.status = sid_core::models::ProfileStatus::Suspended;
    let mut write = DirectoryUserWrite::new(DirectoryWriteMode::Update, profile.clone());
    let end = SessionEnd::new(RevocationReason::Admin, "scim");
    write.end_access = Some(end.clone());
    let ended = backend
        .write_directory_user(&write, test_audit())
        .await
        .unwrap();

    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].id, session.id);
    assert!(backend.get_session(session.id).await.unwrap().is_none());
    assert_eq!(
        backend.get_pat(pat.id).await.unwrap().unwrap().status,
        PatStatus::Revoked
    );
    for owed in end.owed_by(&ended[0]) {
        assert!(backend.get_work(owed.id).await.unwrap().is_some());
    }
    assert_eq!(
        backend
            .get_profile(profile.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        sid_core::models::ProfileStatus::Suspended
    );
}

/// A group is created with its members, updated (renamed, members moved) and
/// a create over an existing group is refused.
pub async fn test_directory_group_writes(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let (first, _, _) = provision(backend).await;
    let (second, _, _) = provision(backend).await;
    let mut group = Group::new(ProjectId::system(), format!("dir_{}", tag()));
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    write.add_members.push(GroupMember::new(group.id, first.id));
    let event = owed_event();
    backend
        .write_directory_group(&write, test_audit().with_work(event.clone()))
        .await
        .unwrap();
    assert!(backend.get_work(event.id).await.unwrap().is_some());
    let members: Vec<ProfileId> = backend
        .list_group_members(group.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.profile_id)
        .collect();
    assert_eq!(members, vec![first.id]);

    group.name = format!("renamed_{}", tag());
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Update, group.clone());
    write
        .add_members
        .push(GroupMember::new(group.id, second.id));
    write.remove_members.push(first.id);
    backend
        .write_directory_group(&write, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend.get_group(group.id).await.unwrap().unwrap().name,
        group.name
    );
    let members: Vec<ProfileId> = backend
        .list_group_members(group.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.profile_id)
        .collect();
    assert_eq!(members, vec![second.id]);

    let again = DirectoryGroupWrite::new(DirectoryWriteMode::Create, group.clone());
    let err = backend
        .write_directory_group(&again, test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let missing = DirectoryGroupWrite::new(
        DirectoryWriteMode::Update,
        Group::new(ProjectId::system(), format!("missing_{}", tag())),
    );
    let err = backend
        .write_directory_group(&missing, test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
}
