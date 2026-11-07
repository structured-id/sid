// SPDX-License-Identifier: AGPL-3.0-only
//! Moving records between stores: what a snapshot exports is stored as it
//! is, an import writes it exactly as exported, a repeat writes nothing and a
//! different record under a stored key is a conflict that writes nothing.

use chrono::{Duration, DurationRound, Utc};
use sid_core::Error;
use sid_core::models::machine_user::CredentialStatus;
use sid_core::models::{
    AccessRequest, AccessRequestStatus, ActionConfig, ActionOnError, ActionPoint, ActionType,
    AnomalyEventId, AnomalyEventRecord, ConnectorCredentialKind, ConnectorState, FlowAction,
    FlowType, Invite, InviteCreator, InviteId, InviteRedemption, IpReputation,
    PasswordResetSession, PrincipalBindingId, PrincipalId, PrincipalType, ProvisioningConnector,
    ProvisioningCredential, ProvisioningDirection, QuarantinedPrincipal, RegistrationSource,
    ResetSessionStatus, StoredPrincipal, StoredUserHandle, WebAuthnUserHandle,
    generate_invite_code,
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

/// An instant every store keeps exactly.
fn instant() -> chrono::DateTime<Utc> {
    Utc::now()
        .duration_trunc(Duration::microseconds(1))
        .unwrap()
}

/// What the sign-in rules learned and fired moves as stored: IP reputation
/// with the score its counts give, anomaly events, allowlist entries with
/// when they were added.
pub async fn test_signals_move_as_stored(backend: &dyn StorageBackend) {
    let ip = format!("rep-{}", Uuid::now_v7().simple());
    backend
        .record_ip_reputation_event(&ip, false)
        .await
        .unwrap();
    backend.record_ip_reputation_event(&ip, true).await.unwrap();
    let held = backend
        .export_ip_reputation()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.ip == ip)
        .expect("exported");
    assert_eq!((held.failed_count, held.success_count), (1, 1));
    assert!(
        !backend
            .import_ip_reputation(&held, test_audit())
            .await
            .unwrap()
    );
    let mut differing = held.clone();
    differing.failed_count += 1;
    let refused = backend.import_ip_reputation(&differing, test_audit()).await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    let moved = IpReputation {
        ip: format!("moved-{}", Uuid::now_v7().simple()),
        failed_count: 3,
        success_count: 0,
        first_seen_at: instant(),
        last_failed_at: Some(instant()),
        last_success_at: None,
        updated_at: instant(),
    };
    assert!(
        backend
            .import_ip_reputation(&moved, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .export_ip_reputation()
            .await
            .unwrap()
            .contains(&moved)
    );
    // The score follows from the counts: 3 / (3 + 0 + 1).
    let score = backend.get_ip_reputation_score(&moved.ip).await.unwrap();
    assert!(score.is_some_and(|s| (s - 0.75).abs() < 1e-6), "{score:?}");

    let mut event = AnomalyEventRecord::new(
        "conformance",
        Uuid::now_v7().to_string(),
        Some("192.0.2.9".parse().unwrap()),
        "fired",
        10,
        "allow",
    );
    event.timestamp = instant();
    backend.save_anomaly_event(&event).await.unwrap();
    assert!(
        !backend
            .import_anomaly_event(&event, test_audit())
            .await
            .unwrap()
    );
    let mut differing = event.clone();
    differing.risk_score += 1;
    let refused = backend.import_anomaly_event(&differing, test_audit()).await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    let moved = AnomalyEventRecord {
        id: AnomalyEventId::new(),
        ..event
    };
    assert!(
        backend
            .import_anomaly_event(&moved, test_audit())
            .await
            .unwrap()
    );
    let listed = backend
        .list_anomaly_events(Some("conformance"), 1000, 0)
        .await
        .unwrap();
    assert!(listed.contains(&moved));

    let cidr = format!("moved-{}", Uuid::now_v7().simple());
    let added = instant() - Duration::days(3);
    assert!(
        backend
            .import_ip_allowlist_entry(&cidr, "moved", added, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .import_ip_allowlist_entry(&cidr, "moved", added, test_audit())
            .await
            .unwrap()
    );
    let refused = backend
        .import_ip_allowlist_entry(&cidr, "other", added, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert!(
        backend
            .list_ip_allowlist_entries()
            .await
            .unwrap()
            .contains(&(cidr, "moved".into(), added))
    );
}

/// The login policy epoch moves into a store that has none; a store that
/// holds it takes the same epoch again and refuses another.
pub async fn test_login_policy_epoch_moves(backend: &dyn StorageBackend) {
    let epoch = match backend.export_login_policy_epoch().await.unwrap() {
        Some(held) => held,
        None => {
            assert!(
                backend
                    .import_login_policy_epoch(7, test_audit())
                    .await
                    .unwrap()
            );
            7
        }
    };
    assert_eq!(
        backend.export_login_policy_epoch().await.unwrap(),
        Some(epoch)
    );
    assert!(
        !backend
            .import_login_policy_epoch(epoch, test_audit())
            .await
            .unwrap()
    );
    let refused = backend
        .import_login_policy_epoch(epoch + 1, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
}

/// A profile's sign-in records move as stored: its locations, its reset
/// sessions in any state and its access requests, decided ones included.
pub async fn test_sign_in_records_move_as_stored(backend: &dyn StorageBackend) {
    let profile = create_test_profile("records_move");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    backend
        .record_login_location(profile.id, "PL", 52.2, 21.0, 2)
        .await
        .unwrap();
    let held = backend
        .export_login_locations()
        .await
        .unwrap()
        .into_iter()
        .find(|(owner, _)| *owner == profile.id)
        .expect("exported")
        .1;
    assert_eq!(held.login_count, 1);
    assert!(
        !backend
            .import_login_location(profile.id, &held, test_audit())
            .await
            .unwrap()
    );
    let mut differing = held.clone();
    differing.login_count += 1;
    let refused = backend
        .import_login_location(profile.id, &differing, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    let moved = sid_plugin::LoginLocation {
        country: "DE".into(),
        login_count: 4,
        designated: true,
        first_seen: instant() - Duration::days(9),
        last_seen: instant(),
        ..held
    };
    assert!(
        backend
            .import_login_location(profile.id, &moved, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .export_login_locations()
            .await
            .unwrap()
            .contains(&(profile.id, moved))
    );
    assert!(
        backend
            .get_designated_countries(profile.id)
            .await
            .unwrap()
            .contains(&"DE".to_string())
    );

    let mut reset = PasswordResetSession::new(
        profile.id,
        "records@sid.example.com".into(),
        "records@sid.example.com".into(),
        format!("hash-{}", Uuid::now_v7()),
    );
    reset.status = ResetSessionStatus::Completed;
    reset.verified_at = Some(reset.created_at);
    reset.completed_at = Some(reset.created_at);
    backend
        .create_reset_session(&reset, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .export_reset_sessions()
            .await
            .unwrap()
            .contains(&reset)
    );

    let mut request = AccessRequest::new(profile.id, sid_core::models::ProjectId::SYSTEM, "editor");
    request.status = AccessRequestStatus::Denied;
    request.reviewed_by = Some(profile.id);
    request.reviewed_at = Some(instant());
    request.created_at = instant();
    backend
        .create_access_request(&request, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .export_access_requests()
            .await
            .unwrap()
            .contains(&request)
    );
}

/// Where a profile came from and the invite it spent move as stored: the
/// redemption leaves the invite's use count as exported.
pub async fn test_enrollment_records_move_as_stored(backend: &dyn StorageBackend) {
    let creator = create_test_profile("invite_creator");
    backend
        .create_profile(&creator, test_audit())
        .await
        .unwrap();
    let invite = Invite {
        id: InviteId::generate(),
        code: generate_invite_code(),
        created_by: InviteCreator::Profile(creator.id),
        created_by_name: "conformance".into(),
        metadata: Default::default(),
        max_uses: 3,
        use_count: 1,
        expires_at: None,
        active: true,
        created_at: instant(),
    };
    backend
        .create_invites(std::slice::from_ref(&invite), test_audit())
        .await
        .unwrap();
    let invited = create_test_profile("invited");
    backend
        .create_profile(&invited, test_audit())
        .await
        .unwrap();
    let redemption = InviteRedemption {
        profile_id: invited.id,
        credential_id: None,
        redeemed_at: instant(),
    };
    assert!(
        backend
            .import_invite_redemption(invite.id, &redemption, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .import_invite_redemption(invite.id, &redemption, test_audit())
            .await
            .unwrap()
    );
    let refused = backend
        .import_invite_redemption(
            invite.id,
            &InviteRedemption {
                redeemed_at: redemption.redeemed_at + Duration::seconds(1),
                ..redemption.clone()
            },
            test_audit(),
        )
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(
        backend
            .list_invite_redemptions(invite.id, 0, 10)
            .await
            .unwrap(),
        vec![redemption]
    );
    assert_eq!(
        backend
            .get_invite(invite.id)
            .await
            .unwrap()
            .map(|i| i.use_count),
        Some(1)
    );

    let mut source = RegistrationSource::from_invite(&invite.code, Some("app".into()));
    source.referrer_id = Some(creator.id);
    source.created_at = instant();
    assert!(
        backend
            .import_registration_source(invited.id, &source, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .import_registration_source(invited.id, &source, test_audit())
            .await
            .unwrap()
    );
    let mut differing = source.clone();
    differing.client_id = None;
    let refused = backend
        .import_registration_source(invited.id, &differing, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(
        backend.get_registration_source(invited.id).await.unwrap(),
        Some(source)
    );
}

/// A connector's credentials move as they were, whatever its state: a
/// revoked credential of a retired connector is still stored after the move.
pub async fn test_connector_credentials_move_as_stored(backend: &dyn StorageBackend) {
    let org = sid_core::models::OrgId::generate();
    let connector = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "moved");
    backend
        .create_provisioning_connector(&connector, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .transition_provisioning_connector(
                connector.id,
                ConnectorState::Active,
                ConnectorState::Retired,
                test_audit(),
            )
            .await
            .unwrap()
    );
    let mut credential = ProvisioningCredential::new(
        connector.id,
        ConnectorCredentialKind::ScimBearer,
        format!("{:064x}", Uuid::now_v7().as_u128()),
    );
    credential.status = CredentialStatus::Revoked;
    credential.created_at = instant();
    assert!(
        backend
            .import_provisioning_credential(&credential, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .import_provisioning_credential(&credential, test_audit())
            .await
            .unwrap()
    );
    let mut differing = credential.clone();
    differing.status = CredentialStatus::Active;
    let refused = backend
        .import_provisioning_credential(&differing, test_audit())
        .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert_eq!(
        backend
            .list_provisioning_credentials(connector.id)
            .await
            .unwrap(),
        vec![credential]
    );
    let exported = backend.export_provisioning_connectors().await.unwrap();
    assert!(
        exported
            .iter()
            .any(|c| c.id == connector.id && c.state == ConnectorState::Retired)
    );
}

/// A restored flow action keeps the revision it was exported at.
pub async fn test_flow_action_restores_at_its_revision(backend: &dyn StorageBackend) {
    let action = FlowAction {
        id: sid_core::models::FlowActionId::generate(),
        project_id: sid_core::models::ProjectId::SYSTEM,
        flow_type: FlowType::Registration,
        action_point: ActionPoint::PostRegistration,
        name: "moved".into(),
        action_type: ActionType::Webhook,
        config: ActionConfig::Webhook {
            url: "https://hooks.sid.example.com/moved".into(),
            timeout_seconds: 5,
            retry_count: 0,
            headers: Default::default(),
        },
        order: 1,
        on_error: ActionOnError::Continue,
        enabled: true,
        revision: 3,
        created_at: instant(),
        updated_at: instant(),
    };
    backend
        .create_flow_action(&action, test_audit())
        .await
        .unwrap();
    let stored = backend.get_flow_action(action.id).await.unwrap().unwrap();
    assert_eq!(stored, action);
    let stale = FlowAction {
        revision: 2,
        ..stored.clone()
    };
    assert!(
        !backend
            .update_flow_action(&stale, test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .update_flow_action(&stored, test_audit())
            .await
            .unwrap()
    );
}
