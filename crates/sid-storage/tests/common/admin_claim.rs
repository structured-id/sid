// SPDX-License-Identifier: AGPL-3.0-only
//! First-administrator claim: the claim is consumed with the role grant, once.
//!
//! Needs a backend holding no administrator yet (an isolated schema or a
//! fresh database): the scenario is the instance's first claim.

use super::{create_test_profile, test_audit};
use sid_core::models::{InstanceSecret, Profile};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

async fn stored_profile(backend: &dyn StorageBackend, name: &str) -> Profile {
    let profile = create_test_profile(name);
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    backend.get_profile(profile.id).await.unwrap().unwrap()
}

fn with_admin(mut profile: Profile) -> Profile {
    profile.roles.push("admin".to_string());
    profile
}

/// The instance never loses its last administrator to a closure request: an
/// administrator's request is stored only while another active or suspended
/// administrator remains, checked in the same write. Of two administrators
/// requesting at once, exactly one closes; a non-administrator is unaffected.
pub async fn test_last_administrator_cannot_request_closure(backend: &dyn StorageBackend) {
    use sid_core::models::{ClosureMode, ClosureRequest, ProfileStatus};
    let tag = Uuid::now_v7().simple().to_string();
    let admin = |name: &str| {
        let mut profile = with_admin(create_test_profile(&format!("{name}_{tag}")));
        profile.status = ProfileStatus::Active;
        profile
    };
    let (a, b) = (admin("adm_a"), admin("adm_b"));
    for profile in [&a, &b] {
        backend.create_profile(profile, test_audit()).await.unwrap();
    }
    let user = stored_profile(backend, &format!("plain_{tag}")).await;
    let request = |profile: &Profile| {
        let stored = profile.clone();
        let mut closing = stored;
        closing
            .transition_status(ProfileStatus::ClosureRequested)
            .unwrap();
        let req = ClosureRequest::new(profile.id, ClosureMode::Voluntary, profile.id)
            .with_grace_period_days(30);
        (closing, req)
    };
    let reread = |id| async move { backend.get_profile(id).await.unwrap().unwrap() };

    // A non-administrator closes whatever the administrators do.
    let (closing, req) = request(&user);
    assert!(
        backend
            .request_profile_closure(&closing, &req, test_audit())
            .await
            .unwrap()
    );

    // Two administrators at once: one closes, the other is the last one.
    let (a_closing, a_req) = request(&reread(a.id).await);
    let (b_closing, b_req) = request(&reread(b.id).await);
    let (ra, rb) = tokio::join!(
        backend.request_profile_closure(&a_closing, &a_req, test_audit()),
        backend.request_profile_closure(&b_closing, &b_req, test_audit()),
    );
    let refused = |r: &sid_core::Result<bool>| matches!(r, Err(sid_core::Error::InvalidState(_)));
    assert!(
        matches!((&ra, &rb), (Ok(true), _) | (_, Ok(true))) && (refused(&ra) ^ refused(&rb)),
        "exactly one administrator closes: {ra:?} {rb:?}"
    );
    let (closed, kept) = if matches!(ra, Ok(true)) {
        (a.id, b.id)
    } else {
        (b.id, a.id)
    };
    assert_eq!(reread(closed).await.status, ProfileStatus::ClosureRequested);
    assert_eq!(reread(kept).await.status, ProfileStatus::Active);
    assert!(
        backend.get_closure_request(kept).await.unwrap().is_none(),
        "the refused request was stored"
    );
}

/// A self-registration presenting the instance claim: while the installation
/// has no administrator it is the only registration that creates an
/// administrator, and it consumes the claim in the same transaction.
pub async fn test_registration_claims_instance(backend: &dyn StorageBackend) {
    use sid_core::models::{NewRegistration, PrincipalType};
    assert!(!backend.admin_exists().await.unwrap());
    let claim = Uuid::now_v7().as_bytes().to_vec();
    backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
        .await
        .unwrap();
    let registration = |name: &str, presented: &[u8]| {
        NewRegistration::new(
            create_test_profile(name),
            sid_core::models::SignupIdentifier::Username(name),
            None,
        )
        .unwrap()
        .claiming_instance(presented.to_vec())
    };
    let refused = |r: &sid_core::Result<()>| matches!(r, Err(sid_core::Error::InvalidState(_)));
    let stored = |name: &'static str| async move {
        backend
            .get_principal_by_value(PrincipalType::Username, name)
            .await
            .unwrap()
    };

    // Another value than the stored claim creates nothing, not even the name.
    let other = Uuid::now_v7().as_bytes().to_vec();
    let result = backend
        .register_profile(&registration("wrong_claim", &other), test_audit())
        .await;
    assert!(refused(&result), "{result:?}");
    assert!(stored("wrong_claim").await.is_none());
    assert_eq!(
        claim_stored(backend).await.as_deref(),
        Some(claim.as_slice())
    );

    // Two registrations racing on one claim: exactly one becomes administrator.
    let (a, b) = (
        registration("claim_a", &claim),
        registration("claim_b", &claim),
    );
    let (ra, rb) = tokio::join!(
        backend.register_profile(&a, test_audit()),
        backend.register_profile(&b, test_audit()),
    );
    assert!(ra.is_ok() ^ rb.is_ok(), "registrations: {ra:?} {rb:?}");
    let (winner, loser, lost) = if ra.is_ok() {
        (&a, "claim_b", rb)
    } else {
        (&b, "claim_a", ra)
    };
    assert!(refused(&lost), "{lost:?}");
    let admin = backend
        .get_profile(winner.profile.id)
        .await
        .unwrap()
        .unwrap();
    assert!(admin.is_admin());
    assert!(
        stored(loser).await.is_none(),
        "the refused registration kept its name"
    );
    assert!(claim_stored(backend).await.is_none());

    // The consumed claim registers nothing more.
    let result = backend
        .register_profile(&registration("claim_late", &claim), test_audit())
        .await;
    assert!(refused(&result), "{result:?}");
    assert!(stored("claim_late").await.is_none());

    // A registration without a claim is an ordinary account.
    let plain = NewRegistration::new(
        create_test_profile("claim_plain"),
        sid_core::models::SignupIdentifier::Username("claim_plain"),
        None,
    )
    .unwrap();
    backend
        .register_profile(&plain, test_audit())
        .await
        .unwrap();
    let plain = backend
        .get_profile(plain.profile.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!plain.is_admin());
}

async fn claim_stored(backend: &dyn StorageBackend) -> Option<Vec<u8>> {
    backend
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await
        .unwrap()
}

pub async fn test_admin_claim_consumed_once(backend: &dyn StorageBackend) {
    assert!(!backend.admin_exists().await.unwrap());
    let claim = Uuid::now_v7().as_bytes().to_vec();
    assert!(
        backend
            .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
            .await
            .unwrap()
    );

    // Another value than the stored claim changes nothing.
    let stranger = stored_profile(backend, "stranger").await;
    let other = Uuid::now_v7().as_bytes().to_vec();
    assert!(
        !backend
            .claim_first_admin(&other, &with_admin(stranger.clone()), test_audit())
            .await
            .unwrap()
    );

    // A profile written since it was read is refused and the claim stays.
    let mut moved = stranger.clone();
    moved.given_name = Some("Moved".into());
    assert!(backend.update_profile(&moved, test_audit()).await.unwrap());
    assert!(
        !backend
            .claim_first_admin(&claim, &with_admin(stranger), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        claim_stored(backend).await.as_deref(),
        Some(claim.as_slice())
    );
    assert!(!backend.admin_exists().await.unwrap());

    // Two claimers racing: exactly one becomes administrator.
    let a = stored_profile(backend, "claimer_a").await;
    let b = stored_profile(backend, "claimer_b").await;
    let (a_claims, b_claims) = (with_admin(a.clone()), with_admin(b.clone()));
    let (ra, rb) = tokio::join!(
        backend.claim_first_admin(&claim, &a_claims, test_audit()),
        backend.claim_first_admin(&claim, &b_claims, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "claims: {ra} {rb}");
    let a_admin = backend.get_profile(a.id).await.unwrap().unwrap().is_admin();
    let b_admin = backend.get_profile(b.id).await.unwrap().unwrap().is_admin();
    assert_eq!((a_admin, b_admin), (ra, rb));
    assert!(backend.admin_exists().await.unwrap());
    assert!(claim_stored(backend).await.is_none());

    // A claim stored beside an administrator grants nothing and is removed.
    let late = Uuid::now_v7().as_bytes().to_vec();
    backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &late, test_audit())
        .await
        .unwrap();
    let c = stored_profile(backend, "claimer_c").await;
    assert!(
        !backend
            .claim_first_admin(&late, &with_admin(c.clone()), test_audit())
            .await
            .unwrap()
    );
    assert!(!backend.get_profile(c.id).await.unwrap().unwrap().is_admin());
    assert!(claim_stored(backend).await.is_none());
}
