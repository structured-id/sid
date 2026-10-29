// SPDX-License-Identifier: AGPL-3.0-only
//! First-administrator claim: the claim is consumed with the installation
//! administrator assignment, once.
//!
//! Needs a backend holding no administrator yet (an isolated schema or a
//! fresh database): the scenario is the instance's first claim.

use super::{create_test_profile, test_audit};
use sid_core::models::{
    InstanceSecret, Profile, ProfileId, Role, RoleAssignment, RoleAssignmentPrincipal,
};
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

/// Make `profile` an installation administrator as role administration
/// does: the built-in role, stored once, assigned across the installation.
async fn make_admin(backend: &dyn StorageBackend, profile: ProfileId) {
    match backend
        .create_role(&Role::installation_administrator(), test_audit())
        .await
    {
        Ok(()) | Err(sid_core::Error::Conflict(_)) => {}
        Err(e) => panic!("store the administrator role: {e}"),
    }
    backend
        .create_role_assignment(
            &RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(profile),
                Role::installation_administrator().id,
            )
            .on_installation(),
            test_audit(),
        )
        .await
        .unwrap();
}

/// Whether `profile` holds the installation administrator assignment.
async fn administers(backend: &dyn StorageBackend, profile: ProfileId) -> bool {
    backend
        .list_role_assignments_for_profile(profile)
        .await
        .unwrap()
        .iter()
        .any(RoleAssignment::administers_installation)
}

/// The instance never loses its last administrator to a closure request: an
/// administrator's request is stored only while another active or suspended
/// administrator remains, checked in the same write. Of two administrators
/// requesting at once, exactly one closes; a non-administrator is unaffected.
pub async fn test_last_administrator_cannot_request_closure(backend: &dyn StorageBackend) {
    use sid_core::models::{ClosureMode, ClosureRequest, ProfileStatus};
    let tag = Uuid::now_v7().simple().to_string();
    let admin = |name: &str| {
        let mut profile = create_test_profile(&format!("{name}_{tag}"));
        profile.status = ProfileStatus::Active;
        profile
    };
    let (a, b) = (admin("adm_a"), admin("adm_b"));
    for profile in [&a, &b] {
        backend.create_profile(profile, test_audit()).await.unwrap();
        make_admin(backend, profile.id).await;
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

/// The installation never loses its last administrator to a revocation:
/// removing an administrator assignment is refused while it is the only
/// one, and allowed once another administrator holds the role. Of two
/// administrators' assignments removed at once, exactly one goes. Deleting
/// the administrator role itself, which would take every assignment with
/// it, is refused while anyone holds it.
pub async fn test_last_administrator_assignment_is_kept(backend: &dyn StorageBackend) {
    let tag = Uuid::now_v7().simple().to_string();
    let a = stored_profile(backend, &format!("keep_a_{tag}")).await;
    let b = stored_profile(backend, &format!("keep_b_{tag}")).await;
    make_admin(backend, a.id).await;
    let assignment_of = |profile: ProfileId| async move {
        backend
            .list_role_assignments_for_profile(profile)
            .await
            .unwrap()
            .into_iter()
            .find(RoleAssignment::administers_installation)
            .unwrap()
            .id
    };
    let refused = |r: &sid_core::Result<()>| matches!(r, Err(sid_core::Error::InvalidState(_)));

    let only = assignment_of(a.id).await;
    let result = backend.delete_role_assignment(only, test_audit()).await;
    assert!(refused(&result), "{result:?}");
    assert!(administers(backend, a.id).await);
    let result = backend
        .delete_role(Role::installation_administrator().id, test_audit())
        .await;
    assert!(refused(&result), "{result:?}");
    assert!(administers(backend, a.id).await);

    make_admin(backend, b.id).await;
    let other = assignment_of(b.id).await;
    let (ra, rb) = tokio::join!(
        backend.delete_role_assignment(only, test_audit()),
        backend.delete_role_assignment(other, test_audit()),
    );
    assert!(
        (ra.is_ok() ^ rb.is_ok()) && (refused(&ra) ^ refused(&rb)),
        "exactly one administrator assignment goes: {ra:?} {rb:?}"
    );
    assert!(backend.admin_exists().await.unwrap());
    assert!(administers(backend, a.id).await ^ administers(backend, b.id).await);
    let result = backend
        .delete_role(Role::installation_administrator().id, test_audit())
        .await;
    assert!(refused(&result), "{result:?}");
    assert!(backend.admin_exists().await.unwrap());
}

/// An administrator closing their account administers nothing more: once A
/// requested closure (allowed while B is active), B's assignment is the last
/// usable one and cannot be removed, while A's still can. Removals and
/// closures racing each other leave one usable administrator.
pub async fn test_closing_administrator_is_not_counted(backend: &dyn StorageBackend) {
    use sid_core::models::{ClosureMode, ClosureRequest, ProfileStatus};
    let tag = Uuid::now_v7().simple().to_string();
    let active = |name: &str| {
        let mut profile = create_test_profile(&format!("{name}_{tag}"));
        profile.status = ProfileStatus::Active;
        profile
    };
    let (a, b) = (active("closing_a"), active("closing_b"));
    for profile in [&a, &b] {
        backend.create_profile(profile, test_audit()).await.unwrap();
        make_admin(backend, profile.id).await;
    }
    let assignment_of = |profile: ProfileId| async move {
        backend
            .list_role_assignments_for_profile(profile)
            .await
            .unwrap()
            .into_iter()
            .find(RoleAssignment::administers_installation)
            .unwrap()
            .id
    };
    let (a_assignment, b_assignment) = (assignment_of(a.id).await, assignment_of(b.id).await);

    let mut closing = backend.get_profile(a.id).await.unwrap().unwrap();
    closing
        .transition_status(ProfileStatus::ClosureRequested)
        .unwrap();
    let request =
        ClosureRequest::new(a.id, ClosureMode::Voluntary, a.id).with_grace_period_days(30);
    assert!(
        backend
            .request_profile_closure(&closing, &request, test_audit())
            .await
            .unwrap()
    );

    let result = backend
        .delete_role_assignment(b_assignment, test_audit())
        .await;
    assert!(
        matches!(result, Err(sid_core::Error::InvalidState(_))),
        "the closing administrator is not counted: {result:?}"
    );
    assert!(administers(backend, b.id).await);
    backend
        .delete_role_assignment(a_assignment, test_audit())
        .await
        .expect("the closing administrator's assignment can go");
    assert!(administers(backend, b.id).await);
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
    assert!(administers(backend, winner.profile.id).await);
    assert!(backend.admin_exists().await.unwrap());
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
    assert!(!administers(backend, plain.profile.id).await);
}

/// A centrally managed installation consumes no local claim: adopting the
/// policy removes the stored claim, the database refuses to store one again
/// (an older replica that knows nothing of the policy fails loudly rather
/// than opening a claim), and the stale token creates no administrator
/// through the claim or a registration. The policy is never undone, and
/// ordinary registration is not trapped behind the missing administrator.
pub async fn test_central_management_refuses_local_claims(backend: &dyn StorageBackend) {
    use sid_core::models::{BootstrapPolicy, CentralAdoption, NewRegistration};
    assert!(!backend.admin_exists().await.unwrap());
    assert_eq!(
        backend.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::SelfManaged
    );
    let claim = Uuid::now_v7().as_bytes().to_vec();
    backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
        .await
        .unwrap();

    assert_eq!(
        backend
            .adopt_central_management(test_audit())
            .await
            .unwrap(),
        CentralAdoption::Adopted
    );
    assert_eq!(
        backend.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::CentrallyManaged
    );
    assert!(claim_stored(backend).await.is_none());

    // An older replica writing a claim again is refused by the database,
    // and the stale token is refused on both paths.
    let rewritten = backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
        .await;
    assert!(rewritten.is_err(), "{rewritten:?}");
    assert!(claim_stored(backend).await.is_none());
    let claimer = stored_profile(backend, "central_claimer").await;
    assert!(
        !backend
            .claim_first_admin(&claim, claimer.id, test_audit())
            .await
            .unwrap()
    );
    let registration = NewRegistration::new(
        create_test_profile("central_registrant"),
        sid_core::models::SignupIdentifier::Username("central_registrant"),
        None,
    )
    .unwrap()
    .claiming_instance(claim.clone());
    let result = backend.register_profile(&registration, test_audit()).await;
    assert!(
        matches!(result, Err(sid_core::Error::InvalidState(_))),
        "{result:?}"
    );
    assert!(!backend.admin_exists().await.unwrap());
    assert!(!administers(backend, claimer.id).await);

    // Ordinary registration is available without a local administrator.
    let plain = NewRegistration::new(
        create_test_profile("central_plain"),
        sid_core::models::SignupIdentifier::Username("central_plain"),
        None,
    )
    .unwrap();
    backend
        .register_profile(&plain, test_audit())
        .await
        .unwrap();

    // Adopting again changes nothing, also once a provisioned
    // administrator exists.
    let provisioned = stored_profile(backend, "central_admin").await;
    make_admin(backend, provisioned.id).await;
    assert_eq!(
        backend
            .adopt_central_management(test_audit())
            .await
            .unwrap(),
        CentralAdoption::AlreadyCentral
    );
    assert_eq!(
        backend.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::CentrallyManaged
    );
}

/// A claimed self-managed installation is not made centrally managed: the
/// adoption is refused and changes nothing.
pub async fn test_claimed_installation_stays_self_managed(backend: &dyn StorageBackend) {
    use sid_core::models::{BootstrapPolicy, CentralAdoption};
    let claim = Uuid::now_v7().as_bytes().to_vec();
    backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
        .await
        .unwrap();
    let owner = stored_profile(backend, "self_owner").await;
    assert!(
        backend
            .claim_first_admin(&claim, owner.id, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend
            .adopt_central_management(test_audit())
            .await
            .unwrap(),
        CentralAdoption::LocalAdministrator
    );
    assert_eq!(
        backend.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::SelfManaged
    );
}

/// An adoption racing a claim: exactly one takes effect. Either the
/// installation becomes centrally managed with no administrator, or the
/// claimer becomes administrator and the installation stays self-managed.
pub async fn test_adoption_races_claim(backend: &dyn StorageBackend) {
    use sid_core::models::{BootstrapPolicy, CentralAdoption};
    let claim = Uuid::now_v7().as_bytes().to_vec();
    backend
        .insert_instance_secret(InstanceSecret::AdminClaim, &claim, test_audit())
        .await
        .unwrap();
    let claimer = stored_profile(backend, "racing_claimer").await;
    let (adopted, claimed) = tokio::join!(
        backend.adopt_central_management(test_audit()),
        backend.claim_first_admin(&claim, claimer.id, test_audit()),
    );
    let (adopted, claimed) = (adopted.unwrap(), claimed.unwrap());
    let policy = backend.bootstrap_policy().await.unwrap();
    let admin = backend.admin_exists().await.unwrap();
    match (adopted, claimed) {
        (CentralAdoption::Adopted, false) => {
            assert_eq!(policy, BootstrapPolicy::CentrallyManaged);
            assert!(!admin);
        }
        (CentralAdoption::LocalAdministrator, true) => {
            assert_eq!(policy, BootstrapPolicy::SelfManaged);
            assert!(admin);
        }
        other => panic!("both or neither took effect: {other:?}"),
    }
    assert!(claim_stored(backend).await.is_none());
}

async fn claim_stored(backend: &dyn StorageBackend) -> Option<Vec<u8>> {
    backend
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await
        .unwrap()
}

/// The claim makes exactly one administrator: a wrong value or a Profile
/// that is not stored changes nothing, two claimers racing yield one
/// administrator, and a claim stored beside an administrator grants nothing
/// and is removed.
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
            .claim_first_admin(&other, stranger.id, test_audit())
            .await
            .unwrap()
    );

    // A Profile that is not stored is refused and the claim stays.
    assert!(
        !backend
            .claim_first_admin(&claim, ProfileId::generate(), test_audit())
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
    let (ra, rb) = tokio::join!(
        backend.claim_first_admin(&claim, a.id, test_audit()),
        backend.claim_first_admin(&claim, b.id, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "claims: {ra} {rb}");
    assert_eq!(
        (
            administers(backend, a.id).await,
            administers(backend, b.id).await
        ),
        (ra, rb)
    );
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
            .claim_first_admin(&late, c.id, test_audit())
            .await
            .unwrap()
    );
    assert!(!administers(backend, c.id).await);
    assert!(claim_stored(backend).await.is_none());
}
