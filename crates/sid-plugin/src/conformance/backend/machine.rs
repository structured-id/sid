// SPDX-License-Identifier: AGPL-3.0-only
//! Machine users and their credentials: a create never replaces, and a
//! lifecycle change or a rotation never undoes a concurrent one.

use chrono::{DateTime, Duration, Utc};
use sid_core::Error;
use sid_core::models::machine_user::{
    CredentialStatus, MachineCredentialType, MachineUserCredential, MachineUserStatus, OwnerType,
};
use sid_core::models::{MachineUser, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

fn tag() -> String {
    Uuid::now_v7().simple().to_string()
}

/// A machine user of the system project, which every store has.
async fn machine_user(backend: &dyn StorageBackend) -> MachineUser {
    backend.ensure_system_project(test_audit()).await.unwrap();
    MachineUser::new(
        ProjectId::system(),
        format!("mu-{}", tag()),
        "ci",
        OwnerType::System,
        "system",
    )
}

/// A stored active machine user.
pub(super) async fn stored_machine_user(backend: &dyn StorageBackend) -> MachineUser {
    let mu = machine_user(backend).await;
    backend
        .create_machine_user(&mu, test_audit())
        .await
        .unwrap();
    mu
}

fn secret(mu: &MachineUser) -> MachineUserCredential {
    MachineUserCredential::new(
        mu.id,
        format!("kid-{}", tag()),
        MachineCredentialType::ClientSecret,
        format!("hash-{}", tag()),
    )
}

async fn status_of(backend: &dyn StorageBackend, kid: &str) -> CredentialStatus {
    backend
        .get_machine_credential_by_kid(kid)
        .await
        .unwrap()
        .unwrap()
        .status
}

/// Creating a machine user never replaces one: a deleted machine user stays
/// deleted when a create with its id arrives.
pub async fn test_create_machine_user_never_replaces(backend: &dyn StorageBackend) {
    let mut deleted = machine_user(backend).await;
    deleted.status = MachineUserStatus::Deleted;
    backend
        .create_machine_user(&deleted, test_audit())
        .await
        .unwrap();

    let mut again = deleted.clone();
    again.status = MachineUserStatus::Active;
    let err = backend
        .create_machine_user(&again, test_audit())
        .await
        .expect_err("a create over an existing machine user");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    let stored = backend.get_machine_user(deleted.id).await.unwrap().unwrap();
    assert_eq!(stored.status, MachineUserStatus::Deleted);
}

/// A settings update keeps the stored status: a suspension made after the
/// updater read the machine user stays, and a deleted one is not updated.
pub async fn test_update_machine_user_keeps_status(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let stale = mu.clone();
    assert!(
        backend
            .transition_machine_user(
                mu.id,
                MachineUserStatus::Active,
                MachineUserStatus::Suspended,
                test_audit(),
            )
            .await
            .unwrap()
    );

    let mut renamed = stale;
    renamed.display_name = "renamed".into();
    assert!(
        backend
            .update_machine_user(&renamed, test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_machine_user(mu.id).await.unwrap().unwrap();
    assert_eq!(stored.display_name, "renamed");
    assert_eq!(stored.status, MachineUserStatus::Suspended);

    backend
        .delete_machine_user(mu.id, test_audit())
        .await
        .unwrap();
    renamed.display_name = "after delete".into();
    assert!(
        !backend
            .update_machine_user(&renamed, test_audit())
            .await
            .unwrap()
    );
}

/// A status change applies only from the status it expects: a deleted
/// machine user is not reactivated, and of two concurrent suspensions one
/// applies.
pub async fn test_transition_machine_user_is_compare_and_swap(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let suspend = || {
        backend.transition_machine_user(
            mu.id,
            MachineUserStatus::Active,
            MachineUserStatus::Suspended,
            test_audit(),
        )
    };
    let (a, b) = tokio::join!(suspend(), suspend());
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one suspension must apply: {a} {b}");

    backend
        .delete_machine_user(mu.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .transition_machine_user(
                mu.id,
                MachineUserStatus::Suspended,
                MachineUserStatus::Active,
                test_audit(),
            )
            .await
            .unwrap(),
        "a deleted machine user was reactivated"
    );
    let stored = backend.get_machine_user(mu.id).await.unwrap().unwrap();
    assert_eq!(stored.status, MachineUserStatus::Deleted);
}

/// Adding a credential never replaces one: a revoked secret stays revoked.
pub async fn test_add_machine_credential_never_replaces(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let mut revoked = secret(&mu);
    revoked.status = CredentialStatus::Revoked;
    backend
        .add_machine_credential(&revoked, None, test_audit())
        .await
        .unwrap();

    let mut again = revoked.clone();
    again.status = CredentialStatus::Active;
    let err = backend
        .add_machine_credential(&again, None, test_audit())
        .await
        .expect_err("an add over an existing credential");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert_eq!(
        status_of(backend, &revoked.kid).await,
        CredentialStatus::Revoked
    );
}

/// The usable-credential limit holds under concurrent adds: of four adds
/// against a limit of two, two are stored.
pub async fn test_add_machine_credential_limit_under_concurrency(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let creds: Vec<_> = (0..4).map(|_| secret(&mu)).collect();
    let (a, b, c, d) = tokio::join!(
        backend.add_machine_credential(&creds[0], Some(2), test_audit()),
        backend.add_machine_credential(&creds[1], Some(2), test_audit()),
        backend.add_machine_credential(&creds[2], Some(2), test_audit()),
        backend.add_machine_credential(&creds[3], Some(2), test_audit()),
    );
    let results = [a, b, c, d];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        2,
        "{results:?}"
    );
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, Error::ResourceExhausted(_))),
        "{results:?}"
    );
}

/// A rotation moves the old credential to its grace period and stores the
/// new one together, only from active: a revoked credential is not brought
/// back to grace, and of two concurrent rotations of one credential one
/// applies, leaving no orphan new credential.
pub async fn test_rotate_machine_credential(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let old = secret(&mu);
    backend
        .add_machine_credential(&old, None, test_audit())
        .await
        .unwrap();

    let (first, second) = (secret(&mu), secret(&mu));
    let grace_until = Utc::now() + Duration::hours(72);
    let (a, b) = tokio::join!(
        backend.rotate_machine_credential(mu.id, &old.kid, &first, grace_until, test_audit()),
        backend.rotate_machine_credential(mu.id, &old.kid, &second, grace_until, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one rotation must apply: {a} {b}");
    assert_eq!(
        status_of(backend, &old.kid).await,
        CredentialStatus::GracePeriod
    );
    // The grace ends: a rotated-out credential does not work for ever.
    assert_close(expiry_of(backend, &old.kid).await, grace_until);
    let (winner, loser) = if a {
        (&first, &second)
    } else {
        (&second, &first)
    };
    assert_eq!(
        status_of(backend, &winner.kid).await,
        CredentialStatus::Active
    );
    assert!(
        backend
            .get_machine_credential_by_kid(&loser.kid)
            .await
            .unwrap()
            .is_none(),
        "the losing rotation stored its credential"
    );

    let revoked = secret(&mu);
    backend
        .add_machine_credential(&revoked, None, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .revoke_machine_credential(mu.id, &revoked.kid, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .rotate_machine_credential(mu.id, &revoked.kid, &secret(&mu), grace_until, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        status_of(backend, &revoked.kid).await,
        CredentialStatus::Revoked
    );

    // A credential that ends before the grace would keeps its own end.
    let other = stored_machine_user(backend).await;
    let soon = Utc::now() + Duration::hours(1);
    let mut short = secret(&other);
    short.expires_at = Some(soon);
    backend
        .add_machine_credential(&short, None, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .rotate_machine_credential(
                other.id,
                &short.kid,
                &secret(&other),
                grace_until,
                test_audit()
            )
            .await
            .unwrap()
    );
    assert_close(expiry_of(backend, &short.kid).await, soon);
}

/// The stored end of credential `kid`.
async fn expiry_of(backend: &dyn StorageBackend, kid: &str) -> Option<DateTime<Utc>> {
    backend
        .get_machine_credential_by_kid(kid)
        .await
        .unwrap()
        .unwrap()
        .expires_at
}

/// `stored` is `expected`, within storage time precision.
fn assert_close(stored: Option<DateTime<Utc>>, expected: DateTime<Utc>) {
    let stored = stored.expect("a rotated credential has an end");
    assert!(
        (stored - expected).num_milliseconds().abs() < 1000,
        "{stored} != {expected}"
    );
}

/// Revocation is scoped to the machine user named: another machine user's
/// kid is not revoked; a second revocation reports nothing to revoke.
pub async fn test_revoke_machine_credential_is_scoped(backend: &dyn StorageBackend) {
    let owner = stored_machine_user(backend).await;
    let other = stored_machine_user(backend).await;
    let cred = secret(&owner);
    backend
        .add_machine_credential(&cred, None, test_audit())
        .await
        .unwrap();

    assert!(
        !backend
            .revoke_machine_credential(other.id, &cred.kid, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        status_of(backend, &cred.kid).await,
        CredentialStatus::Active
    );
    assert!(
        backend
            .revoke_machine_credential(owner.id, &cred.kid, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .revoke_machine_credential(owner.id, &cred.kid, test_audit())
            .await
            .unwrap()
    );
}

/// Revoking all credentials of a machine user (suspension cascade) revokes a
/// credential in its grace period too: it is still accepted until then.
pub async fn test_cascade_revokes_grace_period_credentials(backend: &dyn StorageBackend) {
    let mu = stored_machine_user(backend).await;
    let old = secret(&mu);
    backend
        .add_machine_credential(&old, None, test_audit())
        .await
        .unwrap();
    let new = secret(&mu);
    assert!(
        backend
            .rotate_machine_credential(
                mu.id,
                &old.kid,
                &new,
                Utc::now() + Duration::hours(72),
                test_audit()
            )
            .await
            .unwrap()
    );

    let revoked = backend
        .revoke_active_machine_credentials_by_user(mu.id, test_audit())
        .await
        .unwrap();
    assert_eq!(revoked, 2);
    assert_eq!(
        status_of(backend, &old.kid).await,
        CredentialStatus::Revoked
    );
    assert_eq!(
        status_of(backend, &new.kid).await,
        CredentialStatus::Revoked
    );
}

/// A machine user resolves by its client id, and machine users list per
/// project only.
pub async fn test_machine_users_by_client_and_project(backend: &dyn StorageBackend) {
    let project = sid_core::models::Project::new(format!("mu-{}", tag()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let in_project = |name: &str| {
        MachineUser::new(
            project.id,
            format!("{name}-{}", tag()),
            name,
            OwnerType::System,
            "system",
        )
    };
    let (ci, deploy) = (in_project("ci"), in_project("deploy"));
    let elsewhere = stored_machine_user(backend).await;
    for mu in [&ci, &deploy] {
        backend.create_machine_user(mu, test_audit()).await.unwrap();
    }

    let found = backend
        .get_machine_user_by_client_id(&ci.client_id)
        .await
        .unwrap()
        .expect("the machine user by client id");
    assert_eq!(found.id, ci.id);
    assert!(
        backend
            .get_machine_user_by_client_id("no-such-client")
            .await
            .unwrap()
            .is_none()
    );

    let mut listed: Vec<_> = backend
        .list_machine_users_by_project(project.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.id)
        .collect();
    listed.sort_by_key(|id| id.to_string());
    let mut expected = vec![ci.id, deploy.id];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(listed, expected);
    assert!(!listed.contains(&elsewhere.id));
}

/// Credentials list per machine user; the expiry scan returns active ones
/// expired or expiring within the window, never a later one, one without an
/// expiry or a revoked one.
pub async fn test_machine_credentials_listing_and_expiry(backend: &dyn StorageBackend) {
    use chrono::{Duration, Utc};

    let mu = stored_machine_user(backend).await;
    let other = stored_machine_user(backend).await;
    let mut expired = secret(&mu);
    expired.expires_at = Some(Utc::now() - Duration::days(1));
    let mut soon = secret(&mu);
    soon.expires_at = Some(Utc::now() + Duration::days(3));
    let mut later = secret(&mu);
    later.expires_at = Some(Utc::now() + Duration::days(90));
    let permanent = secret(&mu);
    let mut revoked = secret(&mu);
    revoked.expires_at = Some(Utc::now() + Duration::days(1));
    revoked.status = CredentialStatus::Revoked;
    let foreign = secret(&other);
    for c in [&expired, &soon, &later, &permanent, &revoked, &foreign] {
        backend
            .add_machine_credential(c, None, test_audit())
            .await
            .unwrap();
    }

    let mut kids: Vec<_> = backend
        .list_machine_credentials_by_user(mu.id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.kid)
        .collect();
    kids.sort();
    let mut expected: Vec<_> = [&expired, &soon, &later, &permanent, &revoked]
        .iter()
        .map(|c| c.kid.clone())
        .collect();
    expected.sort();
    assert_eq!(kids, expected);

    let expiring: Vec<_> = backend
        .list_expiring_machine_credentials(7)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.kid)
        .collect();
    assert!(
        expiring.contains(&expired.kid),
        "an expired active credential is missing"
    );
    assert!(
        expiring.contains(&soon.kid),
        "a credential expiring in the window is missing"
    );
    for (c, why) in [
        (&later, "expiring later"),
        (&permanent, "without expiry"),
        (&revoked, "revoked"),
    ] {
        assert!(!expiring.contains(&c.kid), "a credential {why} was listed");
    }
}

/// An impersonation grant is keyed by machine user, target type and target:
/// saving it again, or twice at once, updates its scopes and keeps one grant;
/// deleting one leaves the machine user's others.
pub async fn test_impersonation_grants(backend: &dyn StorageBackend) {
    use sid_core::models::machine_user::{ImpersonationGrant, ImpersonationTargetType};

    let mu = stored_machine_user(backend).await;
    let other = stored_machine_user(backend).await;
    let by_role = ImpersonationGrant::new(
        mu.id,
        ImpersonationTargetType::Role,
        "employee",
        vec!["read".into()],
    );
    let by_user = ImpersonationGrant::new(
        mu.id,
        ImpersonationTargetType::User,
        "some-profile",
        vec!["*".into()],
    );
    let foreign = ImpersonationGrant::new(
        other.id,
        ImpersonationTargetType::Role,
        "employee",
        vec!["read".into()],
    );
    for g in [&by_role, &by_user, &foreign] {
        backend
            .save_impersonation_grant(g, test_audit())
            .await
            .unwrap();
    }

    let mut widened = by_role.clone();
    widened.allowed_scopes = vec!["read".into(), "write".into()];
    let (a, b) = tokio::join!(
        backend.save_impersonation_grant(&widened, test_audit()),
        backend.save_impersonation_grant(&widened, test_audit()),
    );
    a.unwrap();
    b.unwrap();
    let grants = backend.list_impersonation_grants(mu.id).await.unwrap();
    assert_eq!(grants.len(), 2, "{grants:?}");
    let role_grant = grants
        .iter()
        .find(|g| g.target_type == ImpersonationTargetType::Role)
        .unwrap();
    assert_eq!(role_grant.allowed_scopes, widened.allowed_scopes);

    backend
        .delete_impersonation_grant(
            mu.id,
            ImpersonationTargetType::Role.as_str(),
            "employee",
            test_audit(),
        )
        .await
        .unwrap();
    let grants = backend.list_impersonation_grants(mu.id).await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].target, "some-profile");
    assert_eq!(
        backend
            .list_impersonation_grants(other.id)
            .await
            .unwrap()
            .len(),
        1,
        "another machine user's grant was deleted"
    );
}
