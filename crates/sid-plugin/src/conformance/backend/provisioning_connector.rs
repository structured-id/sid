// SPDX-License-Identifier: AGPL-3.0-only
//! Provisioning connectors and their credentials: a create never replaces,
//! every change is a compare-and-swap on the state or revision it read, the
//! usable-credential limit holds under concurrent adds, and a credential is
//! found by its verifier only.

use chrono::{Duration, Utc};
use sid_core::Error;
use sid_core::models::machine_user::CredentialStatus;
use sid_core::models::{
    ActorFence, ConnectorCredentialKind, ConnectorState, OrgId, ProjectId, ProvisioningConnector,
    ProvisioningConnectorId, ProvisioningCredential, ProvisioningDirection, ResourceId, Role,
    RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

const BEARER: ConnectorCredentialKind = ConnectorCredentialKind::ScimBearer;

fn verifier() -> String {
    format!("{:064x}", Uuid::now_v7().as_u128())
}

/// A stored active inbound connector of `org`.
async fn stored(backend: &dyn StorageBackend, org: OrgId) -> ProvisioningConnector {
    let c = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "HR");
    backend
        .create_provisioning_connector(&c, test_audit())
        .await
        .unwrap();
    c
}

async fn state_of(backend: &dyn StorageBackend, c: &ProvisioningConnector) -> ConnectorState {
    backend
        .get_provisioning_connector(c.id)
        .await
        .unwrap()
        .unwrap()
        .state
}

async fn credential(
    backend: &dyn StorageBackend,
    c: &ProvisioningConnector,
) -> ProvisioningCredential {
    let cred = ProvisioningCredential::new(c.id, BEARER, verifier());
    assert!(
        backend
            .add_provisioning_credential(&cred, test_audit())
            .await
            .unwrap()
    );
    cred
}

async fn credential_status(
    backend: &dyn StorageBackend,
    cred: &ProvisioningCredential,
) -> Option<CredentialStatus> {
    backend
        .find_provisioning_credential(&cred.verifier)
        .await
        .unwrap()
        .map(|(c, _)| c.status)
}

/// A create never replaces: a retired connector stays retired when a create
/// with its id arrives, and the stored connector reads back unchanged.
pub async fn test_create_connector_never_replaces(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let read = backend.get_provisioning_connector(c.id).await.unwrap();
    assert_eq!(read.as_ref().map(|r| r.id), Some(c.id));
    let read = read.unwrap();
    assert_eq!(read.org_id, c.org_id);
    assert_eq!(read.direction, c.direction);
    assert_eq!(read.state, ConnectorState::Active);
    assert_eq!(read.revision, 1);

    assert!(
        backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Active,
                ConnectorState::Retired,
                test_audit()
            )
            .await
            .unwrap()
    );
    let err = backend
        .create_provisioning_connector(&c, test_audit())
        .await
        .expect_err("a create over an existing connector");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");
    assert_eq!(state_of(backend, &c).await, ConnectorState::Retired);
}

/// A rename applies only at the revision it read and advances it; a retired
/// connector is not renamed.
pub async fn test_rename_connector_is_revision_checked(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let rename =
        |name: &'static str| backend.rename_provisioning_connector(c.id, 1, name, test_audit());
    let (a, b) = tokio::join!(rename("A"), rename("B"));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(
        a ^ b,
        "exactly one rename at revision 1 must apply: {a} {b}"
    );
    let read = backend
        .get_provisioning_connector(c.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.revision, 2);
    assert_eq!(read.display_name, if a { "A" } else { "B" });

    assert!(
        backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Active,
                ConnectorState::Retired,
                test_audit()
            )
            .await
            .unwrap()
    );
    let revision = backend
        .get_provisioning_connector(c.id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    assert!(
        !backend
            .rename_provisioning_connector(c.id, revision, "after retire", test_audit())
            .await
            .unwrap(),
        "a retired connector was renamed"
    );
}

/// A state change applies only from the state it expects and only along a
/// lifecycle step; of two concurrent disables one applies; retired is final
/// and revokes the usable credentials, while disabling keeps them.
pub async fn test_transition_connector(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let kept = credential(backend, &c).await;
    let disable = || {
        backend.transition_provisioning_connector(
            c.id,
            ConnectorState::Active,
            ConnectorState::Disabled,
            test_audit(),
        )
    };
    let (a, b) = tokio::join!(disable(), disable());
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one disable must apply: {a} {b}");
    assert_eq!(
        credential_status(backend, &kept).await,
        Some(CredentialStatus::Active),
        "disabling revoked a credential"
    );
    let revision = backend
        .get_provisioning_connector(c.id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    assert_eq!(revision, 2, "a state change advances the revision");

    assert!(
        !backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Disabled,
                ConnectorState::Disabled,
                test_audit()
            )
            .await
            .unwrap(),
        "a state changed into itself"
    );
    assert!(
        backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Disabled,
                ConnectorState::Retired,
                test_audit()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        credential_status(backend, &kept).await,
        Some(CredentialStatus::Revoked),
        "retiring left a usable credential"
    );
    for to in [ConnectorState::Active, ConnectorState::Disabled] {
        assert!(
            !backend
                .transition_provisioning_connector(c.id, ConnectorState::Retired, to, test_audit())
                .await
                .unwrap(),
            "a retired connector became {to:?}"
        );
    }
    assert_eq!(state_of(backend, &c).await, ConnectorState::Retired);
}

/// A credential is added only to an active connector; an existing id or
/// verifier is a conflict; of four concurrent adds against the limit of two
/// usable credentials, two are stored.
pub async fn test_add_credential(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let first = credential(backend, &c).await;
    let mut same_verifier = ProvisioningCredential::new(c.id, BEARER, first.verifier.clone());
    same_verifier.status = CredentialStatus::Active;
    let err = backend
        .add_provisioning_credential(&same_verifier, test_audit())
        .await
        .expect_err("a second credential with one verifier");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let creds: Vec<_> = (0..4)
        .map(|_| ProvisioningCredential::new(c.id, BEARER, verifier()))
        .collect();
    let (a, b, cc, d) = tokio::join!(
        backend.add_provisioning_credential(&creds[0], test_audit()),
        backend.add_provisioning_credential(&creds[1], test_audit()),
        backend.add_provisioning_credential(&creds[2], test_audit()),
        backend.add_provisioning_credential(&creds[3], test_audit()),
    );
    let results = [a, b, cc, d];
    assert_eq!(
        results.iter().filter(|r| matches!(r, Ok(true))).count(),
        1,
        "with one usable credential stored, one more fits: {results:?}"
    );
    assert!(
        results
            .iter()
            .filter(|r| !matches!(r, Ok(true)))
            .all(|r| matches!(r, Err(Error::ResourceExhausted(_)))),
        "{results:?}"
    );

    let disabled = stored(backend, OrgId::generate()).await;
    assert!(
        backend
            .transition_provisioning_connector(
                disabled.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                test_audit()
            )
            .await
            .unwrap()
    );
    let refused = ProvisioningCredential::new(disabled.id, BEARER, verifier());
    assert!(
        !backend
            .add_provisioning_credential(&refused, test_audit())
            .await
            .unwrap(),
        "a disabled connector was given a credential"
    );
    assert_eq!(credential_status(backend, &refused).await, None);
}

/// A rotation moves the old credential to its grace and stores the new one
/// together, only from active and only on an active connector; of two
/// concurrent rotations one applies, leaving no orphan.
pub async fn test_rotate_credential(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let old = credential(backend, &c).await;
    let grace_until = Utc::now() + Duration::hours(1);
    let (first, second) = (
        ProvisioningCredential::new(c.id, BEARER, verifier()),
        ProvisioningCredential::new(c.id, BEARER, verifier()),
    );
    let (a, b) = tokio::join!(
        backend.rotate_provisioning_credential(c.id, old.id, &first, grace_until, test_audit()),
        backend.rotate_provisioning_credential(c.id, old.id, &second, grace_until, test_audit()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one rotation must apply: {a} {b}");
    let (old_read, _) = backend
        .find_provisioning_credential(&old.verifier)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old_read.status, CredentialStatus::GracePeriod);
    let ends = old_read.expires_at.expect("the grace ends");
    assert!(
        (ends - grace_until).num_seconds().abs() <= 1,
        "{ends} {grace_until}"
    );
    let (winner, loser) = if a {
        (&first, &second)
    } else {
        (&second, &first)
    };
    assert_eq!(
        credential_status(backend, winner).await,
        Some(CredentialStatus::Active)
    );
    assert_eq!(
        credential_status(backend, loser).await,
        None,
        "the losing rotation stored its credential"
    );

    assert!(
        backend
            .revoke_provisioning_credential(c.id, winner.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .rotate_provisioning_credential(
                c.id,
                winner.id,
                &ProvisioningCredential::new(c.id, BEARER, verifier()),
                grace_until,
                test_audit()
            )
            .await
            .unwrap(),
        "a revoked credential was rotated"
    );
}

/// Revocation is immediate and scoped to the connector named: another
/// connector's credential is not revoked; a second revocation reports
/// nothing to revoke.
pub async fn test_revoke_credential_is_scoped(backend: &dyn StorageBackend) {
    let org = OrgId::generate();
    let owner = stored(backend, org).await;
    let other = stored(backend, org).await;
    let cred = credential(backend, &owner).await;

    assert!(
        !backend
            .revoke_provisioning_credential(other.id, cred.id, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        credential_status(backend, &cred).await,
        Some(CredentialStatus::Active)
    );
    assert!(
        backend
            .revoke_provisioning_credential(owner.id, cred.id, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        credential_status(backend, &cred).await,
        Some(CredentialStatus::Revoked)
    );
    assert!(
        !backend
            .revoke_provisioning_credential(owner.id, cred.id, test_audit())
            .await
            .unwrap()
    );
}

/// A credential is found by its verifier with its connector; an unknown
/// verifier finds nothing. Connectors list per organization and credentials
/// per connector.
pub async fn test_find_and_list(backend: &dyn StorageBackend) {
    let org = OrgId::generate();
    let (a, b) = (stored(backend, org).await, stored(backend, org).await);
    let elsewhere = stored(backend, OrgId::generate()).await;
    let cred = credential(backend, &a).await;
    let foreign = credential(backend, &b).await;

    let (found, connector) = backend
        .find_provisioning_credential(&cred.verifier)
        .await
        .unwrap()
        .expect("the credential by its verifier");
    assert_eq!(found.id, cred.id);
    assert_eq!(connector.id, a.id);
    assert!(
        backend
            .find_provisioning_credential(&verifier())
            .await
            .unwrap()
            .is_none()
    );

    let mut listed: Vec<_> = backend
        .list_provisioning_connectors(org)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect();
    listed.sort();
    let mut expected = vec![a.id, b.id];
    expected.sort();
    assert_eq!(listed, expected);
    assert!(!listed.contains(&elsewhere.id));

    let creds: Vec<_> = backend
        .list_provisioning_credentials(a.id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(creds, vec![cred.id]);
    assert!(!creds.contains(&foreign.id));
}

/// A connector is found by its client_id, which no other connector may
/// take; a credential's kind reads back as stored.
pub async fn test_client_id_and_credential_kind(backend: &dyn StorageBackend) {
    let c = stored(backend, OrgId::generate()).await;
    let found = backend
        .get_provisioning_connector_by_client_id(&c.client_id)
        .await
        .unwrap()
        .expect("found by client_id");
    assert_eq!(found.id, c.id);
    assert_eq!(found.client_id, c.client_id);
    assert!(
        backend
            .get_provisioning_connector_by_client_id("pc_unknown")
            .await
            .unwrap()
            .is_none()
    );

    let mut twin = ProvisioningConnector::new(c.org_id, ProvisioningDirection::Inbound, "twin");
    twin.client_id = c.client_id.clone();
    let err = backend
        .create_provisioning_connector(&twin, test_audit())
        .await
        .expect_err("a second connector with one client_id");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let secret =
        ProvisioningCredential::new(c.id, ConnectorCredentialKind::ClientSecret, verifier());
    assert!(
        backend
            .add_provisioning_credential(&secret, test_audit())
            .await
            .unwrap()
    );
    let (read, _) = backend
        .find_provisioning_credential(&secret.verifier)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.kind, ConnectorCredentialKind::ClientSecret);
    let listed = backend.list_provisioning_credentials(c.id).await.unwrap();
    assert_eq!(listed[0].kind, ConnectorCredentialKind::ClientSecret);
}

/// Store a connector of `org` as a mutation fenced by `fence`; returns
/// whether it was stored.
async fn fenced_write(
    backend: &dyn StorageBackend,
    org: OrgId,
    fence: ActorFence,
) -> Result<ProvisioningConnectorId, Error> {
    let written = ProvisioningConnector::new(org, ProvisioningDirection::Inbound, "fenced");
    backend
        .create_provisioning_connector(&written, test_audit().fenced_by(fence))
        .await?;
    Ok(written.id)
}

async fn assert_fenced(backend: &dyn StorageBackend, org: OrgId, fence: ActorFence, why: &str) {
    let before = backend
        .list_provisioning_connectors(org)
        .await
        .unwrap()
        .len();
    let err = fenced_write(backend, org, fence).await.expect_err(why);
    assert!(matches!(err, Error::Fenced(_)), "{why}: {err:?}");
    assert_eq!(
        backend
            .list_provisioning_connectors(org)
            .await
            .unwrap()
            .len(),
        before,
        "{why}: a fenced write committed"
    );
}

fn fence_of(c: &ProvisioningConnector, cred: &ProvisioningCredential) -> ActorFence {
    ActorFence::Connector {
        connector: c.id,
        revision: c.revision,
        credential: cred.id,
    }
}

async fn current(backend: &dyn StorageBackend, c: &ProvisioningConnector) -> ProvisioningConnector {
    backend
        .get_provisioning_connector(c.id)
        .await
        .unwrap()
        .unwrap()
}

/// A write fenced by a connector commits only while the connector is still
/// active at the revision it was authorized at and its credential is still
/// usable: a rename, a disable, a granted or removed role, a revoked or
/// expired credential each make it commit nothing.
pub async fn test_connector_fence_holds_writes_to_current_authority(backend: &dyn StorageBackend) {
    let org = OrgId::generate();
    let c = stored(backend, org).await;
    let cred = credential(backend, &c).await;
    fenced_write(backend, org, fence_of(&c, &cred))
        .await
        .expect("a current fence holds");

    // A missing connector or a credential of another connector.
    let other = stored(backend, org).await;
    let other_cred = credential(backend, &other).await;
    assert_fenced(
        backend,
        org,
        ActorFence::Connector {
            connector: c.id,
            revision: c.revision,
            credential: other_cred.id,
        },
        "another connector's credential",
    )
    .await;

    // Renamed: its revision moved.
    assert!(
        backend
            .rename_provisioning_connector(c.id, c.revision, "HR 2", test_audit())
            .await
            .unwrap()
    );
    assert_fenced(backend, org, fence_of(&c, &cred), "renamed since").await;
    let c = current(backend, &c).await;
    fenced_write(backend, org, fence_of(&c, &cred))
        .await
        .expect("the new revision holds");

    // A role granted or removed moves the revision.
    backend.ensure_system_project(test_audit()).await.unwrap();
    let key = format!("fence-{}", Uuid::now_v7().simple());
    let role = Role::new(ProjectId::system(), &key, &key);
    backend.create_role(&role, test_audit()).await.unwrap();
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::ProvisioningConnector(c.id),
        role.id,
    )
    .on_resource(ResourceId::generate());
    backend
        .create_role_assignment(&assignment, test_audit())
        .await
        .unwrap();
    assert_fenced(backend, org, fence_of(&c, &cred), "granted a role since").await;
    let c = current(backend, &c).await;
    backend
        .delete_role_assignment(assignment.id, test_audit())
        .await
        .unwrap();
    assert_fenced(backend, org, fence_of(&c, &cred), "a role removed since").await;
    let c = current(backend, &c).await;

    // Disabled, then enabled again: the revision moved both times.
    assert!(
        backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Active,
                ConnectorState::Disabled,
                test_audit()
            )
            .await
            .unwrap()
    );
    let disabled = current(backend, &c).await;
    assert_fenced(backend, org, fence_of(&disabled, &cred), "disabled").await;
    assert!(
        backend
            .transition_provisioning_connector(
                c.id,
                ConnectorState::Disabled,
                ConnectorState::Active,
                test_audit()
            )
            .await
            .unwrap()
    );
    let c = current(backend, &c).await;
    fenced_write(backend, org, fence_of(&c, &cred))
        .await
        .expect("enabled again");

    // The credential revoked, or one already expired.
    let expiring = {
        let mut e = ProvisioningCredential::new(c.id, BEARER, verifier());
        e.expires_at = Some(Utc::now() - Duration::seconds(1));
        assert!(
            backend
                .add_provisioning_credential(&e, test_audit())
                .await
                .unwrap()
        );
        e
    };
    assert_fenced(backend, org, fence_of(&c, &expiring), "expired credential").await;
    assert!(
        backend
            .revoke_provisioning_credential(c.id, cred.id, test_audit())
            .await
            .unwrap()
    );
    assert_fenced(backend, org, fence_of(&c, &cred), "revoked credential").await;
}

/// Fenced writes racing a disable: each write either commits or is fenced,
/// never fails otherwise, and exactly the committed ones are stored.
pub async fn test_connector_fence_races_a_disable(backend: &dyn StorageBackend) {
    let org = OrgId::generate();
    let c = stored(backend, org).await;
    let cred = credential(backend, &c).await;
    let target = OrgId::generate();
    let write = || fenced_write(backend, target, fence_of(&c, &cred));
    let (a, b, disabled, d, e) = tokio::join!(
        write(),
        write(),
        backend.transition_provisioning_connector(
            c.id,
            ConnectorState::Active,
            ConnectorState::Disabled,
            test_audit(),
        ),
        write(),
        write(),
    );
    assert!(disabled.unwrap());
    let mut committed = 0;
    for result in [a, b, d, e] {
        match result {
            Ok(_) => committed += 1,
            Err(Error::Fenced(_)) => {}
            Err(e) => panic!("a racing fenced write failed otherwise: {e:?}"),
        }
    }
    assert_eq!(
        backend
            .list_provisioning_connectors(target)
            .await
            .unwrap()
            .len(),
        committed
    );
    assert_fenced(backend, target, fence_of(&c, &cred), "after the disable").await;
}
