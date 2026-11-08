// SPDX-License-Identifier: AGPL-3.0-only
//! A finished device-key ceremony commits once: the device (created or as
//! the ceremony found it), its binding (a rotation retiring the old one),
//! the consumed ceremony, the audit and the outcome together, and only
//! while the owner, its session and the target are as the ceremony found
//! them.

use std::time::Duration;

use sid_core::Error;
use sid_core::models::{
    ActorFence, AttestationStatus, CeremonyConsumption, Device, DeviceAttestation,
    DeviceAttestationFormat, DeviceEnrollment, DeviceType, EnrollmentTarget, KeyStorageType,
    MutationContext, OperationCompletion, OperationKey, Profile, ProfileStatus, Session,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, create_test_session, test_audit, test_session_end};

const NAMESPACE: &str = "test-device-enrollment";

struct Owner {
    profile: Profile,
    session: Session,
}

async fn owner(backend: &dyn StorageBackend) -> Owner {
    let profile = create_test_profile("enrolling");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let session = create_test_session(profile.id);
    backend
        .create_session(&session, test_audit())
        .await
        .unwrap();
    Owner { profile, session }
}

async fn ceremony(backend: &dyn StorageBackend) -> CeremonyConsumption {
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, b"ceremony", Duration::from_secs(300))
        .await
        .unwrap();
    CeremonyConsumption {
        namespace: NAMESPACE,
        key,
        stored: b"ceremony".to_vec(),
    }
}

fn binding(device: &Device, key: &str) -> DeviceAttestation {
    DeviceAttestation::new_ce(
        device.id,
        device.profile_id,
        DeviceAttestationFormat::None,
        KeyStorageType::SecureEnclave,
        key.to_owned(),
    )
}

fn enrollment(owner: &Owner, target: EnrollmentTarget, key: &str) -> DeviceEnrollment {
    let device = match &target {
        EnrollmentTarget::NewDevice(device) => device.clone(),
        _ => {
            let mut device = Device::new(owner.profile.id, DeviceType::Mobile);
            device.id = target.device();
            device
        }
    };
    DeviceEnrollment {
        profile_id: owner.profile.id,
        attestation: binding(&device, key),
        target,
    }
}

/// A mutation authorized by `owner`'s sign-in, consuming `ceremony`.
fn by(owner: &Owner, ceremony: CeremonyConsumption) -> MutationContext {
    test_audit()
        .fenced_by(ActorFence::Session {
            session: owner.session.id,
            profile: owner.profile.id,
            fresh_until: None,
        })
        .consuming(ceremony)
}

/// An enrolled device of `owner` with key `key`.
async fn enrolled(backend: &dyn StorageBackend, owner: &Owner, key: &str) -> DeviceAttestation {
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    let e = enrollment(owner, EnrollmentTarget::NewDevice(device), key);
    backend
        .commit_device_enrollment(&e, by(owner, ceremony(backend).await))
        .await
        .unwrap();
    e.attestation
}

async fn pending(backend: &dyn StorageBackend, ceremony: &CeremonyConsumption) -> bool {
    backend
        .read_ceremony_state(ceremony.namespace, &ceremony.key)
        .await
        .unwrap()
        .is_some()
}

/// A new device is created with its first key, its ceremony consumed; a
/// key without verified hardware evidence does not mark it attested.
pub async fn test_a_new_device_is_enrolled_with_its_key(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    let ceremony = ceremony(backend).await;
    let e = enrollment(&owner, EnrollmentTarget::NewDevice(device.clone()), "key-1");

    backend
        .commit_device_enrollment(&e, by(&owner, ceremony.clone()))
        .await
        .unwrap();

    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert_eq!(stored.profile_id, owner.profile.id);
    assert!(!stored.hardware_attested);
    let key = backend
        .get_device_attestation_by_device_id(device.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.id, e.attestation.id);
    assert_eq!(key.public_jwk, "key-1");
    assert_eq!(key.status, AttestationStatus::Unverified);
    assert!(!pending(backend, &ceremony).await);
}

/// An existing device without a key is enrolled; one whose key is live, or
/// changed since the ceremony started, is not.
pub async fn test_an_existing_device_is_enrolled_only_as_found(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = Device::new(owner.profile.id, DeviceType::Desktop);
    backend.create_device(&device, test_audit()).await.unwrap();
    let target = || EnrollmentTarget::ExistingDevice {
        device: device.id,
        revoked: None,
    };
    backend
        .commit_device_enrollment(
            &enrollment(&owner, target(), "key-1"),
            by(&owner, ceremony(backend).await),
        )
        .await
        .unwrap();

    // Now it has a live key: an enrollment that found none is stale.
    let again = ceremony(backend).await;
    let refused = backend
        .commit_device_enrollment(
            &enrollment(&owner, target(), "key-2"),
            by(&owner, again.clone()),
        )
        .await
        .expect_err("an enrollment over a live key");
    assert!(matches!(refused, Error::Conflict(_)), "{refused:?}");
    let key = backend
        .get_device_attestation_by_device_id(device.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.public_jwk, "key-1");
    assert!(
        pending(backend, &again).await,
        "a refused commit consumed its ceremony"
    );
}

/// A rotation retires exactly the binding it found; one revoked or rotated
/// meanwhile is never replaced or revived.
pub async fn test_a_rotation_replaces_only_the_binding_it_found(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let current = enrolled(backend, &owner, "key-1").await;
    let rotation = || EnrollmentTarget::Rotation {
        device: current.device_id,
        current: current.id,
        current_key: "key-1".into(),
    };
    let rotated = enrollment(&owner, rotation(), "key-2");
    backend
        .commit_device_enrollment(&rotated, by(&owner, ceremony(backend).await))
        .await
        .unwrap();
    let key = backend
        .get_device_attestation_by_device_id(current.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.id, rotated.attestation.id);
    assert_eq!(key.public_jwk, "key-2");

    // The same rotation again found key-1: it is gone.
    let stale = backend
        .commit_device_enrollment(
            &enrollment(&owner, rotation(), "key-3"),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("a rotation of a key already rotated");
    assert!(matches!(stale, Error::Conflict(_)), "{stale:?}");

    // A key revoked after a rotation started is not replaced.
    let revoked_target = EnrollmentTarget::Rotation {
        device: current.device_id,
        current: rotated.attestation.id,
        current_key: "key-2".into(),
    };
    backend
        .revoke_device_attestation(current.device_id, test_audit())
        .await
        .unwrap();
    let revived = backend
        .commit_device_enrollment(
            &enrollment(&owner, revoked_target, "key-4"),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("a rotation of a revoked key");
    assert!(matches!(revived, Error::Conflict(_)), "{revived:?}");
    let left = backend
        .get_device_attestation_by_device_id(current.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (left.id, left.status),
        (rotated.attestation.id, AttestationStatus::Revoked),
        "a revoked key was revived"
    );
}

/// After revocation a new enrollment that found the revoked binding binds a
/// key; one that found none, or an older one, does not.
pub async fn test_a_revoked_key_is_replaced_only_by_an_enrollment_that_found_it(
    backend: &dyn StorageBackend,
) {
    let owner = owner(backend).await;
    let first = enrolled(backend, &owner, "key-1").await;
    backend
        .revoke_device_attestation(first.device_id, test_audit())
        .await
        .unwrap();

    let blind = backend
        .commit_device_enrollment(
            &enrollment(
                &owner,
                EnrollmentTarget::ExistingDevice {
                    device: first.device_id,
                    revoked: None,
                },
                "key-2",
            ),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment that did not find the revoked binding");
    assert!(matches!(blind, Error::Conflict(_)), "{blind:?}");

    backend
        .commit_device_enrollment(
            &enrollment(
                &owner,
                EnrollmentTarget::ExistingDevice {
                    device: first.device_id,
                    revoked: Some(first.id),
                },
                "key-2",
            ),
            by(&owner, ceremony(backend).await),
        )
        .await
        .unwrap();
    let key = backend
        .get_device_attestation_by_device_id(first.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.public_jwk, "key-2");
}

/// A removed device, another Profile's device, an ended session or an owner
/// who can no longer sign in completes nothing.
pub async fn test_an_enrollment_without_current_authority_commits_nothing(
    backend: &dyn StorageBackend,
) {
    let owner = owner(backend).await;

    let removed = Device::new(owner.profile.id, DeviceType::Mobile);
    backend.create_device(&removed, test_audit()).await.unwrap();
    backend
        .delete_device(removed.id, test_audit())
        .await
        .unwrap();
    let err = backend
        .commit_device_enrollment(
            &enrollment(
                &owner,
                EnrollmentTarget::ExistingDevice {
                    device: removed.id,
                    revoked: None,
                },
                "key",
            ),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment of a removed device");
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");

    let other = self::owner(backend).await;
    let foreign = Device::new(other.profile.id, DeviceType::Mobile);
    backend.create_device(&foreign, test_audit()).await.unwrap();
    let err = backend
        .commit_device_enrollment(
            &enrollment(
                &owner,
                EnrollmentTarget::ExistingDevice {
                    device: foreign.id,
                    revoked: None,
                },
                "key",
            ),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment of another profile's device");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    backend
        .delete_session(owner.session.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    let err = backend
        .commit_device_enrollment(
            &enrollment(&owner, EnrollmentTarget::NewDevice(device.clone()), "key"),
            by(&owner, ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment under an ended session");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert!(backend.get_device(device.id).await.unwrap().is_none());

    let suspended = self::owner(backend).await;
    let mut profile = suspended.profile.clone();
    profile.status = ProfileStatus::Suspended;
    backend
        .update_profile(&profile, test_audit())
        .await
        .unwrap();
    let device = Device::new(suspended.profile.id, DeviceType::Mobile);
    let err = backend
        .commit_device_enrollment(
            &enrollment(
                &suspended,
                EnrollmentTarget::NewDevice(device.clone()),
                "key",
            ),
            by(&suspended, ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment of a suspended owner");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert!(backend.get_device(device.id).await.unwrap().is_none());
}

/// A revocation commits only under the sign-in that authorized it: a sign-in
/// that is past its freshness or ended since revokes nothing.
pub async fn test_a_revocation_holds_only_under_a_live_sign_in(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let key = enrolled(backend, &owner, "key-1").await;
    let fence = |fresh_until| ActorFence::Session {
        session: owner.session.id,
        profile: owner.profile.id,
        fresh_until,
    };
    let live = || async {
        backend
            .get_device_attestation_by_device_id(key.device_id)
            .await
            .unwrap()
            .unwrap()
            .status
            != AttestationStatus::Revoked
    };

    let stale = backend
        .revoke_device_attestation(
            key.device_id,
            test_audit().fenced_by(fence(Some(
                chrono::Utc::now() - chrono::Duration::seconds(1),
            ))),
        )
        .await
        .expect_err("a revocation past its sign-in's freshness");
    assert!(matches!(stale, Error::Fenced(_)), "{stale:?}");
    assert!(live().await);

    backend
        .delete_session(owner.session.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    let ended = backend
        .revoke_device_attestation(key.device_id, test_audit().fenced_by(fence(None)))
        .await
        .expect_err("a revocation under an ended sign-in");
    assert!(matches!(ended, Error::Fenced(_)), "{ended:?}");
    assert!(live().await);

    let current = self::owner(backend).await;
    let other = enrolled(backend, &current, "key-2").await;
    assert!(
        backend
            .revoke_device_attestation(
                other.device_id,
                test_audit().fenced_by(ActorFence::Session {
                    session: current.session.id,
                    profile: current.profile.id,
                    fresh_until: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                }),
            )
            .await
            .unwrap()
    );
}

/// A rotation racing a revocation of the same device ends with one of them
/// applied: the rotation committed or refused as changed, the revocation
/// applied or finding nothing live, never a failure of the store.
pub async fn test_a_rotation_racing_a_revocation_settles(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    for round in 0..16 {
        let current = enrolled(backend, &owner, "key-1").await;
        let rotation = enrollment(
            &owner,
            EnrollmentTarget::Rotation {
                device: current.device_id,
                current: current.id,
                current_key: "key-1".into(),
            },
            "key-2",
        );
        let ceremony = ceremony(backend).await;
        let (rotated, revoked) = tokio::join!(
            backend.commit_device_enrollment(&rotation, by(&owner, ceremony)),
            backend.revoke_device_attestation(current.device_id, test_audit()),
        );
        let revoked = revoked.unwrap_or_else(|e| panic!("round {round}: revocation: {e:?}"));
        match rotated {
            Ok(()) => {}
            Err(Error::Conflict(_)) => assert!(revoked, "round {round}"),
            Err(e) => panic!("round {round}: rotation: {e:?}"),
        }
    }
}

/// Two concurrent finishes of one ceremony bind one key.
pub async fn test_concurrent_finishes_bind_once(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    backend.create_device(&device, test_audit()).await.unwrap();
    let ceremony = ceremony(backend).await;
    let target = || EnrollmentTarget::ExistingDevice {
        device: device.id,
        revoked: None,
    };
    let (a, b) = (
        enrollment(&owner, target(), "key-a"),
        enrollment(&owner, target(), "key-b"),
    );

    let (first, second) = tokio::join!(
        backend.commit_device_enrollment(&a, by(&owner, ceremony.clone())),
        backend.commit_device_enrollment(&b, by(&owner, ceremony.clone())),
    );

    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .iter()
            .filter(|ok| **ok)
            .count(),
        1,
        "first: {first:?}, second: {second:?}"
    );
    let key = backend
        .get_device_attestation_by_device_id(device.id)
        .await
        .unwrap()
        .unwrap();
    let winner = if first.is_ok() { &a } else { &b };
    assert_eq!(key.id, winner.attestation.id);
}

/// A lost response is answered by the recorded outcome: a retry of the
/// committed finish binds nothing more.
pub async fn test_a_retried_finish_is_answered_by_its_outcome(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    let ceremony = ceremony(backend).await;
    let namespace = format!("profile:{}", owner.profile.id);
    let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    let keyed = || {
        by(&owner, ceremony.clone()).with_operation(OperationCompletion::new(
            &namespace,
            key.clone(),
            "sid.v1.attestation.AttestationService/FinishDeviceEnrollment",
            b"inputs",
            b"result".to_vec(),
        ))
    };
    let e = enrollment(&owner, EnrollmentTarget::NewDevice(device.clone()), "key-1");
    backend.commit_device_enrollment(&e, keyed()).await.unwrap();

    let retry = backend
        .commit_device_enrollment(&e, keyed())
        .await
        .expect_err("a retry of a committed finish");

    assert!(matches!(retry, Error::OperationCompleted(_)), "{retry:?}");
    assert_eq!(
        backend
            .list_devices_by_profile(owner.profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
}
