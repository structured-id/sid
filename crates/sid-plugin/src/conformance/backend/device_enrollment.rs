// SPDX-License-Identifier: AGPL-3.0-only
//! A finished device-key ceremony commits once: the device (created or as
//! the ceremony found it), its binding (a rotation retiring the old one),
//! the consumed ceremony, the audit and the outcome together, and only
//! while the owner, its session and the target are as the ceremony found
//! them.

use std::time::Duration;

use sid_core::Error;
use sid_core::models::{
    AttestationStatus, CeremonyConsumption, Device, DeviceAttestation, DeviceAttestationFormat,
    DeviceEnrollment, DeviceType, EnrollmentTarget, KeyStorageType, OperationCompletion,
    OperationKey, Profile, ProfileStatus, Session,
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

fn binding(device: &Device, key: &[u8]) -> DeviceAttestation {
    DeviceAttestation::new_ce(
        device.id,
        device.profile_id,
        DeviceAttestationFormat::None,
        KeyStorageType::SecureEnclave,
        key.to_vec(),
    )
}

fn enrollment(owner: &Owner, target: EnrollmentTarget, key: &[u8]) -> DeviceEnrollment {
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
        session: Some(owner.session.id),
        attestation: binding(&device, key),
        target,
    }
}

/// An enrolled device of `owner` with key `key`.
async fn enrolled(backend: &dyn StorageBackend, owner: &Owner, key: &[u8]) -> DeviceAttestation {
    let device = Device::new(owner.profile.id, DeviceType::Mobile);
    let e = enrollment(owner, EnrollmentTarget::NewDevice(device), key);
    backend
        .commit_device_enrollment(&e, test_audit().consuming(ceremony(backend).await))
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
    let e = enrollment(
        &owner,
        EnrollmentTarget::NewDevice(device.clone()),
        b"key-1",
    );

    backend
        .commit_device_enrollment(&e, test_audit().consuming(ceremony.clone()))
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
    assert_eq!(key.device_public_key, b"key-1");
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
            &enrollment(&owner, target(), b"key-1"),
            test_audit().consuming(ceremony(backend).await),
        )
        .await
        .unwrap();

    // Now it has a live key: an enrollment that found none is stale.
    let again = ceremony(backend).await;
    let refused = backend
        .commit_device_enrollment(
            &enrollment(&owner, target(), b"key-2"),
            test_audit().consuming(again.clone()),
        )
        .await
        .expect_err("an enrollment over a live key");
    assert!(matches!(refused, Error::Conflict(_)), "{refused:?}");
    let key = backend
        .get_device_attestation_by_device_id(device.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.device_public_key, b"key-1");
    assert!(
        pending(backend, &again).await,
        "a refused commit consumed its ceremony"
    );
}

/// A rotation retires exactly the binding it found; one revoked or rotated
/// meanwhile is never replaced or revived.
pub async fn test_a_rotation_replaces_only_the_binding_it_found(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let current = enrolled(backend, &owner, b"key-1").await;
    let rotation = || EnrollmentTarget::Rotation {
        device: current.device_id,
        current: current.id,
        current_key: b"key-1".to_vec(),
    };
    let rotated = enrollment(&owner, rotation(), b"key-2");
    backend
        .commit_device_enrollment(&rotated, test_audit().consuming(ceremony(backend).await))
        .await
        .unwrap();
    let key = backend
        .get_device_attestation_by_device_id(current.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.id, rotated.attestation.id);
    assert_eq!(key.device_public_key, b"key-2");

    // The same rotation again found key-1: it is gone.
    let stale = backend
        .commit_device_enrollment(
            &enrollment(&owner, rotation(), b"key-3"),
            test_audit().consuming(ceremony(backend).await),
        )
        .await
        .expect_err("a rotation of a key already rotated");
    assert!(matches!(stale, Error::Conflict(_)), "{stale:?}");

    // A key revoked after a rotation started is not replaced.
    let revoked_target = EnrollmentTarget::Rotation {
        device: current.device_id,
        current: rotated.attestation.id,
        current_key: b"key-2".to_vec(),
    };
    backend
        .revoke_device_attestation(current.device_id, test_audit())
        .await
        .unwrap();
    let revived = backend
        .commit_device_enrollment(
            &enrollment(&owner, revoked_target, b"key-4"),
            test_audit().consuming(ceremony(backend).await),
        )
        .await
        .expect_err("a rotation of a revoked key");
    assert!(matches!(revived, Error::Conflict(_)), "{revived:?}");
    assert!(
        backend
            .get_device_attestation_by_device_id(current.device_id)
            .await
            .unwrap()
            .is_none(),
        "a revoked key was revived"
    );
}

/// After revocation a new enrollment that found the revoked binding binds a
/// key; one that found none, or an older one, does not.
pub async fn test_a_revoked_key_is_replaced_only_by_an_enrollment_that_found_it(
    backend: &dyn StorageBackend,
) {
    let owner = owner(backend).await;
    let first = enrolled(backend, &owner, b"key-1").await;
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
                b"key-2",
            ),
            test_audit().consuming(ceremony(backend).await),
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
                b"key-2",
            ),
            test_audit().consuming(ceremony(backend).await),
        )
        .await
        .unwrap();
    let key = backend
        .get_device_attestation_by_device_id(first.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(key.device_public_key, b"key-2");
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
                b"key",
            ),
            test_audit().consuming(ceremony(backend).await),
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
                b"key",
            ),
            test_audit().consuming(ceremony(backend).await),
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
            &enrollment(&owner, EnrollmentTarget::NewDevice(device.clone()), b"key"),
            test_audit().consuming(ceremony(backend).await),
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
                b"key",
            ),
            test_audit().consuming(ceremony(backend).await),
        )
        .await
        .expect_err("an enrollment of a suspended owner");
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert!(backend.get_device(device.id).await.unwrap().is_none());
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
        enrollment(&owner, target(), b"key-a"),
        enrollment(&owner, target(), b"key-b"),
    );

    let (first, second) = tokio::join!(
        backend.commit_device_enrollment(&a, test_audit().consuming(ceremony.clone())),
        backend.commit_device_enrollment(&b, test_audit().consuming(ceremony.clone())),
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
        test_audit()
            .with_operation(OperationCompletion::new(
                &namespace,
                key.clone(),
                "sid.v1.attestation.AttestationService/FinishDeviceEnrollment",
                b"inputs",
                b"result".to_vec(),
            ))
            .consuming(ceremony.clone())
    };
    let e = enrollment(
        &owner,
        EnrollmentTarget::NewDevice(device.clone()),
        b"key-1",
    );
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
