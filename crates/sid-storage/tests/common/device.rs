// SPDX-License-Identifier: AGPL-3.0-only
//! Devices: a create never replaces one, a rename touches only the name and
//! never brings back a removed device, and trust changes respect the
//! per-profile limit under concurrency.

use sid_core::Error;
use sid_core::models::{Device, DeviceAssurance, DeviceTrustChange, DeviceType, Profile};
use sid_plugin::storage::StorageBackend;

use super::{create_test_profile, test_audit};

async fn owner(backend: &dyn StorageBackend) -> Profile {
    let profile = create_test_profile("device_owner");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile
}

async fn stored_device(backend: &dyn StorageBackend, owner: &Profile) -> Device {
    let mut device = Device::new(owner.id, DeviceType::Mobile);
    device.display_name = Some("phone".into());
    backend.create_device(&device, test_audit()).await.unwrap();
    device
}

/// A create over an existing device is refused and changes nothing.
pub async fn test_create_device_never_replaces(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = stored_device(backend, &owner).await;

    let mut again = device.clone();
    again.trusted = true;
    again.assurance = DeviceAssurance::Managed;
    let err = backend
        .create_device(&again, test_audit())
        .await
        .expect_err("a create over an existing device");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert!(!stored.trusted);
    assert_eq!(stored.assurance, DeviceAssurance::Unknown);
}

/// A rename keeps a trust change made meanwhile, and after the device is
/// removed it applies nothing and the device stays removed.
pub async fn test_rename_device_keeps_trust(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = stored_device(backend, &owner).await;
    assert_eq!(
        backend
            .set_device_trust(device.id, true, 10, test_audit())
            .await
            .unwrap(),
        DeviceTrustChange::Changed
    );
    assert_eq!(
        backend
            .set_device_trust(device.id, false, 10, test_audit())
            .await
            .unwrap(),
        DeviceTrustChange::Changed
    );

    assert!(
        backend
            .rename_device(device.id, Some("work phone"), test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert_eq!(stored.display_name.as_deref(), Some("work phone"));
    assert!(!stored.trusted, "a rename undid a trust revocation");
    assert_eq!(stored.assurance, DeviceAssurance::Recognized);

    backend
        .delete_device(device.id, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .rename_device(device.id, Some("gone"), test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend.get_device(device.id).await.unwrap().is_none(),
        "a removed device was recreated"
    );
}

/// Trusting raises assurance to trusted, a repeat changes nothing, and
/// distrusting drops it back to recognized; an unknown device is reported.
pub async fn test_device_trust_changes(backend: &dyn StorageBackend) {
    let owner = owner(backend).await;
    let device = stored_device(backend, &owner).await;

    let set = |trusted| backend.set_device_trust(device.id, trusted, 10, test_audit());
    assert_eq!(set(true).await.unwrap(), DeviceTrustChange::Changed);
    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert!(stored.trusted);
    assert_eq!(stored.assurance, DeviceAssurance::Trusted);
    assert_eq!(set(true).await.unwrap(), DeviceTrustChange::Unchanged);
    assert_eq!(set(false).await.unwrap(), DeviceTrustChange::Changed);
    let stored = backend.get_device(device.id).await.unwrap().unwrap();
    assert!(!stored.trusted);
    assert_eq!(stored.assurance, DeviceAssurance::Recognized);

    let unknown = Device::new(owner.id, DeviceType::Desktop);
    assert_eq!(
        backend
            .set_device_trust(unknown.id, true, 10, test_audit())
            .await
            .unwrap(),
        DeviceTrustChange::NotFound
    );
}

/// Concurrent trusts of a profile's devices never exceed its limit.
pub async fn test_device_trust_limit_under_concurrency(backend: &dyn StorageBackend) {
    const LIMIT: usize = 2;
    let owner = owner(backend).await;
    let mut devices = Vec::new();
    for _ in 0..5 {
        devices.push(stored_device(backend, &owner).await);
    }
    let trust = |d: &Device| backend.set_device_trust(d.id, true, LIMIT, test_audit());
    let (a, b, c, d, e) = tokio::join!(
        trust(&devices[0]),
        trust(&devices[1]),
        trust(&devices[2]),
        trust(&devices[3]),
        trust(&devices[4]),
    );
    let outcomes = [a, b, c, d, e].map(Result::unwrap);
    let changed = outcomes
        .iter()
        .filter(|o| **o == DeviceTrustChange::Changed)
        .count();
    assert_eq!(changed, LIMIT, "{outcomes:?}");
    let trusted = backend
        .list_devices_by_profile(owner.id)
        .await
        .unwrap()
        .iter()
        .filter(|d| d.trusted)
        .count();
    assert_eq!(trusted, LIMIT);
}

/// A device is recognized by its fingerprint within its profile only: the
/// same fingerprint under another profile is that profile's device.
pub async fn test_device_by_fingerprint(backend: &dyn StorageBackend) {
    let alice = owner(backend).await;
    let bob = owner(backend).await;
    let fingerprint = format!("fp-{}", uuid::Uuid::now_v7().simple());
    let mut mine = Device::new(alice.id, DeviceType::Desktop);
    mine.fingerprint_hash = Some(fingerprint.clone());
    let mut theirs = Device::new(bob.id, DeviceType::Desktop);
    theirs.fingerprint_hash = Some(fingerprint.clone());
    for d in [&mine, &theirs] {
        backend.create_device(d, test_audit()).await.unwrap();
    }

    let found = backend
        .get_device_by_fingerprint(alice.id, &fingerprint)
        .await
        .unwrap()
        .expect("the device by its fingerprint");
    assert_eq!(found.id, mine.id, "another profile's device was recognized");
    assert_eq!(
        backend
            .get_device_by_fingerprint(bob.id, &fingerprint)
            .await
            .unwrap()
            .unwrap()
            .id,
        theirs.id
    );
    assert!(
        backend
            .get_device_by_fingerprint(alice.id, "unknown")
            .await
            .unwrap()
            .is_none()
    );
}
