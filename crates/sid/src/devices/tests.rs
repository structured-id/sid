use sid_core::models::{AttestationStatus, DeviceType};

use super::*;
use crate::test_support::{storage, stored_profile};

/// An authority that allows other objects only when told to, and records
/// what it was asked.
#[derive(Default)]
struct TestAccess {
    allow_others: bool,
    owner_calls: usize,
    asked: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct Refused;

#[async_trait::async_trait]
impl DeviceAccess for TestAccess {
    type Error = Refused;

    async fn owner(&mut self) -> Result<(), Refused> {
        self.owner_calls += 1;
        Ok(())
    }

    async fn may(&mut self, object: &str) -> Result<bool, Refused> {
        self.asked.push(object.to_string());
        Ok(self.allow_others)
    }

    async fn require(&mut self, object: &str) -> Result<(), Refused> {
        self.asked.push(object.to_string());
        if self.allow_others {
            Ok(())
        } else {
            Err(Refused)
        }
    }
}

fn owner(profile: ProfileId) -> KeyCaller {
    KeyCaller {
        profile: Some(profile),
        subject: profile.to_string(),
        interactive: true,
    }
}

struct Fixture {
    keys: DeviceKeys,
    storage: Arc<dyn StorageBackend>,
    profile: ProfileId,
    device: DeviceId,
}

async fn fixture() -> Fixture {
    let storage: Arc<dyn StorageBackend> = storage().await;
    let profile = stored_profile(storage.as_ref(), "alice").await;
    let device = Device::new(profile, DeviceType::Mobile);
    storage
        .create_device(&device, AuditEntry::system("test", "device").into())
        .await
        .unwrap();
    Fixture {
        keys: DeviceKeys::new(storage.clone()),
        storage,
        profile,
        device: device.id,
    }
}

fn register(device: DeviceId) -> RegisterDeviceKeyRequest {
    RegisterDeviceKeyRequest {
        device_id: device.to_string(),
        device_public_key: vec![1, 2, 3],
        format: v1::AttestationFormat::Packed as i32,
        key_storage: v1::KeyStorageType::SecureEnclave as i32,
        ..Default::default()
    }
}

// The owner registers, reads, rotates and revokes its device's key; the
// registered attestation is unverified and does not mark the device
// hardware-attested.
#[tokio::test]
async fn the_owner_manages_its_device_key() {
    let f = fixture().await;
    let caller = owner(f.profile);
    let mut access = TestAccess::default();

    let registered = f
        .keys
        .register_key(&mut access, &caller, register(f.device))
        .await
        .unwrap();
    assert_eq!(registered.device_public_key, vec![1, 2, 3]);
    assert_ne!(registered.status, v1::AttestationStatus::Verified as i32);
    let device = f.storage.get_device(f.device).await.unwrap().unwrap();
    assert!(!device.hardware_attested);

    let rotated = f
        .keys
        .rotate_key(
            &mut access,
            &caller,
            RotateDeviceKeyRequest {
                device_id: f.device.to_string(),
                new_device_public_key: vec![4, 5, 6],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rotated.device_public_key, vec![4, 5, 6]);

    f.keys
        .revoke_key(
            &mut access,
            &caller,
            RevokeDeviceKeyRequest {
                device_id: f.device.to_string(),
            },
        )
        .await
        .unwrap();
    let stored = f
        .storage
        .get_device_attestation_by_device_id(f.device)
        .await
        .unwrap();
    assert!(stored.is_none_or(|a| a.status == AttestationStatus::Revoked));
    // The owner's calls never asked the authority about another object.
    assert!(access.asked.is_empty());
    assert_eq!(access.owner_calls, 3);
}

// A second registration of a device with a live key is refused: its key is
// rotated instead.
#[tokio::test]
async fn a_live_key_is_not_registered_twice() {
    let f = fixture().await;
    let caller = owner(f.profile);
    let mut access = TestAccess::default();
    f.keys
        .register_key(&mut access, &caller, register(f.device))
        .await
        .unwrap();

    let again = f
        .keys
        .register_key(&mut access, &caller, register(f.device))
        .await;

    assert!(matches!(again, Err(DeviceKeyError::AlreadyEnrolled(d)) if d == f.device));
}

// Another Profile's device is not found unless its authority allows the
// call; nothing is written for the refused caller.
#[tokio::test]
async fn another_profiles_device_is_not_found() {
    let f = fixture().await;
    let stranger = owner(ProfileId::generate());
    let mut access = TestAccess::default();

    let refused = f
        .keys
        .register_key(&mut access, &stranger, register(f.device))
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::DeviceNotFound(d)) if d == f.device));
    assert_eq!(access.asked, vec![format!("device:{}", f.device)]);
    assert!(
        f.storage
            .get_device_attestation_by_device_id(f.device)
            .await
            .unwrap()
            .is_none()
    );
}

// An unknown device is not found, alike for a caller the authority allows.
#[tokio::test]
async fn an_unknown_device_is_not_found() {
    let f = fixture().await;
    let unknown = DeviceId::generate();
    let mut access = TestAccess {
        allow_others: true,
        ..Default::default()
    };

    let refused = f
        .keys
        .get_attestation(
            &mut access,
            &owner(f.profile),
            GetDeviceAttestationRequest {
                device_id: unknown.to_string(),
            },
        )
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::DeviceNotFound(d)) if d == unknown));
}

// An impersonation reads the owner's device key but never changes it.
#[tokio::test]
async fn an_impersonation_does_not_change_a_key() {
    let f = fixture().await;
    let impersonation = KeyCaller {
        interactive: false,
        ..owner(f.profile)
    };
    let mut access = TestAccess::default();

    let refused = f
        .keys
        .register_key(&mut access, &impersonation, register(f.device))
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::Denied)));
}

// An allowed administrator may act on a device it does not own; the audit
// and the attestation name the device's owner Profile.
#[tokio::test]
async fn an_allowed_caller_acts_on_anothers_device() {
    let f = fixture().await;
    let admin = owner(ProfileId::generate());
    let mut access = TestAccess {
        allow_others: true,
        ..Default::default()
    };

    let registered = f
        .keys
        .register_key(&mut access, &admin, register(f.device))
        .await
        .unwrap();

    assert_eq!(registered.profile_id, f.profile.to_string());
}

// Rotating a device without a live key is refused rather than creating one.
#[tokio::test]
async fn rotating_without_a_key_is_refused() {
    let f = fixture().await;
    let mut access = TestAccess::default();

    let refused = f
        .keys
        .rotate_key(
            &mut access,
            &owner(f.profile),
            RotateDeviceKeyRequest {
                device_id: f.device.to_string(),
                new_device_public_key: vec![9],
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(refused, Err(DeviceKeyError::NoAttestation(d)) if d == f.device));
}

// Malformed and missing fields are refused before anything is read.
#[tokio::test]
async fn malformed_requests_are_refused() {
    let f = fixture().await;
    let caller = owner(f.profile);
    let mut access = TestAccess::default();

    let bad_id = f
        .keys
        .register_key(
            &mut access,
            &caller,
            RegisterDeviceKeyRequest {
                device_id: "not-an-id".to_string(),
                device_public_key: vec![1],
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        bad_id,
        Err(DeviceKeyError::InvalidId("device_id"))
    ));

    let no_key = f
        .keys
        .register_key(
            &mut access,
            &caller,
            RegisterDeviceKeyRequest {
                device_id: f.device.to_string(),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        no_key,
        Err(DeviceKeyError::MissingField("device_public_key"))
    ));
    assert_eq!(access.owner_calls, 0);
}

#[test]
fn test_proto_format_mapping() {
    use v1::AttestationFormat as F;
    assert_eq!(
        format_from_proto(F::None as i32),
        DeviceAttestationFormat::None
    );
    assert_eq!(
        format_from_proto(F::Packed as i32),
        DeviceAttestationFormat::Packed
    );
    assert_eq!(
        format_from_proto(F::Tpm as i32),
        DeviceAttestationFormat::Tpm
    );
    assert_eq!(
        format_from_proto(F::AndroidKey as i32),
        DeviceAttestationFormat::AndroidKey
    );
    assert_eq!(
        format_from_proto(F::Apple as i32),
        DeviceAttestationFormat::Apple
    );
    assert_eq!(
        format_from_proto(F::FidoU2f as i32),
        DeviceAttestationFormat::FidoU2f
    );
    assert_eq!(format_from_proto(999), DeviceAttestationFormat::None);
}

#[test]
fn test_proto_key_storage_mapping() {
    use v1::KeyStorageType as K;
    assert_eq!(
        key_storage_from_proto(K::Software as i32),
        KeyStorageType::Software
    );
    assert_eq!(key_storage_from_proto(K::Tpm as i32), KeyStorageType::Tpm);
    assert_eq!(
        key_storage_from_proto(K::SecureEnclave as i32),
        KeyStorageType::SecureEnclave
    );
    assert_eq!(
        key_storage_from_proto(K::Strongbox as i32),
        KeyStorageType::StrongBox
    );
    assert_eq!(key_storage_from_proto(K::Tee as i32), KeyStorageType::Tee);
    assert_eq!(key_storage_from_proto(999), KeyStorageType::Software);
}

#[test]
fn test_domain_to_proto_roundtrip() {
    let att = DeviceAttestation::new_ce(
        DeviceId::generate(),
        ProfileId::generate(),
        DeviceAttestationFormat::Apple,
        KeyStorageType::SecureEnclave,
        vec![0x04, 0x01],
    );
    let proto = attestation_to_proto(&att);
    assert_eq!(proto.format, v1::AttestationFormat::Apple as i32);
    assert_eq!(proto.key_storage, v1::KeyStorageType::SecureEnclave as i32);
    assert_eq!(proto.status, v1::AttestationStatus::Unverified as i32);
    assert_eq!(proto.device_public_key, vec![0x04, 0x01]);
}

// The owner lists its device keys; another caller gets the authority's own
// refusal.
#[tokio::test]
async fn listing_follows_the_profiles_authority() {
    let f = fixture().await;
    let mut access = TestAccess::default();
    f.keys
        .register_key(&mut access, &owner(f.profile), register(f.device))
        .await
        .unwrap();
    let list = || ListDeviceAttestationsRequest {
        profile_id: f.profile.to_string(),
    };

    let own = f
        .keys
        .list_attestations(&mut access, &owner(f.profile), list())
        .await
        .unwrap();
    assert_eq!(own.attestations.len(), 1);

    let refused = f
        .keys
        .list_attestations(&mut access, &owner(ProfileId::generate()), list())
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::Access(Refused))));
}
