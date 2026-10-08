use super::*;

fn make_attestation() -> DeviceAttestation {
    DeviceAttestation::new_ce(
        DeviceId::generate(),
        ProfileId::generate(),
        DeviceAttestationFormat::Apple,
        KeyStorageType::SecureEnclave,
        vec![0x04, 0x01, 0x02, 0x03], // fake DER public key
    )
}

#[test]
fn test_new_ce_defaults() {
    let a = make_attestation();
    assert_eq!(a.format, DeviceAttestationFormat::Apple);
    assert_eq!(a.key_storage, KeyStorageType::SecureEnclave);
    assert_eq!(a.status, AttestationStatus::Unverified);
    assert!(a.is_hardware_backed());
    assert!(a.attestation_object.is_none());
    assert!(a.attestation_certificate.is_none());
    assert!(a.aaguid.is_none());
    assert!(a.credential_id.is_none());
    assert!(a.revoked_at.is_none());
}

#[test]
fn test_rotate_key() {
    let mut a = make_attestation();
    a.attestation_object = Some(vec![0xAA, 0xBB]);
    a.attestation_certificate = Some(vec![0xCC]);
    a.status = AttestationStatus::Verified;

    let old_updated = a.updated_at;
    std::thread::sleep(std::time::Duration::from_millis(10));
    a.rotate_key(vec![0x04, 0x05, 0x06]);

    assert_eq!(a.device_public_key, vec![0x04, 0x05, 0x06]);
    assert_eq!(a.status, AttestationStatus::Unverified);
    assert!(a.attestation_object.is_none());
    assert!(a.attestation_certificate.is_none());
    assert!(a.updated_at >= old_updated);
}

#[test]
fn test_revoke() {
    let mut a = make_attestation();
    assert!(a.revoked_at.is_none());
    assert!(a.status.is_active());

    a.revoke();
    assert_eq!(a.status, AttestationStatus::Revoked);
    assert!(a.revoked_at.is_some());
    assert!(!a.status.is_active());
}

#[test]
fn test_status_is_active() {
    assert!(!AttestationStatus::Pending.is_active());
    assert!(AttestationStatus::Verified.is_active());
    assert!(AttestationStatus::Unverified.is_active());
    assert!(!AttestationStatus::Rejected.is_active());
    assert!(!AttestationStatus::Revoked.is_active());
}

#[test]
fn test_key_storage_hardware_backed() {
    assert!(!KeyStorageType::Software.is_hardware_backed());
    assert!(KeyStorageType::Tpm.is_hardware_backed());
    assert!(KeyStorageType::SecureEnclave.is_hardware_backed());
    assert!(KeyStorageType::StrongBox.is_hardware_backed());
    assert!(KeyStorageType::Tee.is_hardware_backed());
}

/// Every stored name reads back as its value; an unknown one is an error. A
/// damaged status must not read as `pending` (that would un-revoke a key).
#[test]
fn test_stored_names_parse_back() {
    for f in [
        DeviceAttestationFormat::None,
        DeviceAttestationFormat::Packed,
        DeviceAttestationFormat::Tpm,
        DeviceAttestationFormat::AndroidKey,
        DeviceAttestationFormat::Apple,
        DeviceAttestationFormat::FidoU2f,
    ] {
        assert_eq!(f.as_str().parse::<DeviceAttestationFormat>(), Ok(f));
    }
    for k in [
        KeyStorageType::Software,
        KeyStorageType::Tpm,
        KeyStorageType::SecureEnclave,
        KeyStorageType::StrongBox,
        KeyStorageType::Tee,
    ] {
        assert_eq!(k.as_str().parse::<KeyStorageType>(), Ok(k));
    }
    for s in [
        AttestationStatus::Pending,
        AttestationStatus::Verified,
        AttestationStatus::Unverified,
        AttestationStatus::Rejected,
        AttestationStatus::Revoked,
    ] {
        assert_eq!(s.as_str().parse::<AttestationStatus>(), Ok(s));
    }
    assert!("safetynet".parse::<DeviceAttestationFormat>().is_err());
    assert!("hsm".parse::<KeyStorageType>().is_err());
    assert!("revokd".parse::<AttestationStatus>().is_err());
}

#[test]
fn test_format_serde_roundtrip() {
    let f = DeviceAttestationFormat::AndroidKey;
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(json, "\"android_key\"");
    let parsed: DeviceAttestationFormat = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, DeviceAttestationFormat::AndroidKey);
}

#[test]
fn test_attestation_serde_roundtrip() {
    let mut a = make_attestation();
    a.aaguid = Some("2fc0579f-8113-47ea-b116-bb5a8db9202a".into());
    a.credential_id = Some("cred_test_123".into());
    a.attestation_object = Some(vec![0xDE, 0xAD]);

    let json = serde_json::to_string(&a).unwrap();
    let parsed: DeviceAttestation = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.format, DeviceAttestationFormat::Apple);
    assert_eq!(
        parsed.aaguid.as_deref(),
        Some("2fc0579f-8113-47ea-b116-bb5a8db9202a")
    );
    assert_eq!(parsed.credential_id.as_deref(), Some("cred_test_123"));
    assert_eq!(
        parsed.attestation_object.as_deref(),
        Some(&[0xDE, 0xAD][..])
    );
}

#[test]
fn test_id_unique() {
    let id1 = DeviceAttestationId::new();
    let id2 = DeviceAttestationId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_software_key_not_hardware() {
    let a = DeviceAttestation::new_ce(
        DeviceId::generate(),
        ProfileId::generate(),
        DeviceAttestationFormat::None,
        KeyStorageType::Software,
        vec![0x01],
    );
    assert!(!a.is_hardware_backed());
    assert_eq!(a.format, DeviceAttestationFormat::None);
}
