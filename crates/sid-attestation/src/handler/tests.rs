use super::*;

#[test]
fn test_proto_format_mapping() {
    assert_eq!(
        proto_format(AttestationFormat::None as i32),
        DeviceAttestationFormat::None
    );
    assert_eq!(
        proto_format(AttestationFormat::Packed as i32),
        DeviceAttestationFormat::Packed
    );
    assert_eq!(
        proto_format(AttestationFormat::Tpm as i32),
        DeviceAttestationFormat::Tpm
    );
    assert_eq!(
        proto_format(AttestationFormat::AndroidKey as i32),
        DeviceAttestationFormat::AndroidKey
    );
    assert_eq!(
        proto_format(AttestationFormat::Apple as i32),
        DeviceAttestationFormat::Apple
    );
    assert_eq!(
        proto_format(AttestationFormat::FidoU2f as i32),
        DeviceAttestationFormat::FidoU2f
    );
    assert_eq!(proto_format(999), DeviceAttestationFormat::None);
}

#[test]
fn test_proto_key_storage_mapping() {
    assert_eq!(
        proto_key_storage(KeyStorageType2::Software as i32),
        KeyStorageType::Software
    );
    assert_eq!(
        proto_key_storage(KeyStorageType2::Tpm as i32),
        KeyStorageType::Tpm
    );
    assert_eq!(
        proto_key_storage(KeyStorageType2::SecureEnclave as i32),
        KeyStorageType::SecureEnclave
    );
    assert_eq!(
        proto_key_storage(KeyStorageType2::Strongbox as i32),
        KeyStorageType::StrongBox
    );
    assert_eq!(
        proto_key_storage(KeyStorageType2::Tee as i32),
        KeyStorageType::Tee
    );
    assert_eq!(proto_key_storage(999), KeyStorageType::Software);
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
    let proto = domain_to_proto(&att);
    assert_eq!(proto.format, AttestationFormat::Apple as i32);
    assert_eq!(proto.key_storage, KeyStorageType2::SecureEnclave as i32);
    assert_eq!(proto.status, AttestationStatus::Unverified as i32);
    assert_eq!(proto.device_public_key, vec![0x04, 0x01]);
}

/// A malformed identifier names its field and never repeats the value.
#[test]
fn test_parse_id_names_the_field_only() {
    let err = parse_id::<DeviceId>("not-a-uuid", "device_id").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(!err.message().contains("not-a-uuid"), "{err:?}");
    let violation = tonic_types::StatusExt::get_details_bad_request(&err)
        .and_then(|b| b.field_violations.into_iter().next())
        .expect("field violation");
    assert_eq!(violation.field, "device_id");
    assert!(!violation.description.contains("not-a-uuid"));
}
