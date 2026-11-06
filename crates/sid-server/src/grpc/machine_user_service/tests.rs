use super::*;
use sid_core::models::ProjectId;
use uuid::Uuid;

// ── client_id generation ──

#[test]
fn test_generate_client_id_format() {
    let id = generate_client_id();
    assert!(id.starts_with("mu_"));
    assert_eq!(id.len(), 27); // "mu_" (3) + 24 chars
}

#[test]
fn test_generate_client_id_unique() {
    let id1 = generate_client_id();
    let id2 = generate_client_id();
    assert_ne!(id1, id2);
}

#[test]
fn test_generate_client_id_base62_chars_only() {
    let id = generate_client_id();
    let random_part = &id[3..]; // skip "mu_"
    assert!(random_part.chars().all(|c| c.is_ascii_alphanumeric()));
}

// ── kid generation ──

#[test]
fn test_generate_kid_format() {
    let kid = generate_kid();
    assert!(kid.starts_with("kid_"));
    assert_eq!(kid.len(), 20); // "kid_" (4) + 16 chars
}

#[test]
fn test_generate_kid_unique() {
    let kid1 = generate_kid();
    let kid2 = generate_kid();
    assert_ne!(kid1, kid2);
}

// ── SHA-256 ──

#[test]
fn test_sha256_hex_known_value() {
    let hash = sha256_hex(b"");
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha256_hex_length() {
    let hash = sha256_hex(b"test data");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── Domain <-> proto conversion ──

#[test]
fn test_machine_user_to_proto() {
    let mu = MachineUser::new(
        ProjectId::SYSTEM,
        "mu_test123",
        "Test Bot",
        MachineOwner::System,
    );

    let proto = machine_user_to_proto(&mu);
    assert_eq!(proto.id, Some(mu.id.into()));
    assert_eq!(proto.client_id, "mu_test123");
    assert_eq!(proto.display_name, "Test Bot");
    assert_eq!(
        proto.owner.and_then(|o| o.owner),
        Some(v1::machine_user_owner::Owner::System(()))
    );
    assert_eq!(proto.status, ProtoMachineUserStatus::Active as i32);
    assert_eq!(proto.machine_type, ProtoMachineUserType::Service as i32);
    assert!(proto.created_at.is_some());
    assert!(proto.updated_at.is_some());
}

#[test]
fn test_machine_user_to_proto_with_restrictions() {
    let owner = sid_core::models::ProfileId::generate();
    let mut mu = MachineUser::new(
        ProjectId::SYSTEM,
        "mu_restricted",
        "Restricted Bot",
        MachineOwner::Profile(owner),
    );
    mu.restrictions.ip_allowlist = vec!["10.0.0.0/8".into()];
    mu.restrictions.rate_limit_rpm = 100;
    mu.max_token_lifetime = Some(3600);
    mu.scopes = vec!["read".into(), "write".into()];

    let proto = machine_user_to_proto(&mu);
    assert_eq!(proto.ip_allowlist, vec!["10.0.0.0/8"]);
    assert_eq!(proto.rate_limit_rpm, 100);
    assert_eq!(proto.max_token_lifetime, 3600);
    assert_eq!(proto.scopes, vec!["read", "write"]);
    assert_eq!(
        proto.owner.and_then(|o| o.owner),
        Some(v1::machine_user_owner::Owner::Profile(owner.into())),
        "the owner's own id, typed as a profile"
    );
}

#[test]
fn test_credential_to_proto() {
    let cred = MachineUserCredential::new(
        MachineUserId::generate(),
        "kid_test001",
        DomainCredentialType::ClientSecret,
        "hash_data",
    );

    let proto = credential_to_proto(&cred);
    assert_eq!(proto.kid, "kid_test001");
    assert_eq!(
        proto.credential_type,
        ProtoCredentialType::ClientSecret as i32
    );
    assert_eq!(proto.status, ProtoCredentialStatus::Active as i32);
    assert!(proto.created_at.is_some());
}

#[test]
fn test_grant_to_proto() {
    let grant = ImpersonationGrant::new(
        MachineUserId::generate(),
        DomainImpersonationTargetType::Role,
        "admin",
        vec!["*".into()],
    );

    let proto = grant_to_proto(&grant);
    assert_eq!(proto.target_type, ProtoImpersonationTargetType::Role as i32);
    assert_eq!(proto.target, "admin");
    assert_eq!(proto.allowed_scopes, vec!["*"]);
    assert!(proto.created_at.is_some());
}

// ── Wire identifiers ──

/// A machine user's identifier read off the wire is the one sent; a
/// malformed or absent one is refused on its field. A project identifier
/// keeps the system project's nil value.
#[test]
fn test_wire_ids_of_the_machine_api() {
    let id = MachineUserId::generate();
    let wire: sid_ids_proto::MachineUserId = id.into();
    assert_eq!(
        convert::wire_id(Some(&wire), "machine_user_id").unwrap(),
        id
    );
    for bad in [
        Some(sid_ids_proto::MachineUserId {
            value: Uuid::new_v4().as_bytes().to_vec(),
        }),
        Some(sid_ids_proto::MachineUserId { value: vec![] }),
        None,
    ] {
        let status = convert::wire_id(bad.as_ref(), "machine_user_id").unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("machine_user_id"));
    }
    let system: sid_ids_proto::ProjectId = sid_core::models::ProjectId::SYSTEM.into();
    assert_eq!(
        convert::wire_id(Some(&system), "project_id").unwrap(),
        sid_core::models::ProjectId::SYSTEM
    );
}

// ── Type conversion helpers ──

#[test]
fn test_proto_to_machine_type_all_variants() {
    assert_eq!(
        proto_to_machine_type(ProtoMachineUserType::Service as i32),
        DomainMachineUserType::Service
    );
    assert_eq!(
        proto_to_machine_type(ProtoMachineUserType::Bot as i32),
        DomainMachineUserType::Bot
    );
    assert_eq!(
        proto_to_machine_type(ProtoMachineUserType::Agent as i32),
        DomainMachineUserType::Agent
    );
    // Unspecified defaults to Service.
    assert_eq!(
        proto_to_machine_type(ProtoMachineUserType::Unspecified as i32),
        DomainMachineUserType::Service
    );
}

#[test]
fn test_proto_to_credential_type_all_variants() {
    assert!(proto_to_credential_type(ProtoCredentialType::ClientSecret as i32).is_ok());
    assert!(proto_to_credential_type(ProtoCredentialType::PrivateKeyJwt as i32).is_ok());
    assert!(proto_to_credential_type(ProtoCredentialType::Mtls as i32).is_ok());
    assert!(proto_to_credential_type(ProtoCredentialType::WorkloadIdentity as i32).is_ok());
    assert!(proto_to_credential_type(ProtoCredentialType::Unspecified as i32).is_err());
}

#[test]
fn test_proto_to_impersonation_target_all_variants() {
    assert!(proto_to_impersonation_target(ProtoImpersonationTargetType::Role as i32).is_ok());
    assert!(proto_to_impersonation_target(ProtoImpersonationTargetType::User as i32).is_ok());
    assert!(
        proto_to_impersonation_target(ProtoImpersonationTargetType::Unspecified as i32).is_err()
    );
}

#[test]
fn test_roundtrip_machine_type() {
    for domain_type in [
        DomainMachineUserType::Service,
        DomainMachineUserType::Bot,
        DomainMachineUserType::Agent,
    ] {
        let proto_val: i32 = machine_type_to_proto(domain_type).into();
        let back = proto_to_machine_type(proto_val);
        assert_eq!(back, domain_type);
    }
}

#[test]
fn test_status_to_proto_all_variants() {
    assert_eq!(
        status_to_proto(DomainMachineUserStatus::Active),
        ProtoMachineUserStatus::Active
    );
    assert_eq!(
        status_to_proto(DomainMachineUserStatus::Suspended),
        ProtoMachineUserStatus::Suspended
    );
    assert_eq!(
        status_to_proto(DomainMachineUserStatus::Expired),
        ProtoMachineUserStatus::Expired
    );
    assert_eq!(
        status_to_proto(DomainMachineUserStatus::Deleted),
        ProtoMachineUserStatus::Deleted
    );
}

#[test]
fn test_credential_status_to_proto_all_variants() {
    assert_eq!(
        credential_status_to_proto(DomainCredentialStatus::Active),
        ProtoCredentialStatus::Active
    );
    assert_eq!(
        credential_status_to_proto(DomainCredentialStatus::GracePeriod),
        ProtoCredentialStatus::GracePeriod
    );
    assert_eq!(
        credential_status_to_proto(DomainCredentialStatus::Expired),
        ProtoCredentialStatus::Expired
    );
    assert_eq!(
        credential_status_to_proto(DomainCredentialStatus::Revoked),
        ProtoCredentialStatus::Revoked
    );
}
