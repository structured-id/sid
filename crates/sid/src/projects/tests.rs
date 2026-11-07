use super::*;

/// A project and an initial access token travel as their identifiers'
/// bytes; the system project's nil identifier is read back as the system
/// project, and a malformed one is refused on its field.
#[test]
fn test_project_and_iat_wire_ids() {
    let project = ProjectId::generate();
    let wire: sid_ids_proto::ProjectId = project.into();
    assert_eq!(wire_id(Some(&wire), "project_id").unwrap(), project);
    let system: sid_ids_proto::ProjectId = ProjectId::SYSTEM.into();
    let read: ProjectId = wire_id(Some(&system), "project_id").unwrap();
    assert!(read.is_system());
    let bad = sid_ids_proto::ProjectId { value: vec![0; 3] };
    match ProjectError::from(
        wire_id::<sid_ids_proto::ProjectId>(Some(&bad), "project_id").unwrap_err(),
    ) {
        ProjectError::InvalidField { field, .. } => assert_eq!(field, "project_id"),
        other => panic!("refused as {other:?}"),
    }

    let iat = InitialAccessTokenId::generate();
    let wire: sid_ids_proto::InitialAccessTokenId = iat.into();
    assert_eq!(wire_id(Some(&wire), "id").unwrap(), iat);
}

#[test]
fn test_proto_to_app_type() {
    assert_eq!(
        proto_to_app_type(v1::ApplicationType::Web.into()),
        ApplicationType::Web
    );
    assert_eq!(
        proto_to_app_type(v1::ApplicationType::Native.into()),
        ApplicationType::Native
    );
    assert_eq!(
        proto_to_app_type(v1::ApplicationType::Api.into()),
        ApplicationType::Api
    );
    assert_eq!(
        proto_to_app_type(v1::ApplicationType::Spa.into()),
        ApplicationType::Spa
    );
    // Unspecified defaults to Web
    assert_eq!(
        proto_to_app_type(v1::ApplicationType::Unspecified.into()),
        ApplicationType::Web
    );
}

#[test]
fn test_generate_client_secret_length() {
    let secret = generate_client_secret();
    assert_eq!(secret.expose_secret().len(), 64); // 32 bytes * 2 hex chars
}

#[test]
fn test_generate_client_secret_unique() {
    let s1 = generate_client_secret();
    let s2 = generate_client_secret();
    assert_ne!(s1.expose_secret(), s2.expose_secret());
}

#[test]
fn test_hash_secret_produces_argon2_hash() {
    let secret = "test_secret_value";
    let hash = hash_secret(secret).unwrap();
    assert!(hash.starts_with("$argon2id$"));
}

#[test]
fn test_hash_secret_different_salts() {
    let secret = "same_secret";
    let h1 = hash_secret(secret).unwrap();
    let h2 = hash_secret(secret).unwrap();
    assert_ne!(h1, h2); // different salts
}

#[test]
fn test_application_type_mapping_roundtrip() {
    for app_type in [
        ApplicationType::Web,
        ApplicationType::Native,
        ApplicationType::Api,
        ApplicationType::Spa,
    ] {
        let proto_type = view::application_type_to_proto(app_type);
        let back = proto_to_app_type(proto_type.into());
        assert_eq!(back, app_type);
    }
}

/// A refusal the registration rules give for its metadata keeps which check
/// refused it; an ended initial access token is its own refusal, and any
/// other failure of the rules is internal.
#[test]
fn test_dcr_refusals_keep_their_check() {
    let metadata = dcr::DcrError::InvalidRedirectUri("not a URI".into());
    assert!(metadata.metadata_error().is_some());
    match dcr_refusal(metadata, RegistrationCheck::TokenPolicy) {
        ProjectError::Registration { check, .. } => {
            assert_eq!(check, RegistrationCheck::TokenPolicy)
        }
        other => panic!("refused as {other:?}"),
    }
    assert!(matches!(
        dcr_refusal(dcr::DcrError::IatExpired, RegistrationCheck::Metadata),
        ProjectError::IatEnded
    ));
    assert!(matches!(
        dcr_refusal(dcr::DcrError::IatRevoked, RegistrationCheck::Metadata),
        ProjectError::IatEnded
    ));
}
