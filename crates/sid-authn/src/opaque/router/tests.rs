use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

use super::*;
use crate::opaque::{P256Opaque, P384Opaque, P521Opaque, PallasOpaque, RistrettoOpaque};

fn build_ristretto_router() -> OpaqueRouter {
    let primary = Box::new(RistrettoOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
    verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

fn build_pallas_router() -> OpaqueRouter {
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
    verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

#[test]
fn test_primary_curve() {
    let router = build_ristretto_router();
    assert_eq!(router.primary_curve(), CurveId::Ristretto255);

    let router = build_pallas_router();
    assert_eq!(router.primary_curve(), CurveId::Pallas);
}

#[test]
fn test_supports_curve() {
    let router = build_ristretto_router();
    assert!(router.supports_curve(CurveId::Ristretto255));
    assert!(router.supports_curve(CurveId::Pallas));
    assert!(router.supports_curve(CurveId::P256));
    assert!(router.supports_curve(CurveId::P384));
    assert!(router.supports_curve(CurveId::P521));
}

#[test]
fn test_supported_curves() {
    let router = build_ristretto_router();
    let curves = router.supported_curves();
    assert!(curves.contains(&CurveId::Ristretto255));
    assert!(curves.contains(&CurveId::Pallas));
    assert!(curves.contains(&CurveId::P256));
    assert!(curves.contains(&CurveId::P384));
    assert!(curves.contains(&CurveId::P521));
    assert_eq!(curves.len(), 5);
}

#[test]
fn test_full_flow_via_router() {
    use crate::opaque::ristretto::DefaultCipherSuite;
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters,
    };

    let router = build_ristretto_router();
    let credential_id = b"bob@sid.example.com";
    let password = b"hunter2-but-longer";

    // --- Registration via router ---
    let mut rng = UnwrapErr(SysRng);
    let client_reg_start =
        ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let client_reg_request = client_reg_start.message.serialize().to_vec();

    let (server_reg_response, _) = router
        .registration_start(&client_reg_request, credential_id)
        .unwrap();

    let server_reg_msg = sid_opaque_ke::RegistrationResponse::<DefaultCipherSuite>::deserialize(
        &server_reg_response,
    )
    .unwrap();
    let client_reg_finish = client_reg_start
        .state
        .finish(
            &mut rng,
            password,
            server_reg_msg,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let upload_bytes = client_reg_finish.message.serialize().to_vec();

    let stored = router.registration_finish(&upload_bytes).unwrap();
    assert_eq!(stored.curve, CurveId::Ristretto255);

    // --- Login via router ---
    let client_login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let client_login_request = client_login_start.message.serialize().to_vec();

    let (server_login_response, login_state) = router
        .login_start(&stored, &client_login_request, credential_id)
        .unwrap();

    let server_login_msg = sid_opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(
        &server_login_response,
    )
    .unwrap();
    let client_login_finish = client_login_start
        .state
        .finish(
            &mut rng,
            password,
            server_login_msg,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let finalization_bytes = client_login_finish.message.serialize().to_vec();

    let session_key = router
        .login_finish(&login_state, &finalization_bytes)
        .unwrap();
    assert_eq!(
        session_key.expose_secret(),
        &client_login_finish.session_key[..]
    );
}

#[test]
fn test_unsupported_curve_rejected() {
    // Build a router with only Ristretto255 — P384 should be unsupported
    let primary = Box::new(RistrettoOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    let router = OpaqueRouter::new(primary, verifiers, setup);

    let cred = StoredCredential {
        curve: CurveId::P384,
        data: vec![0; 64],
    };
    let result = router.login_start(&cred, b"request", b"id");
    assert!(matches!(result, Err(OpaqueError::UnsupportedCurve(_))));
}

#[test]
fn test_empty_login_state_rejected() {
    let router = build_ristretto_router();
    let result = router.login_finish(&LoginState(vec![]), b"finalization");
    assert!(matches!(result, Err(OpaqueError::Deserialization(_))));
}

#[test]
fn test_invalid_curve_byte_rejected() {
    let router = build_ristretto_router();
    let result = router.login_finish(&LoginState(vec![255, 0, 1, 2]), b"finalization");
    assert!(matches!(result, Err(OpaqueError::Deserialization(_))));
}

#[test]
fn test_fake_login_start_returns_response() {
    use crate::opaque::ristretto::DefaultCipherSuite;
    use sid_opaque_ke::ClientLogin;

    let router = build_ristretto_router();
    let password = b"doesnt-matter-password";
    let fake_credential_id = b"nonexistent@sid.example.com";

    // Generate a real client login request
    let mut rng = UnwrapErr(SysRng);
    let client_login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let client_request = client_login_start.message.serialize().to_vec();

    // Fake login should produce a response (not error)
    let response = router
        .fake_login_start(&client_request, fake_credential_id)
        .unwrap();
    assert!(!response.is_empty());

    // Response should be deserializable as a CredentialResponse
    let parsed = sid_opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&response);
    assert!(parsed.is_ok());
}

#[test]
fn test_fake_login_client_cannot_finish() {
    use crate::opaque::ristretto::DefaultCipherSuite;
    use sid_opaque_ke::{ClientLogin, ClientLoginFinishParameters};

    let router = build_ristretto_router();
    let password = b"any-password";
    let fake_credential_id = b"nonexistent@sid.example.com";

    let mut rng = UnwrapErr(SysRng);
    let client_login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let client_request = client_login_start.message.serialize().to_vec();

    let response = router
        .fake_login_start(&client_request, fake_credential_id)
        .unwrap();

    // Client should fail to finish login with fake response
    let server_msg =
        sid_opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&response).unwrap();
    let result = client_login_start.state.finish(
        &mut rng,
        password,
        server_msg,
        ClientLoginFinishParameters::default(),
    );
    assert!(result.is_err());
}
