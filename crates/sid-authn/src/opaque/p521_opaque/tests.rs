use super::*;

fn provider() -> P521Opaque {
    P521Opaque::new()
}

#[test]
fn test_metadata() {
    let p = provider();
    assert_eq!(p.curve_id(), CurveId::P521);
    assert_eq!(p.security_bits(), 256);
    assert!(!p.is_fips());
    assert_eq!(p.ksf_id(), "pbkdf2-hmac-sha512");
}

#[test]
fn test_create_setup() {
    let p = provider();
    let setup = p.create_setup(None).unwrap();
    assert!(!setup.0.is_empty());
}

#[test]
fn test_setup_roundtrip() {
    let p = provider();
    let setup1 = p.create_setup(None).unwrap();
    let setup2 = p.setup_from_bytes(&setup1.0).unwrap();
    assert_eq!(setup1.0, setup2.0);
}

#[test]
fn test_setup_from_invalid_bytes() {
    let p = provider();
    assert!(p.setup_from_bytes(b"garbage").is_err());
}

#[test]
fn test_full_registration_login_flow() {
    use sid_opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters,
    };

    let p = provider();
    let setup = p.create_setup(None).unwrap();
    let credential_id = b"alice@sid.example.com";
    let password = b"correct-horse-battery-staple";

    // --- Registration ---
    let mut rng = UnwrapErr(SysRng);
    let client_reg_start =
        ClientRegistration::<P521CipherSuite>::start(&mut rng, password).unwrap();
    let client_reg_request = client_reg_start.message.serialize().to_vec();

    let (server_reg_response, _state) = p
        .registration_start(&setup, &client_reg_request, credential_id)
        .unwrap();

    let server_reg_msg =
        sid_opaque_ke::RegistrationResponse::<P521CipherSuite>::deserialize(&server_reg_response)
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

    let stored = p.registration_finish(&upload_bytes).unwrap();
    assert_eq!(stored.curve, CurveId::P521);
    assert!(!stored.data.is_empty());

    // --- Login ---
    let client_login_start = ClientLogin::<P521CipherSuite>::start(&mut rng, password).unwrap();
    let client_login_request = client_login_start.message.serialize().to_vec();

    let (server_login_response, login_state) = p
        .login_start(&setup, &stored, &client_login_request, credential_id, &[])
        .unwrap();

    assert_eq!(login_state.0[0], CurveId::P521 as u8);

    let server_login_msg =
        sid_opaque_ke::CredentialResponse::<P521CipherSuite>::deserialize(&server_login_response)
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

    let session_key = p
        .login_finish(&login_state, &finalization_bytes, &[])
        .unwrap();
    assert!(!session_key.expose_secret().is_empty());
    assert_eq!(
        session_key.expose_secret(),
        &client_login_finish.session_key[..]
    );
}

#[test]
fn test_curve_mismatch_rejected() {
    let p = provider();
    let setup = p.create_setup(None).unwrap();
    let wrong_curve = StoredCredential {
        curve: CurveId::Ristretto255,
        data: vec![0; 64],
    };
    let result = p.login_start(&setup, &wrong_curve, b"request", b"id", &[]);
    assert!(matches!(result, Err(OpaqueError::CurveMismatch { .. })));
}

#[test]
fn test_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<P521Opaque>();
}

#[test]
fn test_object_safety() {
    let _: Box<dyn OpaqueOperations> = Box::new(P521Opaque::new());
}
