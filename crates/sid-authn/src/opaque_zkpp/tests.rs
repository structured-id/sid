use super::*;
use std::collections::HashMap;

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use sid_plugin::crypto::{OpaqueOperations, StoredCredential};

use crate::opaque::{PallasOpaque, RistrettoOpaque};

/// An installation's OPAQUE router whose primary provider is `primary`, on a
/// fresh server setup, as `load_or_create` gives a new installation.
fn router_on(primary: Box<dyn OpaqueOperations>) -> OpaqueRouter {
    let setup = primary.create_setup(None).expect("setup");
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

fn router() -> OpaqueRouter {
    router_on(Box::new(PallasOpaque::new()))
}

fn unproven() -> ZkppConfig {
    ZkppConfig {
        require_proof: false,
        policy_version: 1,
    }
}

#[test]
fn test_zkpp_config_default() {
    let config = ZkppConfig::default();
    assert!(config.require_proof);
    assert_eq!(config.policy_version, 1);
}

/// A server without verifiers can only install unproven passwords.
#[test]
fn a_server_without_verifiers_supports_no_proof() {
    let server = ZkppOpaqueServer::new(&router(), vec![], unproven()).unwrap();
    assert!(!server.config().require_proof);
    assert!(!server.supports_domains(1));
}

/// A server that must require proofs but cannot verify one does not start.
#[test]
fn requiring_proofs_without_a_verifier_is_refused() {
    let config = ZkppConfig {
        require_proof: true,
        policy_version: 1,
    };
    assert!(ZkppOpaqueServer::new(&router(), vec![], config).is_err());
}

/// Proofs bind Pallas OPAQUE elements: another primary curve is refused.
#[test]
fn a_non_pallas_primary_curve_is_refused() {
    let router = router_on(Box::new(RistrettoOpaque::new()));
    assert!(ZkppOpaqueServer::new(&router, vec![], unproven()).is_err());
}

fn verifier_for(policy: sid_pake_core::types::PolicyParams) -> ZkppVerifier {
    use sid_pake_core::{circuit::CircuitShape, keygen};
    let params = keygen::generate_params(sid_pake_core::circuit::ZKPP_K);
    let shape = CircuitShape::single_domain(policy);
    let vk = keygen::generate_vk(&params, shape).unwrap();
    ZkppVerifier::new(params, vk, shape)
}

/// A verifier compiled without the selected policy's minimums must not be
/// labelled as satisfying that policy, even when no-proof setup is allowed.
#[test]
fn a_weaker_compiled_policy_is_refused() {
    let weak = sid_pake_core::types::PolicyParams {
        min_length: 0,
        min_upper: 0,
        min_lower: 0,
        min_digit: 0,
        min_symbol: 0,
    };
    assert!(ZkppOpaqueServer::new(&router(), vec![verifier_for(weak)], unproven()).is_err());
}

/// A version unknown to the selected policy authority cannot turn a known
/// key into evidence for that version merely by relabelling it.
#[test]
fn an_unknown_compiled_policy_version_is_refused() {
    let config = ZkppConfig {
        require_proof: true,
        policy_version: u32::MAX,
    };
    assert!(
        ZkppOpaqueServer::new(
            &router(),
            vec![verifier_for(sid_pake_core::types::CE_DEFAULT_POLICY)],
            config,
        )
        .is_err()
    );
}

/// Domain-count selection must have exactly one accepted verifier, rather
/// than silently choosing whichever duplicate appears first in the list.
#[test]
fn duplicate_domain_verifiers_are_refused() {
    let policy = sid_pake_core::types::CE_DEFAULT_POLICY;
    assert!(
        ZkppOpaqueServer::new(
            &router(),
            vec![verifier_for(policy), verifier_for(policy)],
            ZkppConfig::default()
        )
        .is_err()
    );
}

/// A key with the exact configured minimums remains usable in both strict
/// and policy-unverified setup modes; absence of a proof is a separate choice.
#[test]
fn matching_compiled_policy_is_accepted() {
    for require_proof in [false, true] {
        let server = ZkppOpaqueServer::new(
            &router(),
            vec![verifier_for(sid_pake_core::types::CE_DEFAULT_POLICY)],
            ZkppConfig {
                require_proof,
                policy_version: 1,
            },
        )
        .unwrap();
        assert!(server.supports_domains(1));
    }
}

/// A password installed through the ZKPP server signs in through the
/// router: both run on the installation's one server setup.
#[test]
fn an_installed_password_signs_in_through_the_router() {
    let router = router();
    let server = ZkppOpaqueServer::new(&router, vec![], unproven()).unwrap();
    let password = b"Str0ngP@ssword1";
    let id = b"login@sid.example.com";

    let mut rng = UnwrapErr(SysRng);
    let client = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let response = server
        .opaque_start(&client.message.serialize(), id)
        .unwrap();
    let upload = client
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::deserialize(&response).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = StoredCredential {
        curve: CurveId::Pallas,
        data: server.opaque_finish(&upload.message.serialize()).unwrap(),
    };

    let login = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let (response, state) = router
        .login_start(&stored, &login.message.serialize(), id, &[])
        .unwrap();
    let finished = login
        .state
        .finish(
            &mut rng,
            password,
            CredentialResponse::deserialize(&response).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .expect("the client recovers its envelope");
    let session = router
        .login_finish(&state, &finished.message.serialize(), &[])
        .unwrap();
    assert_eq!(session.expose_secret(), finished.session_key.as_slice());
}

/// A malformed request or upload is refused before anything else.
#[test]
fn malformed_messages_are_refused() {
    let server = ZkppOpaqueServer::new(&router(), vec![], unproven()).unwrap();
    let err = server
        .opaque_start(b"invalid", b"user@sid.example.com")
        .unwrap_err();
    assert!(format!("{err}").contains("Invalid registration request"));
    assert!(server.opaque_finish(b"invalid").is_err());
}
