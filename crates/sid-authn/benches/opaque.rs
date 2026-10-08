// SPDX-License-Identifier: AGPL-3.0-only
//! Criterion benchmarks for OPAQUE operations per curve.
//!
//! Measures registration and login latency for each supported curve:
//! - Ristretto255 (RFC 9807 standard)
//! - Pallas (CE default, Halo2-native)
//! - P-256 (NIST FIPS-approved)

use criterion::{Criterion, criterion_group, criterion_main};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, rand::rngs::OsRng,
};
use sid_authn::opaque::p256_opaque::P256CipherSuite;
use sid_authn::opaque::ristretto::DefaultCipherSuite;
use sid_authn::opaque::{OpaqueRouter, P256Opaque, PallasOpaque, RistrettoOpaque};
use sid_plugin::crypto::{CurveId, OpaqueOperations};
use std::collections::HashMap;

fn build_ristretto_router() -> OpaqueRouter {
    let primary = Box::new(RistrettoOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

fn build_pallas_router() -> OpaqueRouter {
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

fn build_p256_router() -> OpaqueRouter {
    let primary = Box::new(P256Opaque::new());
    let setup = primary.create_setup(None).unwrap();
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    OpaqueRouter::new(primary, verifiers, setup)
}

// ── Registration benchmarks ──

fn bench_registration_ristretto(c: &mut Criterion) {
    let router = build_ristretto_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    c.bench_function("registration/ristretto255", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_start =
                ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_start.message.serialize();

            let (response_bytes, _) = router
                .registration_start(&request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::RegistrationResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_start
                .state
                .finish(
                    &mut rng,
                    password,
                    server_msg,
                    ClientRegistrationFinishParameters::default(),
                )
                .unwrap();
            let upload_bytes = client_finish.message.serialize();

            router.registration_finish(&upload_bytes).unwrap()
        })
    });
}

fn bench_registration_pallas(c: &mut Criterion) {
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let router = build_pallas_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    c.bench_function("registration/pallas", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_start =
                ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_start.message.serialize();

            let (response_bytes, _) = router
                .registration_start(&request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::RegistrationResponse::<PallasCipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_start
                .state
                .finish(
                    &mut rng,
                    password,
                    server_msg,
                    ClientRegistrationFinishParameters::default(),
                )
                .unwrap();
            let upload_bytes = client_finish.message.serialize();

            router.registration_finish(&upload_bytes).unwrap()
        })
    });
}

fn bench_registration_p256(c: &mut Criterion) {
    let router = build_p256_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    c.bench_function("registration/p256", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_start =
                ClientRegistration::<P256CipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_start.message.serialize();

            let (response_bytes, _) = router
                .registration_start(&request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::RegistrationResponse::<P256CipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_start
                .state
                .finish(
                    &mut rng,
                    password,
                    server_msg,
                    ClientRegistrationFinishParameters::default(),
                )
                .unwrap();
            let upload_bytes = client_finish.message.serialize();

            router.registration_finish(&upload_bytes).unwrap()
        })
    });
}

// ── Login benchmarks ──

fn bench_login_ristretto(c: &mut Criterion) {
    let router = build_ristretto_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    // Pre-register
    let mut rng = OsRng;
    let client_reg = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
    let (resp, _) = router
        .registration_start(&client_reg.message.serialize(), credential_id)
        .unwrap();
    let server_msg =
        opaque_ke::RegistrationResponse::<DefaultCipherSuite>::deserialize(&resp).unwrap();
    let client_finish = client_reg
        .state
        .finish(
            &mut rng,
            password,
            server_msg,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = router
        .registration_finish(&client_finish.message.serialize())
        .unwrap();

    c.bench_function("login/ristretto255", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_login =
                ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_login.message.serialize();

            let (response_bytes, login_state) = router
                .login_start(&stored, &request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_login
                .state
                .finish(
                    &mut OsRng,
                    password,
                    server_msg,
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
            let finalization_bytes = client_finish.message.serialize();

            router
                .login_finish(&login_state, &finalization_bytes)
                .unwrap()
        })
    });
}

fn bench_login_pallas(c: &mut Criterion) {
    use sid_pake_core::pallas_opaque::PallasCipherSuite;

    let router = build_pallas_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    // Pre-register
    let mut rng = OsRng;
    let client_reg = ClientRegistration::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let (resp, _) = router
        .registration_start(&client_reg.message.serialize(), credential_id)
        .unwrap();
    let server_msg =
        opaque_ke::RegistrationResponse::<PallasCipherSuite>::deserialize(&resp).unwrap();
    let client_finish = client_reg
        .state
        .finish(
            &mut rng,
            password,
            server_msg,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = router
        .registration_finish(&client_finish.message.serialize())
        .unwrap();

    c.bench_function("login/pallas", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_login = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_login.message.serialize();

            let (response_bytes, login_state) = router
                .login_start(&stored, &request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::CredentialResponse::<PallasCipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_login
                .state
                .finish(
                    &mut OsRng,
                    password,
                    server_msg,
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
            let finalization_bytes = client_finish.message.serialize();

            router
                .login_finish(&login_state, &finalization_bytes)
                .unwrap()
        })
    });
}

fn bench_login_p256(c: &mut Criterion) {
    let router = build_p256_router();
    let credential_id = b"bench@sid.example.com";
    let password = b"benchmark-password-2024";

    // Pre-register
    let mut rng = OsRng;
    let client_reg = ClientRegistration::<P256CipherSuite>::start(&mut rng, password).unwrap();
    let (resp, _) = router
        .registration_start(&client_reg.message.serialize(), credential_id)
        .unwrap();
    let server_msg =
        opaque_ke::RegistrationResponse::<P256CipherSuite>::deserialize(&resp).unwrap();
    let client_finish = client_reg
        .state
        .finish(
            &mut rng,
            password,
            server_msg,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let stored = router
        .registration_finish(&client_finish.message.serialize())
        .unwrap();

    c.bench_function("login/p256", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_login = ClientLogin::<P256CipherSuite>::start(&mut rng, password).unwrap();
            let request_bytes = client_login.message.serialize();

            let (response_bytes, login_state) = router
                .login_start(&stored, &request_bytes, credential_id)
                .unwrap();

            let server_msg =
                opaque_ke::CredentialResponse::<P256CipherSuite>::deserialize(&response_bytes)
                    .unwrap();
            let client_finish = client_login
                .state
                .finish(
                    &mut OsRng,
                    password,
                    server_msg,
                    ClientLoginFinishParameters::default(),
                )
                .unwrap();
            let finalization_bytes = client_finish.message.serialize();

            router
                .login_finish(&login_state, &finalization_bytes)
                .unwrap()
        })
    });
}

// ── Setup creation benchmarks ──

fn bench_setup_creation(c: &mut Criterion) {
    c.bench_function("setup/ristretto255", |b| {
        b.iter(|| {
            let provider = RistrettoOpaque::new();
            provider.create_setup(None).unwrap()
        })
    });

    c.bench_function("setup/pallas", |b| {
        b.iter(|| {
            let provider = PallasOpaque::new();
            provider.create_setup(None).unwrap()
        })
    });

    c.bench_function("setup/p256", |b| {
        b.iter(|| {
            let provider = P256Opaque::new();
            provider.create_setup(None).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_registration_ristretto,
    bench_registration_pallas,
    bench_registration_p256,
    bench_login_ristretto,
    bench_login_pallas,
    bench_login_p256,
    bench_setup_creation,
);
criterion_main!(benches);
