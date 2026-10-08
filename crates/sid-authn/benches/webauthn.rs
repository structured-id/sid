// SPDX-License-Identifier: AGPL-3.0-only
//! Server-side cost of passkey ceremonies: registration (start + finish) and
//! identifier-first sign-in (start + finish), over an in-memory ceremony
//! store. Only the relying party's calls are timed; the software
//! authenticator's work between them is excluded. Allocations per ceremony
//! are printed once before the timing runs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use secrecy::SecretBox;
use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;
use sid_authn::webauthn::{
    AssertionPurpose, AssertionResponse, RegistrationResponse, WebAuthnServer,
};
use sid_core::models::{Credential, CredentialType, ProfileId, WebAuthnUserHandle};
use sid_keys::{KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
use sid_plugin::cache::InMemoryCacheBackend;

/// Counts allocations so a ceremony's allocation total can be reported.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const ORIGIN: &str = "https://sid.example.com";
const RP: &str = "sid.example.com";

fn server() -> WebAuthnServer {
    let keys = Arc::new(
        SoftwareKeyManager::new(
            SecretBox::new(Box::new([3u8; 32])),
            vec![KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            Arc::new(RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );
    WebAuthnServer::new(
        RP,
        &url::Url::parse(ORIGIN).unwrap(),
        Arc::new(InMemoryCacheBackend::new()),
        keys,
    )
    .unwrap()
}

/// One registration; returns the time and allocations spent in the server.
async fn register(
    server: &WebAuthnServer,
    key: &mut SoftAuthenticator,
) -> (Duration, u64, Vec<u8>) {
    let (t0, a0) = (Instant::now(), ALLOCATIONS.load(Ordering::Relaxed));
    let start = server
        .registration_start(WebAuthnUserHandle([1; 16]), "alice", &[])
        .await
        .unwrap();
    let (mut spent, mut allocs) = (t0.elapsed(), ALLOCATIONS.load(Ordering::Relaxed) - a0);
    let response = key.register(&start.options);
    let (t1, a1) = (Instant::now(), ALLOCATIONS.load(Ordering::Relaxed));
    let parsed = RegistrationResponse::parse(&response).unwrap();
    let passkey = server.registration_finish(&parsed).await.unwrap();
    spent += t1.elapsed();
    allocs += ALLOCATIONS.load(Ordering::Relaxed) - a1;
    (spent, allocs, passkey.data)
}

/// One sign-in; returns the time and allocations spent in the server.
async fn sign_in(
    server: &WebAuthnServer,
    key: &mut SoftAuthenticator,
    passkeys: &[Credential],
) -> (Duration, u64) {
    let (t0, a0) = (Instant::now(), ALLOCATIONS.load(Ordering::Relaxed));
    let start = server
        .authentication_start(AssertionPurpose::SignIn, passkeys)
        .await
        .unwrap();
    let (mut spent, mut allocs) = (t0.elapsed(), ALLOCATIONS.load(Ordering::Relaxed) - a0);
    let response = key.assert(&start.options);
    let (t1, a1) = (Instant::now(), ALLOCATIONS.load(Ordering::Relaxed));
    let parsed = AssertionResponse::parse(&response).unwrap();
    server
        .authentication_finish(AssertionPurpose::SignIn, &parsed, passkeys)
        .await
        .unwrap();
    spent += t1.elapsed();
    allocs += ALLOCATIONS.load(Ordering::Relaxed) - a1;
    (spent, allocs)
}

fn ceremonies(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let server = server();
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    // Counter 0 keeps the stored record valid for every sign-in.
    key.behavior.counter = Some(0);
    let (_, reg_allocs, data) = runtime.block_on(register(&server, &mut key));
    let passkeys = [Credential::new(
        ProfileId::generate(),
        CredentialType::WebAuthn,
        data,
        None,
    )];
    let (_, auth_allocs) = runtime.block_on(sign_in(&server, &mut key, &passkeys));
    println!("allocations: registration {reg_allocs}, sign-in {auth_allocs}");

    c.bench_function("webauthn registration (server)", |b| {
        b.iter_custom(|iters| {
            let mut key = SoftAuthenticator::new(ORIGIN, RP);
            (0..iters)
                .map(|_| runtime.block_on(register(&server, &mut key)).0)
                .sum()
        });
    });
    c.bench_function("webauthn sign-in (server)", |b| {
        b.iter_custom(|iters| {
            (0..iters)
                .map(|_| runtime.block_on(sign_in(&server, &mut key, &passkeys)).0)
                .sum()
        });
    });
}

criterion_group!(benches, ceremonies);
criterion_main!(benches);
