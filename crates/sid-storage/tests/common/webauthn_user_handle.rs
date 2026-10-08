// SPDX-License-Identifier: AGPL-3.0-only
//! WebAuthn user handle contract, run against every backend: one handle per Profile and relying party,
//! created once and never replaced, unique among the relying party's
//! accounts, and the only way a discoverable assertion names its Profile.

use sid_core::models::{ProfileId, WebAuthnUserHandle};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

/// A relying party of this test alone, so runs sharing a database never meet.
fn rp() -> String {
    format!("{}.sid.example.com", Uuid::now_v7().simple())
}

fn handle(byte: u8) -> WebAuthnUserHandle {
    let mut bytes = *Uuid::now_v7().as_bytes();
    bytes[0] = byte;
    WebAuthnUserHandle(bytes)
}

async fn profile(backend: &dyn StorageBackend, name: &str) -> ProfileId {
    let profile = create_test_profile(name);
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile.id
}

/// The first enrollment stores its candidate; every later one, with any
/// candidate, gets that same handle back: a Profile keeps one handle for all
/// its passkeys at a relying party.
pub async fn test_user_handle_is_created_once(backend: &dyn StorageBackend) {
    let owner = profile(backend, "wa_once").await;
    let rp = rp();
    let first = handle(1);
    let stored = backend
        .ensure_webauthn_user_handle(owner, &rp, first, test_audit())
        .await
        .unwrap();
    assert_eq!(stored, first);
    let again = backend
        .ensure_webauthn_user_handle(owner, &rp, handle(2), test_audit())
        .await
        .unwrap();
    assert_eq!(again, first, "a stored handle is never replaced");
}

/// Concurrent first enrollments of one Profile agree on one stored handle.
pub async fn test_concurrent_enrollments_agree_on_one_handle(backend: &dyn StorageBackend) {
    let owner = profile(backend, "wa_race").await;
    let rp = rp();
    let (a, b) = (handle(3), handle(4));
    let (ra, rb) = tokio::join!(
        backend.ensure_webauthn_user_handle(owner, &rp, a, test_audit()),
        backend.ensure_webauthn_user_handle(owner, &rp, b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra, rb, "concurrent enrollments agree on one handle");
    assert!(ra == a || ra == b);
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&rp, ra)
            .await
            .unwrap(),
        Some(owner)
    );
    let loser = if ra == a { b } else { a };
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&rp, loser)
            .await
            .unwrap(),
        None,
        "the losing candidate names nobody"
    );
}

/// A handle names its Profile only at its own relying party; an unknown
/// handle names nobody.
pub async fn test_user_handle_resolves_only_at_its_rp(backend: &dyn StorageBackend) {
    let owner = profile(backend, "wa_rp").await;
    let (rp, other_rp) = (rp(), rp());
    let stored = backend
        .ensure_webauthn_user_handle(owner, &rp, handle(5), test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&rp, stored)
            .await
            .unwrap(),
        Some(owner)
    );
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&other_rp, stored)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&rp, handle(6))
            .await
            .unwrap(),
        None
    );

    // The same Profile has an independent handle at another relying party.
    let elsewhere = backend
        .ensure_webauthn_user_handle(owner, &other_rp, handle(7), test_audit())
        .await
        .unwrap();
    assert_ne!(elsewhere, stored);
}

/// Two Profiles cannot share a handle at one relying party: the second is
/// refused and keeps none, so one handle never names two accounts.
pub async fn test_user_handle_is_unique_per_rp(backend: &dyn StorageBackend) {
    let (first, second) = (
        profile(backend, "wa_uniq_a").await,
        profile(backend, "wa_uniq_b").await,
    );
    let rp = rp();
    let shared = handle(8);
    backend
        .ensure_webauthn_user_handle(first, &rp, shared, test_audit())
        .await
        .unwrap();
    let refused = backend
        .ensure_webauthn_user_handle(second, &rp, shared, test_audit())
        .await
        .unwrap_err();
    assert!(
        matches!(refused, sid_core::Error::Conflict(_)),
        "got {refused:?}"
    );
    assert_eq!(
        backend
            .get_profile_by_webauthn_user_handle(&rp, shared)
            .await
            .unwrap(),
        Some(first)
    );
}

/// A Profile that does not exist gets no handle.
pub async fn test_user_handle_needs_a_profile(backend: &dyn StorageBackend) {
    let missing = ProfileId::generate();
    let refused = backend
        .ensure_webauthn_user_handle(missing, &rp(), handle(9), test_audit())
        .await
        .unwrap_err();
    assert!(
        matches!(refused, sid_core::Error::NotFound(_)),
        "got {refused:?}"
    );
}
