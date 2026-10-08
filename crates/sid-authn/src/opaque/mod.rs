// SPDX-License-Identifier: AGPL-3.0-only
//! OPAQUE password authentication (RFC 9807)
//!
//! Multi-curve OPAQUE implementations behind the [`OpaqueOperations`] trait.
//! Each provider wraps a typed `opaque_ke::CipherSuite` internally and exposes
//! curve-erased `OpaqueSetupHandle`, `StoredCredential`, `LoginState`, `SessionKey`.
//!
//! Providers:
//! - [`RistrettoOpaque`] — Ristretto255 + Argon2 (RFC 9807 standard suite)
//! - [`PallasOpaque`] — Pallas + Argon2 (CE default, native Halo2 field)
//! - [`P256Opaque`] — NIST P-256 + PBKDF2-HMAC-SHA256 (FIPS-approved curve)
//! - [`P384Opaque`] — NIST P-384 + PBKDF2-HMAC-SHA384 (FIPS 192-bit)
//! - [`P521Opaque`] — NIST P-521 + PBKDF2-HMAC-SHA512 (FIPS 256-bit)
//!
//! [`OpaqueRouter`] dispatches operations to the correct provider based on
//! the profile's stored `CurveId`; [`server_setup`] loads the server setup
//! every replica shares.

pub mod p256_opaque;
pub mod p384_opaque;
pub mod p521_opaque;
pub mod pallas;
pub mod pbkdf2_ksf;
pub mod ristretto;
pub mod router;
pub mod server_setup;

use opaque_ke::rand::{SeedableRng, rngs::StdRng};

/// Build a seeded CSPRNG from arbitrary-length seed bytes.
/// Pads or truncates to 32 bytes for `StdRng::from_seed`.
fn seeded_rng(seed: &[u8]) -> StdRng {
    let mut seed_bytes = [0u8; 32];
    let len = seed.len().min(32);
    seed_bytes[..len].copy_from_slice(&seed[..len]);
    StdRng::from_seed(seed_bytes)
}

pub use p256_opaque::P256Opaque;
pub use p384_opaque::P384Opaque;
pub use p521_opaque::P521Opaque;
pub use pallas::PallasOpaque;
pub use ristretto::RistrettoOpaque;
pub use router::OpaqueRouter;

pub use ristretto::DefaultCipherSuite;
