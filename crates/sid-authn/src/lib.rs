// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Authentication
//!
//! Core authentication implementations for StructuredID:
//! - OAuth 2.0 / OpenID Connect
//! - WebAuthn / Passkeys
//! - OPAQUE password authentication
//! - TOTP (RFC 6238) MFA
//! - Recovery Codes (fallback MFA)
//! - JWT token management

// Many auth modules are implemented but not yet wired into the server.
// Suppress dead_code until integration is complete.
#![allow(dead_code)]

pub mod account_api;
pub mod account_closure;
pub mod admin_claim;
pub mod anomaly;
pub mod backchannel_logout;
pub mod bearer_secret;
pub mod browser_session;
#[cfg(feature = "grpc")]
pub mod caller;
pub mod captcha;
pub mod challenge_store;
pub mod claim_mapping;
pub mod client_address;
pub mod client_assertion;
pub mod client_auth;
#[cfg(feature = "grpc")]
pub mod connector_auth;
pub mod credential_enrollment;
pub mod data_export;
pub mod dcr;
pub mod device_auth;
pub mod dpop;
pub mod email;
pub mod event_relay;
pub mod geoip;
pub mod instance_org;
pub mod instance_secret;
pub mod ip_intelligence;
pub mod issuer;
pub mod jwt;
pub mod legacy_hash;
#[cfg(feature = "grpc")]
pub mod machine_auth;
pub mod magic_link;
pub mod migration;
pub mod normalize;
pub mod oauth2;
pub mod opaque;
pub mod opaque_zkpp;
#[cfg(feature = "grpc")]
pub mod operation;
pub mod otp;
pub mod passkey_prompt;
pub mod password_history;
pub mod principal_contest;
pub(crate) mod recovery;
// recovery_grpc removed — D014-era handler; per D015 the handler
// lives in sid-saas-central/src/recovery_service.rs instead.
pub mod resource;
pub mod resource_token;
pub mod revocation_cache;
pub mod revocation_cascade;
pub mod sealed_secret;
#[cfg(feature = "grpc")]
pub mod service_auth;
pub mod session_limit;
pub mod step_up;
pub mod subject;
pub mod system_integration;
pub mod target;
#[cfg(test)]
mod test_support;
#[cfg(feature = "grpc")]
pub mod token_state;
pub(crate) mod totp;
pub mod upstream;
pub mod webauthn;
pub mod work_runner;

// TOTP seed import/migration utilities + verification + enrollment helpers
pub use totp::{
    TOTP_DIGITS, TOTP_PERIOD, TotpImportError, TotpReplayGuard, base32_decode, base32_encode,
    build_otpauth_uri, generate_current_totp, generate_secret, import_totp_enrollment, totp_step,
    validate_totp_seed, verify_imported_totp_seed, verify_totp,
};

// Recovery code generation + verification helpers
pub use recovery::{generate_recovery_codes, hash_code, normalize_code};
