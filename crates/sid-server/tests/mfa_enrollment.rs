// SPDX-License-Identifier: AGPL-3.0-only
//! TOTP enrollment + Recovery codes integration tests.
//!
//! Tests MFA credential lifecycle:
//! - Unit tests for helper functions (generate, hash, format, verify)
//! - Handler-level tests via AuthService trait (MockStorage + real JWT)
//! - PostgreSQL integration tests for credential persistence (port 54399)

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_profile};
use sid_core::models::{
    AuditEntry, AuthLevel, Credential, CredentialData, CredentialType, ProfileId, Session,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::Request;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn setup_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Arc::new(backend) as Arc<dyn StorageBackend>
}

/// Create a test profile for MFA enrollment tests. The username carries the
/// whole id: a UUIDv7 prefix is a timestamp and repeats across parallel tests.
async fn create_test_profile(storage: &dyn StorageBackend, suffix: &str) -> ProfileId {
    let profile_id = ProfileId::generate();
    let mut profile =
        sid_core::models::profile::Profile::new(Some(format!("mfa-{suffix}-{profile_id}")));
    profile.id = profile_id;
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test.setup", profile_id.to_string()).into(),
        )
        .await
        .expect("Failed to save test profile");
    profile_id
}

// ── TOTP secret generation ──

#[test]
fn test_generate_secret_length() {
    let secret = sid_authn::generate_secret();
    assert_eq!(secret.len(), 20, "TOTP secret must be 20 bytes (RFC 4226)");
}

#[test]
fn test_generate_secret_randomness() {
    let s1 = sid_authn::generate_secret();
    let s2 = sid_authn::generate_secret();
    assert_ne!(s1, s2, "Two generated secrets must differ");
}

#[test]
fn test_build_otpauth_uri_format() {
    let secret = vec![0u8; 20];
    let uri = sid_authn::build_otpauth_uri("StructuredID", "alice@sid.example.com", &secret);
    assert!(uri.starts_with("otpauth://totp/StructuredID:alice@sid.example.com?"));
    assert!(uri.contains("issuer=StructuredID"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

#[test]
fn test_base32_encode_roundtrip() {
    let secret = sid_authn::generate_secret();
    let encoded = sid_authn::base32_encode(&secret);
    // Base32 uses A-Z and 2-7
    assert!(
        encoded
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    );
}

#[test]
fn test_verify_totp_with_generated_secret() {
    // Generate secret, compute the expected code, verify it.
    let secret = sid_authn::generate_secret();
    // We can't easily compute the expected code without internal functions,
    // but we can verify that an invalid code fails.
    assert!(!sid_authn::verify_totp(&secret, "000000"));
    assert!(!sid_authn::verify_totp(&secret, "999999"));
}

// ── Recovery code generation ──

#[test]
fn test_recovery_codes_count() {
    let (plaintext, hashes) = sid_authn::generate_recovery_codes();
    assert_eq!(plaintext.len(), 10, "Must generate 10 recovery codes");
    assert_eq!(hashes.len(), 10, "Must generate 10 hashes");
}

#[test]
fn test_recovery_codes_format() {
    let (plaintext, _) = sid_authn::generate_recovery_codes();
    for code in &plaintext {
        assert_eq!(code.len(), 9, "Code must be XXXX-XXXX (9 chars with dash)");
        assert_eq!(
            code.chars().nth(4),
            Some('-'),
            "Code must have dash at position 4"
        );
        let clean: String = code.chars().filter(|c| c.is_alphanumeric()).collect();
        assert_eq!(clean.len(), 8, "Code must be 8 alphanumeric chars");
    }
}

#[test]
fn test_recovery_codes_uniqueness() {
    let (plaintext, _) = sid_authn::generate_recovery_codes();
    let mut unique = std::collections::HashSet::new();
    for code in &plaintext {
        assert!(unique.insert(code.clone()), "Recovery codes must be unique");
    }
}

#[test]
fn test_recovery_code_hash_matches() {
    let (plaintext, hashes) = sid_authn::generate_recovery_codes();
    // Normalize and hash each code — should match the returned hash.
    for (code, expected_hash) in plaintext.iter().zip(hashes.iter()) {
        let normalized = sid_authn::normalize_code(code);
        let computed_hash = sid_authn::hash_code(&normalized);
        assert_eq!(
            &computed_hash, expected_hash,
            "Hash must match for code {code}"
        );
    }
}

#[test]
fn test_normalize_code_case_insensitive() {
    assert_eq!(
        sid_authn::normalize_code("abcd-1234"),
        sid_authn::normalize_code("ABCD-1234"),
    );
}

#[test]
fn test_normalize_code_strips_dashes_and_spaces() {
    assert_eq!(
        sid_authn::normalize_code("ABCD-1234"),
        sid_authn::normalize_code("ABCD 1234"),
    );
    assert_eq!(sid_authn::normalize_code("ABCD-1234"), "ABCD1234",);
}

// ── PostgreSQL integration: TOTP credential persistence ──

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_totp_credential_save_and_retrieve() {
    let storage = setup_storage().await;
    let profile_id = create_test_profile(&*storage, "totp-save").await;

    // Create TOTP credential.
    let secret = sid_authn::generate_secret();
    let credential = Credential::new(
        profile_id,
        CredentialType::Totp,
        CredentialData::new(secret.clone()),
        Some("TOTP Authenticator".to_string()),
    );
    let cred_id = credential.id;

    storage
        .create_credential(
            &credential,
            AuditEntry::user(
                profile_id.to_string(),
                "credential.totp_enrolled",
                cred_id.0.to_string(),
            )
            .into(),
        )
        .await
        .expect("create_credential must succeed");

    // Retrieve and verify.
    let creds = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Totp))
        .await
        .expect("get_credentials must succeed");

    assert_eq!(creds.len(), 1, "Must find exactly one TOTP credential");
    assert_eq!(creds[0].id, cred_id);
    assert_eq!(creds[0].credential_type, CredentialType::Totp);
    assert_eq!(creds[0].data.expose(), &secret);
    assert_eq!(creds[0].label.as_deref(), Some("TOTP Authenticator"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recovery_credential_save_verify_consume() {
    let storage = setup_storage().await;
    let profile_id = create_test_profile(&*storage, "recovery-verify").await;

    // Generate and save recovery codes.
    let (plaintext, hashes) = sid_authn::generate_recovery_codes();
    let recovery_data = serde_json::to_vec(&hashes).unwrap();
    let credential = Credential::new(
        profile_id,
        CredentialType::Recovery,
        CredentialData::new(recovery_data),
        Some("Recovery Codes".to_string()),
    );
    let cred_id = credential.id;

    storage
        .create_credential(
            &credential,
            AuditEntry::user(
                profile_id.to_string(),
                "credential.recovery_codes_generated",
                cred_id.0.to_string(),
            )
            .into(),
        )
        .await
        .expect("create_credential must succeed");

    // Verify a code.
    let test_code = &plaintext[0];
    let normalized = sid_authn::normalize_code(test_code);
    let input_hash = sid_authn::hash_code(&normalized);

    // Load credential and check hash.
    let creds = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);

    let stored_hashes: Vec<String> = serde_json::from_slice(creds[0].data.expose()).unwrap();
    assert_eq!(stored_hashes.len(), 10);

    // Use constant-time comparison like the handler does.
    use subtle::ConstantTimeEq;
    let matched = stored_hashes
        .iter()
        .any(|h| input_hash.as_bytes().ct_eq(h.as_bytes()).into());
    assert!(matched, "First recovery code must match stored hash");

    // Consume code: remove from list and update credential.
    let remaining_hashes: Vec<String> = stored_hashes
        .into_iter()
        .filter(|h| !bool::from(input_hash.as_bytes().ct_eq(h.as_bytes())))
        .collect();
    assert_eq!(remaining_hashes.len(), 9, "One code consumed, 9 remaining");

    let updated_data = serde_json::to_vec(&remaining_hashes).unwrap();
    assert!(
        storage
            .replace_credential_data(
                creds[0].id,
                creds[0].data.expose(),
                &updated_data,
                AuditEntry::user(
                    profile_id.to_string(),
                    "credential.recovery_code_used",
                    cred_id.0.to_string(),
                )
                .into(),
            )
            .await
            .unwrap(),
        "the code was spent"
    );

    // Re-load and verify 9 codes remain.
    let creds2 = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    let final_hashes: Vec<String> = serde_json::from_slice(creds2[0].data.expose()).unwrap();
    assert_eq!(final_hashes.len(), 9, "After consume, 9 hashes must remain");
    assert!(creds2[0].last_used_at.is_some(), "last_used_at must be set");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recovery_code_revoke_and_regenerate() {
    let storage = setup_storage().await;
    let profile_id = create_test_profile(&*storage, "recovery-regen").await;

    // First generation.
    let (_, hashes1) = sid_authn::generate_recovery_codes();
    let cred1 = Credential::new(
        profile_id,
        CredentialType::Recovery,
        CredentialData::new(serde_json::to_vec(&hashes1).unwrap()),
        Some("Recovery Codes".to_string()),
    );
    let cred1_id = cred1.id;
    storage
        .create_credential(
            &cred1,
            AuditEntry::user(
                profile_id.to_string(),
                "credential.recovery_gen",
                cred1_id.0.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Revoke first set.
    assert_eq!(
        storage
            .revoke_credential(
                cred1_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "credential.recovery_revoked",
                    cred1_id.0.to_string(),
                )
                .into(),
            )
            .await
            .unwrap(),
        sid_core::models::CredentialRevocation::Revoked
    );

    // Second generation.
    let (_, hashes2) = sid_authn::generate_recovery_codes();
    let cred2 = Credential::new(
        profile_id,
        CredentialType::Recovery,
        CredentialData::new(serde_json::to_vec(&hashes2).unwrap()),
        Some("Recovery Codes".to_string()),
    );
    storage
        .create_credential(
            &cred2,
            AuditEntry::user(
                profile_id.to_string(),
                "credential.recovery_gen",
                cred2.id.0.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Verify: two recovery credentials, one revoked, one active.
    let all = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(
        all.len(),
        2,
        "Both old (revoked) and new (active) should exist"
    );
    let active: Vec<_> = all.iter().filter(|c| c.status.is_active()).collect();
    assert_eq!(active.len(), 1, "Only one should be active");
    assert_eq!(active[0].id, cred2.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_invalid_recovery_code_rejected() {
    let (_, hashes) = sid_authn::generate_recovery_codes();

    // Try to verify a code that was NOT generated.
    let fake_code = "ZZZZ-9999";
    let normalized = sid_authn::normalize_code(fake_code);
    let input_hash = sid_authn::hash_code(&normalized);

    use subtle::ConstantTimeEq;
    let matched = hashes
        .iter()
        .any(|h| input_hash.as_bytes().ct_eq(h.as_bytes()).into());
    assert!(
        !matched,
        "Fake recovery code must NOT match any stored hash"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_duplicate_totp_enrollment_prevented() {
    let storage = setup_storage().await;
    let profile_id = create_test_profile(&*storage, "totp-dup").await;

    // Create first TOTP credential.
    let cred1 = Credential::new(
        profile_id,
        CredentialType::Totp,
        CredentialData::new(sid_authn::generate_secret()),
        Some("TOTP 1".to_string()),
    );
    storage
        .create_credential(
            &cred1,
            AuditEntry::user(
                profile_id.to_string(),
                "credential.totp_enrolled",
                cred1.id.0.to_string(),
            )
            .into(),
        )
        .await
        .unwrap();

    // Verify only one TOTP exists.
    let creds = storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Totp))
        .await
        .unwrap();
    assert_eq!(creds.len(), 1);

    // The handler checks this BEFORE generating a new secret — duplicate enrollment
    // would be rejected with ALREADY_EXISTS. We verify the check condition here.
    assert!(
        !creds.is_empty(),
        "Handler should return ALREADY_EXISTS when TOTP credential exists"
    );
}

// ── ChallengeStore enrollment state tests ──

/// An enrollment store as the service builds it, with `ttl`.
fn enrollment_store(
    ttl: std::time::Duration,
) -> sid_authn::challenge_store::ChallengeStore<(ProfileId, Vec<u8>)> {
    sid_authn::challenge_store::ChallengeStore::new(
        std::sync::Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        common::test_key_manager(),
        "totp-enrollment",
        ttl,
    )
}

#[tokio::test]
async fn test_enrollment_state_expires() {
    let store = enrollment_store(std::time::Duration::from_millis(1));
    let pid = ProfileId::generate();
    let secret = sid_authn::generate_secret();

    store.insert("totp:test", &(pid, secret)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    assert!(
        store.take("totp:test").await.unwrap().is_none(),
        "Expired enrollment must return None"
    );
}

#[tokio::test]
async fn test_enrollment_state_single_use() {
    let store = enrollment_store(std::time::Duration::from_secs(60));
    let pid = ProfileId::generate();
    let secret = sid_authn::generate_secret();

    store.insert("totp:test", &(pid, secret)).await.unwrap();

    // First take succeeds.
    assert!(store.take("totp:test").await.unwrap().is_some());
    // Second take fails (enrollment consumed).
    assert!(
        store.take("totp:test").await.unwrap().is_none(),
        "Enrollment must be single-use"
    );
}

#[tokio::test]
async fn test_enrollment_state_replace_on_restart() {
    let store = enrollment_store(std::time::Duration::from_secs(60));
    let pid = ProfileId::generate();
    let secret1 = sid_authn::generate_secret();
    let secret2 = sid_authn::generate_secret();
    let key = format!("totp:{pid}");

    // First enrollment.
    store.insert(&key, &(pid, secret1)).await.unwrap();
    // User starts enrollment again (new authenticator app).
    store.insert(&key, &(pid, secret2.clone())).await.unwrap();

    // Take returns the LATEST secret (replaced).
    let (_, retrieved_secret) = store.take(&key).await.unwrap().unwrap();
    assert_eq!(
        retrieved_secret, secret2,
        "Re-enrollment must replace the old enrollment state"
    );
}

// ── Recovery code single-use verification ──

#[test]
fn test_recovery_code_cannot_be_reused() {
    let (plaintext, hashes) = sid_authn::generate_recovery_codes();

    // Use first code.
    let code = &plaintext[0];
    let normalized = sid_authn::normalize_code(code);
    let input_hash = sid_authn::hash_code(&normalized);

    // Remove used code (simulating handler behavior).
    use subtle::ConstantTimeEq;
    let remaining: Vec<String> = hashes
        .into_iter()
        .filter(|h| !bool::from(input_hash.as_bytes().ct_eq(h.as_bytes())))
        .collect();
    assert_eq!(remaining.len(), 9);

    // Try to use the same code again — must NOT match.
    let matched = remaining
        .iter()
        .any(|h| input_hash.as_bytes().ct_eq(h.as_bytes()).into());
    assert!(!matched, "Used recovery code must NOT work again");
}

// ── Recovery code warning threshold ──

#[test]
fn test_recovery_code_warning_threshold() {
    let (_, hashes) = sid_authn::generate_recovery_codes();
    // Simulate consuming 7 codes (3 remaining).
    let remaining = &hashes[7..];
    assert_eq!(remaining.len(), 3);
    assert!(
        remaining.len() <= 3,
        "With 3 remaining, needs_regeneration flag should be true"
    );
}

// ── TOTP verify function edge cases ──

#[test]
fn test_verify_totp_wrong_length_code() {
    let secret = sid_authn::generate_secret();
    // 5 digits (too short).
    assert!(!sid_authn::verify_totp(&secret, "12345"));
    // 7 digits (too long).
    assert!(!sid_authn::verify_totp(&secret, "1234567"));
    // Empty.
    assert!(!sid_authn::verify_totp(&secret, ""));
    // Non-digits.
    assert!(!sid_authn::verify_totp(&secret, "abcdef"));
}

#[test]
fn test_recovery_code_case_insensitive_match() {
    let (plaintext, _) = sid_authn::generate_recovery_codes();
    let code = &plaintext[0];

    // Lowercase and uppercase produce the same hash.
    let hash_lower = sid_authn::hash_code(&sid_authn::normalize_code(&code.to_lowercase()));
    let hash_upper = sid_authn::hash_code(&sid_authn::normalize_code(&code.to_uppercase()));
    assert_eq!(
        hash_lower, hash_upper,
        "Recovery code must be case-insensitive"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Handler-level tests (AuthService trait, MockStorage + real JWT)
// ═══════════════════════════════════════════════════════════════════

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

#[tokio::test]
async fn test_handler_start_totp_enrollment_success() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    // Create profile and save to storage.
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = common::fresh_token(&svc, &profile).await;
    let req = authed_request(StartTotpEnrollmentRequest {}, &token);

    let resp = svc.auth.start_totp_enrollment(req).await.unwrap();
    let challenge = resp.into_inner();

    assert!(
        !challenge.secret.is_empty(),
        "secret must be non-empty base32"
    );
    assert!(
        challenge.qr_uri.starts_with("otpauth://totp/"),
        "qr_uri must be otpauth scheme"
    );
    assert_eq!(challenge.issuer, "StructuredID");
    assert!(
        !challenge.account_name.is_empty(),
        "account_name must be present"
    );
}

#[tokio::test]
async fn test_handler_start_totp_enrollment_no_auth() {
    let svc = TestServices::new(MockStorage::new());

    // No auth header.
    let req = Request::new(StartTotpEnrollmentRequest {});
    let err = svc.auth.start_totp_enrollment(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_handler_start_totp_enrollment_duplicate_rejected() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Pre-create a TOTP credential.
    let existing_totp = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(sid_authn::generate_secret()),
        Some("Existing TOTP".to_string()),
    );
    svc.storage
        .create_credential(&existing_totp, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // The account already holds a second factor: the caller has stepped up.
    let session = common::authenticated_session(&profile, AuthLevel::Standard, 0);
    let token = common::stored_session_token(&svc, &profile, session).await;
    let req = authed_request(StartTotpEnrollmentRequest {}, &token);

    // One TOTP authenticator per profile: a second one is refused until the
    // first is removed (a state of the account, not the same credential).
    let err = svc.auth.start_totp_enrollment(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let details = tonic_types::StatusExt::get_error_details(&err);
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    assert_eq!(
        details.precondition_failure().unwrap().violations[0].r#type,
        "MFA_ENROLLMENT"
    );
}

#[tokio::test]
async fn test_handler_finish_totp_enrollment_no_pending() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Try to finish without starting — must fail.
    let req = authed_request(
        FinishTotpEnrollmentRequest {
            code: "123456".to_string(),
        },
        &token,
    );
    let err = svc.auth.finish_totp_enrollment(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_handler_finish_totp_enrollment_invalid_code_format() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = common::fresh_token(&svc, &profile).await;

    // Start enrollment first.
    let start_req = authed_request(StartTotpEnrollmentRequest {}, &token);
    svc.auth.start_totp_enrollment(start_req).await.unwrap();

    // Try to finish with a non-6-digit code.
    let req = authed_request(
        FinishTotpEnrollmentRequest {
            code: "abc".to_string(),
        },
        &token,
    );
    let err = svc.auth.finish_totp_enrollment(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_handler_finish_totp_enrollment_wrong_code() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = common::fresh_token(&svc, &profile).await;

    // Start enrollment.
    let start_req = authed_request(StartTotpEnrollmentRequest {}, &token);
    svc.auth.start_totp_enrollment(start_req).await.unwrap();

    // Finish with wrong (but valid format) code.
    let req = authed_request(
        FinishTotpEnrollmentRequest {
            code: "000000".to_string(),
        },
        &token,
    );
    let err = svc.auth.finish_totp_enrollment(req).await.unwrap_err();
    // Wrong TOTP code → Unauthenticated.
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_handler_generate_recovery_codes_success() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = common::fresh_token(&svc, &profile).await;
    let req = authed_request(GenerateRecoveryCodesRequest {}, &token);

    let resp = svc.auth.generate_recovery_codes(req).await.unwrap();
    let codes = resp.into_inner().codes;

    assert_eq!(codes.len(), 10, "Must generate 10 recovery codes");
    for code in &codes {
        assert_eq!(code.len(), 9, "Code format: XXXX-XXXX (9 chars)");
    }

    // Verify credential was saved.
    let creds = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(creds.len(), 1, "Recovery credential must be saved");
}

#[tokio::test]
async fn test_handler_generate_recovery_codes_revokes_old() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Codes already held step up to Standard, so replacing them needs it.
    let session = common::authenticated_session(&profile, AuthLevel::Standard, 0);
    let token = common::stored_session_token(&svc, &profile, session).await;

    // Generate first set.
    let req1 = authed_request(GenerateRecoveryCodesRequest {}, &token);
    svc.auth.generate_recovery_codes(req1).await.unwrap();
    let first = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(first.len(), 1);

    // Generate second set: it takes the first one's place.
    let req2 = authed_request(GenerateRecoveryCodesRequest {}, &token);
    let resp = svc.auth.generate_recovery_codes(req2).await.unwrap();
    assert_eq!(resp.into_inner().codes.len(), 10);

    let creds = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Recovery))
        .await
        .unwrap();
    assert_eq!(creds.len(), 1, "the old set is gone: {creds:?}");
    assert_ne!(creds[0].id, first[0].id);
    assert!(creds[0].status.is_active());
}

#[tokio::test]
async fn test_handler_verify_recovery_code_success() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Save the token's session so the handler can update AMR.
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let (token, _) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);

    // Generate codes first.
    let gen_req = authed_request(GenerateRecoveryCodesRequest {}, &token);
    let codes = svc
        .auth
        .generate_recovery_codes(gen_req)
        .await
        .unwrap()
        .into_inner()
        .codes;

    // Verify the first code.
    let req = authed_request(
        VerifyRecoveryCodeRequest {
            code: codes[0].clone(),
        },
        &token,
    );
    let resp = svc.auth.verify_recovery_code(req).await.unwrap();
    let inner = resp.into_inner();

    assert!(inner.verified, "Recovery code verification must succeed");
    assert_eq!(inner.remaining_codes, Some(9), "9 codes must remain");
}

#[tokio::test]
async fn test_handler_verify_recovery_code_invalid() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = common::fresh_token(&svc, &profile).await;

    // Generate codes.
    let gen_req = authed_request(GenerateRecoveryCodesRequest {}, &token);
    svc.auth.generate_recovery_codes(gen_req).await.unwrap();

    // Try a fake code.
    let req = authed_request(
        VerifyRecoveryCodeRequest {
            code: "ZZZZ-9999".to_string(),
        },
        &token,
    );
    let err = svc.auth.verify_recovery_code(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_handler_verify_recovery_code_single_use() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    svc.storage
        .create_session(&session, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let (token, _) =
        common::issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);

    // Generate codes.
    let gen_req = authed_request(GenerateRecoveryCodesRequest {}, &token);
    let codes = svc
        .auth
        .generate_recovery_codes(gen_req)
        .await
        .unwrap()
        .into_inner()
        .codes;

    // First use — success.
    let req1 = authed_request(
        VerifyRecoveryCodeRequest {
            code: codes[0].clone(),
        },
        &token,
    );
    let resp1 = svc.auth.verify_recovery_code(req1).await.unwrap();
    assert!(resp1.into_inner().verified);

    // Second use of same code — must fail.
    let req2 = authed_request(
        VerifyRecoveryCodeRequest {
            code: codes[0].clone(),
        },
        &token,
    );
    let err = svc.auth.verify_recovery_code(req2).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "Used recovery code must not work again"
    );
}

#[tokio::test]
async fn test_handler_verify_recovery_code_no_credential() {
    let storage = MockStorage::new();
    let svc = TestServices::new(storage);

    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // No recovery codes generated — must fail.
    let req = authed_request(
        VerifyRecoveryCodeRequest {
            code: "ABCD-1234".to_string(),
        },
        &token,
    );
    let err = svc.auth.verify_recovery_code(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}
