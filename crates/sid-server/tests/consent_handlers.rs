// SPDX-License-Identifier: AGPL-3.0-only
//! Consent gRPC handler integration tests.
//!
//! Tests AccountService consent RPCs (ListConsents, GetConsentDetail,
//! UpdateClaimConsent, DisconnectSite) via handler-level calls (MockStorage +
//! real JWT); storage is covered by the storage conformance suite.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_client, test_profile};
use sid_core::models::AuditEntry;
use sid_core::models::consent::{ClaimType, ConsentRecord};
use sid_core::models::principal::{Principal, PrincipalId, PrincipalType};
use sid_proto::sid::v1::account::account_service_server::AccountService;
use sid_proto::sid::v1::account::*;
use tonic::Request;
use tonic_types::StatusExt;

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

// ═══════════════════════════════════════════════════════════════════
// Handler-level tests (MockStorage + real JWT)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_consents_empty() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(ListConsentsRequest {}, &token);

    let resp = svc.account.list_consents(req).await.unwrap();
    assert!(resp.into_inner().consents.is_empty());
}

#[tokio::test]
async fn test_list_consents_with_data() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Create a consent record.
    let mut consent = ConsentRecord::new(profile.id, "test-app-1");
    consent.grant_claim("email", ClaimType::Data);
    consent.grant_claim("avatar", ClaimType::Attestation);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(ListConsentsRequest {}, &token);

    let resp = svc.account.list_consents(req).await.unwrap();
    let consents = resp.into_inner().consents;
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0].site_id, "test-app-1");
    assert_eq!(consents[0].status, ConsentStatus::Active as i32);
    // Without OAuth2Client in storage, site_name falls back to client_id.
    assert_eq!(consents[0].site_name, "test-app-1");
}

#[tokio::test]
async fn test_list_consents_resolves_site_name() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Register OAuth2Client with a display name and logo.
    let mut client = test_client();
    client.client_id = "named-app".to_string();
    client.client_name = "My Cool App".to_string();
    client.logo_uri = Some("https://app.sid.example.com/logo.png".to_string());
    common::store_client(&*svc.storage, &client).await.unwrap();

    // Create consent for that client.
    let mut consent = ConsentRecord::new(profile.id, "named-app");
    consent.grant_claim("email", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(ListConsentsRequest {}, &token);

    let resp = svc.account.list_consents(req).await.unwrap();
    let consents = resp.into_inner().consents;
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0].site_id, "named-app");
    assert_eq!(
        consents[0].site_name, "My Cool App",
        "site_name must resolve from OAuth2Client.client_name"
    );
    assert_eq!(
        consents[0].site_favicon.as_deref(),
        Some("https://app.sid.example.com/logo.png"),
        "site_favicon must resolve from OAuth2Client.logo_uri"
    );
}

#[tokio::test]
async fn test_get_consent_detail_resolves_site_name() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut client = test_client();
    client.client_id = "detail-named-app".to_string();
    client.client_name = "Detail App Name".to_string();
    client.logo_uri = Some("https://detail.sid.example.com/icon.svg".to_string());
    common::store_client(&*svc.storage, &client).await.unwrap();

    let mut consent = ConsentRecord::new(profile.id, "detail-named-app");
    consent.grant_claim("email", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "detail-named-app".to_string(),
        },
        &token,
    );

    let resp = svc.account.get_consent_detail(req).await.unwrap();
    let detail = resp.into_inner();
    assert_eq!(
        detail.site_info.as_ref().unwrap().site_name,
        "Detail App Name",
        "GetConsentDetail must also resolve site_name"
    );
    assert_eq!(
        detail.site_info.as_ref().unwrap().site_favicon.as_deref(),
        Some("https://detail.sid.example.com/icon.svg"),
        "GetConsentDetail must also resolve site_favicon from logo_uri"
    );
}

#[tokio::test]
async fn test_list_consents_no_auth() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(ListConsentsRequest {});
    let err = svc.account.list_consents(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn test_get_consent_detail_success() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Add email Principal so consent detail can resolve email claim preview
    let mut email_principal = sid_core::models::Principal::new(
        profile.id,
        sid_core::models::PrincipalType::Email,
        "alice@sid.example.com".to_string(),
    );
    email_principal.is_primary = true;
    svc.storage
        .save_principal(&email_principal, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "detail-app");
    consent.grant_claim("email", ClaimType::Data);
    consent.grant_claim("phone", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "detail-app".to_string(),
        },
        &token,
    );

    let resp = svc.account.get_consent_detail(req).await.unwrap();
    let detail = resp.into_inner();
    assert!(detail.site_info.is_some());
    assert_eq!(detail.site_info.as_ref().unwrap().site_id, "detail-app");
    assert_eq!(detail.claims.len(), 2);

    // value_preview: email claim should be masked (Profile has alice@sid.example.com).
    let email_claim = detail.claims.iter().find(|c| c.claim_name == "email");
    assert!(email_claim.is_some(), "email claim should exist");
    assert_eq!(
        email_claim.unwrap().value_preview,
        "a***@sid.example.com",
        "email should be masked: first char + *** + @domain"
    );
}

#[tokio::test]
async fn test_get_consent_detail_attestation_no_preview() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "attest-app");
    consent.grant_claim("passport_verified", ClaimType::Attestation);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "attest-app".to_string(),
        },
        &token,
    );

    let resp = svc.account.get_consent_detail(req).await.unwrap();
    let detail = resp.into_inner();
    let attestation_claim = detail
        .claims
        .iter()
        .find(|c| c.claim_name == "passport_verified");
    assert!(attestation_claim.is_some());
    // Attestation claims have no value to preview.
    assert_eq!(attestation_claim.unwrap().value_preview, "");
}

#[tokio::test]
async fn test_get_consent_detail_phone_masking() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Add phone principal.
    let phone = Principal {
        id: PrincipalId::new(),
        profile_id: profile.id,
        principal_type: PrincipalType::Phone,
        value: "+380501234567".to_string(),
        verified: true,
        verified_at: None,
        verification_expires: None,
        assigned_profile_id: Some(profile.id),
        assignment_revision: 1,
        email_policy_revision: None,
        is_primary: true,
        source_field: Some("phone".into()),
        source_email_id: None,
        source_phone_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    svc.storage
        .save_principal(&phone, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "phone-app");
    consent.grant_claim("phone_number", ClaimType::Data);
    consent.grant_claim("name", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "phone-app".to_string(),
        },
        &token,
    );

    let resp = svc.account.get_consent_detail(req).await.unwrap();
    let detail = resp.into_inner();
    assert_eq!(detail.claims.len(), 2);

    // Phone should be masked.
    let phone_claim = detail
        .claims
        .iter()
        .find(|c| c.claim_name == "phone_number");
    assert!(phone_claim.is_some());
    assert_eq!(phone_claim.unwrap().value_preview, "+38***4567");

    // Name claim: profile has no display_name → empty preview.
    let name_claim = detail.claims.iter().find(|c| c.claim_name == "name");
    assert!(name_claim.is_some());
    assert_eq!(name_claim.unwrap().value_preview, "");
}

#[tokio::test]
async fn test_get_consent_detail_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "nonexistent".to_string(),
        },
        &token,
    );

    let err = svc.account.get_consent_detail(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "CONSENT_NOT_FOUND");
    assert_eq!(
        details.resource_info().unwrap().resource_name,
        "nonexistent"
    );
}

/// Services with one consent for `site`, and a token for its profile.
async fn one_consent(site: &str) -> (TestServices, String) {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, site);
    consent.grant_claim("email", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    (svc, token)
}

/// A consent list whose sites cannot be read fails instead of showing each
/// site under its raw client id as if it had been deleted.
#[tokio::test]
async fn test_list_consents_unreadable_client_is_reported() {
    let (svc, token) = one_consent("some-app").await;
    svc.mock_storage.fail_client_reads();
    let err = svc
        .account
        .list_consents(authed_request(ListConsentsRequest {}, &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

/// Consent detail fails when its site cannot be read.
#[tokio::test]
async fn test_get_consent_detail_unreadable_client_is_reported() {
    let (svc, token) = one_consent("some-app").await;
    svc.mock_storage.fail_client_reads();
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "some-app".to_string(),
        },
        &token,
    );
    let err = svc.account.get_consent_detail(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

/// Consent detail fails when the values it previews cannot be read, instead
/// of showing every claim with an empty preview.
#[tokio::test]
async fn test_get_consent_detail_unreadable_principals_is_reported() {
    let (svc, token) = one_consent("some-app").await;
    svc.mock_storage.fail_principal_reads();
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: "some-app".to_string(),
        },
        &token,
    );
    let err = svc.account.get_consent_detail(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn test_get_consent_detail_empty_site_id() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        GetConsentDetailRequest {
            site_id: String::new(),
        },
        &token,
    );

    let err = svc.account.get_consent_detail(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let details = err.get_error_details();
    assert_eq!(
        details.error_info().unwrap().reason,
        "REQUIRED_FIELD_MISSING"
    );
    assert_eq!(
        details.bad_request().unwrap().field_violations[0].field,
        "site_id"
    );
}

#[tokio::test]
async fn test_update_claim_consent_grant() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Create consent with one claim.
    let mut consent = ConsentRecord::new(profile.id, "update-app");
    consent.grant_claim("email", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Grant a new claim.
    let req = authed_request(
        UpdateClaimConsentRequest {
            site_id: "update-app".to_string(),
            claim_name: "phone".to_string(),
            grant: true,
        },
        &token,
    );
    svc.account.update_claim_consent(req).await.unwrap();

    // Verify: now 2 grants.
    let updated = svc
        .storage
        .get_consent_by_client(profile.id, "update-app")
        .await
        .unwrap()
        .unwrap();
    let active_grants: Vec<_> = updated.grants.iter().filter(|g| g.is_active()).collect();
    assert_eq!(active_grants.len(), 2);
}

/// A claim cannot be granted on a consent the user revoked: the site stays
/// cut off and nothing is shared or announced.
#[tokio::test]
async fn test_update_claim_consent_refused_on_revoked_consent() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "revoked-app");
    consent.grant_claim("email", ClaimType::Data);
    consent.as_requested().unwrap().deny();
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        UpdateClaimConsentRequest {
            site_id: "revoked-app".to_string(),
            claim_name: "phone".to_string(),
            grant: true,
        },
        &token,
    );
    let err = svc.account.update_claim_consent(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "CONSENT_STATE");
    assert_eq!(violation.subject, "revoked-app");

    let stored = svc
        .storage
        .get_consent_by_client(profile.id, "revoked-app")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !stored.grants.iter().any(|g| g.claim_name == "phone"),
        "a claim was granted on a revoked consent"
    );
}

#[tokio::test]
async fn test_update_claim_consent_revoke() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "revoke-app");
    consent.grant_claim("email", ClaimType::Data);
    consent.grant_claim("phone", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);

    // Revoke phone claim.
    let req = authed_request(
        UpdateClaimConsentRequest {
            site_id: "revoke-app".to_string(),
            claim_name: "phone".to_string(),
            grant: false,
        },
        &token,
    );
    svc.account.update_claim_consent(req).await.unwrap();

    // Verify: 1 active, 1 revoked.
    let updated = svc
        .storage
        .get_consent_by_client(profile.id, "revoke-app")
        .await
        .unwrap()
        .unwrap();
    let active: Vec<_> = updated.grants.iter().filter(|g| g.is_active()).collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].claim_name, "email");
}

#[tokio::test]
async fn test_update_claim_consent_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        UpdateClaimConsentRequest {
            site_id: "no-such-app".to_string(),
            claim_name: "email".to_string(),
            grant: true,
        },
        &token,
    );

    let err = svc.account.update_claim_consent(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_disconnect_site_success() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let mut consent = ConsentRecord::new(profile.id, "disconnect-app");
    consent.grant_claim("email", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    svc.storage
        .create_consent(&consent, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        DisconnectSiteRequest {
            site_id: "disconnect-app".to_string(),
        },
        &token,
    );

    svc.account.disconnect_site(req).await.unwrap();

    // Verify: consent deleted.
    let result = svc
        .storage
        .get_consent_by_client(profile.id, "disconnect-app")
        .await
        .unwrap();
    assert!(result.is_none(), "Consent must be deleted after disconnect");
}

#[tokio::test]
async fn test_disconnect_site_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        DisconnectSiteRequest {
            site_id: "nonexistent".to_string(),
        },
        &token,
    );

    let err = svc.account.disconnect_site(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_disconnect_site_empty_id() {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let req = authed_request(
        DisconnectSiteRequest {
            site_id: String::new(),
        },
        &token,
    );

    let err = svc.account.disconnect_site(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
