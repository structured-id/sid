// SPDX-License-Identifier: AGPL-3.0-only
//! Which closure modes a user can request through IdentityService in CE.
//!
//! Admin termination and regulatory-order closure are EE modes with their own
//! RPCs: a regulatory-order closure has no grace period and cannot be
//! cancelled, so a user (or whoever holds their token) could otherwise close
//! the account irreversibly at once by sending any court reference.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_profile};
use sid_core::models::{AuditEntry, ProfileStatus};
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::{ClosureMode, RequestClosureRequest};
use tonic::{Code, Request};
use tonic_types::StatusExt;

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// `mode` requested by the profile itself is FEATURE_NOT_AVAILABLE naming the
/// mode, and the profile stays active.
async fn refused_in_ce(mode: ClosureMode, feature: &str) {
    let svc = TestServices::new(MockStorage::new());
    let profile = test_profile();
    svc.storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let token = issue_token(&svc.jwt, &profile, &["openid".to_string()]);
    let err = svc
        .identity
        .request_closure(authed_request(
            RequestClosureRequest {
                mode: mode.into(),
                court_reference: Some("case-1".to_string()),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);
    let info = err.get_error_details().error_info().cloned().unwrap();
    assert_eq!(info.reason, "FEATURE_NOT_AVAILABLE");
    assert_eq!(info.metadata["feature"], feature);
    let stored = svc.storage.get_profile(profile.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ProfileStatus::Active);
}

/// Regression: a user could put their own account into a regulatory-order
/// closure (no grace period, not cancellable) with any court reference.
#[tokio::test]
async fn test_regulatory_order_is_not_a_ce_self_service_mode() {
    refused_in_ce(ClosureMode::RegulatoryOrder, "regulatory_order_closure").await;
}

/// Regression: admin termination checked for "admin" inside a role UUID, so
/// it was refused even to administrators with a permission error; it is an EE
/// mode served by its own RPC.
#[tokio::test]
async fn test_admin_termination_is_not_a_ce_self_service_mode() {
    refused_in_ce(ClosureMode::AdminTermination, "admin_termination").await;
}
