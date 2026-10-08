// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of UpstreamService: configuring upstream identity providers
//! is instance administration, while the login screen's provider list and the
//! upstream sign-in flow stay open to a user who is not signed in yet.
//! Without this, anyone could register an identity provider of their own and
//! sign in as users it vouches for.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token};
use sid_core::models::{Profile, ProfileId};
use sid_proto::sid::v1::upstream_service_server::UpstreamService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};
use uuid::Uuid;

/// `msg` with `token` as its bearer, or without credentials.
fn req<T>(msg: T, token: Option<&str>) -> Request<T> {
    let mut req = Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    req
}

fn new_provider() -> CreateUpstreamProviderRequest {
    CreateUpstreamProviderRequest {
        name: "rogue".to_string(),
        protocol: UpstreamProtocol::Oidc.into(),
        client_id: "rogue-client".to_string(),
        client_secret: "rogue-secret".to_string(),
        discovery_url: "https://idp.attacker.example.com".to_string(),
        ..Default::default()
    }
}

/// The status code each of the five provider administration RPCs answers for
/// `token`; `None` when the call succeeds.
async fn admin_codes(svc: &TestServices, token: Option<&str>) -> Vec<Option<Code>> {
    let u = &svc.upstream;
    let id = Uuid::now_v7().to_string();
    vec![
        u.create_upstream_provider(req(new_provider(), token))
            .await
            .err()
            .map(|e| e.code()),
        u.get_upstream_provider(req(
            GetUpstreamProviderRequest {
                provider_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        u.update_upstream_provider(req(
            UpdateUpstreamProviderRequest {
                provider_id: id.clone(),
                enabled: Some(true),
                ..Default::default()
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        u.delete_upstream_provider(req(
            DeleteUpstreamProviderRequest {
                provider_id: id.clone(),
            },
            token,
        ))
        .await
        .err()
        .map(|e| e.code()),
        u.list_upstream_providers(req(ListUpstreamProvidersRequest {}, token))
            .await
            .err()
            .map(|e| e.code()),
    ]
}

/// Regression:without a token no provider is configured or read.
#[tokio::test]
async fn test_provider_rpcs_require_a_token() {
    let svc = TestServices::new(MockStorage::new());
    let got = admin_codes(&svc, None).await;
    assert_eq!(got.len(), 5);
    for (i, code) in got.into_iter().enumerate() {
        assert_eq!(code, Some(Code::Unauthenticated), "rpc #{i}");
    }
    assert!(svc.mock_storage.upstream_creations().is_empty());
}

/// Regression:a signed-in user without the administrator role cannot
/// register or change an identity provider.
#[tokio::test]
async fn test_provider_rpcs_refuse_a_non_admin() {
    let user = Profile::new(Some("mallory"));
    let svc = TestServices::new(MockStorage::new().with_profile(user.clone()));
    let token = issue_token(&svc.jwt, &user, &["openid".to_string()]);
    for (i, code) in admin_codes(&svc, Some(&token))
        .await
        .into_iter()
        .enumerate()
    {
        assert_eq!(code, Some(Code::PermissionDenied), "rpc #{i}");
    }
    assert!(svc.mock_storage.upstream_creations().is_empty());
}

/// The login screen lists the enabled providers before anyone signs in.
#[tokio::test]
async fn test_enabled_providers_stay_public() {
    let svc = TestServices::new(MockStorage::new());
    svc.upstream
        .list_enabled_providers(req(ListEnabledProvidersRequest {}, None))
        .await
        .expect("public");
}

/// An administrator asking for a provider that does not exist gets
/// UPSTREAM_PROVIDER_NOT_FOUND naming it in ResourceInfo, not a generic
/// not-found text.
#[tokio::test]
async fn test_unknown_provider_is_upstream_provider_not_found() {
    use tonic_types::StatusExt;
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());
    let id = Uuid::now_v7().to_string();
    let err = svc
        .upstream
        .get_upstream_provider(req(
            GetUpstreamProviderRequest {
                provider_id: id.clone(),
            },
            Some(&token),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(
        details.error_info().unwrap().reason,
        "UPSTREAM_PROVIDER_NOT_FOUND"
    );
    assert_eq!(details.resource_info().unwrap().resource_name, id);
}

/// A provider registered by an administrator records that administrator as
/// the actor, not the system.
#[tokio::test]
async fn test_provider_creation_records_the_administrator() {
    let svc = TestServices::new(MockStorage::new());
    let admin = ProfileId::generate();
    let token = issue_admin_token(&svc.jwt, admin);
    svc.upstream
        .create_upstream_provider(req(new_provider(), Some(&token)))
        .await
        .expect("admin creates");
    let created = svc.mock_storage.upstream_creations();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].1.actor_id, admin.to_string());
}
