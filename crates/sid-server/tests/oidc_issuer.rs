// SPDX-License-Identifier: AGPL-3.0-only
//! Issuer lookup for the protocol edge: a stored handle yields its exact
//! issuer URL and public keys, a registered resource its issuer, indicator
//! and state; anything else yields nothing to fall back on.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerService;
use sid_proto::sid::v1::{GetOidcIssuerRequest, GetProtectedResourceRequest};
use tonic::Request;
use tonic_types::StatusExt;

/// The installation's issuer answers with its stored URL and the public key
/// its signer signs with, under the same `kid`.
#[tokio::test]
async fn a_stored_handle_yields_the_issuer_and_its_keys() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let answer = svc
        .oidc_issuer
        .get_oidc_issuer(Request::new(GetOidcIssuerRequest {
            handle: svc.issuer.handle.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(answer.issuer, svc.issuer.canonical_url);
    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    let published = &signer.jwks().keys;
    assert_eq!(answer.keys.len(), published.len());
    assert_eq!(answer.keys[0].key_id, published[0].kid);
    assert_eq!(answer.keys[0].public_key.len(), 32);
}

/// An unknown or malformed handle is NOT_FOUND with the reason clients
/// switch on and the handle it was asked about; it never resolves to
/// another issuer.
#[tokio::test]
async fn an_unknown_handle_is_not_found() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    for handle in [
        sid_core::models::IssuerHandle::generate().to_string(),
        "../etc".to_string(),
        String::new(),
    ] {
        let status = svc
            .oidc_issuer
            .get_oidc_issuer(Request::new(GetOidcIssuerRequest {
                handle: handle.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound, "{handle:?}");
        let info = status.get_details_error_info().expect("ErrorInfo");
        assert_eq!(info.reason, "OIDC_ISSUER_NOT_FOUND");
        assert_eq!(info.domain, "structured.id");
        let resource = status.get_details_resource_info().expect("ResourceInfo");
        assert_eq!(resource.resource_type, "OidcIssuer");
        assert_eq!(resource.resource_name, handle);
    }
}

fn target_request(handle: &str, resource: &str) -> Request<GetProtectedResourceRequest> {
    Request::new(GetProtectedResourceRequest {
        issuer_handle: handle.to_owned(),
        resource: resource.to_owned(),
    })
}

/// A resource registered under the issuer resolves to that issuer and its
/// indicator, active while it accepts tokens; deactivated, it is reported
/// inactive so a route naming it opens nothing.
#[tokio::test]
async fn a_registered_resource_resolves_with_its_state() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let id = common::userinfo_resource(&svc).await;
    let mut resource = svc
        .storage
        .get_protected_resource(id)
        .await
        .unwrap()
        .unwrap();
    let indicator = resource.indicator.to_string();

    let answer = svc
        .oidc_issuer
        .get_protected_resource(target_request(&svc.issuer.handle.to_string(), &indicator))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(answer.issuer, svc.issuer.canonical_url);
    assert_eq!(answer.resource, indicator);
    assert!(answer.active);
    // The answer names the registered resource itself, the target of
    // permission questions about its requests.
    assert_eq!(
        sid_core::models::ResourceId::try_from(answer.id.as_ref().unwrap()).unwrap(),
        id
    );

    resource.state = sid_core::models::ResourceState::Inactive;
    assert!(
        svc.storage
            .update_protected_resource(
                &resource,
                sid_core::models::AuditEntry::system("test", "resource").into(),
            )
            .await
            .unwrap()
    );
    let answer = svc
        .oidc_issuer
        .get_protected_resource(target_request(&svc.issuer.handle.to_string(), &indicator))
        .await
        .unwrap()
        .into_inner();
    assert!(!answer.active);
}

/// An indicator no resource of the issuer holds, another spelling of a
/// registered one, or an unknown issuer handle are NOT_FOUND: the route
/// naming them has no target and is never served from a different one.
#[tokio::test]
async fn an_unregistered_target_is_not_found() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let id = common::userinfo_resource(&svc).await;
    let registered = svc
        .storage
        .get_protected_resource(id)
        .await
        .unwrap()
        .unwrap()
        .indicator
        .to_string();
    let handle = svc.issuer.handle.to_string();
    let unknown_issuer = sid_core::models::IssuerHandle::generate().to_string();
    for (handle, resource) in [
        (handle.as_str(), "https://api.example.com/unregistered"),
        (handle.as_str(), &format!("{registered}/")),
        (handle.as_str(), "not a uri"),
        (unknown_issuer.as_str(), registered.as_str()),
    ] {
        let status = svc
            .oidc_issuer
            .get_protected_resource(target_request(handle, resource))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::NotFound, "{handle} {resource}");
        let info = status.get_details_error_info().expect("ErrorInfo");
        assert_eq!(info.reason, "RESOURCE_NOT_FOUND");
        let named = status.get_details_resource_info().expect("ResourceInfo");
        assert_eq!(named.resource_type, "ProtectedResource");
        assert_eq!(named.resource_name, resource);
    }
}
