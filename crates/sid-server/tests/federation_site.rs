// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's enrollment as a site through FederationSiteService,
//! over a real store and certificates a development platform really issues:
//! an administrator prepares the request, holds the certificate, reads the
//! site and gets its signed statement, and each refusal is one the
//! administrator can tell apart.

mod common;

use std::sync::Arc;
use std::time::SystemTime;

use common::{issue_admin_token, issue_token, test_jwt, test_key_manager, test_revocation};
use sid::federation_site::FederationSite;
use sid_core::models::{ProfileId, StatusPolicy};
use sid_fed::recipient::{ClassicalVerdict, Recipient};
use sid_fed::test_support::{enroll, platform_cas};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::federation_site_service_server::FederationSiteService;
use sid_proto::sid::v1::{
    GetFederationSiteRequest, HoldSiteCertificateRequest, PrepareSiteEnrollmentRequest,
    SignSiteAdmissionRequest,
};
use sid_server::grpc::federation_site_service::FederationSiteServiceImpl;
use tonic::{Code, Request};
use uuid::Uuid;

/// An installation with its organization and issuer, holding the platform
/// set, and its site service.
struct Installed {
    svc: FederationSiteServiceImpl,
    organization: Uuid,
}

async fn installed() -> Installed {
    let storage: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    );
    let keys = test_key_manager();
    let organization = sid_authn::instance_org::ensure(storage.as_ref(), "b.sid.example.com")
        .await
        .unwrap();
    sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        keys.as_ref(),
        &url::Url::parse("https://b.sid.example.com").unwrap(),
        organization.id,
    )
    .await
    .unwrap();
    let recipient = Arc::new(Recipient::new(storage.clone(), ClassicalVerdict));
    recipient
        .record_platform_cas(&platform_cas(1, &[]))
        .await
        .unwrap();
    Installed {
        svc: FederationSiteServiceImpl::new(
            Arc::new(FederationSite::new(
                storage,
                keys,
                recipient,
                organization.id,
            )),
            test_jwt(),
            test_revocation(),
        ),
        organization: organization.id.into_uuid(),
    }
}

fn from<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn admin() -> String {
    issue_admin_token(&test_jwt(), ProfileId::generate())
}

fn site_id() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0c0c)
}

// The whole path an administrator walks: the request names the key and the
// address; before a certificate is held the installation is no site and
// signs nothing; the platform's certificate is held and read back as the
// site; and the statement it then signs is accepted by an installation
// that holds only the platform set. Bug prevented: a service whose answers
// cannot be carried to the platform and back, or that signs before it is
// enrolled.
#[tokio::test]
async fn an_administrator_enrolls_the_site_and_gets_its_statement() {
    let i = installed().await;
    let token = admin();
    let prepared = i
        .svc
        .prepare_site_enrollment(from(PrepareSiteEnrollmentRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        sid_fed::participant::key_of_record(&prepared.key_record),
        Some(prepared.public_key.clone())
    );
    let [mount] = prepared.mounts.as_slice() else {
        panic!("one address: {:?}", prepared.mounts);
    };
    assert!(mount.starts_with("https://b.sid.example.com/i/"), "{mount}");

    let state = i
        .svc
        .get_federation_site(from(GetFederationSiteRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(state.site, None);
    let early = i
        .svc
        .sign_site_admission(from(
            SignSiteAdmissionRequest {
                mount: mount.clone(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(early.code(), Code::FailedPrecondition);

    let certificate = enroll(i.organization, site_id(), &prepared.public_key, &[mount]);
    let held = i
        .svc
        .hold_site_certificate(from(
            HoldSiteCertificateRequest {
                certificate,
                chain: vec![],
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(held.site, site_id().to_string());
    assert_eq!(held.mounts, prepared.mounts);
    assert_eq!(
        held.organization.as_ref().map(|id| id.value.clone()),
        Some(i.organization.as_bytes().to_vec())
    );
    let state = i
        .svc
        .get_federation_site(from(GetFederationSiteRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(state.site, Some(held));

    let statement = i
        .svc
        .sign_site_admission(from(
            SignSiteAdmissionRequest {
                mount: mount.clone(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner()
        .statement;
    let elsewhere: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let reader = Recipient::new(elsewhere, ClassicalVerdict);
    reader
        .record_platform_cas(&platform_cas(1, &[]))
        .await
        .unwrap();
    let read = reader
        .accept_admission(&statement, &StatusPolicy::default(), SystemTime::now())
        .await
        .unwrap();
    assert_eq!(read.admission.recipient_org, i.organization);
    assert_eq!(read.admission.mount.as_str(), mount);
    assert!(!read.admission.allow_foreign_corporate_profiles);
}

// Each refusal is told apart: a caller who is not an administrator is
// denied before anything is made; a certificate that is not this site's is
// a precondition the administrator can act on; an address that is not a
// mount, or not this site's, names the field. Bug prevented: a user making
// the installation's key or reading its site, or a wrong certificate
// reported as a server fault.
#[tokio::test]
async fn refusals_are_told_apart() {
    let i = installed().await;
    let profile = common::test_profile();
    let user = issue_token(&test_jwt(), &profile, &[]);
    let denied = i
        .svc
        .prepare_site_enrollment(from(PrepareSiteEnrollmentRequest {}, &user))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    let denied = i
        .svc
        .get_federation_site(from(GetFederationSiteRequest {}, &user))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    let anonymous = i
        .svc
        .prepare_site_enrollment(Request::new(PrepareSiteEnrollmentRequest {}))
        .await
        .unwrap_err();
    assert_eq!(anonymous.code(), Code::Unauthenticated);

    let token = admin();
    let prepared = i
        .svc
        .prepare_site_enrollment(from(PrepareSiteEnrollmentRequest {}, &token))
        .await
        .unwrap()
        .into_inner();
    let mount = prepared.mounts[0].as_str();
    let hold = async |certificate: Vec<u8>| {
        i.svc
            .hold_site_certificate(from(
                HoldSiteCertificateRequest {
                    certificate,
                    chain: vec![],
                },
                &token,
            ))
            .await
    };
    let another_organization = enroll(Uuid::now_v7(), site_id(), &prepared.public_key, &[mount]);
    for wrong in [vec![0x30, 0x00], another_organization] {
        let refused = hold(wrong).await.unwrap_err();
        assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
        assert_eq!(
            common::error_reason(&refused).as_deref(),
            Some("INVALID_STATE")
        );
    }
    let elsewhere = enroll(
        i.organization,
        site_id(),
        &prepared.public_key,
        &[mount, "https://c.sid.example.com"],
    );
    assert_eq!(
        hold(elsewhere).await.unwrap_err().code(),
        Code::InvalidArgument
    );

    hold(enroll(
        i.organization,
        site_id(),
        &prepared.public_key,
        &[mount],
    ))
    .await
    .unwrap();
    for (address, code) in [
        ("b.sid.example.com", Code::InvalidArgument),
        ("https://b.sid.example.com/?x=1", Code::InvalidArgument),
        ("https://b.sid.example.com/other", Code::InvalidArgument),
    ] {
        let refused = i
            .svc
            .sign_site_admission(from(
                SignSiteAdmissionRequest {
                    mount: address.into(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), code, "{address}");
    }
}
