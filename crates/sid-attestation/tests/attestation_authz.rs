// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of AttestationService: a device key is registered, rotated,
//! revoked or read by the owner of the device's profile (or an administrator).
//! Without this, anyone could bind their own key to someone else's device.
//!
//! Requires sid-test-postgres on port 54399.

use sid_attestation::handler::AttestationServiceImpl;
use sid_authn::jwt::{JwtService, TokenVerifier};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{AuditEntry, Device, DeviceType, Profile, Session};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationService;
use sid_proto::sid::v1::attestation::*;
use sid_storage::PostgresBackend;
use std::sync::Arc;
use tonic::{Code, Request};

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

fn test_jwt() -> Arc<JwtService> {
    Arc::new(
        JwtService::new(
            include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
            include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
            "https://sid.example.com".to_string(),
        )
        .expect("JWT creation failed"),
    )
}

fn token_for(profile: &Profile) -> String {
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    test_jwt()
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            profile,
            &session,
            &["openid".to_string()],
            None,
            None,
        )
        .unwrap()
}

fn with_token<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

struct Fixture {
    svc: AttestationServiceImpl,
    storage: Arc<dyn StorageBackend>,
    owner: Profile,
    device: Device,
}

async fn fixture() -> Fixture {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let owner = Profile::new(Some(format!("attest-{}", uuid::Uuid::now_v7().simple())));
    storage
        .create_profile(&owner, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let device = Device::new(owner.id, DeviceType::Mobile);
    storage
        .create_device(&device, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    // The service verifies with the public key alone, as in production.
    let verifier = TokenVerifier::new(
        include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
        "https://sid.example.com".to_string(),
    )
    .expect("token verifier");
    let svc = AttestationServiceImpl::new(
        storage.clone(),
        Arc::new(verifier),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    );
    Fixture {
        svc,
        storage,
        owner,
        device,
    }
}

/// `ErrorInfo.reason` of a refusal.
fn reason(status: &tonic::Status) -> Option<String> {
    sid_core::grpc_error::extract_error_info(status).map(|(reason, _, _)| reason)
}

fn register(device: &Device) -> RegisterDeviceKeyRequest {
    RegisterDeviceKeyRequest {
        device_id: device.id.to_string(),
        device_public_key: vec![0x04, 0x01, 0x02],
        ..Default::default()
    }
}

/// Every refusal of the service, without a token and as a device owner,
/// carries ErrorInfo in the structured.id domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_every_refusal_carries_error_info() {
    use sid_proto::sid::v1::attestation::attestation_service_server::AttestationServiceServer;
    use sid_serve::error_contract::{Caller, probe};
    let f = fixture().await;
    let token = token_for(&f.owner);
    let mut services = sid_serve::Services::new();
    services.add(AttestationServiceServer::new(f.svc)).await;
    let (routes, health) = services.into_parts();
    let report = probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[sid_core::grpc_error::DOMAIN_SID],
        &[
            Caller {
                name: "anonymous",
                token: None,
            },
            Caller {
                name: "owner",
                token: Some(&token),
            },
        ],
    )
    .await;
    assert!(report.methods >= 4, "only {} methods", report.methods);
    // Every anonymous call is refused at least.
    assert!(report.refusals >= report.methods, "{report:?}");
    assert!(
        report.violations.is_empty(),
        "{}",
        report.violations.join("\n")
    );
}

/// Regression:without a token no key is bound to the device.
#[tokio::test]
async fn test_attestation_requires_a_token() {
    let f = fixture().await;
    let err = f
        .svc
        .register_device_key(Request::new(register(&f.device)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(
        f.storage
            .get_device_attestation_by_device_id(f.device.id)
            .await
            .unwrap()
            .is_none(),
        "nothing stored"
    );
}

/// Regression:another user cannot bind a key to the victim's device
/// or list the victim's device keys. The victim's device answers exactly as
/// an unknown one, DEVICE_NOT_FOUND, so its existence is not disclosed.
#[tokio::test]
async fn test_attestation_refuses_a_foreign_device() {
    let f = fixture().await;
    let token = token_for(&Profile::new(Some("mallory")));
    let err = f
        .svc
        .register_device_key(with_token(register(&f.device), &token))
        .await
        .expect_err("foreign device");
    let unknown = f
        .svc
        .register_device_key(with_token(
            register(&Device::new(f.owner.id, DeviceType::Mobile)),
            &token,
        ))
        .await
        .expect_err("unknown device");
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(reason(&err).as_deref(), Some("DEVICE_NOT_FOUND"));
    assert_eq!(
        (err.code(), err.message(), reason(&err)),
        (unknown.code(), unknown.message(), reason(&unknown)),
        "a foreign device answers as an unknown one"
    );
    let err = f
        .svc
        .list_device_attestations(with_token(
            ListDeviceAttestationsRequest {
                profile_id: f.owner.id.to_string(),
            },
            &token,
        ))
        .await
        .expect_err("foreign profile");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(
        f.storage
            .get_device_attestation_by_device_id(f.device.id)
            .await
            .unwrap()
            .is_none(),
        "nothing stored"
    );
}

/// The owner registers a key. The attestation is stored unverified, so the
/// device is not marked hardware-attested.
#[tokio::test]
async fn test_attestation_owner_registers_without_claiming_hardware() {
    let f = fixture().await;
    let token = token_for(&f.owner);
    f.svc
        .register_device_key(with_token(register(&f.device), &token))
        .await
        .expect("owner registers");
    let device = f.storage.get_device(f.device.id).await.unwrap().unwrap();
    assert!(
        !device.hardware_attested,
        "unverified attestation must not mark the device hardware-attested"
    );
}
