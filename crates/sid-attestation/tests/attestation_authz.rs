// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of AttestationService behind its receiver: a device key is
//! registered, rotated, revoked or read by the owner of the device's Profile
//! by this service's own rule, or by a caller the issuer allows the action on
//! that device (the installation's administrator). Without this, anyone could
//! bind their own key to someone else's device. Every call carries an access
//! token for the installation's account API, and the issuer says at each
//! admission whether it is still current.

use sid_attestation::handler::AttestationServiceImpl;
use sid_core::models::{AuditEntry, Device, DeviceType, Profile};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::attestation::attestation_service_client::AttestationServiceClient;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationServiceServer;
use sid_proto::sid::v1::attestation::*;
use sid_test_issuer::{Checker, Setup, TestIssuer};
use std::sync::Arc;
use tonic::{Code, Request};

#[allow(dead_code)]
#[path = "../../../tests/support/crypto.rs"]
mod test_crypto;

const API: &str = "https://sid.example.com/api";
const ORIGIN: &str = "https://sid.example.com";
const CHECKER: &str = "sid-attestation";
const CHECKER_SECRET: &str = "attestation-checker-secret";

/// The checker's secret in a file of its own, removed with it.
struct SecretFile(std::path::PathBuf);

impl Drop for SecretFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

struct Fixture {
    issuer: TestIssuer,
    api: sid_auth::config::ReceiverConfig,
    _secret: SecretFile,
    storage: Arc<dyn StorageBackend>,
    owner: Profile,
    device: Device,
}

/// An installation whose account API this service serves, a Profile and its
/// device in the installation's store. The service's checker may also
/// inspect the account API's tokens.
async fn fixture() -> Fixture {
    test_crypto::install_tls();
    let issuer = TestIssuer::start(Setup {
        resources: vec![API.into()],
        checkers: vec![Checker {
            client_id: CHECKER.into(),
            secret: CHECKER_SECRET.into(),
            confirms_proofs: false,
        }],
    })
    .await;
    issuer.grant_inspection(CHECKER).await;
    let secret = SecretFile(
        std::env::temp_dir().join(format!("sid-attestation-checker-{}", uuid::Uuid::now_v7())),
    );
    std::fs::write(&secret.0, CHECKER_SECRET).unwrap();
    let api = issuer.receiver_config(API, ORIGIN, CHECKER, &secret.0);
    let storage = issuer.storage.clone();
    let owner = issuer.profile().await;
    let device = Device::new(owner.id, DeviceType::Mobile);
    storage
        .create_device(&device, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    Fixture {
        issuer,
        api,
        _secret: secret,
        storage,
        owner,
        device,
    }
}

/// The service behind a receiver of `api` on a loopback port.
async fn served(
    storage: Arc<dyn StorageBackend>,
    api: &sid_auth::config::ReceiverConfig,
) -> AttestationServiceClient<tonic::transport::Channel> {
    let receiver = Arc::new(
        sid_auth::receiver::Receiver::connect("sid-attestation", api)
            .await
            .unwrap(),
    );
    let routes = tonic::service::Routes::new(sid_attestation::access::guarded(
        AttestationServiceServer::new(AttestationServiceImpl::new(storage)),
        &receiver,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    AttestationServiceClient::new(
        tonic::transport::Channel::from_shared(address)
            .unwrap()
            .connect_lazy(),
    )
}

fn with_token<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// `ErrorInfo.reason` of a refusal.
fn reason(status: &tonic::Status) -> Option<String> {
    sid_infra::grpc_error::extract_error_info(status).map(|(reason, _, _)| reason)
}

fn register(device: &Device) -> RegisterDeviceKeyRequest {
    RegisterDeviceKeyRequest {
        device_id: device.id.to_string(),
        device_public_key: vec![0x04, 0x01, 0x02],
        ..Default::default()
    }
}

async fn stored(f: &Fixture) -> bool {
    f.storage
        .get_device_attestation_by_device_id(f.device.id)
        .await
        .unwrap()
        .is_some()
}

/// Every refusal of the served service, without a token and as a device
/// owner, carries ErrorInfo in the structured.id domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_every_refusal_carries_error_info() {
    use sid_serve::error_contract::{Caller, probe};
    let f = fixture().await;
    let token = f.issuer.token(&f.owner, API, None).await.token;
    let receiver = Arc::new(
        sid_auth::receiver::Receiver::connect("sid-attestation", &f.api)
            .await
            .unwrap(),
    );
    let mut services = sid_serve::Services::new();
    services
        .add(sid_attestation::access::guarded(
            AttestationServiceServer::new(AttestationServiceImpl::new(f.storage.clone())),
            &receiver,
        ))
        .await;
    let (routes, health) = services.into_parts();
    let report = probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[sid_infra::grpc_error::DOMAIN_SID],
        &[
            Caller::anonymous("anonymous"),
            Caller::bearer("owner", &token),
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

/// Every attestation method has an action, and nothing else is served.
#[test]
fn test_every_method_has_an_action() {
    use sid_attestation::access::{DEVICE_CHANGE, DEVICE_READ, PROFILE_READ, action};
    use sid_auth::receiver::Action::OwnedObject;
    let path = |m: &str| format!("/sid.v1.attestation.AttestationService/{m}");
    for (method, expected) in [
        ("GetDeviceAttestation", DEVICE_READ),
        ("RegisterDeviceKey", DEVICE_CHANGE),
        ("RotateDeviceKey", DEVICE_CHANGE),
        ("RevokeDeviceKey", DEVICE_CHANGE),
        ("ListDeviceAttestations", PROFILE_READ),
    ] {
        assert_eq!(
            action(&path(method)),
            Some(OwnedObject(expected)),
            "{method}"
        );
    }
    assert_eq!(action(&path("Anything")), None);
}

/// Regression: without a token no key is bound to the device.
#[tokio::test]
async fn test_attestation_requires_a_token() {
    let f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let err = client
        .register_device_key(Request::new(register(&f.device)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(!stored(&f).await, "nothing stored");
}

/// Regression: another user cannot bind a key to the victim's device or list
/// the victim's device keys. The victim's device answers exactly as an
/// unknown one, DEVICE_NOT_FOUND, so its existence is not disclosed.
#[tokio::test]
async fn test_attestation_refuses_a_foreign_device() {
    let f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let mallory = f.issuer.profile().await;
    let token = f.issuer.token(&mallory, API, None).await.token;
    let err = client
        .register_device_key(with_token(register(&f.device), &token))
        .await
        .expect_err("foreign device");
    let unknown = client
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
    let err = client
        .list_device_attestations(with_token(
            ListDeviceAttestationsRequest {
                profile_id: f.owner.id.to_string(),
            },
            &token,
        ))
        .await
        .expect_err("foreign profile");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(!stored(&f).await, "nothing stored");
}

/// The owner registers a key and lists its own, with no role at all: the
/// owner rule is this service's. The attestation is stored unverified, so
/// the device is not marked hardware-attested.
#[tokio::test]
async fn test_attestation_owner_registers_without_claiming_hardware() {
    let f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let token = f.issuer.token(&f.owner, API, None).await.token;
    client
        .register_device_key(with_token(register(&f.device), &token))
        .await
        .expect("owner registers");
    let listed = client
        .list_device_attestations(with_token(
            ListDeviceAttestationsRequest {
                profile_id: f.owner.id.to_string(),
            },
            &token,
        ))
        .await
        .expect("owner lists its own")
        .into_inner();
    assert_eq!(listed.attestations.len(), 1);
    let device = f.storage.get_device(f.device.id).await.unwrap().unwrap();
    assert!(
        !device.hardware_attested,
        "unverified attestation must not mark the device hardware-attested"
    );
}

/// The installation's administrator, by its current assignment, reads and
/// revokes another Profile's device key.
#[tokio::test]
async fn test_the_installation_administrator_reaches_any_device() {
    let f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let owner_token = f.issuer.token(&f.owner, API, None).await.token;
    client
        .register_device_key(with_token(register(&f.device), &owner_token))
        .await
        .unwrap();
    let admin = f.issuer.profile().await;
    f.issuer.administrator(&admin).await;
    let token = f.issuer.token(&admin, API, None).await.token;
    client
        .get_device_attestation(with_token(
            GetDeviceAttestationRequest {
                device_id: f.device.id.to_string(),
            },
            &token,
        ))
        .await
        .expect("an administrator reads it");
    client
        .list_device_attestations(with_token(
            ListDeviceAttestationsRequest {
                profile_id: f.owner.id.to_string(),
            },
            &token,
        ))
        .await
        .expect("an administrator lists them");
    client
        .revoke_device_key(with_token(
            RevokeDeviceKeyRequest {
                device_id: f.device.id.to_string(),
            },
            &token,
        ))
        .await
        .expect("an administrator revokes it");
}

/// A machine allowed every attestation action still changes no key: key
/// changes need a Profile's own sign-in. It may read.
#[tokio::test]
async fn test_a_machine_with_the_actions_changes_no_key() {
    let f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let machine = f.issuer.machine("ci-agent", "ci-agent-secret", API).await;
    let role = f
        .issuer
        .role(
            "attestation-all",
            &[
                sid_attestation::access::DEVICE_READ,
                sid_attestation::access::DEVICE_CHANGE,
                sid_attestation::access::PROFILE_READ,
            ],
        )
        .await;
    f.issuer.grant_machine(&machine, &role, API).await;
    let secret =
        SecretFile(std::env::temp_dir().join(format!("ci-agent-{}", uuid::Uuid::now_v7())));
    std::fs::write(&secret.0, "ci-agent-secret").unwrap();
    let credential = sid_infra::client_credential::ClientCredential::for_resource(
        &f.issuer.client_config("ci-agent", &secret.0),
        sid_test_issuer::INSTALLATION,
        sid_infra::deadline::issuer(
            tonic::transport::Channel::from_shared(f.issuer.upstream())
                .unwrap()
                .connect_lazy(),
        ),
        API,
    )
    .unwrap();
    let authorization = credential.authorization().await.expect("machine token");

    let mut call = Request::new(register(&f.device));
    call.metadata_mut()
        .insert("authorization", authorization.clone());
    let err = client
        .register_device_key(call)
        .await
        .expect_err("no sign-in");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(!stored(&f).await, "nothing stored");

    let mut call = Request::new(ListDeviceAttestationsRequest {
        profile_id: f.owner.id.to_string(),
    });
    call.metadata_mut().insert("authorization", authorization);
    client
        .list_device_attestations(call)
        .await
        .expect("a machine with the action reads");
}

/// An ended sign-in's token binds no key: the owner's token is refused once
/// its session ends, by a receiver started afterwards too; no cache is
/// involved, the issuer answers at each admission.
#[tokio::test]
async fn test_an_ended_session_binds_no_key() {
    let f = fixture().await;
    let issued = f.issuer.token(&f.owner, API, None).await;
    f.issuer.end(&issued.session).await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let err = client
        .register_device_key(with_token(register(&f.device), &issued.token))
        .await
        .expect_err("an ended sign-in");
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(!stored(&f).await, "nothing stored");
}

/// Without its issuer no call is admitted: refused as unavailable, nothing
/// stored.
#[tokio::test]
async fn test_without_the_issuer_nothing_is_bound() {
    let mut f = fixture().await;
    let mut client = served(f.storage.clone(), &f.api).await;
    let token = f.issuer.token(&f.owner, API, None).await.token;
    f.issuer.stop().await;
    let err = client
        .register_device_key(with_token(register(&f.device), &token))
        .await
        .expect_err("no issuer");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(!stored(&f).await, "nothing stored");
}
