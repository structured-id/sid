use super::*;

const RESOURCE: &str = "https://ops.example.com/";
const ORIGIN: &str = "https://ops.example.com";
const PATH: &str = "/sid.ops.v1.org.OrgAdminService/GetOrg";

/// The issuer serves what a receiver needs: its registry, its token
/// endpoint for the receiver's own credential and its authorization API,
/// which decides on the stored grants; once stopped, nothing is admitted.
#[tokio::test]
async fn a_receiver_is_admitted_through_the_test_issuer() {
    let mut issuer = TestIssuer::start(Setup {
        resources: vec![RESOURCE.into()],
        checkers: vec![Checker {
            client_id: "ops-receiver".into(),
            secret: "ops-receiver-secret".into(),
            confirms_proofs: false,
        }],
    })
    .await;
    let secret = std::env::temp_dir().join(format!("sid-test-issuer-{}", uuid::Uuid::now_v7()));
    std::fs::write(&secret, "ops-receiver-secret").unwrap();
    let receiver = sid_auth::receiver::Receiver::connect(
        "ops",
        &issuer.receiver_config(RESOURCE, ORIGIN, "ops-receiver", &secret, None),
    )
    .await
    .unwrap();
    let operator = issuer.profile().await;
    assert_ne!(
        issuer.profile().await.id,
        operator.id,
        "profiles are distinct"
    );
    let reader = issuer.role("org-reader", &["ops.org.read"]).await;
    issuer.grant(&operator, &reader, RESOURCE).await;
    let token = issuer.token(&operator, RESOURCE, None).await.token;
    let mut headers = tonic::codegen::http::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    let post = tonic::codegen::http::Method::POST;

    let admitted = receiver
        .admit(&post, PATH, &headers, "ops.org.read")
        .await
        .unwrap();
    assert_eq!(admitted.resource, issuer.resource(RESOURCE).id);
    let denied = receiver
        .admit(&post, PATH, &headers, "ops.org.suspend")
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // A service calling with its own client credentials token, presented
    // per call by the channel it calls through.
    let caller = issuer
        .machine("ops-caller", "ops-caller-secret", RESOURCE)
        .await;
    issuer.grant_machine(&caller, &reader, RESOURCE).await;
    let caller_secret =
        std::env::temp_dir().join(format!("sid-test-issuer-caller-{}", uuid::Uuid::now_v7()));
    std::fs::write(&caller_secret, "ops-caller-secret").unwrap();
    let credential = sid_auth::credential::ClientCredential::for_resource(
        &issuer.client_config("ops-caller", &caller_secret),
        INSTALLATION,
        tonic::transport::Channel::from_shared(issuer.upstream())
            .unwrap()
            .connect_lazy(),
        RESOURCE,
    )
    .unwrap();
    let mut machine_headers = tonic::codegen::http::HeaderMap::new();
    machine_headers.insert(
        "authorization",
        tonic::codegen::http::HeaderValue::from_bytes(
            credential.authorization().await.unwrap().as_encoded_bytes(),
        )
        .unwrap(),
    );
    receiver
        .admit(&post, PATH, &machine_headers, "ops.org.read")
        .await
        .unwrap();
    std::fs::remove_file(&caller_secret).ok();

    issuer.stop().await;
    let unavailable = receiver
        .admit(&post, PATH, &headers, "ops.org.read")
        .await
        .unwrap_err();
    assert_eq!(unavailable.code(), tonic::Code::Unavailable);
    std::fs::remove_file(&secret).ok();
}
