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
    let credential = sid_infra::client_credential::ClientCredential::for_resource(
        &issuer.client_config("ops-caller", &caller_secret),
        INSTALLATION,
        sid_infra::deadline::issuer(
            tonic::transport::Channel::from_shared(issuer.upstream())
                .unwrap()
                .connect_lazy(),
        ),
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

fn manager(master: u8) -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([master; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

/// One listener of the separate evaluator, serving `admission`'s routes;
/// returns its address, the stop signal and the serving task.
async fn evaluator_listener(
    evaluation: Arc<sid_authn::password_operation::HistoryEvaluation>,
    admission: Arc<dyn sid_authn::password_operation::PrepareAdmission>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorServiceServer;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PasswordHistoryEvaluatorServiceServer::new(
                sid_authn::password_operation::PasswordHistoryEvaluatorImpl::new(
                    evaluation, admission,
                ),
            ))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    stopped.await.ok();
                },
            ),
    );
    (url, stop, serving)
}

/// A split deployment: the history evaluator is its own gRPC service with its
/// own history keys, a component of the same password service. The
/// credential service prepares on the evaluator's internal listener, which
/// the deployment keeps internal; clients evaluate on its client listener,
/// which refuses preparation. Registration gets the evaluator's domains and
/// the client's evaluation verifies under them; the credential service
/// serves no evaluator. An unreachable evaluator makes history unavailable
/// rather than letting registration continue without it.
#[tokio::test]
async fn a_split_history_evaluator_takes_preparation_internally_only() {
    use group::{Curve, Group, GroupEncoding};
    use pasta_curves::pallas;
    use sid_authn::password_operation::{
        ClientListener, HistoryEvaluation, InternalTransport, PasswordHistoryAuthority,
        RemoteHistoryEvaluator,
    };
    use sid_proto::sid::v1::auth_service_server::AuthService;
    use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
    use sid_proto::sid::v1::authn::{
        EvaluatePasswordHistoryRequest, PreparePasswordHistoryRequest,
    };

    let issuer = TestIssuer::start(Setup {
        resources: vec![],
        checkers: vec![],
    })
    .await;
    let lazy = |address: &str| {
        tonic::transport::Channel::from_shared(address.to_owned())
            .unwrap()
            .connect_lazy()
    };

    // The evaluator alone holds the history keys, in its own store, and
    // seals its own records. Its two listeners serve the same evaluation.
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let evaluation = Arc::new(HistoryEvaluation::new(
        issuer.history_keys.clone(),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        manager(0x11),
    ));
    let (internal_url, stop_internal, serving_internal) =
        evaluator_listener(evaluation.clone(), Arc::new(InternalTransport)).await;
    let (evaluator_url, stop_client, serving_client) =
        evaluator_listener(evaluation, Arc::new(ClientListener)).await;

    let organization = sid_authn::instance_org::ensure(issuer.storage.as_ref(), "sid.example.com")
        .await
        .unwrap();
    let auth = auth_service(
        issuer.storage.clone(),
        cache.clone(),
        issuer.jwt.clone(),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache.clone(),
        )),
        issuer.issuers.clone(),
        organization.id,
        manager(0x33),
        PasswordHistoryAuthority::Remote(RemoteHistoryEvaluator::new(lazy(&internal_url))),
    );
    assert!(
        auth.history_evaluator().is_none(),
        "the credential service serves no evaluator"
    );

    let start = |name: &str| {
        use sid_opaque_ke::ClientRegistration;
        use sid_pake_core::pallas_opaque::PallasCipherSuite;
        let request = ClientRegistration::<PallasCipherSuite>::start(
            &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            b"Str0ngP@ssword1",
        )
        .unwrap()
        .message
        .serialize()
        .to_vec();
        tonic::Request::new(sid_proto::sid::v1::OpaqueZkppRegistrationStartRequest {
            principal: name.into(),
            registration_request: request,
            claim_token: None,
            invite_code: None,
        })
    };
    // The installation waits for its first administrator, who registers
    // with the claim token: a new owner, whose first epoch the evaluator
    // creates under keys only it holds.
    let claim = sid_authn::admin_claim::open_claim(issuer.storage.as_ref(), manager(0x33).as_ref())
        .await
        .unwrap()
        .expect("an unclaimed installation");
    let claimed = |name: &str| {
        use secrecy::ExposeSecret;
        let mut request = start(name);
        request.get_mut().claim_token = Some(claim.expose_secret().to_owned());
        request
    };
    let history = auth
        .opaque_zkpp_registration_start(claimed("split-admin"))
        .await
        .unwrap()
        .into_inner()
        .history
        .expect("history context");
    assert_eq!(history.domains.len(), 1, "a new owner's first epoch");

    // The client evaluates at the evaluator; the answer verifies under the
    // domain key the registration start handed out, for this operation.
    let mut client = PasswordHistoryEvaluatorServiceClient::connect(evaluator_url.clone())
        .await
        .unwrap();
    let blinded = (pallas::Point::generator() * pallas::Scalar::from(5u64)).to_affine();
    let operation = history.operation_id.clone().expect("an operation id").value;
    let evaluations = client
        .evaluate_password_history(EvaluatePasswordHistoryRequest {
            operation_id: history.operation_id,
            blinded_input: blinded.to_bytes().to_vec(),
        })
        .await
        .unwrap()
        .into_inner()
        .evaluations;
    assert_eq!(evaluations.len(), 1);
    let point = |bytes: &[u8]| -> pallas::Affine {
        pallas::Affine::from_bytes(&bytes.try_into().unwrap()).unwrap()
    };
    let scalar = |bytes: &[u8]| -> pallas::Scalar {
        use ff::PrimeField;
        pallas::Scalar::from_repr(bytes.try_into().unwrap()).unwrap()
    };
    let proof = evaluations[0].proof.as_ref().unwrap();
    assert!(sid_pake_core::history::verify_evaluation(
        point(&history.domains[0].evaluator_public_key),
        blinded,
        point(&evaluations[0].evaluated_element),
        &operation,
        &sid_pake_core::history::EvaluationProof {
            c: scalar(&proof.challenge),
            s: scalar(&proof.response),
        },
    ));

    // A client cannot prepare: the client listener refuses it, whatever the
    // request claims.
    let refused = client
        .prepare_password_history(PreparePasswordHistoryRequest {
            operation_id: Some(sid_ids::PasswordOperationId::generate().into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);

    // Without its evaluator the credential service cannot start a
    // registration: history is unavailable, never skipped.
    stop_internal.send(()).unwrap();
    stop_client.send(()).unwrap();
    serving_internal.await.unwrap().unwrap();
    serving_client.await.unwrap().unwrap();
    let unavailable = auth
        .opaque_zkpp_registration_start(claimed("split-admin"))
        .await
        .unwrap_err();
    assert_eq!(unavailable.code(), tonic::Code::Unavailable);
}
