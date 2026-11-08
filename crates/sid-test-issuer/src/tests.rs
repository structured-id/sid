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
        &issuer.receiver_config(RESOURCE, ORIGIN, "ops-receiver", &secret),
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
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

/// One listener of the separate evaluator, serving `admission`'s routes;
/// returns its address, the stop signal and the serving task.
async fn evaluator_listener(
    evaluation: Arc<sid_authn::password_operation::HistoryEvaluation>,
    admission: Arc<dyn sid_infra::authn::password_operation::PrepareAdmission>,
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
                sid_infra::authn::password_operation::PasswordHistoryEvaluatorImpl::new(
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
    use sid_authn::password_operation::{HistoryEvaluation, PasswordHistoryAuthority};
    use sid_infra::authn::password_operation::{
        ClientListener, InternalTransport, RemoteHistoryEvaluator,
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
        Arc::new(sid_plugin::InProcessCeremonyState::new()),
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
        PasswordHistoryAuthority::Remote(Arc::new(RemoteHistoryEvaluator::new(lazy(
            &internal_url,
        )))),
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

const USER: &str = "native-user@sid.example.com";
const PASSWORD: &[u8] = b"native-user-password-2026";

fn auth_client(
    issuer: &TestIssuer,
) -> sid_proto::sid::v1::auth_service_client::AuthServiceClient<tonic::transport::Channel> {
    sid_proto::sid::v1::auth_service_client::AuthServiceClient::new(
        tonic::transport::Channel::from_shared(issuer.upstream())
            .unwrap()
            .connect_lazy(),
    )
}

/// A registered password account signs in over the network: the finish the
/// client sends answers with the session and its access token.
#[tokio::test]
async fn a_password_account_signs_in_over_the_network() {
    let issuer = TestIssuer::start(Setup::default()).await;
    let profile = issuer.password_account(USER, PASSWORD).await;
    let finish = issuer.start_password_login(USER, PASSWORD).await;
    let signed_in = auth_client(&issuer)
        .opaque_login_finish(finish)
        .await
        .expect("signed in");
    let token = signed_in
        .metadata()
        .get("authorization")
        .expect("the access token")
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    let claims = issuer.jwt.validate_access_token(&token).unwrap();
    assert_eq!(claims.sub, profile.id.to_string());
    assert!(signed_in.into_inner().session_id.is_some());

    // A wrong password signs nobody in.
    let wrong = issuer.start_password_login(USER, b"another password").await;
    assert!(
        auth_client(&issuer)
            .opaque_login_finish(wrong)
            .await
            .is_err()
    );
}

/// An account with an enrolled authenticator owes it at sign-in: the finish
/// answers the pending context and the factor, and a code of the returned
/// seed completes the sign-in with the session.
#[tokio::test]
async fn an_enrolled_authenticator_completes_the_sign_in() {
    use sid_proto::sid::v1::{StepUpMethod, VerifyTotpRequest};
    let issuer = TestIssuer::start(Setup::default()).await;
    let profile = issuer.password_account(USER, PASSWORD).await;
    let seed = issuer.enroll_totp(&profile).await;
    let finish = issuer.start_password_login(USER, PASSWORD).await;
    let answered = auth_client(&issuer)
        .opaque_login_finish(finish)
        .await
        .expect("the pending context");
    let pending = answered
        .metadata()
        .get("authorization")
        .expect("the pending context's token")
        .clone();
    assert_eq!(
        answered.into_inner().second_factors,
        [StepUpMethod::Totp as i32]
    );

    let mut verify = tonic::Request::new(VerifyTotpRequest {
        code: crate::totp_code(&seed),
    });
    verify.metadata_mut().insert("authorization", pending);
    let completed = auth_client(&issuer)
        .verify_totp(verify)
        .await
        .expect("the completed sign-in")
        .into_inner();
    assert!(completed.verified);
    assert!(completed.session_id.is_some());
}

/// Replicas of one installation share its state: a sign-in started at one
/// finishes at the other, and an issuer started again on the store after a
/// restart still knows the account.
#[tokio::test]
async fn replicas_and_a_restart_share_the_installation() {
    let dir = std::env::temp_dir().join(format!("sid-test-issuer-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let installation = Installation::at(&dir.join("sid.db"));
    let mut first = TestIssuer::replica(Setup::default(), &installation).await;
    let second = TestIssuer::replica(Setup::default(), &installation).await;
    first.password_account(USER, PASSWORD).await;

    let finish = first.start_password_login(USER, PASSWORD).await;
    auth_client(&second)
        .opaque_login_finish(finish)
        .await
        .expect("finished at the other replica");

    first.stop().await;
    drop(first);
    let restarted = TestIssuer::replica(Setup::default(), &installation).await;
    let finish = restarted.start_password_login(USER, PASSWORD).await;
    auth_client(&restarted)
        .opaque_login_finish(finish)
        .await
        .expect("signed in after the restart");
    std::fs::remove_dir_all(&dir).ok();
}

/// Bug prevented: a replica started with its installation's setup creating
/// the resource and the proof-confirming checker again (it fails on the
/// existing records), or one started without it losing the checker's
/// trust. Every replica takes the same setup and finds the same records.
#[tokio::test]
async fn replicas_take_the_installations_setup() {
    let dir = std::env::temp_dir().join(format!("sid-test-issuer-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let installation = Installation::at(&dir.join("sid.db"));
    let setup = || Setup {
        resources: vec![RESOURCE.into()],
        checkers: vec![Checker {
            client_id: "replica-checker".into(),
            secret: "replica-checker-secret".into(),
            confirms_proofs: true,
        }],
    };
    let first = TestIssuer::replica(setup(), &installation).await;
    let second = TestIssuer::replica(setup(), &installation).await;
    assert_eq!(
        second.resource(RESOURCE).id,
        first.resource(RESOURCE).id,
        "the replica found the installation's resource"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Bug prevented: an account registered with a spelling its validation
/// changes (surrounding space, case) registering, then not being found. It
/// is found by its resolution key, as a sign-in finds it.
#[tokio::test]
async fn an_account_is_found_by_its_resolution_key() {
    let issuer = TestIssuer::start(Setup::default()).await;
    let profile = issuer
        .password_account("  Spelled-User@SID.example.com ", PASSWORD)
        .await;
    let finish = issuer
        .start_password_login("spelled-user@sid.example.com", PASSWORD)
        .await;
    let signed_in = auth_client(&issuer)
        .opaque_login_finish(finish)
        .await
        .expect("signed in with the canonical spelling");
    let token = signed_in
        .metadata()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned();
    assert_eq!(
        issuer.jwt.validate_access_token(&token).unwrap().sub,
        profile.id.to_string()
    );
}
