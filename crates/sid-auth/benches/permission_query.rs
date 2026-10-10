// SPDX-License-Identifier: AGPL-3.0-only
//! Latency of a remote permission question (D054), P50 and P99, warm, against
//! a real issuer served over gRPC on loopback (SQLite in memory):
//!
//! - `admit`: a protected service admits a call: the token verified locally,
//!   then one request-bound question to the authorization API;
//! - `check`: the request-bound question alone, over the reused channel;
//! - `batch x10`: ten questions about one original request in one call.
//!
//! The checker's own token is obtained once before measuring; no question
//! requests a token.
//!
//! `cargo bench -p sid-auth --bench permission_query`

use std::time::{Duration, Instant};

use sid_proto::sid::v1::authz::check_permission_request::Evaluation;
use sid_proto::sid::v1::authz::permission_target::Scope;
use sid_proto::sid::v1::authz::{
    BatchCheckPermissionRequest, CheckPermissionRequest, PermissionOutcome, PermissionTarget,
    RequestEvaluation,
};
use sid_proto::sid::v1::authz_service_client::AuthzServiceClient;
use sid_test_issuer::{Checker, INSTALLATION, Setup, TestIssuer};

const RESOURCE: &str = "https://orders.example/";
const ORIGIN: &str = "https://orders.example";
const PATH: &str = "/orders.v1.Orders/Read";
const CHECKER: &str = "orders-service";
const SECRET: &str = "orders-service-secret";
const WARMUP: usize = 100;
const QUESTIONS: usize = 2_000;
const BATCHES: usize = 500;
const BATCH: usize = 10;

/// P50 and P99 of `samples`.
fn report(what: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)];
    println!(
        "{what:<12} n={:<5} p50={:>9.1?} p99={:>9.1?}",
        samples.len(),
        at(50),
        at(99)
    );
}

/// `run` timed `n` times after `WARMUP` unmeasured runs.
async fn measure<F, Fut>(n: usize, mut run: F) -> Vec<Duration>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for _ in 0..WARMUP {
        run().await;
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        run().await;
        samples.push(started.elapsed());
    }
    samples
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let issuer = TestIssuer::start(Setup {
            resources: vec![RESOURCE.into()],
            checkers: vec![Checker {
                client_id: CHECKER.into(),
                secret: SECRET.into(),
                confirms_proofs: false,
            }],
        })
        .await;
        let secret =
            std::env::temp_dir().join(format!("sid-bench-checker-{}", uuid::Uuid::now_v7()));
        std::fs::write(&secret, SECRET).expect("secret file");

        let operator = issuer.profile().await;
        let reader = issuer.role("orders-reader", &["orders.read"]).await;
        issuer.grant(&operator, &reader, RESOURCE).await;
        let token = issuer.token(&operator, RESOURCE, None).await.token;
        let resource = issuer.resource(RESOURCE).id;

        // admit
        let receiver = sid_auth::receiver::Receiver::connect(
            "orders",
            &issuer.receiver_config(RESOURCE, ORIGIN, CHECKER, &secret, None),
        )
        .await
        .expect("receiver");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
        let post = http::Method::POST;
        let samples = measure(QUESTIONS, || async {
            receiver
                .admit(&post, PATH, &headers, "orders.read")
                .await
                .expect("admitted");
        })
        .await;
        report("admit", samples);

        // check and batch, with the checker's token held
        let channel = tonic::transport::Channel::from_shared(issuer.upstream())
            .expect("upstream")
            .connect()
            .await
            .expect("channel");
        let checker = sid_authn::client_credential::ClientCredential::checker(
            &issuer.client_config(CHECKER, &secret),
            INSTALLATION,
            channel.clone(),
        )
        .expect("checker credential");
        let authorization = checker.authorization().await.expect("checker token");
        let question = CheckPermissionRequest {
            action: "orders.read".into(),
            target: Some(PermissionTarget {
                scope: Some(Scope::Resource(resource.into())),
                object: String::new(),
            }),
            evaluation: Some(Evaluation::Request(RequestEvaluation {
                access_token: token.clone(),
                confirmation: None,
            })),
            ..Default::default()
        };
        let client = AuthzServiceClient::new(channel);

        let samples = measure(QUESTIONS, || {
            let mut client = client.clone();
            let mut call = tonic::Request::new(question.clone());
            call.metadata_mut()
                .insert("authorization", authorization.clone());
            async move {
                let answer = client.check_permission(call).await.expect("answer");
                assert_eq!(answer.into_inner().outcome(), PermissionOutcome::Allowed);
            }
        })
        .await;
        report("check", samples);

        let batch = BatchCheckPermissionRequest {
            checks: vec![question; BATCH],
        };
        let samples = measure(BATCHES, || {
            let mut client = client.clone();
            let mut call = tonic::Request::new(batch.clone());
            call.metadata_mut()
                .insert("authorization", authorization.clone());
            async move {
                let answers = client.batch_check_permission(call).await.expect("answers");
                assert_eq!(answers.into_inner().results.len(), BATCH);
            }
        })
        .await;
        report(&format!("batch x{BATCH}"), samples);

        std::fs::remove_file(&secret).ok();
    });
}
