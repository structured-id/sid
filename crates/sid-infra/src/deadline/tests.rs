// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;

use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;

/// A service that answers headers at once and then `body`.
fn answering<B>(
    body: B,
) -> impl tower::Service<
    http::Request<Body>,
    Response = http::Response<B>,
    Error = Infallible,
    Future = impl Send,
> + Clone
+ Send
+ 'static
where
    B: Clone + Send + 'static,
{
    tower::service_fn(move |_| {
        let body = body.clone();
        async move { Ok::<_, Infallible>(http::Response::new(body)) }
    })
}

/// A body that never ends.
#[derive(Clone)]
struct Silent;

impl http_body::Body for Silent {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}

/// A body that stops after its headers fails at the deadline, with
/// DEADLINE_EXCEEDED, however far its headers came.
#[tokio::test(start_paused = true)]
async fn a_silent_body_fails_at_the_deadline() {
    let service = Deadline::new(answering(Silent), Duration::from_millis(300));
    let response = service
        .oneshot(http::Request::new(Body::empty()))
        .await
        .unwrap();
    let status = response.into_body().collect().await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
}

/// A body that completes within the bound passes through unchanged.
#[tokio::test(start_paused = true)]
async fn a_complete_body_passes() {
    let service = Deadline::new(
        answering(http_body_util::Full::new(Bytes::from_static(b"answer"))),
        Duration::from_millis(300),
    );
    let response = service
        .oneshot(http::Request::new(Body::empty()))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"answer"));
}

/// Headers that never come fail the call at the deadline too.
#[tokio::test(start_paused = true)]
async fn missing_headers_fail_at_the_deadline() {
    let pending = tower::service_fn(|_: http::Request<Body>| {
        std::future::pending::<Result<http::Response<Body>, Infallible>>()
    });
    let error = Deadline::new(pending, Duration::from_millis(300))
        .oneshot(http::Request::new(Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(
        tonic::Status::from_error(error).code(),
        tonic::Code::DeadlineExceeded
    );
}

/// Waiting for the channel to take the call is part of the call: a channel
/// that never becomes ready fails it at the deadline.
#[tokio::test(start_paused = true)]
async fn waiting_for_readiness_is_bounded() {
    #[derive(Clone)]
    struct NotReady;
    impl tower::Service<http::Request<Body>> for NotReady {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
        fn call(&mut self, _: http::Request<Body>) -> Self::Future {
            panic!("a service that is not ready is never called");
        }
    }
    let call = Deadline::new(NotReady, Duration::from_millis(10))
        .oneshot(http::Request::new(Body::empty()));
    let outcome = tokio::time::timeout(Duration::from_millis(100), call).await;
    let error = outcome
        .expect("readiness does not outlive the deadline")
        .unwrap_err();
    assert_eq!(
        tonic::Status::from_error(error).code(),
        tonic::Code::DeadlineExceeded
    );
}

/// A generated client over a real channel whose bounded request queue is
/// full, with no endpoint to drain it, fails its call at the deadline with
/// DEADLINE_EXCEEDED, not UNKNOWN.
#[tokio::test(start_paused = true)]
async fn a_generated_call_is_bounded_under_channel_backpressure() {
    use sid_proto::sid::v1::GetOidcIssuerRequest;
    use sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient;

    let (mut channel, discovery) = tonic::transport::Channel::balance_channel::<String>(1);
    // Every taken call stays alive, so none frees its place in the queue;
    // yielding between them tells a full queue from the cooperative budget.
    let mut pending = Vec::new();
    let mut full = false;
    for _ in 0..2048 {
        tokio::task::yield_now().await;
        let readiness =
            std::future::poll_fn(|cx| Poll::Ready(tower::Service::poll_ready(&mut channel, cx)))
                .await;
        match readiness {
            Poll::Ready(Ok(())) => pending.push(tower::Service::call(
                &mut channel,
                http::Request::new(Body::empty()),
            )),
            Poll::Pending => {
                full = true;
                break;
            }
            Poll::Ready(Err(e)) => panic!("unexpected channel error: {e}"),
        }
    }
    assert!(full, "the channel's request queue is full");
    assert!(
        pending.len() >= 1024,
        "the queue, not the budget, is exhausted"
    );
    let mut client =
        OidcIssuerServiceClient::new(Deadline::new(channel, Duration::from_millis(10)));
    let outcome = tokio::time::timeout(
        Duration::from_millis(100),
        client.get_oidc_issuer(GetOidcIssuerRequest {
            handle: "0123456789abcdef0123456789abcdef".into(),
        }),
    )
    .await;
    drop(client);
    drop(pending);
    drop(discovery);
    let status = outcome
        .expect("the call does not outlive its deadline waiting for capacity")
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
}
