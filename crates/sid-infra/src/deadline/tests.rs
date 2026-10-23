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
