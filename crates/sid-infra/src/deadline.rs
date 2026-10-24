// SPDX-License-Identifier: AGPL-3.0-only
//! A gRPC channel whose every call ends within a bound: the whole answer,
//! its message and its final status included.
//!
//! The transport's own timeout ends at the response headers. A peer that
//! sends them and then stops before the message or the trailers holds a
//! unary call for as long as the connection lives. The bound here runs from
//! the call's start to the end of the answer's body. For unary calls to an
//! issuer only: a server stream outlives any such bound by design.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use tonic::body::Body;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// `inner`, every call of which ends within `limit`.
#[derive(Clone, Debug)]
pub struct Deadline<S> {
    inner: S,
    limit: Duration,
}

impl<S> Deadline<S> {
    pub fn new(inner: S, limit: Duration) -> Self {
        Self { inner, limit }
    }
}

/// How long a call to the issuer may take, its whole answer included.
pub const ISSUER_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The channel every issuer client calls over: each call bounded by
/// [`ISSUER_CALL_TIMEOUT`].
pub type IssuerChannel = Deadline<tonic::transport::Channel>;

/// `channel` as an issuer channel.
pub fn issuer(channel: tonic::transport::Channel) -> IssuerChannel {
    Deadline::new(channel, ISSUER_CALL_TIMEOUT)
}

/// The channel to `address`, every call ending within `limit`; connecting
/// is bounded by it too.
pub fn bounded_channel(
    address: &str,
    limit: Duration,
) -> Result<Deadline<tonic::transport::Channel>, tonic::transport::Error> {
    let channel = tonic::transport::Endpoint::from_shared(address.to_owned())?
        .connect_timeout(limit)
        .connect_lazy();
    Ok(Deadline::new(channel, limit))
}

fn exceeded() -> tonic::Status {
    tonic::Status::deadline_exceeded("the call did not complete in time")
}

impl<S, B> tower::Service<http::Request<Body>> for Deadline<S>
where
    S: tower::Service<http::Request<Body>, Response = http::Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = http::Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    /// Always ready: waiting for the inner channel to take the call (a full
    /// request queue, no endpoint yet) is part of the call, so it happens in
    /// [`call`](Self::call), under the call's deadline. A readiness wait here
    /// would run before the deadline starts.
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let mut deadline = Box::pin(tokio::time::sleep(self.limit));
        // A clone takes this call and waits for its own readiness, as tower's
        // buffered services do; the channel's clones share one connection.
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let response = async {
                std::future::poll_fn(|cx| inner.poll_ready(cx))
                    .await
                    .map_err(Into::into)?;
                inner.call(request).await.map_err(Into::into)
            };
            let response = tokio::select! {
                response = response => response?,
                () = &mut deadline => return Err(exceeded().into()),
            };
            Ok(response.map(|body| {
                Body::new(Bounded {
                    body: Box::pin(body),
                    deadline,
                })
            }))
        })
    }
}

/// An answer's body that fails at the call's deadline.
struct Bounded<B> {
    body: Pin<Box<B>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<B> http_body::Body for Bounded<B>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Poll::Ready(frame) = self.body.as_mut().poll_frame(cx) {
            return Poll::Ready(frame.map(|frame| frame.map_err(Into::into)));
        }
        ready!(self.deadline.as_mut().poll(cx));
        Poll::Ready(Some(Err(exceeded().into())))
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests;
