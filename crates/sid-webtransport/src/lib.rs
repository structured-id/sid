// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID WebTransport (HTTP/3 QUIC) Server
//!
//! Provides a WebTransport endpoint that reuses existing tonic service
//! implementations via a type-erased dispatcher. Each unary RPC uses
//! one bidirectional QUIC stream with length-prefixed protobuf framing:
//!
//! ```text
//! Client → Server: [4B len][RequestHeader] [4B len][request body]
//! Server → Client: [4B len][ResponseHeader] [4B len][response body]
//! ```

pub mod config;
pub mod dispatcher;
pub mod framing;
pub mod tls;

use crate::config::Config;
use crate::dispatcher::{Dispatcher, metadata_from_map};
use crate::framing::{read_frame, write_frame};
use crate::tls::{TlsError, resolve_identity};
use prost::Message;
use sid_proto::sid::v1::{RequestHeader, ResponseHeader};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tonic::Status;
use tracing::{debug, info, warn};
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig, VarInt};

/// WebTransport server that dispatches RPCs to registered handlers.
pub struct WebTransportServer {
    config: Config,
    dispatcher: Arc<Dispatcher>,
    cert_hash: Option<String>,
    resolved_identity: Option<Identity>,
}

impl WebTransportServer {
    /// Create a new server with the given config and dispatcher.
    pub fn new(config: Config, dispatcher: Dispatcher) -> Self {
        WebTransportServer {
            config,
            dispatcher: Arc::new(dispatcher),
            cert_hash: None,
            resolved_identity: None,
        }
    }

    /// Get the certificate hash (available after `resolve_cert_hash()` or `serve()`).
    pub fn cert_hash(&self) -> Option<&str> {
        self.cert_hash.as_deref()
    }

    /// Pre-resolve TLS identity and return the certificate hash.
    ///
    /// Call this before `serve()` to make the cert hash available for
    /// REST endpoints (e.g. `/.well-known/webtransport-cert-hash`).
    /// The resolved identity is reused by `serve()`.
    pub async fn resolve_cert_hash(&mut self) -> Result<String, TlsError> {
        let resolved = resolve_identity(&self.config).await?;
        let hash = resolved.cert_hash.clone();
        self.cert_hash = Some(hash.clone());
        self.resolved_identity = Some(resolved.identity);
        Ok(hash)
    }

    /// Resolve the TLS identity (if not pre-resolved) and serve until
    /// `shutdown` resolves; sessions in flight then have `drain` to finish
    /// before the endpoint closes the rest.
    pub async fn serve(
        mut self,
        shutdown: impl Future<Output = ()>,
        drain: Duration,
    ) -> Result<(), ServeError> {
        let identity = match self.resolved_identity.take() {
            Some(id) => id,
            None => {
                let resolved = resolve_identity(&self.config).await?;
                self.cert_hash = Some(resolved.cert_hash);
                resolved.identity
            }
        };

        let wt_config = ServerConfig::builder()
            .with_bind_address(self.config.bind)
            .with_identity(identity)
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .build();

        let server = Endpoint::server(wt_config).map_err(ServeError::Bind)?;

        info!("WebTransport listening on {}", self.config.bind);

        let mut sessions = JoinSet::new();
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                incoming = server.accept() => {
                    let dispatcher = self.dispatcher.clone();
                    sessions.spawn(async move {
                        if let Err(e) = handle_session(incoming, dispatcher).await {
                            warn!("WebTransport session error: {e}");
                        }
                    });
                }
                Some(ended) = sessions.join_next(), if !sessions.is_empty() => {
                    if let Err(e) = ended {
                        warn!("WebTransport session task failed: {e}");
                    }
                }
            }
        }

        // No new sessions are accepted; the ones in flight get `drain`.
        let finished = tokio::time::timeout(drain, async {
            while sessions.join_next().await.is_some() {}
        })
        .await;
        if finished.is_err() {
            warn!(
                "WebTransport drain of {drain:?} ended with {} session(s) open; closing them",
                sessions.len()
            );
        }
        sessions.abort_all();
        server.close(VarInt::from_u32(0), b"server shutting down");
        if tokio::time::timeout(drain, server.wait_idle())
            .await
            .is_err()
        {
            warn!("WebTransport connections did not close within {drain:?}");
        }
        Ok(())
    }
}

/// The WebTransport server could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("binding the WebTransport endpoint: {0}")]
    Bind(std::io::Error),
}

/// Handle one WebTransport session (one browser connection). Its streams end
/// with it.
async fn handle_session(
    incoming: IncomingSession,
    dispatcher: Arc<Dispatcher>,
) -> anyhow::Result<()> {
    let session_request = incoming.await?;

    debug!(
        "WebTransport session: authority='{}' path='{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection = session_request.accept().await?;

    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept_bi() => match accepted {
                Ok((send, recv)) => {
                    let dispatcher = dispatcher.clone();
                    streams.spawn(async move {
                        if let Err(e) = handle_stream(send, recv, dispatcher).await {
                            debug!("Stream error: {e}");
                        }
                    });
                }
                Err(e) => {
                    debug!("Session closed: {e}");
                    return Ok(());
                }
            },
            Some(ended) = streams.join_next(), if !streams.is_empty() => {
                if let Err(e) = ended {
                    warn!("WebTransport stream task failed: {e}");
                }
            }
        }
    }
}

/// Handle one bidirectional stream (one RPC call).
async fn handle_stream(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    dispatcher: Arc<Dispatcher>,
) -> anyhow::Result<()> {
    // 1. Read RequestHeader
    let header_bytes = read_frame(&mut recv).await?;
    let header = RequestHeader::decode(header_bytes.as_slice())?;

    debug!("RPC: {}", header.method);

    // 2. Read request body
    let request_bytes = read_frame(&mut recv).await?;

    // 3. Convert metadata
    let metadata = metadata_from_map(&header.metadata);

    // 4. Dispatch
    let result = dispatcher
        .dispatch(&header.method, request_bytes, metadata)
        .await;

    // 5. Write response
    match result {
        Ok(response_bytes) => {
            let resp_header = ResponseHeader {
                status_code: 0, // OK
                status_message: String::new(),
                metadata: Default::default(),
            };
            write_frame(&mut send, &resp_header.encode_to_vec()).await?;
            write_frame(&mut send, &response_bytes).await?;
        }
        Err(status) => {
            let resp_header = ResponseHeader {
                status_code: status_to_code(&status),
                status_message: status.message().to_string(),
                metadata: Default::default(),
            };
            write_frame(&mut send, &resp_header.encode_to_vec()).await?;
            // Empty body for error responses
            write_frame(&mut send, &[]).await?;
        }
    }

    Ok(())
}

/// Map tonic Status code to gRPC numeric code.
fn status_to_code(status: &Status) -> u32 {
    match status.code() {
        tonic::Code::Ok => 0,
        tonic::Code::Cancelled => 1,
        tonic::Code::Unknown => 2,
        tonic::Code::InvalidArgument => 3,
        tonic::Code::DeadlineExceeded => 4,
        tonic::Code::NotFound => 5,
        tonic::Code::AlreadyExists => 6,
        tonic::Code::PermissionDenied => 7,
        tonic::Code::ResourceExhausted => 8,
        tonic::Code::FailedPrecondition => 9,
        tonic::Code::Aborted => 10,
        tonic::Code::OutOfRange => 11,
        tonic::Code::Unimplemented => 12,
        tonic::Code::Internal => 13,
        tonic::Code::Unavailable => 14,
        tonic::Code::DataLoss => 15,
        tonic::Code::Unauthenticated => 16,
    }
}

#[cfg(test)]
mod tests;
