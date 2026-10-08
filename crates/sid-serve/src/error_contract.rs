// SPDX-License-Identifier: Apache-2.0
//! The error contract of a served process, checked from outside: every
//! refusal is a canonical `google.rpc.Status` carrying `google.rpc.ErrorInfo`
//! in the service's domain (AIP-193).
//!
//! [`probe`] serves the routes on a loopback listener and calls every unary
//! and server-streaming method of the served services with an empty request
//! (every field at its default), once per caller. Client-streaming methods
//! are not called: an empty stream says nothing about their refusals.

use std::time::Duration;

use bytes::{Buf, BufMut};
use prost_reflect::DescriptorPool;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::http;
use tonic::service::Routes;
use tonic::{Request, Status};
use tonic_types::StatusExt;

/// How long one call may take before it counts as a refusal of its own.
const CALL_BOUND: Duration = Duration::from_secs(10);

/// What a probe found.
#[derive(Debug)]
pub struct Report {
    /// Methods called.
    pub methods: usize,
    /// Calls that ended in a non-OK status.
    pub refusals: usize,
    /// Each refusal that breaks the contract: method path, caller, why.
    pub violations: Vec<String>,
}

/// A caller of the probe: a name for the report and the bearer token it
/// presents, if any.
pub struct Caller<'a> {
    pub name: &'a str,
    pub token: Option<&'a str>,
}

/// How `status` breaks the contract of a service whose reasons live in
/// `domains` (the shared domain plus a tier's own), if it does.
pub fn violation(status: &Status, domains: &[&str]) -> Option<String> {
    match status.get_details_error_info() {
        Some(info) if domains.contains(&info.domain.as_str()) => None,
        Some(info) => Some(format!(
            "{:?} {} in domain {}",
            status.code(),
            info.reason,
            info.domain
        )),
        None => Some(format!(
            "{:?} without ErrorInfo: {}",
            status.code(),
            status.message()
        )),
    }
}

/// Serves `routes` and calls every method of the services named `served`, as
/// declared in `descriptors` (encoded `FileDescriptorSet`s), once per caller.
/// A refusal must carry `ErrorInfo` in one of `domains`.
///
/// # Panics
///
/// When the descriptors do not decode or the loopback listener cannot be
/// served: the probe has nothing to report then.
pub async fn probe(
    routes: Routes,
    served: &[&str],
    descriptors: &[&[u8]],
    domains: &[&str],
    callers: &[Caller<'_>],
) -> Report {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("loopback endpoint")
        .connect()
        .await
        .expect("loopback connection");

    let methods = methods_of(served, descriptors);
    let mut report = Report {
        methods: methods.len(),
        refusals: 0,
        violations: Vec::new(),
    };
    for method in &methods {
        for caller in callers {
            let Err(status) = call(&channel, method, caller.token).await else {
                continue;
            };
            report.refusals += 1;
            if let Some(why) = violation(&status, domains) {
                report
                    .violations
                    .push(format!("{} ({}): {why}", method.path, caller.name));
            }
        }
    }
    report
}

/// One method to call: its path and whether the server streams its answer.
struct Method {
    path: String,
    server_streaming: bool,
}

fn methods_of(served: &[&str], descriptors: &[&[u8]]) -> Vec<Method> {
    let mut pool = DescriptorPool::new();
    for set in descriptors {
        pool.decode_file_descriptor_set(*set)
            .expect("descriptor set");
    }
    pool.services()
        .filter(|service| served.contains(&service.full_name()))
        .flat_map(|service| {
            service
                .methods()
                .filter(|method| !method.is_client_streaming())
                .map(|method| Method {
                    path: format!("/{}/{}", service.full_name(), method.name()),
                    server_streaming: method.is_server_streaming(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The status `method` answers an empty request with; a server-streaming
/// method is judged by the status that opens its stream.
async fn call(
    channel: &tonic::transport::Channel,
    method: &Method,
    token: Option<&str>,
) -> Result<(), Status> {
    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(e.to_string()))?;
    let mut request = Request::new(Vec::new());
    if let Some(token) = token {
        let value = format!("Bearer {token}")
            .parse()
            .map_err(|_| Status::invalid_argument("token is not a header value"))?;
        request.metadata_mut().insert("authorization", value);
    }
    let path = http::uri::PathAndQuery::from_maybe_shared(method.path.clone())
        .map_err(|_| Status::invalid_argument("method path"))?;
    let answer = async {
        if method.server_streaming {
            grpc.server_streaming(request, path, RawCodec)
                .await
                .map(drop)
        } else {
            grpc.unary(request, path, RawCodec).await.map(drop)
        }
    };
    tokio::time::timeout(CALL_BOUND, answer)
        .await
        .unwrap_or_else(|_| Err(Status::deadline_exceeded("no answer within the bound")))
}

/// Passes message bytes through: the probe sends the empty encoding and never
/// needs the answer's type.
#[derive(Clone, Copy)]
struct RawCodec;

struct RawEncoder;
struct RawDecoder;

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawDecoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        Ok(Some(src.copy_to_bytes(src.remaining()).to_vec()))
    }
}

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;
    fn encoder(&mut self) -> RawEncoder {
        RawEncoder
    }
    fn decoder(&mut self) -> RawDecoder {
        RawDecoder
    }
}

#[cfg(test)]
mod tests;
