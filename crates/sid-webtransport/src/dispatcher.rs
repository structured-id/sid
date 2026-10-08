// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tonic::Status;
use tonic::metadata::{Ascii, MetadataKey, MetadataMap, MetadataValue};

/// Type-erased async RPC handler: takes raw request bytes + metadata,
/// returns raw response bytes or a gRPC Status error.
type HandlerFn = Box<
    dyn Fn(Vec<u8>, MetadataMap) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Status>> + Send>>
        + Send
        + Sync,
>;

/// Method dispatch table for WebTransport RPC.
///
/// Maps gRPC-style method paths (e.g. `sid.v1.AuthService/OpaqueLoginStart`)
/// to type-erased handlers that decode/encode protobuf and delegate to the
/// existing tonic service trait implementations.
pub struct Dispatcher {
    handlers: HashMap<String, HandlerFn>,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub fn new() -> Self {
        Dispatcher {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a method path.
    pub fn register(&mut self, method: &str, handler: HandlerFn) {
        self.handlers.insert(method.to_string(), handler);
    }

    /// Dispatch an incoming RPC call.
    pub async fn dispatch(
        &self,
        method: &str,
        request_bytes: Vec<u8>,
        metadata: MetadataMap,
    ) -> Result<Vec<u8>, Status> {
        // The method path is the caller's text: it is not repeated back.
        let handler = self.handlers.get(method).ok_or_else(|| {
            sid_core::grpc_error::refuse::not_in_this_build("webtransport_method")
        })?;

        handler(request_bytes, metadata).await
    }
}

/// Convert a string→string map from the WebTransport RequestHeader metadata
/// into a tonic MetadataMap.
pub fn metadata_from_map(map: &HashMap<String, String>) -> MetadataMap {
    let mut meta = MetadataMap::new();
    for (key, value) in map {
        if let Ok(name) = key.parse::<MetadataKey<Ascii>>()
            && let Ok(val) = value.parse::<MetadataValue<Ascii>>()
        {
            meta.insert(name, val);
        }
    }
    meta
}

/// Register a single RPC method on the dispatcher.
///
/// Takes a shared service impl, extracts the method as an async closure,
/// and wraps it in protobuf decode/encode + tonic Request construction.
///
/// # Example
///
/// ```ignore
/// register_rpc!(dispatcher, auth_svc,
///     "sid.v1.AuthService/OpaqueLoginStart",
///     opaque_login_start,
///     OpaqueLoginStartRequest,
///     OpaqueLoginStartResponse
/// );
/// ```
#[macro_export]
macro_rules! register_rpc {
    ($dispatcher:expr, $svc:expr, $path:literal, $method:ident, $req:ty, $resp:ty) => {{
        let svc = $svc.clone();
        $dispatcher.register(
            $path,
            Box::new(
                move |bytes: Vec<u8>, metadata: tonic::metadata::MetadataMap| {
                    let svc = svc.clone();
                    Box::pin(async move {
                        let req_msg =
                            <$req as prost::Message>::decode(bytes.as_slice()).map_err(|_| {
                                ::sid_core::grpc_error::refuse::invalid_field(
                                    "request",
                                    "not an encoded request message",
                                )
                            })?;
                        let mut tonic_req = tonic::Request::new(req_msg);
                        *tonic_req.metadata_mut() = metadata;
                        let resp = svc.$method(tonic_req).await?;
                        let resp_msg = resp.into_inner();
                        let mut buf = Vec::new();
                        prost::Message::encode(&resp_msg, &mut buf).map_err(|e| {
                            ::sid_core::grpc_error::refuse::internal("encode response", e)
                        })?;
                        Ok(buf)
                    })
                },
            ),
        );
    }};
}

#[cfg(test)]
mod tests;
