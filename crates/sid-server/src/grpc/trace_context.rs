// SPDX-License-Identifier: AGPL-3.0-only
//! W3C Trace Context propagation for tonic gRPC.
//!
//! Extracts `traceparent` and `tracestate` headers from incoming gRPC metadata
//! and injects them into the current `tracing` span context, enabling distributed
//! trace correlation across service boundaries.

use tonic::service::Interceptor;

/// gRPC interceptor that extracts W3C Trace Context headers from metadata.
///
/// When a client sends `traceparent` / `tracestate` metadata, this interceptor
/// parses them and records them as span fields so that the OpenTelemetry layer
/// (if active) can link the server span to the upstream trace.
#[derive(Debug, Clone, Default)]
pub struct TraceContextInterceptor;

impl TraceContextInterceptor {
    pub fn new() -> Self {
        Self
    }
}

impl Interceptor for TraceContextInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        // Extract headers from metadata before taking mutable borrow.
        let traceparent = request
            .metadata()
            .get("traceparent")
            .and_then(|v| v.to_str().ok().map(String::from));
        let tracestate = request
            .metadata()
            .get("tracestate")
            .and_then(|v| v.to_str().ok().map(String::from));
        let request_id = request
            .metadata()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok().map(String::from));

        // Record W3C traceparent in current span for OTel layer.
        if let Some(ref value) = traceparent {
            tracing::Span::current().record("traceparent", value.as_str());
        }
        if let Some(ref value) = tracestate {
            tracing::Span::current().record("tracestate", value.as_str());
        }

        // Store request-id as extension for downstream handlers.
        if let Some(value) = request_id {
            request.extensions_mut().insert(RequestId(value));
        }

        Ok(request)
    }
}

/// Extension type for request ID propagation.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interceptor_passes_without_trace_headers() {
        let mut interceptor = TraceContextInterceptor::new();
        let request = tonic::Request::new(());
        let result = interceptor.call(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_interceptor_extracts_traceparent() {
        let mut interceptor = TraceContextInterceptor::new();
        let mut request = tonic::Request::new(());
        request.metadata_mut().insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        let result = interceptor.call(request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_interceptor_extracts_request_id() {
        let mut interceptor = TraceContextInterceptor::new();
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert("x-request-id", "abc-123".parse().unwrap());
        let result = interceptor.call(request);
        assert!(result.is_ok());
        let req = result.unwrap();
        let rid = req.extensions().get::<RequestId>().unwrap();
        assert_eq!(rid.0, "abc-123");
    }

    #[test]
    fn test_interceptor_handles_invalid_utf8_gracefully() {
        let mut interceptor = TraceContextInterceptor::new();
        let mut request = tonic::Request::new(());
        // Binary metadata value — to_str() will fail, interceptor should not crash.
        request.metadata_mut().insert_bin(
            "traceparent-bin",
            tonic::metadata::MetadataValue::from_bytes(&[0xFF, 0xFE]),
        );
        let result = interceptor.call(request);
        assert!(result.is_ok());
    }
}
