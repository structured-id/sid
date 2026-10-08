// SPDX-License-Identifier: AGPL-3.0-only
//! Telemetry initialization: tracing + OTLP trace export.
//!
//! - `SID_LOG_FORMAT`: `json` (production) or `text` (dev, default).
//! - `SID_OTLP_ENDPOINT`: OTLP gRPC endpoint (e.g., `http://localhost:4317`).
//!   If set, distributed traces are exported via OTLP.
//! - `OTEL_SERVICE_NAME`: service name in traces (default: `sid`).

#[cfg(feature = "telemetry")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "telemetry")]
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;

/// Guard that shuts down the OTLP trace provider on drop.
pub struct TelemetryGuard {
    #[cfg(feature = "telemetry")]
    _provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "telemetry")]
        if let Some(ref provider) = self._provider
            && let Err(e) = provider.shutdown()
        {
            eprintln!("OTLP shutdown error: {e}");
        }
    }
}

/// Initialize tracing subscriber with optional OTLP trace export.
///
/// Returns a guard that must be held for the lifetime of the application.
pub fn init_telemetry() -> Result<TelemetryGuard, Box<dyn std::error::Error>> {
    let log_format = std::env::var("SID_LOG_FORMAT").unwrap_or_else(|_| "text".to_string());
    let env_filter = EnvFilter::from_default_env().add_directive("sid=info".parse()?);

    #[cfg(feature = "telemetry")]
    {
        let otlp_endpoint = std::env::var("SID_OTLP_ENDPOINT").ok();

        if let Some(endpoint) = otlp_endpoint {
            return init_with_otlp(log_format, env_filter, &endpoint);
        }
    }

    init_plain_logging(log_format, env_filter);

    #[cfg(feature = "telemetry")]
    return Ok(TelemetryGuard { _provider: None });
    #[cfg(not(feature = "telemetry"))]
    Ok(TelemetryGuard {})
}

#[cfg(feature = "telemetry")]
fn init_with_otlp(
    log_format: String,
    env_filter: EnvFilter,
    endpoint: &str,
) -> Result<TelemetryGuard, Box<dyn std::error::Error>> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Install W3C TraceContext propagator for distributed trace correlation.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "sid".to_string());

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name)
                .build(),
        )
        .build();

    // OTel layer must be created per-subscriber type (JSON vs text produce different Layered types).
    if log_format == "json" {
        let tracer = provider.tracer("sid");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(false)
                    .with_line_number(false),
            )
            .with(otel_layer)
            .init();
    } else {
        let tracer = provider.tracer("sid-text");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_layer)
            .init();
    }

    tracing::info!(endpoint = %endpoint, "OTLP trace export enabled");

    Ok(TelemetryGuard {
        _provider: Some(provider),
    })
}

fn init_plain_logging(log_format: String, env_filter: EnvFilter) {
    if log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_file(false)
            .with_line_number(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_default_log_format() {
        let format = std::env::var("SID_LOG_FORMAT").unwrap_or_else(|_| "text".to_string());
        assert!(format == "text" || format == "json");
    }
}
