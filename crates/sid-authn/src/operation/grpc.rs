// SPDX-License-Identifier: AGPL-3.0-only
//! Keyed commands over gRPC: the operation context of a call, read once at
//! the transport boundary from its metadata, and the status each
//! [`OperationError`] answers with.

use std::task::{Context, Poll};

use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{OperationContext, OperationKey, OperationPeriod};
use tonic::Status;
use tonic::metadata::MetadataMap;

use super::OperationError;

/// The metadata carrying the operation key: the `Idempotency-Key` header of
/// draft-ietf-httpapi-idempotency-key-header-08 §2.1, a Structured Field
/// String, the same encoded value in gRPC metadata and HTTP.
pub const OPERATION_KEY_HEADER: &str = "idempotency-key";

/// The metadata carrying the period the command was named with
/// (`SID-Operation-Period` in HTTP): one canonical unsigned decimal.
pub const OPERATION_PERIOD_HEADER: &str = sid_core::grpc_error::refuse::OPERATION_PERIOD_FIELD;

/// A keyed command's effect that did not commit, refused with a status.
pub type Effect = super::Effect<Status>;

impl super::KeyedCommand {
    /// [`super::KeyedCommand::execute`] for a method refusing with a status.
    pub async fn run<T, F, Fut>(
        &self,
        storage: &(impl sid_plugin::OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, Status>
    where
        T: prost::Message + Default,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect>>,
    {
        self.execute(storage, effect).await
    }

    /// [`super::KeyedCommand::execute_recorded`] for a method refusing with
    /// a status.
    pub async fn run_recorded<T, F, Fut>(
        &self,
        storage: &(impl sid_plugin::OperationResultStore + ?Sized),
        effect: F,
    ) -> Result<T, Status>
    where
        T: serde::de::DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Effect>>,
    {
        self.execute_recorded(storage, effect).await
    }
}

impl From<Status> for super::Effect<Status> {
    fn from(status: Status) -> Self {
        Self::Refused(status)
    }
}

impl From<OperationError> for super::Effect<Status> {
    fn from(e: OperationError) -> Self {
        Self::Refused(e.into())
    }
}

impl From<OperationError> for Status {
    fn from(e: OperationError) -> Self {
        match e {
            OperationError::KeyConflict => ApiError::new(
                ErrorReason::OperationKeyConflict,
                "the operation key already names another command",
            )
            .into(),
            OperationError::PeriodRefused(refusal) => {
                sid_core::grpc_error::refuse::operation_period_refused(refusal)
            }
            OperationError::OutcomeUnknown => ApiError::new(
                ErrorReason::OperationOutcomeUnknown,
                "retry the operation with the same key",
            )
            .into(),
            OperationError::Store(e) => {
                tracing::warn!(error = %e, "operation store failed");
                ApiError::internal().into()
            }
            OperationError::ResultUnreadable => ApiError::internal().into(),
        }
    }
}

/// The operation context of `request`: the one the transport boundary
/// ([`OperationContextLayer`]) decoded, else decoded from its metadata. A
/// missing, malformed or repeated value is refused before any effect.
#[allow(clippy::result_large_err)]
pub fn context<T>(request: &tonic::Request<T>) -> Result<OperationContext, Status> {
    match request.extensions().get::<OperationContext>() {
        Some(context) => Ok(context.clone()),
        None => metadata_context(request.metadata()),
    }
}

/// `metadata` naming the command by `context`, as a client sends it: the key
/// as a Structured Field String and the period as its decimal, replacing
/// any earlier values.
pub fn insert_context(metadata: &mut MetadataMap, context: &OperationContext) {
    let key = context
        .key
        .to_header()
        .parse()
        .expect("a Structured Field String of printable ASCII is a metadata value");
    let period = context
        .period
        .to_string()
        .parse()
        .expect("a decimal is a metadata value");
    metadata.insert(OPERATION_KEY_HEADER, key);
    metadata.insert(OPERATION_PERIOD_HEADER, period);
}

/// The operation context `metadata` carries.
#[allow(clippy::result_large_err)]
pub fn metadata_context(metadata: &MetadataMap) -> Result<OperationContext, Status> {
    let values = |name| {
        metadata
            .get_all(name)
            .iter()
            .map(|v| v.as_encoded_bytes())
            .collect::<Vec<_>>()
    };
    decode(
        &values(OPERATION_KEY_HEADER),
        &values(OPERATION_PERIOD_HEADER),
    )
}

/// The operation context HTTP `headers` carry.
#[allow(clippy::result_large_err)]
fn header_context(headers: &http::HeaderMap) -> Result<OperationContext, Status> {
    let values = |name| {
        headers
            .get_all(name)
            .iter()
            .map(http::HeaderValue::as_bytes)
            .collect::<Vec<_>>()
    };
    decode(
        &values(OPERATION_KEY_HEADER),
        &values(OPERATION_PERIOD_HEADER),
    )
}

/// The context of exactly one key and one period value.
#[allow(clippy::result_large_err)]
fn decode(keys: &[&[u8]], periods: &[&[u8]]) -> Result<OperationContext, Status> {
    let key = single(OPERATION_KEY_HEADER, keys)?;
    let period = single(OPERATION_PERIOD_HEADER, periods)?;
    let key = std::str::from_utf8(key)
        .ok()
        .and_then(|v| OperationKey::from_header(v).ok())
        .ok_or_else(|| {
            malformed(
                OPERATION_KEY_HEADER,
                "the operation key is a Structured Field String of 1 to 255 printable characters",
            )
        })?;
    let period = std::str::from_utf8(period)
        .ok()
        .and_then(|v| OperationPeriod::parse(v).ok())
        .ok_or_else(|| {
            malformed(
                OPERATION_PERIOD_HEADER,
                "the operation period is one canonical unsigned decimal",
            )
        })?;
    Ok(OperationContext::new(key, period))
}

#[allow(clippy::result_large_err)]
fn single<'a>(name: &'static str, values: &[&'a [u8]]) -> Result<&'a [u8], Status> {
    match values {
        [value] => Ok(value),
        [] => Err(ApiError::new(
            ErrorReason::RequiredFieldMissing,
            "this method requires an operation context",
        )
        .with_field_violation(name, "required")
        .into()),
        _ => Err(malformed(name, "the operation context is given once")),
    }
}

fn malformed(name: &'static str, message: &'static str) -> Status {
    ApiError::new(ErrorReason::InvalidFieldValue, message)
        .with_field_violation(name, "malformed")
        .into()
}

/// Decodes the operation context of every call to a keyed method before the
/// method runs, refusing a call without a valid one, and hands it to the
/// method in the request extensions. Which methods are keyed is generated
/// from their proto declaration ([`sid_proto::keyed`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct OperationContextLayer;

impl<S> tower::Layer<S> for OperationContextLayer {
    type Service = OperationContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OperationContextService { inner }
    }
}

/// The service of [`OperationContextLayer`].
#[derive(Debug, Clone)]
pub struct OperationContextService<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for OperationContextService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<tonic::body::Body>>,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future =
        futures::future::Either<std::future::Ready<Result<Self::Response, Self::Error>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if sid_proto::keyed::is_keyed_path(request.uri().path()) {
            match header_context(request.headers()) {
                Ok(context) => {
                    request.extensions_mut().insert(context);
                }
                Err(refused) => {
                    return futures::future::Either::Left(std::future::ready(Ok(
                        refused.into_http()
                    )));
                }
            }
        }
        futures::future::Either::Right(self.inner.call(request))
    }
}

#[cfg(test)]
mod tests;
