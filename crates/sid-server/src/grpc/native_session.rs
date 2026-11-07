// SPDX-License-Identifier: AGPL-3.0-only
//! The transport half of native session renewal (native_session.proto): the
//! SID native proof a ceremony completion or a refresh carries, read from its
//! metadata and checked against the request as it was addressed, and the
//! answers the shared rotation core's refusals get.

use sid_authn::dpop::{DPopError, DPopValidator, NativeProofBinding};
use sid_authn::native_session::{NativeError, PROOF_METADATA};
use sid_authn::resource::RequestTarget;
use sid_authn::sign_in_delivery::CeremonyClient;
use sid_infra::authn::resource::request_target;
use sid_infra::grpc_error::refuse::{dependency_unavailable, internal, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason};
use tonic::metadata::MetadataMap;
use tonic::{Request, Status};
use tracing::warn;

/// INVALID_FIELD_VALUE on the metadata `field`: it is malformed, repeated or
/// does not prove what the call needs.
pub(crate) fn field_refused(field: &'static str, detail: impl std::fmt::Display) -> Status {
    ApiError::new(
        ErrorReason::InvalidFieldValue,
        format!("invalid {field}: {detail}"),
    )
    .with_metadata("field", field)
    .into()
}

/// The single value of the ASCII metadata `name`, none when absent. Two
/// values are refused, not one picked: a proof or credential is presented
/// once (RFC 9449 §4.3 step 1 for proofs).
#[allow(clippy::result_large_err)]
pub(crate) fn single_value(
    metadata: &MetadataMap,
    name: &'static str,
) -> Result<Option<String>, Status> {
    let mut values = metadata.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(field_refused(name, "presented more than once"));
    }
    let value = value
        .to_str()
        .map_err(|_| field_refused(name, "not visible ASCII"))?;
    if value.is_empty() {
        return Err(field_refused(name, "empty"));
    }
    Ok(Some(value.to_owned()))
}

/// A SID native proof a request carries, with the request it must name.
pub(crate) struct NativeProof {
    proof: String,
    target: RequestTarget,
}

impl NativeProof {
    /// The proof `request` to the RPC at `rpc` carries, none when it carries
    /// none, checked against `origin`, the issuer's configured public origin.
    /// A browser renews its session by its cookie: a native proof from it is
    /// refused rather than ignored.
    #[allow(clippy::result_large_err)]
    pub(crate) fn of<T>(
        request: &Request<T>,
        client: CeremonyClient,
        origin: &str,
        rpc: &str,
    ) -> Result<Option<Self>, Status> {
        let Some(proof) = single_value(request.metadata(), PROOF_METADATA)? else {
            return Ok(None);
        };
        if client == CeremonyClient::Browser {
            return Err(field_refused(
                PROOF_METADATA,
                "a browser session is not renewed by a native proof",
            ));
        }
        Ok(Some(Self {
            proof,
            target: request_target(request, origin, rpc),
        }))
    }

    /// The thumbprint of the application key that proved the ceremony whose
    /// echoed reference is `reference`. A proof that does not verify fails
    /// the call: no session is created without the binding it asked for.
    pub(crate) async fn ceremony_key(
        &self,
        proofs: &DPopValidator,
        reference: &[u8],
    ) -> Result<String, Status> {
        proofs
            .validate_native(
                &self.proof,
                &self.target.method,
                &self.target.uri,
                NativeProofBinding::Ceremony { reference },
            )
            .await
            .map(|binding| binding.jkt)
            .map_err(proof_refusal)
    }

    pub(crate) fn proof(&self) -> &str {
        &self.proof
    }

    pub(crate) fn target(&self) -> &RequestTarget {
        &self.target
    }
}

/// The answer to a native proof that failed verification.
fn proof_refusal(e: DPopError) -> Status {
    match e {
        // An unreachable replay record cannot rule out a replay; the client
        // retries with a new proof.
        DPopError::ReplayStoreUnavailable => {
            dependency_unavailable("native proof replay record", "replay store unreachable")
        }
        other => {
            warn!(error = %other, "native proof refused");
            field_refused(PROOF_METADATA, other)
        }
    }
}

/// The answer to a refused or failed native session step. A credential no
/// generation holds, one presented without the session's key, an expired or
/// reused one and an ended session get one answer: the session has ended
/// and the client signs in again, learning nothing about the credential.
pub(crate) fn refusal(e: NativeError) -> Status {
    match e {
        NativeError::Proof(e) => proof_refusal(e),
        NativeError::UnknownCredential
        | NativeError::KeyMismatch
        | NativeError::Expired
        | NativeError::Reused
        | NativeError::Ended => {
            ApiError::new(ErrorReason::TokenExpired, "the session has ended").into()
        }
        NativeError::Sealing(e) => internal("seal the native refresh result", e),
        NativeError::Storage(e) => storage_failure(e),
    }
}

#[cfg(test)]
mod tests;
