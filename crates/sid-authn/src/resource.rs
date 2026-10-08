// SPDX-License-Identifier: AGPL-3.0-only
//! A protected resource's side of an access token: how it was presented
//! (RFC 6750 §2.1, RFC 9449 §7.1) and whether the sender honours the token's
//! key binding (RFC 9449 §7).
//!
//! A token bound to a key (`cnf.jkt`) is accepted only under the `DPoP`
//! scheme with exactly one proof for this request, signed by that key and
//! naming the token in `ath`. Presented any other way it is refused, so a
//! stolen bound token is useless without the key.

#[cfg(feature = "grpc")]
use tonic::Request;

use crate::dpop::{DPopError, DPopValidator};

/// The authorization scheme a token was presented under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `Bearer` (RFC 6750 §2.1), or any carrier without a proof (a cookie).
    Bearer,
    /// `DPoP` (RFC 9449 §7.1).
    DPoP,
}

/// Why a validated token may not be used on this request.
#[derive(Debug, thiserror::Error)]
pub enum SenderError {
    /// A bound token without exactly one `DPoP` proof (RFC 9449 §7.1).
    #[error("DPoP-bound token presented without a proof")]
    ProofRequired,
    /// The `DPoP` scheme with a token bound to no key (RFC 9449 §7.1).
    #[error("DPoP scheme used with an unbound token")]
    NotBound,
    /// The request URI is not known, so `htu` cannot be checked.
    #[error("request URI unknown")]
    UriUnknown,
    #[error(transparent)]
    Proof(#[from] DPopError),
}

impl SenderError {
    /// `WWW-Authenticate` challenge for the refusal (RFC 9449 §7.1).
    pub fn challenge(&self) -> &'static str {
        match self {
            Self::Proof(_) | Self::UriUnknown => r#"DPoP error="invalid_dpop_proof""#,
            Self::ProofRequired | Self::NotBound => r#"DPoP error="invalid_token""#,
        }
    }
}

/// Check that `token`, presented under `scheme` and bound to `bound_jkt`
/// (its `cnf.jkt`, if any), honours its binding on a `method` request to
/// `uri` carrying the DPoP `proofs`.
pub async fn check_sender(
    dpop: &DPopValidator,
    scheme: Scheme,
    token: &str,
    bound_jkt: Option<&str>,
    proofs: &[&str],
    method: &str,
    uri: Option<&str>,
) -> Result<(), SenderError> {
    match (bound_jkt, scheme) {
        (None, Scheme::DPoP) => Err(SenderError::NotBound),
        (None, Scheme::Bearer) => Ok(()),
        (Some(jkt), Scheme::DPoP) => {
            // Exactly one proof (RFC 9449 §4.3 step 1).
            let [proof] = proofs else {
                return Err(SenderError::ProofRequired);
            };
            let uri = uri.ok_or(SenderError::UriUnknown)?;
            dpop.validate_for_resource(proof, method, uri, token, jkt)
                .await?;
            Ok(())
        }
        (Some(_), Scheme::Bearer) => Err(SenderError::ProofRequired),
    }
}

/// The access token of a gRPC request and its scheme, from the
/// `authorization` metadata (RFC 7235 §2.1: the scheme is case-insensitive);
/// `None` when there is none.
#[cfg(feature = "grpc")]
pub fn presented<T>(request: &Request<T>) -> Option<(Scheme, &str)> {
    let header = request.metadata().get("authorization")?.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        Some((Scheme::Bearer, token))
    } else if scheme.eq_ignore_ascii_case("DPoP") {
        Some((Scheme::DPoP, token))
    } else {
        None
    }
}

/// The HTTP request a call was transcoded from, as the transcoder serving
/// the call in process received it: the method and the path (with any public
/// prefix or alias). Only that transcoder puts it in a call's extensions; a
/// gRPC client cannot send it.
#[cfg(feature = "grpc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscodedRequest {
    method: String,
    path: String,
}

#[cfg(feature = "grpc")]
impl TranscodedRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
        }
    }
}

/// The method and URI a sender proof on a request must name (RFC 9449 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    pub method: String,
    pub uri: String,
}

/// The request `request` to the RPC at `rpc` (`/package.Service/Method`) was
/// received as, for its sender proof, at the service's configured public
/// `origin` (scheme and authority; never taken from the request): the
/// transcoded HTTP request when a transcoder served the call, otherwise the
/// gRPC call itself, a POST to its RPC path (RFC 9449 §4.3).
#[cfg(feature = "grpc")]
pub fn request_target<T>(request: &Request<T>, origin: &str, rpc: &str) -> RequestTarget {
    let origin = origin.trim_end_matches('/');
    match request.extensions().get::<TranscodedRequest>() {
        Some(transcoded) => RequestTarget {
            method: transcoded.method.clone(),
            uri: format!("{origin}{}", transcoded.path),
        },
        None => RequestTarget {
            method: "POST".into(),
            uri: format!("{origin}{rpc}"),
        },
    }
}

/// The DPoP proofs a gRPC request carries in its `dpop` metadata, one entry
/// per value. A value that is not visible ASCII stays in as an empty proof,
/// which fails validation: dropping it would let two values count as the
/// single proof RFC 9449 §4.3 step 1 requires.
#[cfg(feature = "grpc")]
pub fn proofs<T>(request: &Request<T>) -> Vec<&str> {
    request
        .metadata()
        .get_all("dpop")
        .iter()
        .map(|value| value.to_str().unwrap_or(""))
        .collect()
}

#[cfg(test)]
mod tests;
