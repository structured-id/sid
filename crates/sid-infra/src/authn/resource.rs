// SPDX-License-Identifier: AGPL-3.0-only
//! A protected resource's gRPC request as its sender proof checks it: the
//! token and scheme presented, the DPoP proofs carried and the request the
//! proof must name (RFC 9449 §4.3, §7.1). The checks are
//! [`sid_authn::resource`]'s.

use sid_authn::resource::{RequestTarget, Scheme};
use tonic::Request;

/// The access token of a gRPC request and its scheme, from the
/// `authorization` metadata (RFC 7235 §2.1: the scheme is case-insensitive);
/// `None` when there is none.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscodedRequest {
    method: String,
    path: String,
}

impl TranscodedRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
        }
    }
}

/// The request `request` to the RPC at `rpc` (`/package.Service/Method`) was
/// received as, for its sender proof, at the service's configured public
/// `origin` (scheme and authority; never taken from the request): the
/// transcoded HTTP request when a transcoder served the call, otherwise the
/// gRPC call itself, a POST to its RPC path (RFC 9449 §4.3).
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
