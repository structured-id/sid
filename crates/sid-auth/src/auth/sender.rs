// SPDX-License-Identifier: AGPL-3.0-only
//! Sender constraint at a protected resource (RFC 9449 §7), for tokens that
//! arrive over HTTP here. The rule itself is `sid_authn::resource`; the
//! proof is checked here and admitted once by the token's issuer.

use http::HeaderMap;
use sid_authn::dpop::VerifiedProof;
use sid_authn::resource::Scheme;
pub use sid_authn::resource::SenderError;

use super::jwt::{ForwardAuthClaims, Presented};

/// Check that `presented`, whose claims are `claims`, honours its binding on
/// a `method` request to `uri`; the checked proof, for the issuer to admit,
/// when the token is bound to a key.
pub fn check_sender(
    presented: Presented<'_>,
    claims: &ForwardAuthClaims,
    headers: &HeaderMap,
    method: &str,
    uri: Option<&str>,
) -> Result<Option<VerifiedProof>, SenderError> {
    let scheme = match presented {
        Presented::DPoP(_) => Scheme::DPoP,
        Presented::Bearer(_) => Scheme::Bearer,
    };
    // Every value counts: an unreadable one stays as an empty proof, so two
    // values never pass as the single proof RFC 9449 §4.3 step 1 requires.
    let proofs: Vec<&str> = headers
        .get_all("dpop")
        .iter()
        .map(|value| value.to_str().unwrap_or(""))
        .collect();
    sid_authn::resource::verify_sender(
        scheme,
        presented.token(),
        claims.cnf.as_ref().map(|cnf| cnf.jkt.as_str()),
        &proofs,
        method,
        uri,
    )
}

#[cfg(test)]
mod tests;
