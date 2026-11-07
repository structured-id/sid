// SPDX-License-Identifier: AGPL-3.0-only
//! A protected resource's side of an access token: how it was presented
//! (RFC 6750 §2.1, RFC 9449 §7.1) and whether the sender honours the token's
//! key binding (RFC 9449 §7).
//!
//! A token bound to a key (`cnf.jkt`) is accepted only under the `DPoP`
//! scheme with exactly one proof for this request, signed by that key and
//! naming the token in `ath`. Presented any other way it is refused, so a
//! stolen bound token is useless without the key.

use crate::dpop::{DPopError, DPopValidator, VerifiedProof};

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

/// The checks of [`check_sender`] for a verifier outside the token's issuer:
/// the proof is checked, not admitted, and returned for the issuer to admit
/// once (RFC 9449 §11.1). `None` for an unbound token presented as Bearer.
pub fn verify_sender(
    scheme: Scheme,
    token: &str,
    bound_jkt: Option<&str>,
    proofs: &[&str],
    method: &str,
    uri: Option<&str>,
) -> Result<Option<VerifiedProof>, SenderError> {
    match (bound_jkt, scheme) {
        (None, Scheme::DPoP) => Err(SenderError::NotBound),
        (None, Scheme::Bearer) => Ok(None),
        (Some(jkt), Scheme::DPoP) => {
            // Exactly one proof (RFC 9449 §4.3 step 1).
            let [proof] = proofs else {
                return Err(SenderError::ProofRequired);
            };
            let uri = uri.ok_or(SenderError::UriUnknown)?;
            Ok(Some(DPopValidator::verify_for_resource(
                proof, method, uri, token, jkt,
            )?))
        }
        (Some(_), Scheme::Bearer) => Err(SenderError::ProofRequired),
    }
}

/// The method and URI a sender proof on a request must name (RFC 9449 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    pub method: String,
    pub uri: String,
}

#[cfg(test)]
mod tests;
