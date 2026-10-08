// SPDX-License-Identifier: AGPL-3.0-only
//! Which services this installation trusts to confirm checks of an original
//! request (D054, receiver-side verifier trust).
//!
//! A permission checker may hand over, with a request-bound question, its
//! testimony that it verified the original request's sender proof. That
//! testimony is accepted only from a service this installation's deployment
//! configuration names as the verifier for the target resource and proof
//! kind, and only while the service also holds the checker role there: the
//! checker role alone never makes a caller a verifier.

use serde::Deserialize;

/// A kind of sender proof a verifier may confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofProfile {
    /// A DPoP proof (RFC 9449).
    Dpop,
}

/// One trusted verifier integration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestVerifier {
    /// The service as the authorization engine names it:
    /// `machine:<machine user id>` or `oauth_client:<client_id>`.
    pub subject: String,
    /// Resource indicators (RFC 8707) of this installation's registered
    /// resources whose requests it verifies.
    pub resources: Vec<String>,
    /// The proof kinds it verifies.
    pub profiles: Vec<ProofProfile>,
}

/// The configured verifiers; empty trusts nobody.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestVerifiers {
    #[serde(default)]
    verifiers: Vec<RequestVerifier>,
}

/// Why a verifier configuration cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum RequestVerifiersError {
    #[error("verifier configuration is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verifier {0:?} is not a machine user or OAuth client subject")]
    Subject(String),
    #[error("verifier {subject:?} names {resource:?}, which is not a resource indicator")]
    Resource { subject: String, resource: String },
    #[error("verifier {0:?} names no resource or no proof kind")]
    Empty(String),
}

impl RequestVerifiers {
    /// Parse and check a JSON configuration (`{"verifiers": [...]}`).
    pub fn from_json(text: &str) -> Result<Self, RequestVerifiersError> {
        let parsed: Self = serde_json::from_str(text)?;
        for verifier in &parsed.verifiers {
            let kind_ok = matches!(
                verifier.subject.split_once(':'),
                Some(("machine" | "oauth_client", id)) if !id.is_empty()
            );
            if !kind_ok {
                return Err(RequestVerifiersError::Subject(verifier.subject.clone()));
            }
            if verifier.resources.is_empty() || verifier.profiles.is_empty() {
                return Err(RequestVerifiersError::Empty(verifier.subject.clone()));
            }
            if let Some(resource) = verifier
                .resources
                .iter()
                .find(|r| sid_core::models::ResourceIndicator::parse(r).is_err())
            {
                return Err(RequestVerifiersError::Resource {
                    subject: verifier.subject.clone(),
                    resource: resource.clone(),
                });
            }
        }
        Ok(parsed)
    }

    /// Whether `subject` is configured to confirm `profile` proofs of
    /// requests to the resource `indicator`.
    pub fn permits(&self, subject: &str, indicator: &str, profile: ProofProfile) -> bool {
        self.verifiers.iter().any(|v| {
            v.subject == subject
                && v.profiles.contains(&profile)
                && v.resources.iter().any(|r| r == indicator)
        })
    }
}

#[cfg(test)]
mod tests;
