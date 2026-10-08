// SPDX-License-Identifier: AGPL-3.0-only
//! Federation PKI error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Generation(String),

    #[error("certificate parsing failed: {0}")]
    Parse(String),

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("certificate expired")]
    Expired,

    #[error("certificate not yet valid")]
    NotYetValid,

    #[error("certificate revoked")]
    Revoked,

    #[error("chain validation failed: {0}")]
    ChainInvalid(String),

    #[error("issuer not found in trust store")]
    IssuerNotFound,

    #[error("certificate type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    #[error("missing required extension: {0}")]
    MissingExtension(String),

    #[error("path length constraint violated")]
    PathLengthExceeded,

    #[error("enrollment error: {0}")]
    Enrollment(String),
}
