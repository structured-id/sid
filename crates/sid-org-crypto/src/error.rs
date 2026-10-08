// SPDX-License-Identifier: AGPL-3.0-only
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrgCryptoError {
    #[error("KEK source unavailable: {0}")]
    KekUnavailable(String),

    #[error("invalid KEK length: expected 32 bytes, got {0}")]
    InvalidKekLength(usize),

    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("AES-GCM error: {0}")]
    Aes(String),

    #[error("invalid wrapped blob: too short ({0} bytes)")]
    InvalidWrap(usize),

    #[error("KEK version mismatch: have {have}, need {need}")]
    KekVersionMismatch { have: u32, need: u32 },
}
