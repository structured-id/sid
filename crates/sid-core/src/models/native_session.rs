// SPDX-License-Identifier: AGPL-3.0-only
//! Native session refresh: each generation of a native session's refresh
//! credentials is bound to the application instance's key. Any credential of
//! the current generation, with a fresh proof by that key, rotates the
//! generation once; a retry of the same exchange within the redelivery
//! window receives the committed successor again, and nothing branches.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::SessionId;

/// The most refresh credentials one generation may hold.
pub const NATIVE_GENERATION_SIZE_MAX: u32 = 16;

/// Bytes of a logical exchange reference.
pub const NATIVE_EXCHANGE_LEN: usize = 16;

/// The logical refresh exchange a client names and keeps across its retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeExchange([u8; NATIVE_EXCHANGE_LEN]);

impl NativeExchange {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; NATIVE_EXCHANGE_LEN]>::try_from(bytes).ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; NATIVE_EXCHANGE_LEN] {
        &self.0
    }
}

/// One generation of a native session's refresh credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeGeneration {
    pub id: Uuid,
    pub session_id: SessionId,
    /// RFC 7638 thumbprint of the application key every proof is signed by.
    pub key_jkt: String,
    /// SHA-256 of each credential, never the credential itself.
    pub credential_hashes: Vec<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Where the generation a presented credential belongs to stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeGenerationState {
    /// No refresh has rotated it yet.
    Current,
    /// Rotated by `exchange` into `successor`; `sealed` is the protected
    /// successor result kept for a retry of that exchange until
    /// `redeliver_until`, gone once the successor is used.
    Rotated {
        exchange: NativeExchange,
        successor: Uuid,
        redeliver_until: DateTime<Utc>,
        sealed: Option<Vec<u8>>,
    },
}

/// The generation a presented credential belongs to, as its store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePresented {
    pub generation: Uuid,
    pub session_id: SessionId,
    pub key_jkt: String,
    pub expires_at: DateTime<Utc>,
    pub state: NativeGenerationState,
}

/// One rotation a verified refresh asks its store to commit.
#[derive(Debug, Clone, Copy)]
pub struct NativeRotation<'a> {
    /// The generation the presented credential belongs to.
    pub presented: Uuid,
    pub exchange: NativeExchange,
    pub successor: &'a NativeGeneration,
    /// The successor's credentials, sealed for redelivery.
    pub sealed: &'a [u8],
    pub redeliver_until: DateTime<Utc>,
}

/// What committing a rotation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRotationOutcome {
    /// The presented generation rotated into the successor.
    Rotated,
    /// It had rotated by this same exchange, inside its redelivery window,
    /// and its successor is unused: the sealed result to deliver again.
    Redeliver(Vec<u8>),
    /// It had rotated otherwise (another exchange, the window passed or the
    /// successor used): a retired credential presented with its key.
    Retired,
    /// The session ended or expired: nothing rotates.
    Ended,
}

#[cfg(test)]
mod tests;
