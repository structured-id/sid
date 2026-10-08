// SPDX-License-Identifier: AGPL-3.0-only
//! Durable results of ordinary mutations: a caller's key names one logical
//! command, and the owning database records that command's completion in the
//! same transaction as its effect, so a retry after a lost response finds
//! the result instead of executing the command again.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The longest operation key accepted.
pub const MAX_OPERATION_KEY_LEN: usize = 255;

/// A caller's key for one logical command, created before its first attempt
/// and kept across every retry of it. It carries no authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationKey(String);

impl TryFrom<String> for OperationKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<OperationKey> for String {
    fn from(key: OperationKey) -> Self {
        key.0
    }
}

impl OperationKey {
    /// A key of 1 to 255 visible ASCII characters (the header value of
    /// draft-ietf-httpapi-idempotency-key-header §2, as an RFC 8941 string
    /// without quotes).
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_OPERATION_KEY_LEN
            || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::Validation(format!(
                "an operation key is 1 to {MAX_OPERATION_KEY_LEN} visible ASCII characters"
            )));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a command commits besides its effect: under `namespace` (the
/// authorized actor/scope the key belongs to), `key` names a call of
/// `method` with inputs digesting to `fingerprint`, and `result` is what a
/// retry of it returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCompletion {
    pub namespace: String,
    pub key: OperationKey,
    pub method: String,
    pub fingerprint: Vec<u8>,
    pub result: Vec<u8>,
}

impl OperationCompletion {
    /// The completion of `method` called with `inputs` (the significant
    /// inputs in a canonical encoding) and producing `result`.
    pub fn new(
        namespace: impl Into<String>,
        key: OperationKey,
        method: impl Into<String>,
        inputs: &[u8],
        result: Vec<u8>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key,
            method: method.into(),
            fingerprint: fingerprint(inputs),
            result,
        }
    }
}

/// A committed completion, as the owning database holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub completion: OperationCompletion,
    pub completed_at: DateTime<Utc>,
}

impl OperationRecord {
    /// Whether this record is the completion of the call `method` with
    /// `inputs`: a retry. Anything else under the same key is a conflict.
    pub fn matches(&self, method: &str, inputs: &[u8]) -> bool {
        self.completion.method == method && self.completion.fingerprint == fingerprint(inputs)
    }
}

/// The digest of a command's significant inputs.
pub fn fingerprint(inputs: &[u8]) -> Vec<u8> {
    Sha256::digest(inputs).to_vec()
}

#[cfg(test)]
mod tests;
