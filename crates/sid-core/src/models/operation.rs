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
    /// A key as its logical value: 1 to 255 characters a Structured Field
    /// String carries (RFC 9651 §3.3.3: printable ASCII, space included).
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_OPERATION_KEY_LEN
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(Error::Validation(format!(
                "an operation key is 1 to {MAX_OPERATION_KEY_LEN} printable ASCII characters"
            )));
        }
        Ok(Self(value.to_string()))
    }

    /// The key an `Idempotency-Key` header value encodes: a Structured Field
    /// String (draft-ietf-httpapi-idempotency-key-header-08 §2.1, RFC 9651
    /// §4.2.5), the same encoded value in HTTP and gRPC metadata.
    pub fn from_header(value: &str) -> Result<Self> {
        let malformed = || {
            Error::Validation(
                "an Idempotency-Key is a Structured Field String (RFC 9651 §3.3.3)".into(),
            )
        };
        let inner = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(malformed)?;
        let mut logical = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(escaped @ ('"' | '\\')) => logical.push(escaped),
                    _ => return Err(malformed()),
                },
                '"' => return Err(malformed()),
                c => logical.push(c),
            }
        }
        Self::parse(&logical)
    }

    /// This key as an `Idempotency-Key` header value (a Structured Field
    /// String, RFC 9651 §4.1.6).
    pub fn to_header(&self) -> String {
        let mut encoded = String::with_capacity(self.0.len() + 2);
        encoded.push('"');
        for c in self.0.chars() {
            if matches!(c, '"' | '\\') {
                encoded.push('\\');
            }
            encoded.push(c);
        }
        encoded.push('"');
        encoded
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A period the owning operation store issued: an unsigned epoch bounding
/// when a keyed command is admitted, not a timestamp. Constructing one checks
/// its representation only; whether the store issued it and still admits it
/// is the store's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationPeriod(u64);

impl OperationPeriod {
    pub const fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The period a `sid-operation-period` value names: one canonical
    /// unsigned decimal integer, no sign and no leading zero except `0`.
    pub fn parse(value: &str) -> Result<Self> {
        let canonical = !value.is_empty()
            && value.bytes().all(|b| b.is_ascii_digit())
            && (value == "0" || !value.starts_with('0'));
        canonical
            .then(|| value.parse::<u64>().ok())
            .flatten()
            .map(Self)
            .ok_or_else(|| {
                Error::Validation(
                    "an operation period is one canonical unsigned decimal integer".into(),
                )
            })
    }
}

impl std::fmt::Display for OperationPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A period as its store issued it: new commands named with it are admitted
/// until `accepted_until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedOperationPeriod {
    pub period: OperationPeriod,
    pub accepted_until: DateTime<Utc>,
}

/// The policy a store issues and retires periods under, the same for every
/// replica: a period accepts new commands for `acceptance` from its issue,
/// and its commands are kept for retries `retention` past that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationPeriodPolicy {
    pub acceptance: chrono::Duration,
    pub retention: chrono::Duration,
}

/// A period still admitted, as its store holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPeriodRecord {
    pub issued: IssuedOperationPeriod,
    pub issued_at: DateTime<Utc>,
}

/// A store's periods, carried between stores with its completions: every
/// period through `issued_through` (`0` before the first) was issued, and
/// those not `active` are retired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPeriodState {
    pub issued_through: OperationPeriod,
    pub active: Vec<OperationPeriodRecord>,
}

/// Why a store does not admit the period a keyed command names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPeriodRefusal {
    /// The store never issued it.
    NotIssued,
    /// The store retired it: its commands are no longer told apart from new
    /// ones, so none is admitted under it again.
    Retired,
}

impl std::fmt::Display for OperationPeriodRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotIssued => "not issued",
            Self::Retired => "retired",
        })
    }
}

/// The context naming one logical keyed command: the caller's key and the
/// period it was created under, kept together across every retry and every
/// transport. It carries no authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationContext {
    pub key: OperationKey,
    pub period: OperationPeriod,
}

impl OperationContext {
    pub fn new(key: OperationKey, period: OperationPeriod) -> Self {
        Self { key, period }
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
    /// The period a caller's keyed command was named with: the commit is
    /// admitted only while the store has not retired it, and the record goes
    /// with it. `None` for the record a ceremony keeps of its own operation.
    pub period: Option<OperationPeriod>,
    /// When the completion stops being kept: past it the key resolves to
    /// nothing and the record is dropped. `None` keeps it until its owner
    /// purges it.
    pub retain_until: Option<DateTime<Utc>>,
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
            period: None,
            retain_until: None,
        }
    }

    /// The same completion, of a keyed command named with `period`.
    #[must_use]
    pub fn in_period(mut self, period: OperationPeriod) -> Self {
        self.period = Some(period);
        self
    }

    /// The same completion, kept no longer than `until`.
    #[must_use]
    pub fn retained_until(mut self, until: DateTime<Utc>) -> Self {
        self.retain_until = Some(until);
        self
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
    /// `inputs` named with `period`: a retry. Anything else under the same
    /// key is a conflict, a different period included.
    pub fn matches(&self, method: &str, inputs: &[u8], period: Option<OperationPeriod>) -> bool {
        self.completion.method == method
            && self.completion.period == period
            && self.completion.fingerprint == fingerprint(inputs)
    }
}

/// The identifier a keyed creation allocated for what it creates, bound in
/// the owning operation store to the command that named it: under
/// `namespace`, `key` names a call of `method` with inputs digesting to
/// `fingerprint` named with `period`, and `resource` is what that command
/// creates. Every attempt of the command resolves the same `resource`; the
/// key bound to another call is a conflict. A binding is not a completion:
/// it proves neither that the creation finished nor who executes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationResourceBinding {
    pub namespace: String,
    pub key: OperationKey,
    pub method: String,
    pub fingerprint: Vec<u8>,
    pub period: Option<OperationPeriod>,
    pub resource: uuid::Uuid,
}

impl OperationResourceBinding {
    /// Whether this binding names the call `method` with `fingerprint`
    /// named with `period`: the same command. Anything else under its key is
    /// a conflict.
    pub fn same_command(&self, other: &Self) -> bool {
        self.method == other.method
            && self.period == other.period
            && self.fingerprint == other.fingerprint
    }
}

/// The digest of a command's significant inputs.
pub fn fingerprint(inputs: &[u8]) -> Vec<u8> {
    Sha256::digest(inputs).to_vec()
}

#[cfg(test)]
mod tests;
