// SPDX-License-Identifier: AGPL-3.0-only
//! The stored form of a registered passkey (`Credential::data`): an explicit
//! SID format version over the `structured-webauthn` binary codecs, decoded
//! strictly on every read (arch/auth/webauthn.md#credential-storage-model).
//!
//! Version 1, fields in order, lengths big-endian:
//!
//! | field | bytes |
//! |---|---|
//! | version (`1`) | 1 |
//! | credential id | u16 length, then the id |
//! | user handle | 16 |
//! | transports | 1 |
//! | static state (key, static extensions) | u16 length, then the codec output |
//! | dynamic state (UV, backup, counter, attachment) | 7 |
//! | metadata (attestation, AAGUID, extensions, resident key) | u16 length, then the codec output |
//!
//! Only the dynamic state changes after registration; it is rewritten in
//! place and every other byte is kept.

use sid_core::{Error as SidError, Result as SidResult};
use structured_webauthn::RegisteredCredential;
use structured_webauthn::bin::{Decode, Encode};
use structured_webauthn::response::register::bin::MetadataOwned;
use structured_webauthn::response::register::{CompressedPubKeyOwned, DynamicState, StaticState};
use structured_webauthn::response::{AuthTransports, CredentialId};

use super::USER_HANDLE_LEN;

/// The record format this build writes and reads.
const VERSION_1: u8 = 1;

/// Length of the encoded dynamic state.
const DYNAMIC_LEN: usize = 7;

/// A stored passkey, decoded and validated.
pub(super) struct PasskeyRecord<'a> {
    pub id: CredentialId<&'a [u8]>,
    pub user_handle: [u8; USER_HANDLE_LEN],
    pub transports: AuthTransports,
    pub static_state: StaticState<CompressedPubKeyOwned>,
    pub dynamic_state: DynamicState,
    pub metadata: MetadataOwned,
    /// Where the dynamic state starts in the stored bytes.
    pub dynamic_at: usize,
}

fn malformed(what: &str) -> SidError {
    SidError::Internal(format!("stored passkey record is malformed: {what}"))
}

/// The bytes of a newly registered credential.
pub(super) fn encode(credential: &RegisteredCredential<'_, USER_HANDLE_LEN>) -> SidResult<Vec<u8>> {
    let (id, transports, user_handle, static_state, dynamic_state, metadata) =
        credential.as_parts();
    let id = id.encode().unwrap_or_else(|never| match never {});
    let static_state = static_state.encode().unwrap_or_else(|never| match never {});
    let metadata = metadata.encode().unwrap_or_else(|never| match never {});
    let mut out = Vec::with_capacity(
        1 + 2
            + id.len()
            + USER_HANDLE_LEN
            + 1
            + 2
            + static_state.len()
            + DYNAMIC_LEN
            + 2
            + metadata.len(),
    );
    out.push(VERSION_1);
    put_prefixed(&mut out, id, "credential id")?;
    out.extend_from_slice(user_handle.as_slice());
    out.push(transports.encode().unwrap_or_else(|never| match never {}));
    put_prefixed(&mut out, &static_state, "static state")?;
    out.extend_from_slice(
        &dynamic_state
            .encode()
            .unwrap_or_else(|never| match never {}),
    );
    put_prefixed(&mut out, &metadata, "metadata")?;
    Ok(out)
}

/// `bytes` with its dynamic state replaced by `dynamic`; `dynamic_at` is
/// [`PasskeyRecord::dynamic_at`] of `bytes` decoded.
pub(super) fn with_dynamic_state(
    bytes: &[u8],
    dynamic_at: usize,
    dynamic: DynamicState,
) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[dynamic_at..dynamic_at + DYNAMIC_LEN]
        .copy_from_slice(&dynamic.encode().unwrap_or_else(|never| match never {}));
    out
}

fn put_prefixed(out: &mut Vec<u8>, field: &[u8], what: &str) -> SidResult<()> {
    let len = u16::try_from(field.len())
        .map_err(|_| SidError::Internal(format!("passkey {what} longer than 65535 bytes")))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// A reader over the stored bytes that refuses to read past their end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &str) -> SidResult<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(what))?;
        let field = &self.bytes[self.at..end];
        self.at = end;
        Ok(field)
    }

    fn array<const N: usize>(&mut self, what: &str) -> SidResult<[u8; N]> {
        let field = self.take(N, what)?;
        Ok(field.try_into().expect("take returned N bytes"))
    }

    fn prefixed(&mut self, what: &str) -> SidResult<&'a [u8]> {
        let len = u16::from_be_bytes(self.array::<2>(what)?);
        self.take(usize::from(len), what)
    }
}

/// Decode `bytes` as a stored passkey: every component through its codec,
/// nothing left over. An unknown version is refused.
pub(super) fn decode(bytes: &[u8]) -> SidResult<PasskeyRecord<'_>> {
    let mut r = Reader { bytes, at: 0 };
    let [version] = r.array::<1>("version")?;
    if version != VERSION_1 {
        return Err(malformed(&format!("unknown version {version}")));
    }
    let id = CredentialId::<&[u8]>::decode(r.prefixed("credential id")?)
        .map_err(|e| malformed(&format!("credential id: {e}")))?;
    let user_handle = r.array::<USER_HANDLE_LEN>("user handle")?;
    let [transports] = r.array::<1>("transports")?;
    let transports =
        AuthTransports::decode(transports).map_err(|e| malformed(&format!("transports: {e}")))?;
    let static_state = StaticState::<CompressedPubKeyOwned>::decode(r.prefixed("static state")?)
        .map_err(|e| malformed(&format!("static state: {e}")))?;
    let dynamic_at = r.at;
    let dynamic_state = DynamicState::decode(r.array::<DYNAMIC_LEN>("dynamic state")?)
        .map_err(|e| malformed(&format!("dynamic state: {e}")))?;
    let metadata = MetadataOwned::decode(r.prefixed("metadata")?)
        .map_err(|e| malformed(&format!("metadata: {e}")))?;
    if r.at != bytes.len() {
        return Err(malformed("trailing data"));
    }
    Ok(PasskeyRecord {
        id,
        user_handle,
        transports,
        static_state,
        dynamic_state,
        metadata,
        dynamic_at,
    })
}

#[cfg(test)]
mod tests;
