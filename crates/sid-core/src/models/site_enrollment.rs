// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's enrollment as a site of the federation: the
//! certificate the platform issued for the site's key, with the certificates
//! above it.
//!
//! In plain words: once the platform has enrolled this installation's site,
//! the installation keeps the certificate it was given. It shows that
//! certificate when it tells others whom it admits. The site's private key
//! is not here: it is one of the installation's sealed secrets.

use serde::{Deserialize, Serialize};

/// The most certificates kept above the site's own.
pub const MAX_CHAIN: usize = 8;

/// The largest certificate kept, in bytes: a certificate carrying two
/// signatures and two keys is a few kilobytes.
pub const MAX_CERTIFICATE: usize = 1 << 16;

/// The site's participant certificate and the certificates above it, all
/// DER, as the platform issued them. Public material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteEnrollment {
    /// The site's participant certificate.
    pub certificate: Vec<u8>,
    /// The certificates above it, its issuer first.
    pub chain: Vec<Vec<u8>>,
}

impl SiteEnrollment {
    /// Whether the enrollment is within what a store keeps: a certificate,
    /// at most [`MAX_CHAIN`] above it, none empty or over
    /// [`MAX_CERTIFICATE`].
    pub fn check(&self) -> crate::Result<()> {
        let sized = |der: &Vec<u8>| !der.is_empty() && der.len() <= MAX_CERTIFICATE;
        if sized(&self.certificate) && self.chain.len() <= MAX_CHAIN && self.chain.iter().all(sized)
        {
            Ok(())
        } else {
            Err(crate::Error::Validation(
                "a site enrollment is a certificate and at most 8 above it, each up to 64 KiB"
                    .into(),
            ))
        }
    }

    /// The chain as one stored value: each certificate behind its length
    /// (four bytes, big-endian), in order.
    pub fn chain_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.chain.iter().map(|der| 4 + der.len()).sum());
        for der in &self.chain {
            // Checked by `check`: far below four bytes of length.
            bytes.extend_from_slice(&u32::try_from(der.len()).unwrap_or(u32::MAX).to_be_bytes());
            bytes.extend_from_slice(der);
        }
        bytes
    }

    /// The chain a stored value holds; none when it is not what
    /// [`SiteEnrollment::chain_bytes`] writes.
    pub fn chain_from_bytes(mut bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut chain = Vec::new();
        while !bytes.is_empty() {
            let (length, rest) = bytes.split_first_chunk::<4>()?;
            let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
            if length == 0 || length > MAX_CERTIFICATE || chain.len() == MAX_CHAIN {
                return None;
            }
            let (der, rest) = rest.split_at_checked(length)?;
            chain.push(der.to_vec());
            bytes = rest;
        }
        Some(chain)
    }
}

#[cfg(test)]
mod tests;
