// SPDX-License-Identifier: AGPL-3.0-only
//! Logical OIDC issuers.
//!
//! One issuer exists for each issuing authority and recipient organization.
//! Its canonical URL names it by an opaque handle and never changes; tokens
//! for the organization's applications carry that URL as `iss` and are signed
//! with the issuer's own keys.

use std::fmt;

use chrono::{DateTime, Utc};
use rand::TryRng;
use serde::{Deserialize, Serialize};

pub use sid_ids::IssuerId;

use super::OrgId;

/// The public routing name of an issuer: 16 random bytes, lowercase hex.
///
/// Not derived from an organization, profile, binding, name or slug, so the
/// URL reveals nothing about who it serves.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IssuerHandle(String);

impl IssuerHandle {
    /// Length of a handle in characters.
    pub const LEN: usize = 32;

    /// A new random handle.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("the operating system random source is available");
        Self(hex::encode(bytes))
    }

    /// A handle in exactly the generated shape; anything else is refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        let valid = text.len() == Self::LEN
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err("not an issuer handle".to_owned())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IssuerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuerHandle({})", self.0)
    }
}

impl fmt::Display for IssuerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for IssuerHandle {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<IssuerHandle> for String {
    fn from(handle: IssuerHandle) -> Self {
        handle.0
    }
}

/// Who issues under an issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerAuthority {
    /// This installation, for its own organization's applications.
    Local,
}

impl IssuerAuthority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
        }
    }
}

parse_stored!(IssuerAuthority, "issuer authority", [Local]);

/// A logical OIDC issuer. `handle` and `canonical_url` never change and are
/// never given to another issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIssuer {
    pub id: IssuerId,
    pub handle: IssuerHandle,
    /// The exact `iss` value; stored, never rebuilt from a request.
    pub canonical_url: String,
    pub authority: IssuerAuthority,
    /// The organization whose applications this issuer serves.
    pub recipient_org: OrgId,
    pub created_at: DateTime<Utc>,
}

impl OidcIssuer {
    /// Whether this issuer serves a client registered to `client_org`: the
    /// organization's base issuer serves its clients and no one else's.
    pub fn serves(&self, client_org: Option<OrgId>) -> bool {
        client_org == Some(self.recipient_org)
    }

    /// Whether `key` may be this issuer's first key: its own, generation 1.
    pub fn check_first_key(&self, key: &IssuerSigningKey) -> crate::Result<()> {
        if key.issuer_id != self.id {
            return Err(crate::Error::Validation(format!(
                "signing key of issuer {} offered to issuer {}",
                key.issuer_id, self.id
            )));
        }
        if key.generation != 1 {
            return Err(crate::Error::Validation(format!(
                "first signing key of issuer {} has generation {}",
                self.id, key.generation
            )));
        }
        Ok(())
    }
}

/// One generation of an issuer's Ed25519 token-signing key.
///
/// The private key is stored only sealed under the key manager, bound to
/// [`IssuerSigningKey::sealing_context`].
#[derive(Clone)]
pub struct IssuerSigningKey {
    pub issuer_id: IssuerId,
    /// 1 for the first key; the highest generation signs.
    pub generation: u32,
    /// The JWS `kid`: SHA-256 thumbprint of the public key, base64url.
    pub key_id: String,
    pub public_key: [u8; 32],
    pub sealed_private_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl IssuerSigningKey {
    /// The context the private key of `generation` is sealed under.
    pub fn sealing_context(issuer_id: IssuerId, generation: u32) -> String {
        format!("oidc-issuer-key:{issuer_id}:{generation}")
    }
}

impl fmt::Debug for IssuerSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerSigningKey")
            .field("issuer_id", &self.issuer_id)
            .field("generation", &self.generation)
            .field("key_id", &self.key_id)
            .field("sealed_private_key", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
