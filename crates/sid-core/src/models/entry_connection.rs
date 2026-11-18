// SPDX-License-Identifier: AGPL-3.0-only
//! The registered connections an installation receives federated sign-ins
//! through.
//!
//! In plain words: to let people sign in here with an identity issued by
//! another SID installation, this installation is first registered there as
//! a client. A connection is the record of one such registration: the exact
//! issuer it trusts for that sign-in, its own client there with the
//! credential it authenticates with, and the exact address the issuer
//! returns the browser to.
//!
//! A connection is transport configuration only. It does not admit anyone:
//! whether an identity signed in through it is let in is decided by the
//! installation's login settings and, after that, by its ordinary
//! permissions. A browser may name a registered connection by its handle; it
//! never supplies an issuer, an endpoint or a credential.

use std::fmt;

use jiff::Timestamp;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sid_keys::EncryptedField;

use super::{IssuerId, OrgId};

/// The public routing name of a connection: 16 random bytes, shown as
/// lowercase hex. It reveals nothing about the issuer or organization
/// behind it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryHandle([u8; 16]);

impl EntryHandle {
    /// Length of a handle's text in characters.
    pub const LEN: usize = 32;

    /// A new random handle.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("the operating system random source is available");
        Self(bytes)
    }

    /// The handle `text` spells: exactly 32 lowercase hex characters.
    pub fn parse(text: &str) -> Result<Self, MalformedHandle> {
        let canonical = text.len() == Self::LEN
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if !canonical {
            return Err(MalformedHandle);
        }
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| MalformedHandle)?;
        Ok(Self(bytes))
    }

    /// The handle a store kept as its 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for EntryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for EntryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryHandle({self})")
    }
}

/// Text that is not a connection handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an entry connection handle")]
pub struct MalformedHandle;

/// Who may write a connection. The two are not interchangeable: sharing the
/// store gives neither writer the other's authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOwner {
    /// Set by the installation's provisioning: the authority the
    /// installation's own Profiles sign in through. An administrator's
    /// command never creates, changes or removes it.
    Provisioning,
    /// Managed by the installation's administrators: a connection to an
    /// outside issuer.
    Administration,
}

impl ConnectionOwner {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Administration => "administration",
        }
    }
}

parse_stored!(
    ConnectionOwner,
    "entry connection owner",
    [Provisioning, Administration]
);

/// How this installation authenticates as the issuer's client, with the
/// credential it does so with. The method is the one actually registered at
/// the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCredential {
    /// `client_secret_basic` (RFC 6749 §2.3.1): the client secret, sealed
    /// under the installation's key manager in [`credential_context`].
    SecretBasic(EncryptedField),
}

impl ClientCredential {
    /// The stored name of the method.
    pub const fn method(&self) -> &'static str {
        match self {
            Self::SecretBasic(_) => "client_secret_basic",
        }
    }
}

/// The context a connection's client credential is sealed and opened under:
/// a credential copied to another connection does not open.
pub fn credential_context(handle: EntryHandle) -> String {
    format!("entry-connection:{handle}:client-credential")
}

/// The route, below an installation issuer's URL, that starts an entry: the
/// browser leaves for the issuer of the connection it names.
pub const START: &str = "/auth/federation/start";

/// The route, below an installation issuer's URL, an issuer returns the
/// browser to: the one redirect URI every connection of that installation
/// issuer registers. Whoever registers this installation as a client
/// derives it from the installation issuer's URL and this path alone.
pub const CALLBACK: &str = "/auth/federation/callback";

/// Whether `issuer` is an OpenID Connect Issuer Identifier: an https URL
/// with a host and no query or fragment (OpenID Connect Core 1.0 §1.2).
/// Plain `http` is accepted only on a loopback host, for local development,
/// as an installation's own issuer is.
pub fn is_issuer_identifier(issuer: &str) -> bool {
    let Ok(url) = url::Url::parse(issuer) else {
        return false;
    };
    let loopback = matches!(
        url.host(),
        Some(url::Host::Domain("localhost"))
            | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
            | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
    );
    let scheme = match url.scheme() {
        "https" => true,
        "http" => loopback,
        _ => false,
    };
    scheme && url.host_str().is_some() && url.query().is_none() && url.fragment().is_none()
}

/// Whether `url` can be a connection's use return: an https URL with a host
/// and neither query nor fragment, so the continuation appended to it is
/// its only parameter. Plain `http` only on a loopback host, as for an
/// issuer identifier.
pub fn is_use_return(url: &str) -> bool {
    is_issuer_identifier(url)
}

/// The longest display name of a connection.
pub const MAX_NAME: usize = 128;

/// One registered connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryConnection {
    /// Names the connection in the browser's routes; never changes.
    pub handle: EntryHandle,
    /// Who may write it; never changes.
    pub owner: ConnectionOwner,
    /// How the sign-in page names it; presentation only.
    pub name: String,
    /// The exact issuer identifier, as its ID Tokens name it; never changes.
    /// An identity recorded here is found by this issuer and its subject, so
    /// one issuer has one connection and a changed issuer is another one.
    pub issuer: String,
    /// The organization whose installation issues there, when the
    /// registration names one: a Corporate Profile signed in through the
    /// connection is that organization's. None for an issuer that signs in
    /// identities of more than one origin.
    pub source: Option<OrgId>,
    /// The installation's issuer whose sign-in the connection serves.
    pub recipient_issuer: IssuerId,
    /// The exact redirect URI registered at the issuer; never changes.
    pub callback: String,
    /// Where a holder's browser goes back to the issuer's side after
    /// authenticating here for a use that side coordinates: the exact URL
    /// the connection's provisioning supplied as data (the coordinating
    /// service derives it from its own route and mount), to which only the
    /// use's continuation is appended. Not the callback above, which points
    /// the other way, and never taken from a request. None for a connection
    /// without such a route; a use that needs one is then refused.
    pub use_return: Option<String>,
    /// This installation's client id at the issuer.
    pub client_id: String,
    pub credential: ClientCredential,
    /// Whether entries are started and completed through it now.
    pub enabled: bool,
    /// Stored revision: 0 when created, moved on by every change. A change
    /// applies only over the revision it was read at.
    pub revision: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl EntryConnection {
    /// Whether `changed` is this same registration with only what may
    /// change: its name, its client and credential, and whether it is
    /// enabled. Its handle, owner, issuer, source, recipient issuer,
    /// callback and use return are its identity.
    pub fn same_registration(&self, changed: &Self) -> bool {
        self.handle == changed.handle
            && self.owner == changed.owner
            && self.issuer == changed.issuer
            && self.source == changed.source
            && self.recipient_issuer == changed.recipient_issuer
            && self.callback == changed.callback
            && self.use_return == changed.use_return
            && self.created_at == changed.created_at
    }
}

#[cfg(test)]
mod tests;
