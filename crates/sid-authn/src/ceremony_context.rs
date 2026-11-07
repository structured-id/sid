// SPDX-License-Identifier: AGPL-3.0-only
//! The protected context of a ceremony operation that takes several steps
//! before any login session exists, such as a registration whose client
//! stages data between its start and its finish.
//!
//! The operation's id names it but is no secret: it travels in messages and
//! other services see it. The context is: a 256-bit secret the operation
//! stores only the hash of, delivered at the start like a session credential
//! (an HttpOnly transaction cookie of its own name for the browser sign-in
//! page, `authorization` in the response for a native client, never the
//! message), plus a CSRF token for the browser. Every later step presents
//! it over the same transport, so only the client that started the operation
//! continues it, and a page on another site cannot.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_core::models::BrowserCsrfToken;
use subtle::ConstantTimeEq;

use crate::browser_session::{BrowserCookie, BrowserCsrf, BrowserSecret, CSRF_HEADER};
use crate::sign_in_delivery::CeremonyClient;

/// What an operation stores of its context: the secret's hash and, for a
/// browser, the CSRF token (kept as is, since the start returns it).
#[derive(Clone, Serialize, Deserialize)]
pub struct CeremonyBinding {
    secret_hash: [u8; 32],
    csrf: Option<[u8; 32]>,
}

impl std::fmt::Debug for CeremonyBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonyBinding")
            .field("browser", &self.csrf.is_some())
            .finish_non_exhaustive()
    }
}

/// A context just opened, until its start delivers it.
pub struct CeremonyContext {
    secret: BrowserSecret,
    csrf: Option<BrowserCsrfToken>,
}

impl CeremonyContext {
    /// A fresh context for `client` and the binding its operation stores.
    pub fn open(client: CeremonyClient) -> (Self, CeremonyBinding) {
        let secret = BrowserSecret::generate();
        let csrf = matches!(client, CeremonyClient::Browser).then(BrowserCsrf::generate);
        let binding = CeremonyBinding {
            secret_hash: *secret.hash().as_bytes(),
            csrf: csrf.map(|token| *token.as_bytes()),
        };
        (Self { secret, csrf }, binding)
    }

    /// The response headers the start delivers the context in, all live
    /// secrets: for the browser the transaction `cookie`, living until the
    /// operation's `expires_at` and no longer, and the CSRF token in
    /// [`CSRF_HEADER`] of this origin-checked response; for a native client
    /// the secret as `authorization: Bearer`. An HTTP front serving the page
    /// must expose [`CSRF_HEADER`] to its script and forward it on the next
    /// step, as sid-server's transcoder does.
    pub fn headers(
        self,
        cookie: &BrowserCookie,
        expires_at: DateTime<Utc>,
    ) -> Vec<(&'static str, String)> {
        match self.csrf {
            Some(csrf) => {
                let max_age = (expires_at - Utc::now()).num_seconds();
                vec![
                    ("set-cookie", cookie.set(&self.secret, max_age)),
                    (CSRF_HEADER, BrowserCsrf::encode(&csrf)),
                ]
            }
            None => vec![(
                "authorization",
                format!("Bearer {}", self.secret.encode().as_str()),
            )],
        }
    }
}

/// Why a step does not continue its operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyRefusal {
    /// The request does not hold this operation's context, or presents it
    /// over another transport than the one it was opened for.
    #[error("the request does not hold this operation's ceremony context")]
    NotHeld,
    /// The browser holds the context but not its CSRF token.
    #[error("the request does not carry this operation's CSRF token")]
    Csrf,
}

impl CeremonyBinding {
    /// Whether a step of `client` continues this operation by the `secret`
    /// it presents (the transaction cookie's for the browser, the single
    /// bearer's for a native client) and, for the browser, the values of
    /// [`CSRF_HEADER`] it sent. A context continues only over the transport
    /// it was opened for; which client a request is, the sign-in page's
    /// Origin included, is decided before
    /// ([`crate::sign_in_delivery::ceremony_client`]).
    pub fn admit<'a>(
        &self,
        client: CeremonyClient,
        secret: Option<BrowserSecret>,
        csrf_sent: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), CeremonyRefusal> {
        match (client, self.csrf) {
            (CeremonyClient::Browser, Some(csrf)) => {
                self.check(secret)?;
                // Checked after the secret: the token only binds a request
                // to a context it already holds.
                if BrowserCsrf::matches(csrf_sent, &BrowserCsrfToken::from_bytes(csrf)) {
                    Ok(())
                } else {
                    Err(CeremonyRefusal::Csrf)
                }
            }
            (CeremonyClient::Native, None) => self.check(secret),
            _ => Err(CeremonyRefusal::NotHeld),
        }
    }

    fn check(&self, secret: Option<BrowserSecret>) -> Result<(), CeremonyRefusal> {
        let presented = secret.ok_or(CeremonyRefusal::NotHeld)?.hash();
        if bool::from(presented.as_bytes().ct_eq(&self.secret_hash)) {
            Ok(())
        } else {
            Err(CeremonyRefusal::NotHeld)
        }
    }
}

#[cfg(test)]
mod tests;
