// SPDX-License-Identifier: AGPL-3.0-only
//! The protected context of a ceremony operation that takes several steps
//! before any login session exists, such as a registration whose client
//! stages data between its start and its finish.
//!
//! The operation's id names it but is no secret: it travels in messages and
//! other services see it. The context is: a 256-bit secret the operation
//! stores only the hash of, delivered at the start like a session credential
//! (an HttpOnly transaction cookie of its own name for the browser sign-in
//! page, `authorization` response metadata for a native client, never the
//! message), plus a CSRF token for the browser. Every later step presents
//! it over the same transport, so only the client that started the operation
//! continues it, and a page on another site cannot.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_core::grpc_error::refuse::internal;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::BrowserCsrfToken;
use subtle::ConstantTimeEq;
use tonic::Status;
use tonic::metadata::{MetadataMap, MetadataValue};

use crate::browser_session::{BrowserCookie, BrowserCsrf, BrowserSecret, CSRF_HEADER};
use crate::sign_in_delivery::{CeremonyClient, ceremony_client};

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

    /// Put the context into the start's response `metadata`: for the
    /// browser the transaction `cookie`, living until the operation's
    /// `expires_at` and no longer, and the CSRF token in [`CSRF_HEADER`] of
    /// this origin-checked response; for a native client the secret as
    /// `authorization: Bearer`.
    #[allow(clippy::result_large_err)]
    pub fn deliver(
        self,
        cookie: &BrowserCookie,
        expires_at: DateTime<Utc>,
        metadata: &mut MetadataMap,
    ) -> Result<(), Status> {
        match self.csrf {
            Some(csrf) => {
                let max_age = (expires_at - Utc::now()).num_seconds();
                insert(metadata, "set-cookie", cookie.set(&self.secret, max_age))?;
                insert(metadata, CSRF_HEADER, BrowserCsrf::encode(&csrf))
            }
            None => insert(
                metadata,
                "authorization",
                format!("Bearer {}", self.secret.encode().as_str()),
            ),
        }
    }
}

impl CeremonyBinding {
    /// Whether the request with `metadata` continues this operation: a
    /// browser by exactly the sign-in page's Origin, the transaction
    /// `cookie` and the CSRF token; a native client by the bearer secret. A
    /// context continues only over the transport it was opened for, and a
    /// browser request from any other Origin is refused, never taken as
    /// native.
    #[allow(clippy::result_large_err)]
    pub fn admit(
        &self,
        metadata: &MetadataMap,
        cookie: &BrowserCookie,
        sign_in_origin: Option<&url::Origin>,
    ) -> Result<(), Status> {
        match (ceremony_client(metadata, sign_in_origin)?, self.csrf) {
            (CeremonyClient::Browser, Some(csrf)) => {
                let cookies = metadata
                    .get_all("cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok());
                self.check(cookie.secret(cookies))?;
                // Checked after the secret: the token only binds a request
                // to a context it already holds.
                let sent = metadata
                    .get_all(CSRF_HEADER)
                    .iter()
                    .filter_map(|v| v.to_str().ok());
                if BrowserCsrf::matches(sent, &BrowserCsrfToken::from_bytes(csrf)) {
                    Ok(())
                } else {
                    Err(ApiError::new(
                        ErrorReason::InsufficientPermissions,
                        "the request does not carry this operation's CSRF token",
                    )
                    .into())
                }
            }
            (CeremonyClient::Native, None) => self.check(bearer(metadata)),
            _ => Err(context_refused()),
        }
    }

    #[allow(clippy::result_large_err)]
    fn check(&self, secret: Option<BrowserSecret>) -> Result<(), Status> {
        let presented = secret.ok_or_else(context_refused)?.hash();
        if bool::from(presented.as_bytes().ct_eq(&self.secret_hash)) {
            Ok(())
        } else {
            Err(context_refused())
        }
    }
}

/// The secret of the single `authorization: Bearer` value in `metadata`.
/// Two values are ambiguous and present none (RFC 9110 §11.6.2 allows one).
fn bearer(metadata: &MetadataMap) -> Option<BrowserSecret> {
    let mut values = metadata.get_all("authorization").iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let (scheme, secret) = value.to_str().ok()?.split_once(' ')?;
    // RFC 9110 §11.1: the auth-scheme is case-insensitive.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    BrowserSecret::decode(secret.trim())
}

fn context_refused() -> Status {
    ApiError::new(
        ErrorReason::TokenInvalid,
        "the request does not hold this operation's ceremony context",
    )
    .into()
}

#[allow(clippy::result_large_err)]
fn insert(metadata: &mut MetadataMap, name: &'static str, value: String) -> Result<(), Status> {
    let mut value: MetadataValue<_> = value
        .parse()
        .map_err(|e| internal("encode ceremony context", e))?;
    // A live secret or its CSRF token: kept out of debug output and HPACK
    // indexing.
    value.set_sensitive(true);
    metadata.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests;
