// SPDX-License-Identifier: AGPL-3.0-only
//! How a sign-in ceremony hands its session's credential to the client:
//! the configured browser sign-in page gets the HttpOnly session cookie, a
//! native client the access token in response metadata, never the message.

use chrono::Utc;
use secrecy::ExposeSecret;
use sid_core::grpc_error::refuse::internal;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::Session;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Response, Status};

use crate::browser_session::{BrowserCookie, BrowserSecret, origin_is};

/// Who completes a sign-in ceremony: the browser sign-in page or a native
/// client. It decides how the session's credential is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyClient {
    /// The configured sign-in page: the credential is the HttpOnly session
    /// cookie, and no access token is issued.
    Browser,
    /// A client without `Origin`: the access token in `authorization`
    /// response metadata.
    Native,
}

/// Who completes a sign-in ceremony sent with `metadata`, and so how its
/// credential is delivered: a request without `Origin` is a native client;
/// a browser sends `Origin` on every such request (Fetch §3.1), and only the
/// sign-in page at `sign_in_origin` may complete one, by exactly one `Origin`
/// equal to that page's. Any other browser request, including `null`, a
/// repeated `Origin` or one with no sign-in page configured, is refused
/// rather than answered as a native client: it is the login-CSRF defence of
/// the cookie and keeps the token out of page scripts.
#[allow(clippy::result_large_err)]
pub fn ceremony_client(
    metadata: &MetadataMap,
    sign_in_origin: Option<&url::Origin>,
) -> Result<CeremonyClient, Status> {
    let mut origins = metadata.get_all("origin").iter();
    let Some(origin) = origins.next() else {
        return Ok(CeremonyClient::Native);
    };
    let sign_in_page = origins.next().is_none()
        && sign_in_origin.is_some_and(|allowed| {
            origin
                .to_str()
                .is_ok_and(|origin| origin_is(origin, allowed))
        });
    if !sign_in_page {
        return Err(ApiError::new(
            ErrorReason::SignInRefused,
            "a browser signs in only on the configured sign-in page",
        )
        .into());
    }
    Ok(CeremonyClient::Browser)
}

/// How a session's credential reaches its client, never in the message.
pub enum Delivery {
    /// The `Set-Cookie` value of the browser's session cookie.
    Cookie(String),
    /// The session's access token, sent as `authorization: Bearer`.
    Bearer(secrecy::SecretString),
}

impl Delivery {
    /// Put the credential into `metadata`.
    #[allow(clippy::result_large_err)]
    pub fn deliver(self, metadata: &mut MetadataMap) -> Result<(), Status> {
        let (name, value) = match self {
            Self::Cookie(cookie) => ("set-cookie", cookie),
            Self::Bearer(token) => ("authorization", format!("Bearer {}", token.expose_secret())),
        };
        let mut value: MetadataValue<_> = value
            .parse()
            .map_err(|e| internal("encode session credential", e))?;
        // A live credential: kept out of debug output and HPACK indexing.
        value.set_sensitive(true);
        metadata.insert(name, value);
        Ok(())
    }
}

/// A session a sign-in ceremony created: its id, the lifetime of the
/// credential delivered, and that credential.
pub struct SignedIn {
    pub session_id: String,
    pub expires_in: i64,
    pub delivery: Delivery,
}

impl SignedIn {
    /// The ceremony's answer `message` builds from the session id and the
    /// credential's lifetime, its credential in the response metadata.
    #[allow(clippy::result_large_err)]
    pub fn respond<T>(self, message: impl FnOnce(String, i64) -> T) -> Result<Response<T>, Status> {
        let mut response = Response::new(message(self.session_id, self.expires_in));
        self.delivery.deliver(response.metadata_mut())?;
        Ok(response)
    }
}

/// A browser sign-in's secret, bound to its session before the session is
/// stored and delivered in the cookie once it is.
pub struct BrowserCredential(BrowserSecret);

impl BrowserCredential {
    /// A fresh secret, whose hash `session` now stores.
    pub fn bind<O>(session: &mut Session<O>) -> Self {
        let secret = BrowserSecret::generate();
        session.browser_secret_hash = Some(secret.hash());
        Self(secret)
    }

    /// The stored `session`'s sign-in, its secret in `cookie`. The cookie
    /// lives for what remains of the session now, after storing it took
    /// its time, so it never outlives the session it names.
    pub fn signed_in<O>(self, cookie: &BrowserCookie, session: &Session<O>) -> SignedIn {
        let expires_in = (session.expires_at - Utc::now()).num_seconds();
        SignedIn {
            session_id: session.id.to_string(),
            expires_in,
            delivery: Delivery::Cookie(cookie.set(&self.0, expires_in)),
        }
    }
}

#[cfg(test)]
mod tests;
