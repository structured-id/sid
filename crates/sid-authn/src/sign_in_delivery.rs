// SPDX-License-Identifier: AGPL-3.0-only
//! How a sign-in ceremony hands its session's credential to the client:
//! the configured browser sign-in page gets the HttpOnly session cookie, a
//! native client the access token in response metadata, never the message.

use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use sid_core::grpc_error::refuse::internal;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::Session;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Response, Status};

use crate::browser_session::{BrowserCookie, BrowserCsrf, BrowserSecret, origin_is};
use crate::sealed_secret::{self, SealedSecretError};

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
    /// A fresh secret, whose hash `session` now stores together with a fresh
    /// CSRF token of its own.
    pub fn bind<O>(session: &mut Session<O>) -> Self {
        let secret = BrowserSecret::generate();
        session.browser_secret_hash = Some(secret.hash());
        session.browser_csrf = Some(BrowserCsrf::generate());
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

    /// This credential of `session`, sealed under `keys` to `context` (one
    /// operation of one issuer) until `deadline`: what a lost response is
    /// answered with again. The session itself stores only the hash.
    pub async fn retain<O>(
        &self,
        keys: &dyn sid_keys::KeyManager,
        context: &str,
        session: &Session<O>,
        deadline: DateTime<Utc>,
    ) -> Result<Vec<u8>, SealedSecretError> {
        let retained = Retained {
            session: session.id.to_string(),
            secret: self.0.encode().to_string(),
            deadline,
        };
        let plain = zeroize::Zeroizing::new(
            serde_json::to_vec(&retained).expect("a retained delivery encodes"),
        );
        sealed_secret::seal(keys, context, &plain).await
    }
}

/// A browser sign-in's delivery kept for a lost response, as sealed.
#[derive(serde::Serialize, serde::Deserialize)]
struct Retained {
    session: String,
    secret: String,
    deadline: DateTime<Utc>,
}

/// A retained browser delivery opened again: the session it names, until
/// when it may be redelivered, and its credential.
pub struct RetainedDelivery {
    pub session_id: String,
    pub deadline: DateTime<Utc>,
    credential: BrowserCredential,
}

impl RetainedDelivery {
    /// The delivery `sealed` under `keys` for `context`; a value sealed for
    /// another context or malformed is an error.
    pub async fn open(
        keys: &dyn sid_keys::KeyManager,
        context: &str,
        sealed: &[u8],
    ) -> Result<Self, SealedSecretError> {
        let opened = sealed_secret::open(keys, context, sealed).await?;
        let retained: Retained =
            serde_json::from_slice(&opened.secret).map_err(|_| SealedSecretError::NotSealed)?;
        let secret = BrowserSecret::decode(&retained.secret).ok_or(SealedSecretError::NotSealed)?;
        Ok(Self {
            session_id: retained.session,
            deadline: retained.deadline,
            credential: BrowserCredential(secret),
        })
    }

    /// The same sign-in delivered again for the stored `session` it names,
    /// only while that session still stores this credential's hash: none for
    /// any other session.
    pub fn signed_in<O>(self, cookie: &BrowserCookie, session: &Session<O>) -> Option<SignedIn> {
        let matches = session.id.to_string() == self.session_id
            && session.browser_secret_hash == Some(self.credential.0.hash());
        matches.then(|| self.credential.signed_in(cookie, session))
    }
}

#[cfg(test)]
mod tests;
