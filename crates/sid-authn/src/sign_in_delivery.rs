// SPDX-License-Identifier: AGPL-3.0-only
//! How a sign-in ceremony hands its session's credential to the client:
//! the configured browser sign-in page gets the HttpOnly session cookie, a
//! native client the access token in a response header, never the message.

use chrono::{DateTime, Utc};
use prost::Message;
use secrecy::ExposeSecret;
use sid_core::models::Session;
use sid_proto::sid::v1::authn::NativeCredentialSet;

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

/// A browser request from anywhere but the configured sign-in page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a browser signs in only on the configured sign-in page")]
pub struct NotSignInPage;

/// Who completes a sign-in ceremony whose request sent the `Origin` values
/// `origins` (`None` for a value that is not text), and so how its
/// credential is delivered: a request without `Origin` is a native client;
/// a browser sends `Origin` on every such request (Fetch §3.1), and only the
/// sign-in page at `sign_in_origin` may complete one, by exactly one `Origin`
/// equal to that page's. Any other browser request, including `null`, a
/// repeated `Origin` or one with no sign-in page configured, is refused
/// rather than answered as a native client: it is the login-CSRF defence of
/// the cookie and keeps the token out of page scripts.
pub fn ceremony_client<'a>(
    origins: impl IntoIterator<Item = Option<&'a str>>,
    sign_in_origin: Option<&url::Origin>,
) -> Result<CeremonyClient, NotSignInPage> {
    let mut origins = origins.into_iter();
    let Some(origin) = origins.next() else {
        return Ok(CeremonyClient::Native);
    };
    let sign_in_page = origins.next().is_none()
        && sign_in_origin
            .is_some_and(|allowed| origin.is_some_and(|origin| origin_is(origin, allowed)));
    if !sign_in_page {
        return Err(NotSignInPage);
    }
    Ok(CeremonyClient::Browser)
}

/// How a session's credential reaches its client, never in the message:
/// the adapter of the client's protocol puts it in the response headers.
pub enum Delivery {
    /// The `Set-Cookie` value of the browser's session cookie.
    Cookie(String),
    /// The session's access token, sent as `authorization: Bearer`, with the
    /// native session's refresh generation when the client proved its key.
    Bearer {
        token: secrecy::SecretString,
        refresh: Option<NativeCredentialSet>,
    },
}

impl Delivery {
    /// A native client's access token without a refresh generation.
    pub fn bearer(token: secrecy::SecretString) -> Self {
        Self::Bearer {
            token,
            refresh: None,
        }
    }

    /// The response header that carries the credential and its value, and
    /// the encoded refresh generation for
    /// [`crate::native_session::CREDENTIALS_METADATA`] when there is one.
    /// Both are live secrets.
    pub fn header(self) -> (&'static str, String, Option<Vec<u8>>) {
        match self {
            Self::Cookie(cookie) => ("set-cookie", cookie, None),
            Self::Bearer { token, refresh } => (
                "authorization",
                format!("Bearer {}", token.expose_secret()),
                refresh.map(|refresh| refresh.encode_to_vec()),
            ),
        }
    }
}

/// A session a sign-in ceremony created: its id, the lifetime of the
/// credential delivered, and that credential.
pub struct SignedIn {
    pub session_id: sid_ids::SessionId,
    pub expires_in: i64,
    pub delivery: Delivery,
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
            session_id: session.id,
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
        seal_retained(
            keys,
            context,
            &Retained {
                session: session.id,
                deadline,
                credential: RetainedCredential::Browser {
                    secret: self.0.encode().to_string(),
                },
            },
        )
        .await
    }
}

/// A native client's credential for a session: its access token, until
/// when that token is valid, and the session's first generation when the
/// client proved its key.
pub struct BearerCredential<'a> {
    pub token: &'a secrecy::SecretString,
    pub token_expires_at: DateTime<Utc>,
    pub refresh: Option<&'a NativeCredentialSet>,
}

/// A native sign-in's delivery of `credential` for `session`, sealed under
/// `keys` to `context` until `deadline`: what a lost response is answered
/// with again.
pub async fn retain_bearer<O>(
    keys: &dyn sid_keys::KeyManager,
    context: &str,
    session: &Session<O>,
    credential: BearerCredential<'_>,
    deadline: DateTime<Utc>,
) -> Result<Vec<u8>, SealedSecretError> {
    seal_retained(
        keys,
        context,
        &Retained {
            session: session.id,
            deadline,
            credential: RetainedCredential::Bearer {
                token: credential.token.expose_secret().to_owned(),
                token_expires_at: credential.token_expires_at,
                refresh: credential.refresh.map(Message::encode_to_vec),
            },
        },
    )
    .await
}

async fn seal_retained(
    keys: &dyn sid_keys::KeyManager,
    context: &str,
    retained: &Retained,
) -> Result<Vec<u8>, SealedSecretError> {
    let plain =
        zeroize::Zeroizing::new(serde_json::to_vec(retained).expect("a retained delivery encodes"));
    sealed_secret::seal(keys, context, &plain).await
}

/// A sign-in's delivery kept for a lost response, as sealed: the one form
/// the store holds (an earlier form goes with the database it was in).
#[derive(serde::Serialize, serde::Deserialize)]
struct Retained {
    session: sid_ids::SessionId,
    deadline: DateTime<Utc>,
    credential: RetainedCredential,
}

/// The credential a retained delivery hands out again.
#[derive(serde::Serialize, serde::Deserialize)]
enum RetainedCredential {
    /// The browser's session cookie secret.
    Browser { secret: String },
    /// A native client's access token, its expiry and the encoded first
    /// generation.
    Bearer {
        token: String,
        token_expires_at: DateTime<Utc>,
        refresh: Option<Vec<u8>>,
    },
}

/// The credential of an opened retained delivery.
enum Opened {
    Browser(BrowserCredential),
    Bearer {
        token: secrecy::SecretString,
        token_expires_at: DateTime<Utc>,
        refresh: Option<NativeCredentialSet>,
    },
}

/// A retained delivery opened again: the session it names, until when it
/// may be redelivered, and its credential.
pub struct RetainedDelivery {
    pub session_id: sid_ids::SessionId,
    pub deadline: DateTime<Utc>,
    credential: Opened,
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
        let credential = match retained.credential {
            RetainedCredential::Browser { secret } => Opened::Browser(BrowserCredential(
                BrowserSecret::decode(&secret).ok_or(SealedSecretError::NotSealed)?,
            )),
            RetainedCredential::Bearer {
                token,
                token_expires_at,
                refresh,
            } => Opened::Bearer {
                token: token.into(),
                token_expires_at,
                refresh: refresh
                    .map(|bytes| NativeCredentialSet::decode(bytes.as_slice()))
                    .transpose()
                    .map_err(|_| SealedSecretError::NotSealed)?,
            },
        };
        Ok(Self {
            session_id: retained.session,
            deadline: retained.deadline,
            credential,
        })
    }

    /// The access token a native delivery carries, for a protocol that
    /// returns it in its own message (a step-up's rotated token).
    pub fn into_bearer_token(self) -> Option<secrecy::SecretString> {
        match self.credential {
            Opened::Bearer { token, .. } => Some(token),
            Opened::Browser(_) => None,
        }
    }

    /// One refresh credential of the native first generation this delivery
    /// carries, to tell whether that generation is still the session's.
    pub fn refresh_credential(&self) -> Option<&str> {
        match &self.credential {
            Opened::Bearer {
                refresh: Some(set), ..
            } => set.refresh_credentials.first().map(String::as_str),
            _ => None,
        }
    }

    /// The same sign-in delivered again for the stored `session` it names:
    /// a browser's only while that session still stores this credential's
    /// hash; none for any other session.
    pub fn signed_in<O>(self, cookie: &BrowserCookie, session: &Session<O>) -> Option<SignedIn> {
        if session.id != self.session_id {
            return None;
        }
        match self.credential {
            Opened::Browser(credential) => (session.browser_secret_hash
                == Some(credential.0.hash()))
            .then(|| credential.signed_in(cookie, session)),
            // The token as issued: its lifetime is what remains of it.
            Opened::Bearer {
                token,
                token_expires_at,
                refresh,
            } => Some(SignedIn {
                session_id: session.id,
                expires_in: (token_expires_at.min(session.expires_at) - Utc::now()).num_seconds(),
                delivery: Delivery::Bearer { token, refresh },
            }),
        }
    }
}

#[cfg(test)]
mod tests;
