// SPDX-License-Identifier: AGPL-3.0-only
//! The IdP browser session: the random secret an authority's browser cookie
//! holds, the cookie itself, and the same-site relation the sign-in page and
//! the issuer host must share for the ceremony response to set it. The
//! session stores only the secret's hash.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use sha2::{Digest, Sha256};
use sid_core::models::{BrowserCsrfToken, BrowserSecretHash};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The cookie name of an authority that is alone on its host.
pub const DEFAULT_COOKIE_NAME: &str = "__Host-sid_session";

/// The prefix that makes a browser accept a cookie only with `Secure`,
/// `Path=/` and no `Domain`, so it binds to the one host that set it
/// (RFC 6265bis §4.1.3.2).
const HOST_PREFIX: &str = "__Host-";

/// Attributes every value of the cookie carries: host-only, TLS only, out of
/// reach of scripts, and sent on top-level navigations from other sites but
/// not on their subrequests or POSTs (RFC 6265bis §5.6.7.1).
const ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";

/// A cookie name that is not a `__Host-` token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("browser session cookie name {0:?} is not a __Host- cookie token")]
pub struct InvalidCookieName(String);

/// One authority's browser-session cookie. Authorities that share a host
/// each have their own name and read, set and clear only that cookie, so one
/// sign-in never replaces or reads another authority's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCookie {
    name: String,
}

impl Default for BrowserCookie {
    fn default() -> Self {
        Self {
            name: DEFAULT_COOKIE_NAME.to_owned(),
        }
    }
}

impl BrowserCookie {
    /// The cookie named `name`: `__Host-` and at least one more token
    /// character (RFC 6265bis §4.1.1 cookie-name, RFC 9110 §5.6.2 tchar).
    pub fn new(name: &str) -> Result<Self, InvalidCookieName> {
        let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
        match name.strip_prefix(HOST_PREFIX) {
            Some(rest) if !rest.is_empty() && rest.bytes().all(token) => Ok(Self {
                name: name.to_owned(),
            }),
            _ => Err(InvalidCookieName(name.to_owned())),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `Set-Cookie` value carrying `secret` for `max_age_secs` seconds,
    /// which the caller bounds by the session's absolute expiry.
    pub fn set(&self, secret: &BrowserSecret, max_age_secs: i64) -> String {
        format!(
            "{}={}; {ATTRIBUTES}; Max-Age={}",
            self.name,
            URL_SAFE_NO_PAD.encode(secret.0.as_ref()),
            max_age_secs.max(0)
        )
    }

    /// The secret in the `Cookie` request header values `headers`, when this
    /// cookie is present exactly once and holds a well-formed secret. Two
    /// values are ambiguous and name no session: a `__Host-` cookie has one
    /// host and one path, so a browser never sends two. Other cookies,
    /// including other authorities' sessions, are ignored.
    pub fn secret<'a>(&self, headers: impl IntoIterator<Item = &'a str>) -> Option<BrowserSecret> {
        let mut found = None;
        for header in headers {
            // RFC 6265bis §4.2.1: cookie-pair *( ";" SP cookie-pair ).
            for pair in header.split(';') {
                let Some((name, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                if name != self.name {
                    continue;
                }
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
        BrowserSecret::decode(found?)
    }

    /// The `Set-Cookie` value that removes this cookie; its attributes match
    /// the ones that set it, so the browser replaces that cookie
    /// (RFC 6265bis §5.7).
    pub fn clear(&self) -> String {
        format!("{}=; {ATTRIBUTES}; Max-Age=0", self.name)
    }
}

/// A browser session's 256-bit secret.
pub struct BrowserSecret(Zeroizing<[u8; 32]>);

impl BrowserSecret {
    /// A fresh secret from the operating system's generator.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(bytes.as_mut())
            .expect("the operating system random source is available");
        Self(bytes)
    }

    /// The hash a session stores in place of the secret.
    pub fn hash(&self) -> BrowserSecretHash {
        BrowserSecretHash::from_bytes(Sha256::digest(self.0.as_ref()).into())
    }

    fn decode(value: &str) -> Option<Self> {
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).ok()?);
        let bytes: [u8; 32] = decoded.as_slice().try_into().ok()?;
        Some(Self(Zeroizing::new(bytes)))
    }
}

/// The request header a page echoes its session's CSRF token in.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// A browser session's CSRF token, as the session stores it and as the page
/// receives and echoes it: the synchronizer token pattern, bound to the one
/// session it was generated with (OWASP CSRF Prevention Cheat Sheet,
/// "Synchronizer Token Pattern").
pub struct BrowserCsrf;

impl BrowserCsrf {
    /// A fresh token from the operating system's generator.
    pub fn generate() -> BrowserCsrfToken {
        let mut bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .expect("the operating system random source is available");
        BrowserCsrfToken::from_bytes(bytes)
    }

    /// The token as the page receives it.
    pub fn encode(token: &BrowserCsrfToken) -> String {
        URL_SAFE_NO_PAD.encode(token.as_bytes())
    }

    /// Whether `sent`, the [`CSRF_HEADER`] values of a request, is exactly
    /// one value equal to `token`, compared in constant time so a mismatch
    /// says nothing about how much of a guess was right.
    pub fn matches<'a>(sent: impl IntoIterator<Item = &'a str>, token: &BrowserCsrfToken) -> bool {
        let mut sent = sent.into_iter();
        let (Some(value), None) = (sent.next(), sent.next()) else {
            return false;
        };
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(value) else {
            return false;
        };
        decoded.len() == token.as_bytes().len()
            && bool::from(decoded.as_slice().ct_eq(token.as_bytes()))
    }
}

/// Whether the request's `Origin` header value `origin` is exactly `allowed`
/// (RFC 6454 §7). `null` and anything but the serialized origin match nothing.
pub fn origin_is(origin: &str, allowed: &url::Origin) -> bool {
    allowed.is_tuple() && origin == allowed.ascii_serialization()
}

/// Whether `a` and `b` are the same site: the same scheme and the same
/// registrable domain under the Public Suffix List; ports and sub-domains
/// may differ (HTML "same site", RFC 6265bis §5.2). A host with no
/// registrable domain (an IP address, `localhost`) is the same site only as
/// itself.
pub fn same_site(a: &url::Url, b: &url::Url) -> bool {
    if a.scheme() != b.scheme() {
        return false;
    }
    let (Some(a), Some(b)) = (a.host(), b.host()) else {
        return false;
    };
    match (a, b) {
        (url::Host::Domain(a), url::Host::Domain(b)) => {
            let a = a.to_ascii_lowercase();
            let b = b.to_ascii_lowercase();
            match (registrable(&a), registrable(&b)) {
                (Some(a), Some(b)) => a == b,
                _ => a == b,
            }
        }
        (a, b) => a == b,
    }
}

/// The registrable domain of `host`, under the list's implicit `*` rule for
/// a suffix it does not name, as browsers apply it; none for a host that is
/// itself a public suffix, such as `localhost`.
fn registrable(host: &str) -> Option<&str> {
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.trim().as_bytes()).ok()
}

#[cfg(test)]
mod tests;
