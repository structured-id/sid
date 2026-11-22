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

/// The prefix of the same cookie widened to a domain: a browser accepts it
/// only with `Secure`, and unlike `__Host-` it may carry `Domain`
/// (RFC 6265bis §4.1.3.1).
const SECURE_PREFIX: &str = "__Secure-";

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

    /// The cookie of the issuer `handle` names: issuers sharing a host each
    /// have their own, derived from the issuer rather than configured.
    pub fn for_issuer(handle: &sid_core::models::IssuerHandle) -> Self {
        // A handle is lowercase hex, so the name is always a `__Host-` token.
        Self {
            name: format!("{DEFAULT_COOKIE_NAME}-{handle}"),
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
            secret.encode().as_str(),
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

    /// The name this cookie takes widened to a domain: `__Secure-` in place
    /// of `__Host-`, since a browser rejects a `__Host-` cookie with `Domain`
    /// (RFC 6265bis §4.1.3.2).
    pub fn domain_name(&self) -> String {
        let rest = self
            .name
            .strip_prefix(HOST_PREFIX)
            .expect("a browser cookie name is a __Host- name");
        format!("{SECURE_PREFIX}{rest}")
    }

    /// `set`, a `Set-Cookie` value [`set`](Self::set) or
    /// [`clear`](Self::clear) of this cookie made, for `domain` and its
    /// subdomains: the same value and lifetime under [`domain_name`]
    /// (Self::domain_name) with `Domain`. None for another cookie's value.
    pub fn for_domain(&self, set: &str, domain: &str) -> Option<String> {
        let (pair, attributes) = set.split_once(';')?;
        let value = pair.strip_prefix(self.name.as_str())?.strip_prefix('=')?;
        let max_age = attributes
            .split(';')
            .find_map(|a| a.trim().strip_prefix("Max-Age="))?;
        Some(format!(
            "{}={value}; Domain={domain}; {ATTRIBUTES}; Max-Age={max_age}",
            self.domain_name()
        ))
    }

    /// The `Set-Cookie` value that removes this cookie widened to `domain`.
    pub fn clear_for_domain(&self, domain: &str) -> String {
        format!(
            "{}=; Domain={domain}; {ATTRIBUTES}; Max-Age=0",
            self.domain_name()
        )
    }

    /// The `Cookie` request header values `headers` with this cookie's
    /// domain-widened copy resolved: when `admitted` it is read in place of
    /// this cookie (its pairs take this cookie's name, a host-only pair gives
    /// way to it); otherwise it is dropped. Also whether such a copy was
    /// present. Other cookies are kept as sent.
    pub fn with_domain_variant<'a>(
        &self,
        headers: impl IntoIterator<Item = &'a str>,
        admitted: bool,
    ) -> (Vec<String>, bool) {
        let domain_name = self.domain_name();
        let headers: Vec<&str> = headers.into_iter().collect();
        let named =
            |pair: &str, name: &str| pair.trim().split_once('=').is_some_and(|(n, _)| n == name);
        let present = headers
            .iter()
            .any(|h| h.split(';').any(|p| named(p, &domain_name)));
        if !present {
            return (headers.into_iter().map(str::to_owned).collect(), false);
        }
        let rewritten = headers
            .into_iter()
            .map(|header| {
                header
                    .split(';')
                    .filter_map(|pair| {
                        if named(pair, &domain_name) {
                            admitted.then(|| {
                                let value = pair.trim().split_once('=').map_or("", |(_, v)| v);
                                format!("{}={value}", self.name)
                            })
                        } else if admitted && named(pair, &self.name) {
                            None
                        } else {
                            Some(pair.trim().to_owned())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .filter(|header| !header.is_empty())
            .collect();
        (rewritten, true)
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

    /// The secret as its holder carries it: unpadded base64url, the value of
    /// its cookie or of a native client's bearer.
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_ref()))
    }

    /// The secret `value` carries, when it is exactly 32 bytes of unpadded
    /// base64url: what a transport adapter reads from a presented bearer.
    pub fn decode(value: &str) -> Option<Self> {
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

    /// The session's token bound to `context` as well (an operation and the
    /// revision reviewed): HMAC-SHA-256 keyed by the token (RFC 2104). Only
    /// a holder of the session's token makes it, and it matches no other
    /// context, so a value for an earlier revision or another operation is
    /// useless.
    pub fn bound(token: &BrowserCsrfToken, context: &[u8]) -> [u8; 32] {
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(token.as_bytes())
            .expect("HMAC takes a key of any length");
        mac.update(context);
        mac.finalize().into_bytes().into()
    }

    /// Whether `sent` is the session's token bound to `context`, compared in
    /// constant time.
    pub fn bound_matches(sent: &[u8], token: &BrowserCsrfToken, context: &[u8]) -> bool {
        let expected = Self::bound(token, context);
        sent.len() == expected.len() && bool::from(sent.ct_eq(&expected))
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

/// Whether a cookie may name `host` in its `Domain` attribute and so reach
/// its subdomains: a domain name that is not itself a public suffix. A
/// browser ignores `Domain` naming a public suffix (RFC 6265bis §5.7 step
/// 9), and an address or `localhost` has no subdomains to share with.
pub fn domain_cookie_allowed(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => registrable(&domain.to_ascii_lowercase()).is_some(),
        _ => false,
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
