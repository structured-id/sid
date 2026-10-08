// SPDX-License-Identifier: AGPL-3.0-only
//! The IdP browser session: the random secret a browser's
//! `__Host-sid_session` cookie holds, the cookie itself, and the same-site
//! relation the sign-in page and the issuer host must share for the ceremony
//! response to set it. The session stores only the secret's hash.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use sha2::{Digest, Sha256};
use sid_core::models::BrowserSecretHash;
use zeroize::Zeroizing;

/// The cookie's name. The `__Host-` prefix makes a browser accept it only
/// with `Secure`, `Path=/` and no `Domain`, so it binds to the one host that
/// set it (RFC 6265bis §4.1.3.2).
pub const COOKIE_NAME: &str = "__Host-sid_session";

/// Attributes every value of the cookie carries: host-only, TLS only, out of
/// reach of scripts, and sent on top-level navigations from other sites but
/// not on their subrequests or POSTs (RFC 6265bis §5.6.7.1).
const ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";

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

    /// The `Set-Cookie` value carrying this secret for `max_age_secs`
    /// seconds, which the caller bounds by the session's absolute expiry.
    pub fn set_cookie(&self, max_age_secs: i64) -> String {
        format!(
            "{COOKIE_NAME}={}; {ATTRIBUTES}; Max-Age={}",
            URL_SAFE_NO_PAD.encode(self.0.as_ref()),
            max_age_secs.max(0)
        )
    }

    /// The secret in the `Cookie` request header values `headers`, when the
    /// cookie is present exactly once and holds a well-formed secret. Two
    /// values are ambiguous and name no session: a `__Host-` cookie has one
    /// host and one path, so a browser never sends two.
    pub fn from_cookie_headers<'a>(headers: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let mut found = None;
        for header in headers {
            // RFC 6265bis §4.2.1: cookie-pair *( ";" SP cookie-pair ).
            for pair in header.split(';') {
                let Some((name, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                if name != COOKIE_NAME {
                    continue;
                }
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
        Self::decode(found?)
    }

    fn decode(value: &str) -> Option<Self> {
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).ok()?);
        let bytes: [u8; 32] = decoded.as_slice().try_into().ok()?;
        Some(Self(Zeroizing::new(bytes)))
    }
}

/// The `Set-Cookie` value that removes the cookie; its attributes match the
/// ones that set it, so the browser replaces that cookie (RFC 6265bis §5.7).
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; {ATTRIBUTES}; Max-Age=0")
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
