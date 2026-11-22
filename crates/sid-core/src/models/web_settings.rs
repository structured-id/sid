// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings: its public URL override, where
//! the administration console is served and the domain scope of its browser
//! session cookie.

use serde::{Deserialize, Serialize};

/// Where the installation's browser session cookie is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "snake_case")]
pub enum CookieScope {
    /// The exact public host only: a host-only cookie.
    #[default]
    ThisHost,
    /// The base domain and every subdomain, including future ones: the
    /// cookie carries `Domain` and reaches every server under it.
    AllSubdomains,
    /// The base domain and the subdomains named in `hosts` or matched by
    /// `pattern` (whole normalized host name); each establishes its own
    /// host-only cookie through the installation's session endpoint served
    /// there.
    SelectedSubdomains {
        /// Full lowercase host names, each a descendant of the base domain.
        hosts: Vec<String>,
        /// A regular expression matched against a descendant's whole name.
        pattern: Option<String>,
    },
}

impl CookieScope {
    /// Whether `self` admits strictly fewer hosts than `before`: the cookie
    /// and the secrets shared under `before` must not keep access.
    pub fn narrows(&self, before: &CookieScope) -> bool {
        match (before, self) {
            (Self::AllSubdomains, Self::AllSubdomains) => false,
            (Self::AllSubdomains, _) => true,
            (Self::SelectedSubdomains { .. }, Self::ThisHost) => true,
            // A host no longer listed is lost; a pattern changed or removed
            // may admit fewer names, so only an unchanged or newly added
            // pattern keeps the former hosts for certain.
            (
                Self::SelectedSubdomains {
                    hosts: old_hosts,
                    pattern: old_pattern,
                },
                Self::SelectedSubdomains { hosts, pattern },
            ) => {
                old_hosts.iter().any(|h| !hosts.contains(h))
                    || (old_pattern.is_some() && old_pattern != pattern)
            }
            _ => false,
        }
    }
}

/// The installation's stored browser-facing settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSettings {
    /// The public URL an administrator set for a deployment behind a reverse
    /// proxy; `None` uses the installation's own URL.
    pub public_url: Option<String>,
    /// Where the administration console is served, ending with `/`; `None`
    /// is the default, `/admin/` on the public URL.
    pub console_url: Option<String>,
    /// The session cookie's domain scope.
    pub cookie_scope: CookieScope,
    /// Changes of these settings so far: 0 while never changed.
    pub revision: u64,
}

/// The console's default base path on the public URL.
pub const DEFAULT_CONSOLE_PATH: &str = "/admin/";

/// Whether `path` can mount a web UI: absolute, ending with `/`, literal
/// (unreserved characters and `/`, RFC 3986 §2.3) and free of empty, `.` or
/// `..` segments, which a browser would normalize away (WHATWG URL, path
/// state), leaving the UI unreachable.
pub fn is_ui_mount(path: &str) -> bool {
    path.starts_with('/')
        && path.ends_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
        && !path.contains("//")
        && !path.split('/').any(|s| s == "." || s == "..")
}

#[cfg(test)]
mod tests;
