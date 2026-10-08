// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID i18n — compile-time locale loading with selective compilation.
//!
//! Locale JSON files are embedded into the binary via `include_str!`.
//! Only locales enabled via Cargo feature flags are compiled in.
//! English is always available as the fallback locale.
//!
//! # Usage
//!
//! ```rust
//! use sid_i18n::{available_locales, t, negotiate_locale};
//!
//! // Check which locales are compiled
//! let locales = available_locales();
//! assert!(locales.contains(&"en"));
//!
//! // Get a translated string
//! let msg = t("en", "errors.auth.invalid_credentials");
//! assert_eq!(msg, Some("Invalid email or password"));
//!
//! // Negotiate locale from Accept-Language header
//! let locale = negotiate_locale("de, en;q=0.8, fr;q=0.5");
//! // Returns "de" if compiled, otherwise falls back to "en"
//! ```

mod negotiate;

use std::collections::HashMap;
use std::sync::OnceLock;

pub use negotiate::{negotiate_locale, parse_accept_language};

/// All known namespaces in the locale system.
pub const NAMESPACES: &[&str] = &[
    "auth",
    "errors",
    "common",
    "consent",
    "dashboard",
    "admin",
    "scim",
    "saml",
];

/// Returns the list of locales compiled into this binary.
pub fn available_locales() -> &'static [&'static str] {
    &[
        "en", // Always present
        #[cfg(feature = "i18n-ru")]
        "ru",
        #[cfg(feature = "i18n-de")]
        "de",
        #[cfg(feature = "i18n-fr")]
        "fr",
        #[cfg(feature = "i18n-es")]
        "es",
        #[cfg(feature = "i18n-it")]
        "it",
        #[cfg(feature = "i18n-nl")]
        "nl",
        #[cfg(feature = "i18n-pl")]
        "pl",
        #[cfg(feature = "i18n-pt")]
        "pt",
        #[cfg(feature = "i18n-ja")]
        "ja",
        #[cfg(feature = "i18n-ko")]
        "ko",
        #[cfg(feature = "i18n-zh")]
        "zh",
        #[cfg(feature = "i18n-ar")]
        "ar",
        #[cfg(feature = "i18n-tr")]
        "tr",
        #[cfg(feature = "i18n-uk")]
        "uk",
        #[cfg(feature = "i18n-cs")]
        "cs",
        #[cfg(feature = "i18n-sv")]
        "sv",
        #[cfg(feature = "i18n-da")]
        "da",
        #[cfg(feature = "i18n-fi")]
        "fi",
        #[cfg(feature = "i18n-nb")]
        "nb",
        #[cfg(feature = "i18n-el")]
        "el",
        #[cfg(feature = "i18n-he")]
        "he",
        #[cfg(feature = "i18n-th")]
        "th",
        #[cfg(feature = "i18n-vi")]
        "vi",
        #[cfg(feature = "i18n-id")]
        "id",
        #[cfg(feature = "i18n-ms")]
        "ms",
        #[cfg(feature = "i18n-hi")]
        "hi",
        #[cfg(feature = "i18n-bn")]
        "bn",
        #[cfg(feature = "i18n-ro")]
        "ro",
        #[cfg(feature = "i18n-hu")]
        "hu",
    ]
}

/// Returns whether a locale is available (compiled into this binary).
pub fn is_locale_available(locale: &str) -> bool {
    available_locales().contains(&locale)
}

/// Load raw JSON string for a locale+namespace pair.
///
/// Returns `None` if the locale or namespace is not compiled in.
pub fn load_locale(locale: &str, namespace: &str) -> Option<&'static str> {
    match (locale, namespace) {
        // English — always available
        ("en", "auth") => Some(include_str!("../locales/en/auth.json")),
        ("en", "errors") => Some(include_str!("../locales/en/errors.json")),
        ("en", "common") => Some(include_str!("../locales/en/common.json")),
        ("en", "consent") => Some(include_str!("../locales/en/consent.json")),
        ("en", "dashboard") => Some(include_str!("../locales/en/dashboard.json")),
        ("en", "admin") => Some(include_str!("../locales/en/admin.json")),
        ("en", "scim") => Some(include_str!("../locales/en/scim.json")),
        ("en", "saml") => Some(include_str!("../locales/en/saml.json")),
        // Ukrainian
        #[cfg(feature = "i18n-uk")]
        ("uk", "auth") => Some(include_str!("../locales/uk/auth.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "errors") => Some(include_str!("../locales/uk/errors.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "common") => Some(include_str!("../locales/uk/common.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "consent") => Some(include_str!("../locales/uk/consent.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "dashboard") => Some(include_str!("../locales/uk/dashboard.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "admin") => Some(include_str!("../locales/uk/admin.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "scim") => Some(include_str!("../locales/uk/scim.json")),
        #[cfg(feature = "i18n-uk")]
        ("uk", "saml") => Some(include_str!("../locales/uk/saml.json")),
        // Other locales gated by feature flags
        // (locale files will be added as translations are contributed)
        _ => None,
    }
}

/// Flattened key-value store for a single locale.
///
/// Keys use dot notation: `"errors.auth.invalid_credentials"`. Keys and values
/// are fixed for the life of the process when the cache is built, so lookups
/// return references and never allocate.
type FlatMap = HashMap<&'static str, &'static str>;

/// Global cache of parsed locale data.
static LOCALE_CACHE: OnceLock<HashMap<&'static str, FlatMap>> = OnceLock::new();

/// Initialize the locale cache. Called lazily on first `t()` call.
fn init_cache() -> HashMap<&'static str, FlatMap> {
    let mut cache = HashMap::new();

    for &locale in available_locales() {
        let mut flat = HashMap::new();

        for &ns in NAMESPACES {
            if let Some(json_str) = load_locale(locale, ns) {
                let value: serde_json::Value = serde_json::from_str(json_str)
                    .expect("embedded locale JSON is valid (checked by the locale tests)");
                flatten_json(&value, ns, &mut flat);
            }
        }

        cache.insert(locale, flat);
    }

    cache
}

/// Flatten a nested JSON value into dot-separated keys.
fn flatten_json(value: &serde_json::Value, prefix: &str, out: &mut FlatMap) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let full_key = format!("{prefix}.{key}");
                flatten_json(val, &full_key, out);
            }
        }
        serde_json::Value::String(s) => {
            // Fixed once for the process: the cache is built a single time and
            // never dropped, so the entries are bounded by the locale files.
            let key: &'static str = Box::leak(prefix.to_string().into_boxed_str());
            let text: &'static str = Box::leak(s.clone().into_boxed_str());
            out.insert(key, text);
        }
        _ => {}
    }
}

/// Look up a translated string by dot-separated key.
///
/// Returns `None` if the key or locale is not found.
/// Does NOT perform parameter substitution — use `t_fmt` for that.
///
/// # Examples
///
/// ```rust
/// use sid_i18n::t;
///
/// assert_eq!(t("en", "errors.auth.mfa_required"),
///            Some("Multi-factor authentication is required"));
/// ```
pub fn t(locale: &str, key: &str) -> Option<&'static str> {
    let cache = LOCALE_CACHE.get_or_init(init_cache);

    if let Some(flat) = cache.get(locale)
        && let Some(&text) = flat.get(key)
    {
        return Some(text);
    }

    // Fallback to English
    if locale != "en"
        && let Some(flat) = cache.get("en")
        && let Some(&text) = flat.get(key)
    {
        return Some(text);
    }

    None
}

/// Look up a translated string and substitute named parameters.
///
/// Parameters use `{name}` syntax in locale files.
///
/// # Examples
///
/// ```rust
/// use sid_i18n::t_fmt;
///
/// let msg = t_fmt("en", "errors.auth.account_locked", &[("minutes", "15")]);
/// assert!(msg.unwrap().contains("15 minutes"));
/// ```
pub fn t_fmt(locale: &str, key: &str, params: &[(&str, &str)]) -> Option<String> {
    let template = t(locale, key)?;
    let mut result = template.to_string();
    for (name, value) in params {
        result = result.replace(&format!("{{{name}}}"), value);
    }
    Some(result)
}

#[cfg(test)]
mod tests;
