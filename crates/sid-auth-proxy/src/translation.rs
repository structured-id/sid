// SPDX-License-Identifier: AGPL-3.0-only
//! Auth translation — header and cookie modes for upstream apps.
//!
//! CE supports two modes:
//! - **header**: template-based header injection (e.g., `X-WEBAUTH-USER: "{{ .Email }}"`)
//! - **cookie**: set session cookie on upstream domain with JWT

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

/// What a translation discloses to one upstream: the verified values its
/// policy permits that application, and nothing more. A value the request
/// did not prove is absent and renders empty, never invented; roles are not
/// group membership.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamIdentity {
    /// The application's subject: the opaque `sub` of its token.
    pub subject: String,
    /// The email the policy discloses to this application.
    pub email: Option<String>,
    /// The display name the policy discloses to this application.
    pub display_name: Option<String>,
    /// The username the policy discloses to this application.
    pub preferred_username: Option<String>,
    /// The groups the policy discloses to this application.
    pub groups: Vec<String>,
}

/// Auth translation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthTranslation {
    pub mode: TranslationMode,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub cookie: Option<CookieTranslation>,
}

/// Translation mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranslationMode {
    Header,
    Cookie,
}

/// Cookie translation config.
#[derive(Debug, Clone, Deserialize)]
pub struct CookieTranslation {
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    #[serde(default = "default_content")]
    pub content: String,
}

fn default_true() -> bool {
    true
}
fn default_same_site() -> String {
    "lax".into()
}
fn default_content() -> String {
    "jwt".into()
}

/// Apply auth translation to produce headers for the upstream.
pub fn translate(
    identity: &UpstreamIdentity,
    config: &AuthTranslation,
    raw_token: Option<&str>,
) -> HeaderMap {
    match config.mode {
        TranslationMode::Header => translate_headers(identity, &config.headers),
        TranslationMode::Cookie => translate_cookie(config, raw_token),
    }
}

/// Header mode: render templates in header values.
fn translate_headers(
    identity: &UpstreamIdentity,
    templates: &std::collections::HashMap<String, String>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (name, template) in templates {
        let value = render_template(template, identity);
        if let (Ok(name), Ok(val)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, val);
        }
    }

    headers
}

/// Cookie mode: set a cookie with the JWT.
fn translate_cookie(config: &AuthTranslation, raw_token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let (Some(cookie_config), Some(token)) = (&config.cookie, raw_token) {
        let mut cookie = format!("{}={}", cookie_config.name, token);
        if let Some(domain) = &cookie_config.domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }
        if cookie_config.secure {
            cookie.push_str("; Secure");
        }
        if cookie_config.http_only {
            cookie.push_str("; HttpOnly");
        }
        cookie.push_str(&format!("; SameSite={}", cookie_config.same_site));
        cookie.push_str("; Path=/");

        if let Ok(val) = HeaderValue::from_str(&cookie) {
            headers.insert("set-cookie", val);
        }
    }

    headers
}

/// Simple template renderer for auth translation headers.
///
/// Supported placeholders:
/// Supported placeholders:
/// - `{{ .Email }}`: the disclosed email
/// - `{{ .Subject }}`: the application's subject (opaque: UUID or pairwise)
/// - `{{ .User }}`: the same subject, the forward-auth user template
/// - `{{ .DisplayName }}`: the disclosed display name
/// - `{{ .PreferredUsername }}`: the disclosed username
/// - `{{ .Groups }}` / `{{ .Groups | join ',' }}`: comma-separated groups
/// - `{{ .Groups | join ';' }}`: semicolon-separated groups
fn render_template(template: &str, identity: &UpstreamIdentity) -> String {
    let mut result = template.to_string();

    result = result.replace("{{ .Email }}", identity.email.as_deref().unwrap_or(""));
    result = result.replace("{{ .Subject }}", &identity.subject);
    result = result.replace("{{ .User }}", &identity.subject);
    result = result.replace(
        "{{ .DisplayName }}",
        identity.display_name.as_deref().unwrap_or(""),
    );
    result = result.replace(
        "{{ .PreferredUsername }}",
        identity.preferred_username.as_deref().unwrap_or(""),
    );
    result = result.replace("{{ .Groups | join ';' }}", &identity.groups.join(";"));
    result = result.replace("{{ .Groups | join ',' }}", &identity.groups.join(","));
    result = result.replace("{{ .Groups }}", &identity.groups.join(","));

    result
}

#[cfg(test)]
mod tests;
