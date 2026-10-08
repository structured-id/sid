// SPDX-License-Identifier: AGPL-3.0-only
//! Header injection for forward auth responses.
//!
//! Maps JWT claims to response headers per the arch doc table.
//! Configurable: route policy specifies which headers to inject.

use http::{HeaderMap, HeaderName, HeaderValue};

use super::jwt::ForwardAuthClaims;

/// Standard header names for forward auth.
const X_FORWARDED_USER: &str = "x-forwarded-user";
const X_AUTH_REQUEST_EMAIL: &str = "x-auth-request-email";
const X_AUTH_REQUEST_GROUPS: &str = "x-auth-request-groups";
const X_AUTH_REQUEST_NAME: &str = "x-auth-request-name";
const X_AUTH_REQUEST_PREFERRED_USERNAME: &str = "x-auth-request-preferred-username";
const X_AUTH_REQUEST_ACCESS_TOKEN: &str = "x-auth-request-access-token";
const X_SID_AUTH_LEVEL: &str = "x-sid-auth-level";

/// Every identity header a decision can emit. A proxy that applies the
/// decision removes client-supplied copies of all of them, not only of those
/// set this time, so a claim the token lacks cannot be forged by the client.
pub const IDENTITY_HEADERS: [&str; 7] = [
    X_FORWARDED_USER,
    X_AUTH_REQUEST_EMAIL,
    X_AUTH_REQUEST_GROUPS,
    X_AUTH_REQUEST_NAME,
    X_AUTH_REQUEST_PREFERRED_USERNAME,
    X_AUTH_REQUEST_ACCESS_TOKEN,
    X_SID_AUTH_LEVEL,
];

/// Build response headers from JWT claims.
///
/// `inject` is a list of header shortnames from the route policy:
/// "user", "email", "groups", "name", "preferred_username", "access_token", "auth_level".
///
/// If `inject` is empty, injects the default set: user + auth_level.
pub fn build_auth_headers(
    claims: &ForwardAuthClaims,
    inject: &[String],
    raw_token: Option<&str>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let inject_all = inject.is_empty();

    // Always inject user (subject) and auth level
    if (inject_all || inject.iter().any(|h| h == "user"))
        && let Ok(val) = HeaderValue::from_str(&claims.sub)
    {
        headers.insert(HeaderName::from_static(X_FORWARDED_USER), val);
    }

    if (inject_all || inject.iter().any(|h| h == "auth_level"))
        && let Ok(val) = HeaderValue::from_str(&claims.acr)
    {
        headers.insert(HeaderName::from_static(X_SID_AUTH_LEVEL), val);
    }

    // Only inject email if the token has `email` scope (PII protection)
    if inject.iter().any(|h| h == "email")
        && claims.scope.split_whitespace().any(|s| s == "email")
        && let Some(email) = &claims.email
        && let Ok(val) = HeaderValue::from_str(email)
    {
        headers.insert(HeaderName::from_static(X_AUTH_REQUEST_EMAIL), val);
    }

    if inject.iter().any(|h| h == "groups") && !claims.roles.is_empty() {
        // Convert space-separated to comma-separated
        let groups = claims.roles.replace(' ', ",");
        if let Ok(val) = HeaderValue::from_str(&groups) {
            headers.insert(HeaderName::from_static(X_AUTH_REQUEST_GROUPS), val);
        }
    }

    if inject.iter().any(|h| h == "name")
        && let Some(name) = &claims.name
        && let Ok(val) = HeaderValue::from_str(name)
    {
        headers.insert(HeaderName::from_static(X_AUTH_REQUEST_NAME), val);
    }

    if inject.iter().any(|h| h == "preferred_username")
        && let Some(username) = &claims.preferred_username
        && let Ok(val) = HeaderValue::from_str(username)
    {
        headers.insert(
            HeaderName::from_static(X_AUTH_REQUEST_PREFERRED_USERNAME),
            val,
        );
    }

    if inject.iter().any(|h| h == "access_token")
        && let Some(token) = raw_token
        && let Ok(val) = HeaderValue::from_str(token)
    {
        headers.insert(HeaderName::from_static(X_AUTH_REQUEST_ACCESS_TOKEN), val);
    }

    headers
}

#[cfg(test)]
mod tests;
