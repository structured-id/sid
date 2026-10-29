// SPDX-License-Identifier: AGPL-3.0-only
//! The browser-facing route contract of an issuer's HTTP surface: where the
//! browser's RPCs are mounted and which cookies of its issuer each endpoint
//! receives and sets. The serving issuer and every edge in front of it read
//! this one declaration; an edge keeps no list of its own.

/// The public mount of a browser's RPCs on a single-authority surface:
/// `/api/{package.Service}/{Method}`, the gRPC path under it unchanged.
pub const API_MOUNT: &str = "/api";

/// The gRPC path of a call under [`API_MOUNT`]; `None` for any other path.
pub fn api_method(path: &str) -> Option<&str> {
    let method = path.strip_prefix(API_MOUNT)?;
    method.starts_with('/').then_some(method)
}

/// What an issuer endpoint does with its issuer's browser-session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCookieUse {
    /// Reads the session; sets nothing.
    Read,
    /// Sets the session a completed sign-in creates; reads none.
    Issue,
    /// Reads the sign-in's pending context and sets the session it completes.
    ReadAndIssue,
    /// Reads the session and clears it when single sign-on ends.
    ReadAndClear,
}

/// What a federated entry endpoint does with its correlation cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryCookieUse {
    /// Sets the correlation cookie of the entry it starts.
    Start,
    /// Reads the returning entry's correlation cookie and clears it; may set
    /// the cookie of a new entry it restarts.
    Return,
}

/// The cookies of its own issuer an endpoint below `/i/{handle}` receives
/// and sets; an edge in front of the issuer forwards nothing else either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IssuerCookies {
    pub session: Option<SessionCookieUse>,
    pub entry: Option<EntryCookieUse>,
}

impl IssuerCookies {
    /// Whether the endpoint is sent the issuer's session cookie.
    pub fn receives_session(&self) -> bool {
        matches!(
            self.session,
            Some(
                SessionCookieUse::Read
                    | SessionCookieUse::ReadAndIssue
                    | SessionCookieUse::ReadAndClear
            )
        )
    }

    /// Whether the endpoint's answer may set or clear the session cookie.
    pub fn sets_session(&self) -> bool {
        matches!(
            self.session,
            Some(
                SessionCookieUse::Issue
                    | SessionCookieUse::ReadAndIssue
                    | SessionCookieUse::ReadAndClear
            )
        )
    }

    /// Whether the endpoint is sent the entries' correlation cookies.
    pub fn receives_entry(&self) -> bool {
        self.entry == Some(EntryCookieUse::Return)
    }

    /// Whether the endpoint's answer may set or clear correlation cookies.
    pub fn sets_entry(&self) -> bool {
        self.entry.is_some()
    }
}

/// The sign-in surface's methods whose answer delivers the session a
/// completed sign-in creates.
pub const ISSUING_METHODS: &[&str] = &[
    "/sid.v1.authn.AuthService/OpaqueLoginFinish",
    "/sid.v1.authn.AuthService/LegacyMigrateFinish",
    "/sid.v1.authn.AuthService/WebAuthnAuthenticationFinish",
    "/sid.v1.authn.AuthService/VerifyOtp",
    "/sid.v1.authn.AuthService/VerifyMagicLink",
    "/sid.v1.authn.AuthService/CompletePasswordReset",
];

/// The second factor that completes a pending sign-in: it reads that context
/// and delivers the session.
pub const PENDING_COMPLETING_METHOD: &str = "/sid.v1.authn.AuthService/VerifyTotp";

/// The cookies of its issuer the CE endpoint `endpoint` (the path below
/// `/i/{handle}`) receives and sets: authorization reads the session for
/// single sign-on, end-session reads and clears it, the sign-in ceremonies
/// that complete a session set it, and a second factor completing a pending
/// sign-in reads that context first. Discovery, keys, token, UserInfo,
/// introspection, revocation and every other method use no cookie.
pub fn issuer_cookies(endpoint: &str) -> IssuerCookies {
    let session = match endpoint {
        "/oauth2/authorize" => Some(SessionCookieUse::Read),
        "/oauth2/end-session" => Some(SessionCookieUse::ReadAndClear),
        _ => match api_method(endpoint) {
            Some(PENDING_COMPLETING_METHOD) => Some(SessionCookieUse::ReadAndIssue),
            Some(method) if ISSUING_METHODS.contains(&method) => Some(SessionCookieUse::Issue),
            _ => None,
        },
    };
    IssuerCookies {
        session,
        entry: None,
    }
}

#[cfg(test)]
mod tests;
