// SPDX-License-Identifier: AGPL-3.0-only
//! The browser-facing route contract of an issuer's HTTP surface: where the
//! browser's RPCs are mounted and which cookies of its issuer each endpoint
//! receives and sets. The serving issuer and every edge in front of it read
//! this one declaration; an edge keeps no list of its own.

/// The public mount of a browser's RPCs on a single-authority surface:
/// `/api/{package.Service}/{Method}`, the gRPC path under it unchanged.
pub const API_MOUNT: &str = "/api";

/// The base URL of an issuer's browser sign-in surface on `public_origin`, as
/// the route serving the call reached it: [`API_MOUNT`] on a single-authority
/// surface, `/i/<handle>/api` for a call `addressed` to the issuer with that
/// handle on a shared host, whatever the issuer's own URL.
pub fn ceremony_api(public_origin: &str, addressed: Option<&str>) -> String {
    match addressed {
        Some(handle) => format!("{public_origin}/i/{handle}{API_MOUNT}"),
        None => format!("{public_origin}{API_MOUNT}"),
    }
}

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

/// What a passwordless registration endpoint does with the context cookie
/// of the registration it continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCookieUse {
    /// Sets the context a confirmed address opens; reads none.
    Open,
    /// Reads the context it continues; sets nothing.
    Present,
}

/// The cookies of its own issuer an endpoint below `/i/{handle}` receives
/// and sets; an edge in front of the issuer forwards nothing else either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IssuerCookies {
    pub session: Option<SessionCookieUse>,
    pub entry: Option<EntryCookieUse>,
    pub registration: Option<RegistrationCookieUse>,
}

/// The cookie a browser holds its issuer's passwordless registration
/// context in, named after that issuer's session cookie `session`.
pub fn registration_cookie(session: &str) -> String {
    format!("{session}_registration")
}

/// The registration step whose answer opens the context cookie.
pub const REGISTRATION_OPENING_METHOD: &str = "/sid.v1.authn.AuthService/VerifyEmailRegistration";

/// The registration steps that present the context cookie.
pub const REGISTRATION_CONTEXT_METHODS: &[&str] = &[
    "/sid.v1.authn.AuthService/PasskeyRegistrationStart",
    "/sid.v1.authn.AuthService/PasskeyRegistrationFinish",
];

impl IssuerCookies {
    /// Whether the endpoint is sent the registration context cookie.
    pub fn receives_registration(&self) -> bool {
        self.registration == Some(RegistrationCookieUse::Present)
    }

    /// Whether the endpoint's answer may set the registration context cookie.
    pub fn sets_registration(&self) -> bool {
        self.registration == Some(RegistrationCookieUse::Open)
    }

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
/// sign-in reads that context first. A federated entry's start sets the
/// correlation cookie of the entry it starts and reads none; its return
/// reads and clears that cookie, may set a further entry's and sets the
/// session it admits. Discovery, keys, token, UserInfo, introspection,
/// revocation and every other method use no cookie.
pub fn issuer_cookies(endpoint: &str) -> IssuerCookies {
    use sid_core::models::entry_connection::{CALLBACK, START};
    match endpoint {
        START => {
            return IssuerCookies {
                entry: Some(EntryCookieUse::Start),
                ..IssuerCookies::default()
            };
        }
        CALLBACK => {
            return IssuerCookies {
                session: Some(SessionCookieUse::Issue),
                entry: Some(EntryCookieUse::Return),
                ..IssuerCookies::default()
            };
        }
        _ => {}
    }
    let registration = match api_method(endpoint) {
        Some(REGISTRATION_OPENING_METHOD) => Some(RegistrationCookieUse::Open),
        Some(method) if REGISTRATION_CONTEXT_METHODS.contains(&method) => {
            Some(RegistrationCookieUse::Present)
        }
        _ => None,
    };
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
        registration,
    }
}

/// One HTTP route of an issuer method: its path segments, `None` for a
/// `{variable}` segment.
#[cfg(feature = "issuer-routes")]
type Route = Vec<Option<String>>;

/// The root routes of the root-addressed base issuer, read once from the
/// `google.api.http` rules: of every method bound under `/i/{issuer_handle}`,
/// each binding that names no issuer handle. The shared-host browser RPCs,
/// mounted under `/i/{handle}/api`, have no root binding and are not among
/// them.
#[cfg(feature = "issuer-routes")]
static ROOT_ROUTES: std::sync::LazyLock<Vec<Route>> = std::sync::LazyLock::new(|| {
    use prost_reflect::{DescriptorPool, Value};
    let pool = DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET)
        .expect("the built-in descriptor set decodes");
    let http = pool
        .get_extension_by_name("google.api.http")
        .expect("google/api/annotations.proto is in the descriptor set");
    let mut routes = Vec::new();
    for method in pool
        .services()
        .flat_map(|service| service.methods().collect::<Vec<_>>())
    {
        let options = method.options();
        if !options.has_extension(&http) {
            continue;
        }
        let Value::Message(rule) = options.get_extension(&http).into_owned() else {
            continue;
        };
        let mut patterns = Vec::new();
        http_patterns(&rule, &mut patterns);
        if !patterns.iter().any(|p| p.starts_with("/i/{issuer_handle}")) {
            continue;
        }
        routes.extend(
            patterns
                .iter()
                .filter(|p| !p.contains("{issuer_handle}"))
                .map(|p| {
                    p.split('/')
                        .skip(1)
                        .map(|segment| (!segment.starts_with('{')).then(|| segment.to_owned()))
                        .collect::<Route>()
                }),
        );
    }
    routes
});

/// Every path pattern of the HTTP rule `rule`, its additional bindings
/// included (`google/api/http.proto`).
#[cfg(feature = "issuer-routes")]
fn http_patterns(rule: &prost_reflect::DynamicMessage, out: &mut Vec<String>) {
    use prost_reflect::Value;
    for verb in ["get", "put", "post", "delete", "patch"] {
        if let Some(value) = rule.get_field_by_name(verb)
            && let Value::String(pattern) = value.as_ref()
            && !pattern.is_empty()
        {
            out.push(pattern.clone());
        }
    }
    if let Some(value) = rule.get_field_by_name("additional_bindings")
        && let Value::List(bindings) = value.as_ref()
    {
        for binding in bindings {
            if let Value::Message(binding) = binding {
                http_patterns(binding, out);
            }
        }
    }
}

/// `path` when it is a root route of the root-addressed base issuer (its
/// discovery, keys, UserInfo, OAuth and federated entry endpoints), the
/// endpoint path [`issuer_cookies`] classifies; `None` for any other path.
#[cfg(feature = "issuer-routes")]
pub fn root_issuer_endpoint(path: &str) -> Option<&str> {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    ROOT_ROUTES
        .iter()
        .any(|route| {
            route.len() == segments.len()
                && route
                    .iter()
                    .zip(&segments)
                    .all(|(expected, segment)| match expected {
                        Some(literal) => literal == segment,
                        None => !segment.is_empty(),
                    })
        })
        .then_some(path)
}

#[cfg(test)]
mod tests;
