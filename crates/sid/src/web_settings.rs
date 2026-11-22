// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings as an administrator reads and
//! changes them: the public URL (an override for a deployment behind a
//! reverse proxy), where the administration console is served, and the
//! domain scope of the browser session cookie. The settings in force are read
//! through [`WebSettingsAdmin::recent`] by the HTTP edge and the UI host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use prost::Message;
use sid_authn::browser_session::{domain_cookie_allowed, same_site};
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, CookieScope, DEFAULT_CONSOLE_PATH, MutationContext, OperationContext,
    RevocationReason, SessionEnd, WebSettings,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::realm_service as keyed;
use sid_proto::sid::v1::admin as wire;
use url::Url;

/// How many times a change is decided again when another change lands
/// between its read and its write.
const WRITE_ATTEMPTS: usize = 8;

/// How long the settings read last serve before they are read again: a
/// change committed on another replica applies here within it.
pub const RECENT_FOR: Duration = Duration::from_secs(1);

/// The most subdomains a selected scope names.
pub const MAX_SELECTED_SUBDOMAINS: usize = 100;

/// The longest subdomain pattern accepted, in bytes.
const MAX_PATTERN_LEN: usize = 512;

/// The compiled size a subdomain pattern may take: enough for any practical
/// host pattern, bounded so a stored pattern never costs a request more.
const PATTERN_SIZE_LIMIT: usize = 1 << 16;

/// Paths the installation itself serves on its public origin: a console
/// placed at or under one would shadow it.
const RESERVED_PATHS: [&str; 7] = [
    "/account/",
    "/api/",
    "/v1/",
    "/.well-known/",
    "/oauth2/",
    "/health/",
    "/session/",
];

/// Why a web settings operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum WebSettingsError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A field of the change is not a value its setting takes.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// Other changes kept landing between this one's read and its write.
    #[error("the web settings kept changing")]
    Contended,
}

impl From<WebSettingsError> for Effect<WebSettingsError> {
    fn from(e: WebSettingsError) -> Self {
        Self::Refused(e)
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> WebSettingsError {
    WebSettingsError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// The settings in force, resolved against the installation's own URL.
#[derive(Debug, Clone)]
pub struct InForce {
    /// The URL browsers reach the installation at, ending with `/`.
    pub public_url: Url,
    /// Whether `public_url` is an administrator's override.
    pub public_url_overridden: bool,
    /// Where the console is served, ending with `/`.
    pub console_url: Url,
    /// The session cookie's domain scope.
    pub cookie_scope: CookieScope,
    /// The stored settings' revision.
    pub revision: u64,
    /// The selected scope's pattern, compiled once for every host it is
    /// asked about.
    host_pattern: Option<regex::Regex>,
}

impl InForce {
    /// The public URL's host: the base domain of the cookie scope.
    pub fn base_domain(&self) -> &str {
        self.public_url.host_str().unwrap_or_default()
    }

    /// Whether the scope admits `host`: the base itself, any descendant
    /// under every subdomain, or under selected ones a listed descendant or
    /// one the pattern matches whole.
    pub fn admits(&self, host: &str) -> bool {
        let base = self.base_domain();
        let host = host.trim_end_matches('.');
        if host.eq_ignore_ascii_case(base) {
            return true;
        }
        let lower = host.to_ascii_lowercase();
        let Some(label) = lower.strip_suffix(base).and_then(|h| h.strip_suffix('.')) else {
            return false;
        };
        if label.is_empty() {
            return false;
        }
        match &self.cookie_scope {
            CookieScope::ThisHost => false,
            CookieScope::AllSubdomains => true,
            CookieScope::SelectedSubdomains { hosts, .. } => {
                hosts.contains(&lower)
                    || self
                        .host_pattern
                        .as_ref()
                        .is_some_and(|re| re.is_match(&lower))
            }
        }
    }
}

/// A subdomain pattern compiled to match whole names.
fn compile_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(&format!("^(?:{pattern})$"))
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
}

/// An absolute URL a browser reaches: https, or http on a loopback host; no
/// credentials, query or fragment.
fn browser_url(value: &str, field: &'static str) -> Result<Url, WebSettingsError> {
    let url = Url::parse(value).map_err(|e| invalid(field, format!("not an absolute URL: {e}")))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(invalid(field, "no host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(invalid(field, "https, or http on a loopback host")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(field, "carries credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(field, "carries a query or a fragment"));
    }
    Ok(url)
}

/// A public URL override: an origin, without a path.
fn public_url(value: &str) -> Result<Url, WebSettingsError> {
    let url = browser_url(value, "public_url")?;
    if url.path() != "/" {
        return Err(invalid("public_url", "an origin, without a path"));
    }
    Ok(url)
}

/// A console address on the public URL's site, ending with `/`; on the
/// public origin itself, away from the root and the paths the installation
/// serves.
fn console_url(value: &str, public: &Url) -> Result<Url, WebSettingsError> {
    const FIELD: &str = "console_url";
    let mut url = browser_url(value, FIELD)?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    // A path the console's bundle cannot be mounted at would leave it
    // unreachable everywhere once saved.
    if !sid_core::models::is_ui_mount(url.path()) {
        return Err(invalid(
            FIELD,
            "a literal path of letters, digits, `-._~` and `/`",
        ));
    }
    // The console calls the installation's cookie-owning endpoint; a browser
    // sends the session to it only from the same site (RFC 6265bis §5.2).
    if !same_site(&url, public) {
        return Err(invalid(FIELD, "on the public URL's site"));
    }
    if url.origin() == public.origin() {
        let path = url.path();
        if path == "/" {
            return Err(invalid(
                FIELD,
                "the public URL's root serves the installation",
            ));
        }
        if let Some(reserved) = RESERVED_PATHS
            .iter()
            .find(|r| path.starts_with(**r) || r.starts_with(path))
        {
            return Err(invalid(
                FIELD,
                format!("{reserved} is served by the installation"),
            ));
        }
    }
    Ok(url)
}

/// The settings in force from `stored` and the installation's own URL `own`.
/// A stored value that no longer validates (the own URL moved) falls back to
/// its default rather than serving an address on another site.
fn resolve(own: &Url, stored: Option<&WebSettings>) -> InForce {
    let held = stored.cloned().unwrap_or_default();
    let overridden = held.public_url.as_deref().and_then(|v| public_url(v).ok());
    let public = overridden.clone().unwrap_or_else(|| own.clone());
    let console = held
        .console_url
        .as_deref()
        .and_then(|v| console_url(v, &public).ok())
        .unwrap_or_else(|| default_console(&public));
    let host_pattern = match &held.cookie_scope {
        // A stored pattern compiled when it was set; one that no longer does
        // admits nothing rather than everything.
        CookieScope::SelectedSubdomains {
            pattern: Some(p), ..
        } => compile_pattern(p).ok(),
        _ => None,
    };
    InForce {
        public_url_overridden: overridden.is_some(),
        public_url: public,
        console_url: console,
        cookie_scope: held.cookie_scope,
        revision: held.revision,
        host_pattern,
    }
}

fn default_console(public: &Url) -> Url {
    public
        .join(DEFAULT_CONSOLE_PATH)
        .expect("the default console path joins any origin")
}

/// A selected scope's subdomains, normalized: lowercase, no trailing dot,
/// each a descendant of `base`, without repeats.
fn selected_hosts(hosts: &[String], base: &str) -> Result<Vec<String>, WebSettingsError> {
    const FIELD: &str = "subdomains";
    if hosts.len() > MAX_SELECTED_SUBDOMAINS {
        return Err(invalid(FIELD, format!("at most {MAX_SELECTED_SUBDOMAINS}")));
    }
    let suffix = format!(".{base}");
    let mut normalized = Vec::with_capacity(hosts.len());
    for host in hosts {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        if host.len() > 253 || !host.split('.').all(label_ok) {
            return Err(invalid(FIELD, format!("{host:?} is not a host name")));
        }
        if !host.ends_with(&suffix) {
            return Err(invalid(FIELD, format!("{host} is not under {base}")));
        }
        if !normalized.contains(&host) {
            normalized.push(host);
        }
    }
    Ok(normalized)
}

/// A subdomain pattern, compiled to check it; matched later against whole
/// names (`^(?:pattern)$`).
fn subdomain_pattern(pattern: &str) -> Result<Option<String>, WebSettingsError> {
    const FIELD: &str = "subdomain_pattern";
    if pattern.is_empty() {
        return Ok(None);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(invalid(FIELD, format!("at most {MAX_PATTERN_LEN} bytes")));
    }
    compile_pattern(pattern).map_err(|e| invalid(FIELD, e.to_string()))?;
    Ok(Some(pattern.to_owned()))
}

/// The scope a change sets, validated against the public URL's host.
fn requested_scope(
    req: &wire::UpdateSessionCookieScopeRequest,
    public: &Url,
) -> Result<CookieScope, WebSettingsError> {
    let domain = wire::SessionCookieDomain::try_from(req.domain)
        .unwrap_or(wire::SessionCookieDomain::Unspecified);
    let host = public.host().ok_or_else(|| invalid("domain", "no host"))?;
    let base = public.host_str().unwrap_or_default();
    let widened = |scope: CookieScope| {
        if domain_cookie_allowed(&host) {
            Ok(scope)
        } else {
            Err(invalid(
                "domain",
                format!("{base} cannot carry a cookie for its subdomains"),
            ))
        }
    };
    let only_selected = || {
        if req.subdomains.is_empty() && req.subdomain_pattern.is_empty() {
            Ok(())
        } else {
            Err(invalid("subdomains", "only with SELECTED_SUBDOMAINS"))
        }
    };
    match domain {
        wire::SessionCookieDomain::Unspecified => Err(invalid("domain", "a scope is required")),
        wire::SessionCookieDomain::ThisHost => {
            only_selected()?;
            Ok(CookieScope::ThisHost)
        }
        wire::SessionCookieDomain::AllSubdomains => {
            only_selected()?;
            widened(CookieScope::AllSubdomains)
        }
        wire::SessionCookieDomain::SelectedSubdomains => {
            let hosts = selected_hosts(&req.subdomains, base)?;
            let pattern = subdomain_pattern(&req.subdomain_pattern)?;
            if hosts.is_empty() && pattern.is_none() {
                return Err(invalid(
                    "subdomains",
                    "a subdomain or a pattern is required",
                ));
            }
            widened(CookieScope::SelectedSubdomains { hosts, pattern })
        }
    }
}

fn addresses_view(in_force: &InForce) -> wire::InstallationAddresses {
    wire::InstallationAddresses {
        public_url: in_force.public_url.to_string(),
        public_url_overridden: in_force.public_url_overridden,
        console_url: in_force.console_url.to_string(),
    }
}

fn scope_view(in_force: &InForce) -> wire::SessionCookieScope {
    let (domain, subdomains, pattern) = match &in_force.cookie_scope {
        CookieScope::ThisHost => (
            wire::SessionCookieDomain::ThisHost,
            Vec::new(),
            String::new(),
        ),
        CookieScope::AllSubdomains => (
            wire::SessionCookieDomain::AllSubdomains,
            Vec::new(),
            String::new(),
        ),
        CookieScope::SelectedSubdomains { hosts, pattern } => (
            wire::SessionCookieDomain::SelectedSubdomains,
            hosts.clone(),
            pattern.clone().unwrap_or_default(),
        ),
    };
    wire::SessionCookieScope {
        domain: domain as i32,
        base_domain: in_force.base_domain().to_owned(),
        subdomains,
        subdomain_pattern: pattern,
        revision: in_force.revision,
    }
}

/// Settings read at a moment.
struct Held {
    read: Instant,
    in_force: Arc<InForce>,
}

/// The browser-facing settings of one installation.
pub struct WebSettingsAdmin {
    storage: Arc<dyn StorageBackend>,
    /// The installation's own URL: the origin of its issuer.
    own: Url,
    /// The settings read last in this process: a routing hint for the
    /// requests of the next [`RECENT_FOR`], never shared state.
    held: ArcSwapOption<Held>,
}

impl WebSettingsAdmin {
    /// The settings of the installation whose own URL is `issuer`'s origin.
    pub fn new(storage: Arc<dyn StorageBackend>, issuer: &Url) -> Self {
        let own = Url::parse(&issuer.origin().ascii_serialization())
            .expect("an issuer's origin is an absolute URL");
        Self {
            storage,
            own,
            held: ArcSwapOption::empty(),
        }
    }

    /// The settings in force, read from the store now.
    pub async fn in_force(&self) -> Result<InForce, SidError> {
        let in_force = resolve(&self.own, self.storage.web_settings().await?.as_ref());
        self.hold(in_force.clone());
        Ok(in_force)
    }

    /// The settings in force as read within the last [`RECENT_FOR`]: what
    /// every request consults, so the store is read about once a second
    /// whatever the traffic. A failed read is returned, not answered from
    /// older settings.
    pub async fn recent(&self) -> Result<Arc<InForce>, SidError> {
        if let Some(held) = self.held.load().as_ref()
            && held.read.elapsed() < RECENT_FOR
        {
            return Ok(held.in_force.clone());
        }
        let in_force = resolve(&self.own, self.storage.web_settings().await?.as_ref());
        Ok(self.hold(in_force))
    }

    /// The settings read last, without reading: for a check that cannot
    /// wait on the store (a browser's CORS admission, which grants nothing
    /// by itself). None before the first read.
    pub fn last(&self) -> Option<Arc<InForce>> {
        self.held.load().as_ref().map(|held| held.in_force.clone())
    }

    fn hold(&self, in_force: InForce) -> Arc<InForce> {
        let in_force = Arc::new(in_force);
        self.held.store(Some(Arc::new(Held {
            read: Instant::now(),
            in_force: in_force.clone(),
        })));
        in_force
    }

    /// The addresses, for an administrator.
    pub async fn addresses(
        &self,
        caller: &Caller,
    ) -> Result<wire::InstallationAddresses, WebSettingsError> {
        caller.require_admin()?;
        Ok(addresses_view(&self.in_force().await?))
    }

    /// The cookie scope, for an administrator.
    pub async fn cookie_scope(
        &self,
        caller: &Caller,
    ) -> Result<wire::SessionCookieScope, WebSettingsError> {
        caller.require_admin()?;
        Ok(scope_view(&self.in_force().await?))
    }

    /// Change the addresses `req` names and keep the other as stored. A
    /// public URL whose host differs from the current one is refused while
    /// the cookie scope reaches subdomains of the current host: the scope is
    /// narrowed first.
    pub async fn update_addresses(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: wire::UpdateInstallationAddressesRequest,
    ) -> Result<wire::InstallationAddresses, WebSettingsError> {
        caller.require_admin()?;
        let command = KeyedCommand::by_profile::<keyed::UpdateInstallationAddresses>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                for _ in 0..WRITE_ATTEMPTS {
                    let stored = self.storage.web_settings().await?;
                    let held = stored.clone().unwrap_or_default();
                    let mut changed = held.clone();
                    if let Some(value) = &req.public_url {
                        changed.public_url = if value.is_empty() {
                            None
                        } else {
                            Some(public_url(value)?.to_string())
                        };
                    }
                    let current = resolve(&self.own, stored.as_ref());
                    let public = changed
                        .public_url
                        .as_deref()
                        .map(Url::parse)
                        .transpose()
                        .map_err(|e| invalid("public_url", e.to_string()))?
                        .unwrap_or_else(|| self.own.clone());
                    if public.host_str() != current.public_url.host_str()
                        && held.cookie_scope != CookieScope::ThisHost
                    {
                        return Err(invalid(
                            "public_url",
                            "the cookie scope reaches the current host's subdomains; narrow it first",
                        )
                        .into());
                    }
                    if let Some(value) = &req.console_url {
                        changed.console_url = if value.is_empty() {
                            None
                        } else {
                            Some(console_url(value, &public)?.to_string())
                        };
                    }
                    // A stored console address must stay valid for the new
                    // public URL: it is checked again, not only when named.
                    if let Some(value) = &changed.console_url {
                        console_url(value, &public)?;
                    }
                    if changed != held {
                        changed.revision += 1;
                    }
                    let response = addresses_view(&resolve(&self.own, Some(&changed)));
                    let audit = MutationContext::from(AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "web_settings.update_addresses",
                        "web_settings",
                    ))
                    .with_operation(command.completion(response.encode_to_vec()));
                    if self
                        .storage
                        .set_web_settings(&changed, stored.as_ref(), None, audit)
                        .await?
                    {
                        self.hold(resolve(&self.own, Some(&changed)));
                        tracing::info!(
                            public_url = %response.public_url,
                            console_url = %response.console_url,
                            revision = changed.revision,
                            "installation addresses updated"
                        );
                        return Ok(response);
                    }
                }
                Err(WebSettingsError::Contended.into())
            })
            .await
            .map_err(CommandError::<WebSettingsError>::refusal)
    }

    /// Replace the cookie scope. A scope that admits fewer hosts than the
    /// stored one ends every browser session in the same commit: their
    /// secrets were shared under the former scope.
    pub async fn update_cookie_scope(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: wire::UpdateSessionCookieScopeRequest,
    ) -> Result<wire::SessionCookieScope, WebSettingsError> {
        caller.require_admin()?;
        let command = KeyedCommand::by_profile::<keyed::UpdateSessionCookieScope>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                for _ in 0..WRITE_ATTEMPTS {
                    let stored = self.storage.web_settings().await?;
                    let held = stored.clone().unwrap_or_default();
                    let current = resolve(&self.own, stored.as_ref());
                    let scope = requested_scope(&req, &current.public_url)?;
                    let narrowed = scope.narrows(&held.cookie_scope);
                    let mut changed = WebSettings {
                        cookie_scope: scope,
                        ..held.clone()
                    };
                    if changed != held {
                        changed.revision += 1;
                    }
                    let response = scope_view(&resolve(&self.own, Some(&changed)));
                    let end = narrowed.then(|| {
                        SessionEnd::new(RevocationReason::Admin, caller.profile_id.to_string())
                    });
                    let audit = MutationContext::from(AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "web_settings.update_cookie_scope",
                        "web_settings",
                    ))
                    .with_operation(command.completion(response.encode_to_vec()));
                    if self
                        .storage
                        .set_web_settings(&changed, stored.as_ref(), end.as_ref(), audit)
                        .await?
                    {
                        self.hold(resolve(&self.own, Some(&changed)));
                        tracing::info!(
                            domain = response.domain,
                            narrowed,
                            revision = changed.revision,
                            "session cookie scope updated"
                        );
                        return Ok(response);
                    }
                }
                Err(WebSettingsError::Contended.into())
            })
            .await
            .map_err(CommandError::<WebSettingsError>::refusal)
    }
}

#[cfg(test)]
mod tests;
