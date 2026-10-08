// SPDX-License-Identifier: AGPL-3.0-only
//! Route policy engine: the protected applications forward auth decides for.
//!
//! Each application names the registered resource its tokens are issued for
//! (exact issuer and resource indicator) and its routes. The ingress names the
//! application in the forward-auth address it is configured with
//! (`/auth/verify/{name}`), so nothing the client sends selects the target.
//! Within an application the first route matching path and method wins; an
//! unmatched request requires authentication.
//!
//! CE supports: path glob, method filter, role requirements.
//! EE extends with: regex, claims, assurance level, device assurance, geo, time.

use std::collections::{HashMap, HashSet};

use globset::{Glob, GlobMatcher};
use http::Method;
use serde::Deserialize;

/// Route policy configuration loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicyConfig {
    #[serde(default)]
    pub applications: Vec<ApplicationEntry>,
}

/// A protected application from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationEntry {
    /// Name the ingress puts in the forward-auth address: `/auth/verify/{name}`.
    pub name: String,
    /// Public origin of the application (`https://host[:port]`), the scheme and
    /// authority of every request the ingress protects with this entry.
    pub origin: String,
    /// Exact issuer the resource is registered under (`https://<host>/i/<handle>`).
    pub issuer: String,
    /// The registered resource indicator its access tokens name in `aud`.
    pub resource: String,
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
}

/// A single route entry from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEntry {
    #[serde(rename = "match")]
    pub match_: RouteMatch,
    pub policy: RoutePolicyDef,
}

/// Route match criteria.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    pub path: String,
    #[serde(default)]
    pub methods: Vec<String>,
}

/// Route policy definition from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicyDef {
    pub auth: AuthRequirementDef,
    #[serde(default)]
    pub require: Option<RequirementsDef>,
    #[serde(default)]
    pub headers: Option<HeadersDef>,
    #[serde(default)]
    pub check_authz: bool,
    /// The application operation sid-authz decides for this route, in the
    /// application's own vocabulary (for example `orders.read`). Required
    /// with `check_authz`, refused without it.
    #[serde(default)]
    pub action: Option<String>,
}

/// Auth requirement from YAML.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirementDef {
    None,
    Required,
    Optional,
}

/// Additional requirements (roles, etc.).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementsDef {
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Header injection config.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersDef {
    #[serde(default)]
    pub inject: Vec<String>,
}

/// Compiled route policy (ready for matching).
struct CompiledRoute {
    matcher: GlobMatcher,
    methods: HashSet<Method>,
    policy: RoutePolicy,
}

/// Evaluated route policy.
#[derive(Debug, Clone)]
pub struct RoutePolicy {
    pub auth: AuthRequirement,
    pub required_roles: Vec<String>,
    pub inject_headers: Vec<String>,
    /// The operation sid-authz decides for this route; `None` when the route
    /// does not ask sid-authz.
    pub authz_action: Option<String>,
}

impl RoutePolicy {
    fn authenticated() -> Self {
        Self {
            auth: AuthRequirement::Required,
            required_roles: vec![],
            inject_headers: vec![],
            authz_action: None,
        }
    }
}

/// Auth requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequirement {
    None,
    Required,
    Optional,
}

/// The registered resource an application's tokens must be issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Exact issuer identifier.
    pub issuer: String,
    /// Resource indicator, the required `aud`.
    pub resource: String,
}

/// A protected application with its target and routes.
pub struct ProtectedApplication {
    /// Scheme and authority of its requests, without a trailing slash.
    pub origin: String,
    pub target: Target,
    routes: Vec<CompiledRoute>,
    /// What an unmatched request gets: authentication required.
    default_policy: RoutePolicy,
}

impl ProtectedApplication {
    /// The first route matching `path` and `method`; an unmatched request
    /// requires authentication.
    pub fn match_route(&self, path: &str, method: &Method) -> &RoutePolicy {
        for route in &self.routes {
            if route.matcher.is_match(path)
                && (route.methods.is_empty() || route.methods.contains(method))
            {
                return &route.policy;
            }
        }
        &self.default_policy
    }
}

impl std::fmt::Debug for ProtectedApplication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedApplication")
            .field("origin", &self.origin)
            .field("target", &self.target)
            .field("routes", &self.routes.len())
            .finish()
    }
}

/// Policy engine: the protected applications by name.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    applications: HashMap<String, ProtectedApplication>,
}

impl PolicyEngine {
    /// Load policies from a YAML file.
    pub fn load(path: &str) -> Result<Self, PolicyError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| PolicyError::IoError(path.to_string(), e))?;
        Self::from_yaml(&content)
    }

    /// Parse policies from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let config: RoutePolicyConfig =
            serde_yaml::from_str(yaml).map_err(PolicyError::YamlError)?;
        Self::from_config(config)
    }

    /// Build from parsed config.
    pub fn from_config(config: RoutePolicyConfig) -> Result<Self, PolicyError> {
        let mut applications = HashMap::with_capacity(config.applications.len());
        for entry in config.applications {
            let name = entry.name.clone();
            let application = compile_application(entry)?;
            if applications.insert(name.clone(), application).is_some() {
                return Err(PolicyError::DuplicateApplication(name));
            }
        }
        Ok(Self { applications })
    }

    /// No protected applications: every forward-auth request is refused.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The application the ingress names, if configured.
    pub fn application(&self, name: &str) -> Option<&ProtectedApplication> {
        self.applications.get(name)
    }
}

fn compile_application(entry: ApplicationEntry) -> Result<ProtectedApplication, PolicyError> {
    let invalid = |field: &'static str, why: String| PolicyError::InvalidApplication {
        name: entry.name.clone(),
        field,
        why,
    };
    let name_ok = !entry.name.is_empty()
        && entry
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !name_ok {
        return Err(invalid(
            "name",
            "letters, digits, '-' and '_' only, not empty".into(),
        ));
    }
    let origin = parse_origin(&entry.origin).map_err(|why| invalid("origin", why))?;
    let issuer = url::Url::parse(&entry.issuer).map_err(|e| invalid("issuer", e.to_string()))?;
    if issuer.scheme() != "https" && issuer.scheme() != "http" {
        return Err(invalid("issuer", "not an http(s) URL".into()));
    }
    // RFC 8707 §2: an absolute URI without a fragment, compared as registered.
    sid_core::models::ResourceIndicator::parse(&entry.resource)
        .map_err(|e| invalid("resource", e.to_string()))?;

    let mut routes = Vec::with_capacity(entry.routes.len());
    for route in entry.routes {
        let matcher = Glob::new(&route.match_.path)
            .map_err(|e| PolicyError::GlobError(route.match_.path.clone(), e))?
            .compile_matcher();
        // A method that does not parse would drop out of the set, and an
        // emptied set matches every method: refuse it instead.
        let methods = route
            .match_
            .methods
            .iter()
            .map(|m| {
                m.parse::<Method>()
                    .map_err(|_| PolicyError::InvalidMethod(m.clone()))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let requirements = route.policy.require.unwrap_or_default();
        let headers = route.policy.headers.unwrap_or_default();
        let authz_action = match (route.policy.check_authz, route.policy.action) {
            (true, Some(action)) if !action.is_empty() => Some(action),
            (false, None) => None,
            (true, _) => {
                return Err(invalid(
                    "action",
                    "a route asking sid-authz names the operation it decides".into(),
                ));
            }
            (false, Some(_)) => {
                return Err(invalid(
                    "action",
                    "an action is named only for a route asking sid-authz".into(),
                ));
            }
        };
        routes.push(CompiledRoute {
            matcher,
            methods,
            policy: RoutePolicy {
                auth: match route.policy.auth {
                    AuthRequirementDef::None => AuthRequirement::None,
                    AuthRequirementDef::Required => AuthRequirement::Required,
                    AuthRequirementDef::Optional => AuthRequirement::Optional,
                },
                required_roles: requirements.roles,
                inject_headers: headers.inject,
                authz_action,
            },
        });
    }
    Ok(ProtectedApplication {
        origin,
        target: Target {
            issuer: entry.issuer,
            resource: entry.resource,
        },
        routes,
        default_policy: RoutePolicy::authenticated(),
    })
}

/// `scheme://host[:port]` of an http(s) origin: no path, query, fragment or
/// credentials, so the request URI is this plus the forwarded path.
fn parse_origin(origin: &str) -> Result<String, String> {
    let url = url::Url::parse(origin).map_err(|e| e.to_string())?;
    let is_origin = matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !is_origin {
        return Err("not an http(s) origin (scheme://host[:port])".into());
    }
    Ok(url.origin().ascii_serialization())
}

/// Policy loading error.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file {0}: {1}")]
    IoError(String, std::io::Error),
    #[error("invalid YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("invalid glob pattern '{0}': {1}")]
    GlobError(String, globset::Error),
    #[error("invalid HTTP method '{0}'")]
    InvalidMethod(String),
    #[error("application '{0}' is configured twice")]
    DuplicateApplication(String),
    #[error("application '{name}': invalid {field}: {why}")]
    InvalidApplication {
        name: String,
        field: &'static str,
        why: String,
    },
}

#[cfg(test)]
mod tests;
