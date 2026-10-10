// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration of the forward-auth decision service.
//!
//! Loaded from a YAML file (`sid-auth --config sid-auth.yaml`) or, without
//! one, from `SID_*` environment variables.

use serde::Deserialize;
use sid_authn::client_credential::ClientCredentialConfig;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Where the gRPC services listen: `ForwardAuthService`, Envoy ext_authz
    /// `Authorization` and gRPC health.
    #[serde(default = "default_grpc_listen")]
    pub grpc_listen: String,
    /// The SID server's gRPC address: its issuer registry and sid-authz.
    pub upstream: String,
    /// The installation's public URL, the base of its issuers' URLs.
    pub issuer_url: String,
    /// Where a 401 sends a browser to sign in; empty for no redirect.
    #[serde(default)]
    pub login_url: String,
    /// The protected applications file (targets and routes). Without it
    /// every decision is refused.
    #[serde(default)]
    pub route_policy_path: Option<String>,
    /// The shared cache (Redis/Dragonfly/Valkey URL) holding revocations and
    /// DPoP proof `jti`s. Unset keeps them in this process, which is correct
    /// for exactly one replica.
    #[serde(default)]
    pub cache_url: Option<String>,
    /// This service's own credential for the authorization API, which routes
    /// asking sid-authz need. Without it such routes have no verdict.
    #[serde(default)]
    pub authz_checker: Option<ClientCredentialConfig>,
    /// The HTTP form of forward auth for reverse proxies (`/auth/verify/...`),
    /// served by the embedded transcoder: a structured-proxy configuration
    /// (listen address, CORS, rate limits, health, metrics). Its upstream and
    /// the request headers it forwards are set by this service.
    #[cfg(feature = "http")]
    #[serde(default)]
    pub http: Option<serde_yaml::Value>,
}

/// The variable prefix of the permission-checking client.
pub const CHECKER_ENV: &str = "SID_AUTHZ_CHECKER";

/// A gRPC service admitting calls with access tokens for its registered
/// resource ([`crate::receiver`]): where it reaches its issuer and how it
/// authenticates to the issuer's authorization API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverConfig {
    /// The SID server's gRPC address: its issuer registry and sid-authz.
    pub upstream: String,
    /// The installation's public URL, the base of its issuers' URLs.
    pub issuer_url: String,
    /// The service's registered resource indicator, the `aud` every
    /// admitted token carries.
    pub resource: String,
    /// Scheme and authority callers address the service at: the prefix of
    /// every DPoP proof's `htu`.
    pub origin: String,
    /// The shared cache (Redis/Dragonfly/Valkey URL) recording DPoP proof
    /// `jti`s across replicas. Unset keeps them in this process, which is
    /// correct for exactly one replica.
    #[serde(default)]
    pub cache_url: Option<String>,
    /// The service's own client at the authorization API. Its issuer is the
    /// issuer every admitted token is from.
    pub checker: ClientCredentialConfig,
}

impl ReceiverConfig {
    /// From `SID_GRPC_UPSTREAM`, `SID_ISSUER_URL`, `SID_RECEIVER_RESOURCE`,
    /// `SID_RECEIVER_ORIGIN`, `SID_CACHE_URL` and `SID_AUTHZ_CHECKER_*`, all
    /// required but the cache.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let required = |name: &str| var(name).ok_or_else(|| anyhow::anyhow!("{name} is required"));
        Ok(Self {
            upstream: required("SID_GRPC_UPSTREAM")?,
            issuer_url: required("SID_ISSUER_URL")?,
            resource: required("SID_RECEIVER_RESOURCE")?,
            origin: required("SID_RECEIVER_ORIGIN")?,
            cache_url: var("SID_CACHE_URL").or_else(|| var("SID_REDIS_URL")),
            checker: ClientCredentialConfig::from_vars(CHECKER_ENV, &var)?
                .ok_or_else(|| anyhow::anyhow!("{CHECKER_ENV}_CLIENT_ID is required"))?,
        })
    }
}

fn default_grpc_listen() -> String {
    "0.0.0.0:50061".into()
}

impl AuthConfig {
    /// Load from a YAML file.
    pub fn from_yaml(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {path}: {e}"))?;
        serde_yaml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("failed to parse config {path}: {e}"))
    }

    /// Load from `SID_*` environment variables. `SID_ISSUER_URL` is required;
    /// `SID_AUTH_HTTP_BIND` turns the HTTP form on at that address.
    pub fn from_env() -> anyhow::Result<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Ok(Self {
            grpc_listen: var("SID_AUTH_GRPC_BIND").unwrap_or_else(default_grpc_listen),
            upstream: var("SID_GRPC_UPSTREAM")
                .ok_or_else(|| anyhow::anyhow!("SID_GRPC_UPSTREAM is required"))?,
            issuer_url: var("SID_ISSUER_URL")
                .ok_or_else(|| anyhow::anyhow!("SID_ISSUER_URL is required"))?,
            login_url: var("SID_LOGIN_URL").unwrap_or_default(),
            route_policy_path: var("SID_ROUTE_POLICY_PATH"),
            // The deployment's general cache first; the specific name exists
            // for a stack that keeps this service's cache apart.
            cache_url: var("SID_CACHE_URL").or_else(|| var("SID_REDIS_URL")),
            authz_checker: ClientCredentialConfig::from_vars(CHECKER_ENV, var)?,
            #[cfg(feature = "http")]
            http: var("SID_AUTH_HTTP_BIND").map(|bind| sid_infra::http::listening_on(&bind)),
        })
    }
}

#[cfg(test)]
mod tests;
