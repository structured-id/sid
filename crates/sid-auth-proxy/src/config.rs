// SPDX-License-Identifier: AGPL-3.0-only
//! Application proxy configuration.
//!
//! Loaded from a YAML file (`sid-auth-proxy --config sid-auth-proxy.yaml`) or,
//! without one, from `SID_*` environment variables.

use serde::Deserialize;

/// Top-level proxy configuration (YAML-deserializable).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Service identity section.
    #[serde(default)]
    pub service: ServiceConfig,

    /// Listen address.
    #[serde(default)]
    pub listen: ListenConfig,

    /// gRPC upstream endpoint.
    pub upstream: UpstreamConfig,

    /// OIDC / issuer settings.
    #[serde(default)]
    pub oidc: OidcConfig,

    /// CORS settings.
    #[serde(default)]
    pub cors: CorsConfig,

    /// Shield rate limiting settings.
    #[serde(default)]
    pub shield: ShieldYamlConfig,

    /// Where the shared cache lives, as a Redis/Dragonfly/Valkey URL.
    ///
    /// It carries what every replica has to agree on: BFF sessions and the
    /// rate-limit counters. Unset means this process keeps both to itself,
    /// which is correct for exactly one replica and wrong for any deployment
    /// that runs two.
    #[serde(default)]
    pub cache_url: Option<String>,

    /// BFF (Backend-for-Frontend) settings.
    #[serde(default)]
    pub bff: BffConfig,
}

/// Service identity.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_service_name")]
    pub name: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: default_service_name(),
        }
    }
}

fn default_service_name() -> String {
    "sid-auth-proxy".into()
}

/// Listen address config.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_bind_addr")]
    pub http: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            http: default_bind_addr(),
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:8080".into()
}

/// gRPC upstream config.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// Default gRPC upstream URL.
    pub default: String,
}

/// OIDC / issuer settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The installation's public URL, the base of its issuers' URLs.
    #[serde(default)]
    pub issuer_url: String,
}

/// CORS config.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub origins: Vec<String>,
}

/// Shield (rate limiting) YAML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ShieldYamlConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Per-IP rate limit for auth endpoints (per minute).
    #[serde(default = "default_auth_rate")]
    pub auth_rate: u32,
    /// Per-IP rate limit for registration endpoints (per minute).
    #[serde(default = "default_register_rate")]
    pub register_rate: u32,
    /// Per-IP default rate limit (per minute).
    #[serde(default = "default_default_rate")]
    pub default_rate: u32,
    /// Per-principal rate limit (per minute).
    #[serde(default = "default_principal_rate")]
    pub principal_rate: u32,
    /// Per-IP rate limit for magic-link endpoints (per minute).
    #[serde(default = "default_magic_link_rate")]
    pub magic_link_rate: u32,
    /// Per-principal rate limit for magic-link endpoints (per minute).
    #[serde(default = "default_magic_link_principal_rate")]
    pub magic_link_principal_rate: u32,
    /// Window size in seconds.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// IP blocklist.
    #[serde(default)]
    pub ip_blocklist: Vec<String>,
    /// Endpoint class patterns (path prefix → class name).
    #[serde(default = "default_endpoint_classes")]
    pub endpoint_classes: Vec<EndpointClassPattern>,
}

impl Default for ShieldYamlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth_rate: 20,
            register_rate: 5,
            default_rate: 100,
            principal_rate: 5,
            magic_link_rate: 3,
            magic_link_principal_rate: 1,
            window_secs: 60,
            ip_blocklist: vec![],
            endpoint_classes: default_endpoint_classes(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_auth_rate() -> u32 {
    20
}
fn default_register_rate() -> u32 {
    5
}
fn default_default_rate() -> u32 {
    100
}
fn default_principal_rate() -> u32 {
    5
}
fn default_magic_link_rate() -> u32 {
    3
}
fn default_magic_link_principal_rate() -> u32 {
    1
}
fn default_window_secs() -> u64 {
    60
}

/// Endpoint class pattern for Shield rate limiting.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointClassPattern {
    /// Path prefix to match.
    pub prefix: String,
    /// Class name: "auth", "register", "magic_link", "health".
    pub class: String,
}

fn default_endpoint_classes() -> Vec<EndpointClassPattern> {
    vec![
        EndpointClassPattern {
            prefix: "/health".into(),
            class: "health".into(),
        },
        EndpointClassPattern {
            prefix: "/v1/auth/magic-link".into(),
            class: "magic_link".into(),
        },
        EndpointClassPattern {
            prefix: "/v1/auth/opaque/register".into(),
            class: "register".into(),
        },
        EndpointClassPattern {
            prefix: "/v1/auth/webauthn/register".into(),
            class: "register".into(),
        },
        EndpointClassPattern {
            prefix: "/v1/identity/profiles".into(),
            class: "register".into(),
        },
        EndpointClassPattern {
            prefix: "/v1/auth/".into(),
            class: "auth".into(),
        },
        EndpointClassPattern {
            prefix: "/oauth2/token".into(),
            class: "auth".into(),
        },
    ]
}

/// BFF (Backend-for-Frontend) config.
///
/// Issuer, client, resource, scopes and callback are not settings: SID
/// provisions the account integration and hands them to the holder of the
/// client key, so an operator never copies them by hand.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BffConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_bff_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_bff_max_age")]
    pub max_age: u64,
    #[serde(default = "default_bff_idle_timeout")]
    pub idle_timeout: u64,
    /// How long an unfinished authorization may sit between the login redirect
    /// and the callback, in seconds.
    ///
    /// The same trade-off as the two above, over a much shorter span: long
    /// enough covers a login that detours through an upstream IdP's MFA or a
    /// switch to another app, and short keeps the window in which a leaked
    /// `state` could be replayed. Deployments differ on which side they need,
    /// so it is set rather than assumed.
    #[serde(default = "default_bff_pending_ttl")]
    pub pending_ttl: u64,
    /// Path of the BFF's client key: an Ed25519 private key, PKCS#8 PEM
    /// (RFC 8410), made by `sid-auth-proxy keygen`. SID holds its public
    /// JWK Set; the BFF proves the key to learn its connection and signs its
    /// token endpoint assertions with it. The BFF is off without it.
    #[serde(default)]
    pub client_key: Option<String>,
    /// The account API's gRPC-Web endpoint, where `/api/*` goes with the
    /// `/api` prefix removed.
    #[serde(default)]
    pub api_upstream: Option<String>,
    /// Dev mode: no Secure flag on the cookies (a plain-HTTP localhost), and
    /// with it no `__Host-` prefix on their names, which needs the flag.
    #[serde(default)]
    pub dev_mode: bool,
}

impl Default for BffConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_name: default_bff_cookie_name(),
            max_age: default_bff_max_age(),
            idle_timeout: default_bff_idle_timeout(),
            pending_ttl: default_bff_pending_ttl(),
            client_key: None,
            api_upstream: None,
            dev_mode: false,
        }
    }
}

fn default_bff_cookie_name() -> String {
    "__Host-sid-bff".into()
}
fn default_bff_max_age() -> u64 {
    86400
}
fn default_bff_idle_timeout() -> u64 {
    3600
}
fn default_bff_pending_ttl() -> u64 {
    300
}

impl ProxyConfig {
    /// Load from YAML file.
    pub fn from_yaml(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path, e))?;
        let config: Self = serde_yaml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse config {}: {}", path, e))?;
        Ok(config)
    }

    /// Load configuration from environment variables (legacy mode).
    pub fn from_env() -> Self {
        let cors_origins = std::env::var("SID_CORS_ORIGINS")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
            .unwrap_or_default();

        let issuer_url = std::env::var("SID_ISSUER_URL").expect("SID_ISSUER_URL is required");

        Self {
            service: ServiceConfig::default(),
            listen: ListenConfig {
                http: std::env::var("SID_PROXY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            },
            upstream: UpstreamConfig {
                default: std::env::var("SID_GRPC_UPSTREAM")
                    .unwrap_or_else(|_| "http://127.0.0.1:50051".into()),
            },
            oidc: OidcConfig { issuer_url },
            cors: CorsConfig {
                origins: cors_origins,
            },
            shield: ShieldYamlConfig::from_env(),
            // The deployment's general cache first; the specific name exists
            // for a stack that keeps this service's cache apart.
            cache_url: std::env::var("SID_CACHE_URL")
                .or_else(|_| std::env::var("SID_REDIS_URL"))
                .ok()
                .filter(|url| !url.is_empty()),
            bff: BffConfig {
                enabled: std::env::var("SID_BFF_ENABLED")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
                cookie_name: std::env::var("SID_BFF_COOKIE_NAME")
                    .unwrap_or_else(|_| "__Host-sid-bff".into()),
                max_age: std::env::var("SID_BFF_MAX_AGE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(86400),
                idle_timeout: std::env::var("SID_BFF_IDLE_TIMEOUT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3600),
                pending_ttl: std::env::var("SID_BFF_PENDING_TTL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(default_bff_pending_ttl),
                client_key: std::env::var("SID_BFF_CLIENT_KEY")
                    .ok()
                    .filter(|path| !path.is_empty()),
                api_upstream: std::env::var("SID_BFF_API_UPSTREAM")
                    .ok()
                    .filter(|url| !url.is_empty()),
                dev_mode: std::env::var("SID_BFF_DEV_MODE")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
            },
        }
    }

    // -- Convenience accessors --

    /// Bind address.
    pub fn bind_addr(&self) -> &str {
        &self.listen.http
    }

    /// gRPC upstream URL.
    pub fn grpc_upstream(&self) -> &str {
        &self.upstream.default
    }

    /// Public issuer URL.
    pub fn issuer_url(&self) -> &str {
        &self.oidc.issuer_url
    }

    /// CORS origins.
    pub fn cors_origins(&self) -> &[String] {
        &self.cors.origins
    }

    /// BFF enabled.
    pub fn bff_enabled(&self) -> bool {
        self.bff.enabled
    }

    /// The session cookie's name. Dev mode leaves the Secure flag off, and
    /// the `__Host-` prefix requires it (RFC 6265bis 4.1.3.2): a browser
    /// refuses the prefixed cookie without it, so the prefix goes with the flag.
    pub fn bff_cookie_name(&self) -> &str {
        let name = self.bff.cookie_name.as_str();
        match name.strip_prefix("__Host-") {
            Some(bare) if self.bff.dev_mode => bare,
            _ => name,
        }
    }

    /// Path of the BFF's client key.
    pub fn bff_client_key(&self) -> Option<&str> {
        self.bff.client_key.as_deref()
    }

    /// The account API's gRPC-Web endpoint.
    pub fn bff_api_upstream(&self) -> Option<&str> {
        self.bff.api_upstream.as_deref()
    }

    /// BFF dev mode (skip Secure flag on cookies for localhost).
    pub fn bff_dev_mode(&self) -> bool {
        self.bff.dev_mode
    }

    /// Absolute session lifetime in seconds.
    pub fn bff_max_age(&self) -> u64 {
        self.bff.max_age
    }

    /// Idle session lifetime in seconds.
    pub fn bff_idle_timeout(&self) -> u64 {
        self.bff.idle_timeout
    }

    /// Lifetime of an unfinished authorization in seconds.
    pub fn bff_pending_ttl(&self) -> u64 {
        self.bff.pending_ttl
    }

    /// URL of the shared cache, if the deployment named one.
    pub fn cache_url(&self) -> Option<&str> {
        self.cache_url.as_deref()
    }
}

impl ShieldYamlConfig {
    /// Load from environment variables.
    fn from_env() -> Self {
        let enabled = std::env::var("SID_SHIELD_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        Self {
            enabled,
            auth_rate: parse_env("SID_SHIELD_AUTH_RATE", 20),
            register_rate: parse_env("SID_SHIELD_REGISTER_RATE", 5),
            default_rate: parse_env("SID_SHIELD_DEFAULT_RATE", 100),
            principal_rate: parse_env("SID_SHIELD_PRINCIPAL_RATE", 5),
            magic_link_rate: parse_env("SID_SHIELD_MAGIC_LINK_RATE", 3),
            magic_link_principal_rate: parse_env("SID_SHIELD_MAGIC_LINK_PRINCIPAL_RATE", 1),
            window_secs: parse_env("SID_SHIELD_WINDOW_SECS", 60),
            ip_blocklist: vec![],
            endpoint_classes: default_endpoint_classes(),
        }
    }

    /// Convert to ShieldConfig for the Shield middleware.
    pub fn to_shield_config(&self) -> crate::shield::ShieldConfig {
        use crate::shield::EndpointClass;

        let endpoint_classes: Vec<(String, EndpointClass)> = self
            .endpoint_classes
            .iter()
            .map(|p| (p.prefix.clone(), EndpointClass::from_name(&p.class)))
            .collect();

        crate::shield::ShieldConfig {
            enabled: self.enabled,
            auth_rate: self.auth_rate,
            register_rate: self.register_rate,
            default_rate: self.default_rate,
            principal_rate: self.principal_rate,
            magic_link_rate: self.magic_link_rate,
            magic_link_principal_rate: self.magic_link_principal_rate,
            window_secs: self.window_secs,
            endpoint_classes,
        }
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests;
