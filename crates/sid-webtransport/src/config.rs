// SPDX-License-Identifier: AGPL-3.0-only
use std::net::SocketAddr;
use std::path::PathBuf;

/// WebTransport server configuration.
pub struct Config {
    /// Listen address for the QUIC endpoint.
    pub bind: SocketAddr,
    /// TLS mode: either dev (auto-generated cert) or prod (PEM files).
    pub tls: TlsMode,
}

pub enum TlsMode {
    /// Auto-generate a short-lived self-signed dev certificate.
    Dev,
    /// Load PEM cert + key from disk.
    Pem { cert: PathBuf, key: PathBuf },
}

/// A WebTransport setting that is missing or malformed.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("SID_WEBTRANSPORT_BIND must be a socket address, got {0:?}")]
    InvalidBind(String),
    #[error("SID_WEBTRANSPORT_CERT_PATH or SID_WEBTRANSPORT_DEV_TLS is required")]
    MissingCert,
    #[error("SID_WEBTRANSPORT_KEY_PATH is required when using PEM TLS")]
    MissingKey,
}

impl Config {
    /// Build config from the process environment.
    ///
    /// - `SID_WEBTRANSPORT_BIND` — listen address (default `127.0.0.1:4433`)
    /// - `SID_WEBTRANSPORT_DEV_TLS` — `true` or `1` to auto-generate a dev cert
    /// - `SID_WEBTRANSPORT_CERT_PATH` / `SID_WEBTRANSPORT_KEY_PATH` — PEM paths
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Build config from settings returned by `get` (setting name to value).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let bind_value =
            get("SID_WEBTRANSPORT_BIND").unwrap_or_else(|| "127.0.0.1:4433".to_string());
        let bind: SocketAddr = bind_value
            .parse()
            .map_err(|_| ConfigError::InvalidBind(bind_value))?;

        let dev_tls = get("SID_WEBTRANSPORT_DEV_TLS").is_some_and(|v| v == "true" || v == "1");

        let tls = if dev_tls {
            TlsMode::Dev
        } else {
            let cert = get("SID_WEBTRANSPORT_CERT_PATH").ok_or(ConfigError::MissingCert)?;
            let key = get("SID_WEBTRANSPORT_KEY_PATH").ok_or(ConfigError::MissingKey)?;
            TlsMode::Pem {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            }
        };

        Ok(Config { bind, tls })
    }
}

#[cfg(test)]
mod tests;
