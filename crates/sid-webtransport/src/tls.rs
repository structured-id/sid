// SPDX-License-Identifier: AGPL-3.0-only
use crate::config::{Config, TlsMode};
use std::path::PathBuf;
use tracing::info;
use wtransport::Identity;

/// Resolved TLS identity with computed certificate hash.
pub struct ResolvedIdentity {
    pub identity: Identity,
    /// SHA-256 hash of the leaf certificate (hex string).
    /// Browsers use this for `serverCertificateHashes` with self-signed certs.
    pub cert_hash: String,
}

/// The TLS identity could not be built; the server does not start without it.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("generating the development certificate: {0}")]
    SelfSigned(#[from] wtransport::tls::error::InvalidSan),
    #[error("loading the WebTransport certificate {cert:?} and key {key:?}: {source}")]
    Pem {
        cert: PathBuf,
        key: PathBuf,
        source: wtransport::tls::error::PemLoadError,
    },
    #[error("the WebTransport certificate chain is empty")]
    EmptyChain,
}

/// Build wtransport Identity from config, returning the identity and cert hash.
pub async fn resolve_identity(config: &Config) -> Result<ResolvedIdentity, TlsError> {
    let identity = match &config.tls {
        TlsMode::Dev => {
            let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])?;
            info!("Generated dev WebTransport certificate");
            identity
        }
        TlsMode::Pem { cert, key } => {
            let identity =
                Identity::load_pemfiles(cert, key)
                    .await
                    .map_err(|source| TlsError::Pem {
                        cert: cert.clone(),
                        key: key.clone(),
                        source,
                    })?;
            info!("Loaded WebTransport certificate from {:?}", cert);
            identity
        }
    };
    let cert_hash = compute_cert_hash(&identity)?;
    info!("Certificate hash (SHA-256): {}", cert_hash);
    Ok(ResolvedIdentity {
        identity,
        cert_hash,
    })
}

/// Compute SHA-256 hex hash of the first certificate in the chain.
fn compute_cert_hash(identity: &Identity) -> Result<String, TlsError> {
    let chain = identity.certificate_chain();
    let cert = chain.as_slice().first().ok_or(TlsError::EmptyChain)?;
    Ok(format!("{}", cert.hash()))
}

#[cfg(test)]
mod tests;
