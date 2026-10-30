// SPDX-License-Identifier: AGPL-3.0-only
//! The HTTP form of a service's own annotated RPCs: structured-proxy embedded
//! as a library, calling the service's own gRPC services in process. The
//! service writes no HTTP code; the transcoder mounts the `google.api.http`
//! routes of the proto files the service serves.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use structured_proxy::client_address::{ClientAddressLayer, Resolution};
use structured_proxy::config::ClientAddressConfig;
use structured_proxy::upstream::Upstream;
use structured_proxy::{ClientAddress, ProxyServer};

/// A transcoder for the RPCs in the proto files `files` selects.
///
/// `config` is a structured-proxy configuration tree, read from YAML or built
/// in code (listen address, CORS, rate limits, health, metrics). It names no
/// upstream: [`serve`] hands the
/// transcoder the service's own gRPC services. `forwarded_headers` are
/// forwarded whatever it lists, since the RPCs read them as metadata.
pub fn embedded_transcoder(
    config: &serde_json::Value,
    forwarded_headers: &[&str],
    files: impl Fn(&str) -> bool,
) -> anyhow::Result<ProxyServer> {
    embedded_transcoder_with_sets(config, forwarded_headers, files, &[])
}

/// [`embedded_transcoder`] also serving the annotated RPCs of `added`, the
/// encoded file descriptor sets of services a host adds beside SID's. A
/// file present in several sets is taken once.
pub fn embedded_transcoder_with_sets(
    config: &serde_json::Value,
    forwarded_headers: &[&str],
    files: impl Fn(&str) -> bool,
    added: &[&[u8]],
) -> anyhow::Result<ProxyServer> {
    let mut config = config.clone();
    let map = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration must be a mapping"))?;
    anyhow::ensure!(
        !map.contains_key("upstream"),
        "the HTTP configuration names no upstream: it serves this service's own RPCs"
    );

    let mut forwarded: Vec<serde_json::Value> = map
        .get("forwarded_headers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for name in forwarded_headers {
        if !forwarded.iter().any(|v| v.as_str() == Some(name)) {
            forwarded.push((*name).into());
        }
    }
    map.insert("forwarded_headers".into(), forwarded.into());

    let mut pool =
        prost_reflect::DescriptorPool::decode(sid_proto::descriptor_set_of(files).as_slice())?;
    for set in added {
        pool.decode_file_descriptor_set(*set)?;
    }
    // JSON text is YAML (YAML 1.2 §1.3), so the transcoder reads the
    // configuration as it reads its own file.
    Ok(ProxyServer::from_yaml_str(&serde_json::to_string(&config)?)?.with_descriptors(pool))
}

/// Serve `proxy` on its listen address in front of `upstream`, the service's
/// own gRPC services, called in process: REST, native gRPC and gRPC-Web share
/// the port, and a handler sees the HTTP client's address. When `shutdown`
/// resolves the listener closes and calls in flight get `drain`, the
/// process's drain interval, to finish.
pub async fn serve<U: Upstream>(
    proxy: &ProxyServer,
    upstream: U,
    shutdown: impl Future<Output = ()>,
    drain: Duration,
) -> anyhow::Result<()> {
    let bind = &proxy.config().listen.http;
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("HTTP listen address {bind:?}: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_on(proxy, upstream, listener, shutdown, drain).await
}

/// [`serve`] on `listener`, already bound, instead of the listen address.
pub async fn serve_on<U: Upstream>(
    proxy: &ProxyServer,
    upstream: U,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()>,
    drain: Duration,
) -> anyhow::Result<()> {
    let service = proxy.service(upstream)?;
    // One drain interval for every listener of the process.
    let options = proxy.serve_options()?.drain_timeout(Some(drain));
    structured_proxy::serve_with_shutdown(listener, service, options, shutdown).await?;
    Ok(())
}

/// A structured-proxy configuration listening on `bind` and nothing else.
pub fn listening_on(bind: &str) -> serde_json::Value {
    serde_json::json!({ "listen": { "http": bind } })
}

/// The address of the client behind `request`: what the proxy in front of the
/// service resolved, or the transport peer of a direct call, where no proxy
/// took part. An address the proxy could not resolve is a refusal: a call
/// with none would pass the checks that key on it.
pub fn client_ip<T>(request: &tonic::Request<T>) -> Result<Option<IpAddr>, tonic::Status> {
    let Some(client) = request.extensions().get::<ClientAddress>() else {
        return Ok(request.remote_addr().map(|peer| peer.ip()));
    };
    match client.resolution() {
        Resolution::Peer(ip) | Resolution::Forwarded(ip) => Ok(Some(ip)),
        Resolution::Invalid(why) => Err(sid_core::grpc_error::refuse::invalid_field(
            "x-forwarded-for",
            format!("a trusted proxy's report is {why}"),
        )),
        _ => Err(sid_core::grpc_error::refuse::internal(
            "client address",
            "not resolved",
        )),
    }
}

/// The client address settings of a service behind the comma-separated
/// `proxies`: an address they do not report readably is refused, never
/// replaced by a proxy's own, and they are the only hops believed (RFC 7239
/// §8.1). Empty means no proxy: every peer is the client.
fn edge_trust(proxies: &str) -> serde_json::Value {
    let trusted: Vec<&str> = proxies
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    serde_json::json!({ "required": !trusted.is_empty(), "trusted_proxies": trusted })
}

/// What the proxies in front of a service report the client in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeReport {
    /// The `X-Forwarded-For` chain, walked through them.
    Chain,
    /// One address in `X-Real-IP`, from a reporter that resolved it already:
    /// a list, a repeat or any other header disagreeing with it is refused,
    /// and no chain is walked.
    Resolved,
}

impl EdgeReport {
    /// The report `name` selects, `x-forwarded-for` or `x-real-ip`.
    pub fn parse(name: &str) -> anyhow::Result<Self> {
        match name {
            "x-forwarded-for" => Ok(Self::Chain),
            "x-real-ip" => Ok(Self::Resolved),
            _ => anyhow::bail!("{name:?} is neither x-forwarded-for nor x-real-ip"),
        }
    }
}

/// `config` resolving the client address behind `proxies`, read from `report`;
/// a `client_address` section of its own is refused, so the setting has one
/// source.
pub fn with_edge_trust(
    config: &mut serde_json::Value,
    proxies: &str,
    report: EdgeReport,
) -> anyhow::Result<()> {
    let map = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration must be a mapping"))?;
    anyhow::ensure!(
        !map.contains_key("client_address"),
        "the client address is configured by SID_EDGE_TRUSTED_PROXIES, not in the HTTP configuration"
    );
    let mut section = edge_trust(proxies);
    if report == EdgeReport::Resolved {
        section["header"] = "cleaned_report".into();
    }
    map.insert("client_address".into(), section);
    Ok(())
}

/// Resolves the client address behind `proxies` for a tonic server with no
/// transcoder in front of its services, and leaves only that address in the
/// forwarding headers, so a call it sends on reports the client alone. The
/// layer does not refuse: a handler reads [`client_ip`].
pub fn edge_layer(proxies: &str) -> anyhow::Result<ClientAddressLayer> {
    let mut section = edge_trust(proxies);
    section["forward"] = serde_json::json!({ "x_forwarded_for": "resolved" });
    let config: ClientAddressConfig = serde_json::from_value(section)?;
    ClientAddressLayer::new(&config)
}

#[cfg(test)]
mod tests;
