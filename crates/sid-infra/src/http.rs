// SPDX-License-Identifier: AGPL-3.0-only
//! The HTTP form of a service's own annotated RPCs: structured-proxy embedded
//! as a library, calling the service's own gRPC services in process. The
//! service writes no HTTP code; the transcoder mounts the `google.api.http`
//! routes of the proto files the service serves.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use structured_proxy::ProxyServer;
use structured_proxy::upstream::Upstream;

/// A transcoder for the RPCs in the proto files `files` selects.
///
/// `config` is a structured-proxy configuration (listen address, CORS, rate
/// limits, health, metrics). It names no upstream: [`serve`] hands the
/// transcoder the service's own gRPC services. `forwarded_headers` are
/// forwarded whatever it lists, since the RPCs read them as metadata.
pub fn embedded_transcoder(
    config: &serde_yaml::Value,
    forwarded_headers: &[&str],
    files: impl Fn(&str) -> bool,
) -> anyhow::Result<ProxyServer> {
    let mut config = config.clone();
    let map = config
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("the HTTP configuration must be a mapping"))?;
    anyhow::ensure!(
        !map.contains_key("upstream"),
        "the HTTP configuration names no upstream: it serves this service's own RPCs"
    );

    let mut forwarded: Vec<serde_yaml::Value> = map
        .get("forwarded_headers")
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    for name in forwarded_headers {
        if !forwarded.iter().any(|v| v.as_str() == Some(name)) {
            forwarded.push((*name).into());
        }
    }
    map.insert("forwarded_headers".into(), forwarded.into());

    let pool =
        prost_reflect::DescriptorPool::decode(sid_proto::descriptor_set_of(files).as_slice())?;
    Ok(ProxyServer::from_yaml_str(&serde_yaml::to_string(&config)?)?.with_descriptors(pool))
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
pub fn listening_on(bind: &str) -> serde_yaml::Value {
    let mut listen = serde_yaml::Mapping::new();
    listen.insert("http".into(), bind.into());
    let mut config = serde_yaml::Mapping::new();
    config.insert("listen".into(), listen.into());
    config.into()
}

#[cfg(test)]
mod tests;
