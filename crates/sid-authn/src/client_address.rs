// SPDX-License-Identifier: AGPL-3.0-only
//! The address of the client behind a request.
//!
//! Forwarding headers are written by whoever sends them, so they count only
//! when the transport peer is a configured trusted proxy. `X-Forwarded-For` is
//! appended to by each proxy on the way, so the client is the rightmost entry
//! that is not itself a trusted proxy; everything left of it is what the
//! client claimed (RFC 7239 §5.2 and §8.1 describe the same trust model for
//! `Forwarded`).

use ipnet::IpNet;
use std::net::IpAddr;

/// Proxies whose forwarding headers are believed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<IpNet>);

/// A trusted-proxy entry that is neither an address nor a CIDR range.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("trusted proxy {0:?} is not an IP address or CIDR range")]
pub struct InvalidProxy(pub String);

impl TrustedProxies {
    /// No proxy is trusted: the transport peer is the client.
    pub fn none() -> Self {
        Self::default()
    }

    /// Parse a comma-separated list of addresses and CIDR ranges.
    pub fn parse(list: &str) -> Result<Self, InvalidProxy> {
        list.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| InvalidProxy(entry.to_owned()))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    fn trusts(&self, addr: &IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(addr))
    }

    /// The client address of a request that arrived from `peer` carrying the
    /// given `X-Forwarded-For` and `X-Real-IP` values. `None` only without a
    /// transport peer.
    pub fn client_ip(
        &self,
        peer: Option<IpAddr>,
        forwarded_for: Option<&str>,
        real_ip: Option<&str>,
    ) -> Option<IpAddr> {
        let peer = peer?;
        if !self.trusts(&peer) {
            return Some(peer);
        }
        if let Some(chain) = forwarded_for {
            let mut client = peer;
            for entry in chain.rsplit(',') {
                let Ok(hop) = entry.trim().parse::<IpAddr>() else {
                    // Unreadable input is not trusted to name anyone.
                    return Some(client);
                };
                client = hop;
                if !self.trusts(&hop) {
                    break;
                }
            }
            return Some(client);
        }
        real_ip.and_then(|v| v.trim().parse().ok()).or(Some(peer))
    }
}

#[cfg(test)]
mod tests;
