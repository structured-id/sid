use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn proxies() -> TrustedProxies {
    TrustedProxies::parse("10.0.0.0/8, 192.168.1.5").unwrap()
}

/// A peer that is no trusted proxy is the client, whatever headers it sends:
/// a spoofed `X-Forwarded-For` cannot pick an address.
#[test]
fn untrusted_peer_is_the_client() {
    assert_eq!(
        proxies().client_ip(Some(ip("203.0.113.9")), Some("1.2.3.4"), Some("5.6.7.8")),
        Some(ip("203.0.113.9"))
    );
    assert_eq!(
        TrustedProxies::none().client_ip(Some(ip("10.1.1.1")), Some("1.2.3.4"), None),
        Some(ip("10.1.1.1"))
    );
}

/// Behind trusted proxies the client is the rightmost untrusted entry; what
/// the client itself put on the left is ignored.
#[test]
fn rightmost_untrusted_entry_is_the_client() {
    assert_eq!(
        proxies().client_ip(
            Some(ip("10.0.0.2")),
            Some("6.6.6.6, 198.51.100.7, 10.0.0.3"),
            None
        ),
        Some(ip("198.51.100.7"))
    );
}

/// Only trusted hops in the chain: the leftmost is the best that is known.
#[test]
fn all_trusted_hops_yield_the_leftmost() {
    assert_eq!(
        proxies().client_ip(Some(ip("10.0.0.2")), Some("10.0.0.9, 192.168.1.5"), None),
        Some(ip("10.0.0.9"))
    );
}

/// An unreadable entry stops the walk at the last address known good.
#[test]
fn unreadable_entry_stops_the_walk() {
    assert_eq!(
        proxies().client_ip(Some(ip("10.0.0.2")), Some("198.51.100.7, garbage"), None),
        Some(ip("10.0.0.2"))
    );
}

/// `X-Real-IP` counts from a trusted peer without `X-Forwarded-For`.
#[test]
fn real_ip_from_trusted_peer() {
    assert_eq!(
        proxies().client_ip(Some(ip("10.0.0.2")), None, Some("198.51.100.7")),
        Some(ip("198.51.100.7"))
    );
    assert_eq!(
        proxies().client_ip(Some(ip("10.0.0.2")), None, None),
        Some(ip("10.0.0.2"))
    );
}

/// Without a transport peer there is no address to believe.
#[test]
fn no_peer_no_address() {
    assert_eq!(proxies().client_ip(None, Some("1.2.3.4"), None), None);
}

/// Configuration accepts addresses and ranges and refuses anything else.
#[test]
fn parse_proxy_list() {
    assert_eq!(TrustedProxies::parse("").unwrap(), TrustedProxies::none());
    assert!(TrustedProxies::parse("::1, fd00::/8").is_ok());
    assert_eq!(
        TrustedProxies::parse("10.0.0.0/8, proxy.local"),
        Err(InvalidProxy("proxy.local".into()))
    );
}
