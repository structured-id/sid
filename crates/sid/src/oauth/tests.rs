use super::*;

#[test]
fn test_ip_matches_exact_v4() {
    let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(ip_matches("10.0.0.1", &addr));
    assert!(!ip_matches("10.0.0.2", &addr));
}

#[test]
fn test_ip_matches_cidr_v4() {
    let addr: std::net::IpAddr = "10.0.0.42".parse().unwrap();
    assert!(ip_matches("10.0.0.0/24", &addr));
    assert!(!ip_matches("10.0.1.0/24", &addr));
}

#[test]
fn test_ip_matches_cidr_v4_16() {
    let addr: std::net::IpAddr = "172.16.5.10".parse().unwrap();
    assert!(ip_matches("172.16.0.0/16", &addr));
    assert!(!ip_matches("172.17.0.0/16", &addr));
}

#[test]
fn test_ip_matches_exact_v6() {
    let addr: std::net::IpAddr = "::1".parse().unwrap();
    assert!(ip_matches("::1", &addr));
    assert!(!ip_matches("::2", &addr));
}

#[test]
fn test_ip_matches_cidr_v6() {
    let addr: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    assert!(ip_matches("2001:db8::/32", &addr));
    assert!(!ip_matches("2001:db9::/32", &addr));
}

#[test]
fn test_ip_matches_invalid_entry() {
    let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!ip_matches("not-an-ip", &addr));
    assert!(!ip_matches("not-a-cidr/24", &addr));
    // A prefix beyond the family's width matches nothing.
    assert!(!ip_matches("10.0.0.0/33", &addr));
}

/// A /0 block holds every address of its family.
#[test]
fn test_ip_matches_zero_prefix() {
    let v4: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    assert!(ip_matches("0.0.0.0/0", &v4));
    let v6: std::net::IpAddr = "2001:db8::9".parse().unwrap();
    assert!(ip_matches("::/0", &v6));
}

#[test]
fn test_ip_matches_mixed_v4_v6() {
    let v4: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!ip_matches("::1/128", &v4));
    let v6: std::net::IpAddr = "::1".parse().unwrap();
    assert!(!ip_matches("10.0.0.0/24", &v6));
}
