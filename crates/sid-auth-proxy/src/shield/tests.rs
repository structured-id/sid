// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sid_plugin::cache::InMemoryCacheBackend;
use std::net::Ipv4Addr;

/// One instance with a cache of its own: the shared count then tracks the
/// local one, so these tests read the same as before the count was shared.
fn for_test(config: ShieldConfig) -> Shield {
    Shield::new(config, Arc::new(InMemoryCacheBackend::new()))
}

/// Two instances behind a load balancer, counting into one cache.
fn replica_pair(config: ShieldConfig) -> (Shield, Shield) {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    (
        Shield::new(config.clone(), cache.clone()),
        Shield::new(config, cache),
    )
}

fn test_shield() -> Shield {
    for_test(ShieldConfig {
        enabled: true,
        auth_rate: 3,
        register_rate: 2,
        default_rate: 5,
        principal_rate: 5,
        magic_link_rate: 2,
        magic_link_principal_rate: 1,
        window_secs: 60,
        endpoint_classes: EndpointClass::default_patterns(),
    })
}

#[tokio::test]
async fn test_disabled_shield_allows_all() {
    let shield = for_test(ShieldConfig {
        enabled: false,
        ..Default::default()
    });
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for _ in 0..1000 {
        assert!(
            shield
                .check(ip, "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn test_ip_blocklist() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    assert!(shield.check(ip, "/").await.is_ok());
    shield.block_ip(ip);
    assert_eq!(
        shield.check(ip, "/").await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
    shield.unblock_ip(&ip);
    assert!(shield.check(ip, "/").await.is_ok());
}

#[tokio::test]
async fn test_auth_rate_limit() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // auth_rate = 3
    for _ in 0..3 {
        assert!(
            shield
                .check(ip, "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
    // 4th request exceeds limit
    assert_eq!(
        shield
            .check(ip, "/v1/auth/opaque/login/start")
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_register_rate_limit() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // register_rate = 2
    for _ in 0..2 {
        assert!(
            shield
                .check(ip, "/v1/auth/opaque/register/start")
                .await
                .is_ok()
        );
    }
    assert_eq!(
        shield
            .check(ip, "/v1/auth/opaque/register/start")
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_health_not_rate_limited() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    for _ in 0..100 {
        assert!(shield.check(ip, "/health").await.is_ok());
        assert!(shield.check(ip, "/health/ready").await.is_ok());
    }
}

#[tokio::test]
async fn test_different_ips_independent() {
    let shield = test_shield();
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Fill ip1's auth limit
    for _ in 0..3 {
        assert!(
            shield
                .check(ip1, "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
    assert!(
        shield
            .check(ip1, "/v1/auth/opaque/login/start")
            .await
            .is_err()
    );

    // ip2 should still be allowed
    assert!(
        shield
            .check(ip2, "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_different_endpoint_classes_independent() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // Fill auth limit (3)
    for _ in 0..3 {
        assert!(
            shield
                .check(ip, "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
    assert!(
        shield
            .check(ip, "/v1/auth/opaque/login/start")
            .await
            .is_err()
    );

    // Default endpoint class should still work (limit 5)
    assert!(shield.check(ip, "/v1/identity/me").await.is_ok());
}

#[tokio::test]
async fn test_cleanup_removes_old_entries() {
    let shield = test_shield();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let _ = shield.check(ip, "/").await;
    assert!(!shield.windows.is_empty());

    // Cleanup won't remove recent entries
    shield.cleanup();
    assert!(!shield.windows.is_empty());
}

#[test]
fn test_endpoint_classification() {
    let config = ShieldConfig::default();
    assert_eq!(config.classify_path("/health"), EndpointClass::Health);
    assert_eq!(config.classify_path("/health/ready"), EndpointClass::Health);
    assert_eq!(
        config.classify_path("/v1/auth/opaque/login/start"),
        EndpointClass::Auth
    );
    assert_eq!(
        config.classify_path("/v1/auth/opaque/register/start"),
        EndpointClass::Register
    );
    assert_eq!(
        config.classify_path("/v1/auth/webauthn/register/start"),
        EndpointClass::Register
    );
    assert_eq!(config.classify_path("/oauth2/token"), EndpointClass::Auth);
    // Every issuer's token endpoint gets the token endpoint's limit.
    assert_eq!(
        config.classify_path("/i/0123456789abcdef0123456789abcdef/oauth2/token"),
        EndpointClass::Auth
    );
    assert_eq!(
        config.classify_path("/i/0123456789abcdef0123456789abcdef/jwks"),
        EndpointClass::Default
    );
    assert_eq!(
        config.classify_path("/v1/auth/magic-link/send"),
        EndpointClass::MagicLink
    );
    assert_eq!(
        config.classify_path("/v1/auth/magic-link/verify"),
        EndpointClass::MagicLink
    );
    assert_eq!(
        config.classify_path("/v1/identity/me"),
        EndpointClass::Default
    );
}

#[test]
fn test_custom_endpoint_classes() {
    let config = ShieldConfig {
        endpoint_classes: vec![
            ("/api/v2/login".into(), EndpointClass::Auth),
            ("/api/v2/signup".into(), EndpointClass::Register),
        ],
        ..Default::default()
    };
    assert_eq!(
        config.classify_path("/api/v2/login/start"),
        EndpointClass::Auth
    );
    assert_eq!(
        config.classify_path("/api/v2/signup"),
        EndpointClass::Register
    );
    // No /health pattern → falls through to Default
    assert_eq!(config.classify_path("/health"), EndpointClass::Default);
}

#[test]
fn test_endpoint_class_from_name() {
    assert_eq!(EndpointClass::from_name("auth"), EndpointClass::Auth);
    assert_eq!(
        EndpointClass::from_name("register"),
        EndpointClass::Register
    );
    assert_eq!(
        EndpointClass::from_name("magic_link"),
        EndpointClass::MagicLink
    );
    assert_eq!(EndpointClass::from_name("health"), EndpointClass::Health);
    assert_eq!(EndpointClass::from_name("unknown"), EndpointClass::Default);
}

#[test]
fn test_config_defaults() {
    let config = ShieldConfig::default();
    assert!(config.enabled);
    assert_eq!(config.auth_rate, 20);
    assert_eq!(config.register_rate, 5);
    assert_eq!(config.default_rate, 100);
    assert_eq!(config.principal_rate, 5);
    assert_eq!(config.magic_link_rate, 3);
    assert_eq!(config.magic_link_principal_rate, 1);
    assert_eq!(config.window_secs, 60);
    assert_eq!(config.endpoint_classes.len(), 7);
}

// ── Per-principal rate limiting tests ──────────────────────

#[tokio::test]
async fn test_principal_rate_limit() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 3,
        ..Default::default()
    });

    for _ in 0..3 {
        assert!(
            shield
                .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
    assert_eq!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_principal_rate_limit_case_insensitive() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 2,
        ..Default::default()
    });

    assert!(
        shield
            .check_principal("Alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@SID.EXAMPLE.COM", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    // 3rd request: same principal case-folded → over limit
    assert!(
        shield
            .check_principal("ALICE@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_principal_rate_limit_different_principals_independent() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 2,
        ..Default::default()
    });

    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_err()
    );

    // bob should still be allowed
    assert!(
        shield
            .check_principal("bob@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_principal_rate_limit_disabled_when_zero() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 0,
        ..Default::default()
    });

    for _ in 0..100 {
        assert!(
            shield
                .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn test_principal_rate_limit_disabled_when_shield_off() {
    let shield = for_test(ShieldConfig {
        enabled: false,
        principal_rate: 1,
        ..Default::default()
    });

    for _ in 0..100 {
        assert!(
            shield
                .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn test_principal_cleanup() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 5,
        ..Default::default()
    });

    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(!shield.principal_windows.is_empty());

    // Cleanup won't remove recent entries
    shield.cleanup();
    assert!(!shield.principal_windows.is_empty());
}

#[test]
fn test_needs_principal_check() {
    assert!(needs_principal_check("/v1/auth/opaque/login/start"));
    assert!(needs_principal_check("/v1/auth/opaque/register/start"));
    assert!(needs_principal_check("/v1/auth/webauthn/login/start"));
    assert!(needs_principal_check("/v1/auth/webauthn/register/start"));
    assert!(needs_principal_check("/v1/auth/magic-link/send"));
    assert!(needs_principal_check("/v1/auth/resolve"));

    assert!(!needs_principal_check("/v1/auth/opaque/login/finish"));
    assert!(!needs_principal_check("/oauth2/token"));
    assert!(!needs_principal_check("/health"));
    assert!(!needs_principal_check("/v1/identity/me"));
}

// ── Magic-link separate rate class tests ──────────────────

#[tokio::test]
async fn test_magic_link_ip_rate_limit() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        auth_rate: 20,
        magic_link_rate: 3,
        ..Default::default()
    });
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));

    // magic_link_rate = 3
    for _ in 0..3 {
        assert!(shield.check(ip, "/v1/auth/magic-link/send").await.is_ok());
    }
    // 4th request exceeds magic-link limit
    assert_eq!(
        shield
            .check(ip, "/v1/auth/magic-link/send")
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // Auth endpoints should still work (separate bucket, limit 20)
    assert!(
        shield
            .check(ip, "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_magic_link_principal_rate_limit() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 5,
        magic_link_principal_rate: 1,
        ..Default::default()
    });

    // magic_link_principal_rate = 1
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/magic-link/send")
            .await
            .is_ok()
    );
    assert_eq!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/magic-link/send")
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // Same principal on auth endpoint should still work (separate bucket, limit 5)
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_magic_link_and_auth_independent_principal_buckets() {
    let shield = for_test(ShieldConfig {
        enabled: true,
        principal_rate: 2,
        magic_link_principal_rate: 1,
        ..Default::default()
    });

    // Use up magic-link principal budget
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/magic-link/send")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/magic-link/send")
            .await
            .is_err()
    );

    // Auth principal budget is independent
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_ok()
    );
    assert!(
        shield
            .check_principal("alice@sid.example.com", "/v1/auth/opaque/login/start")
            .await
            .is_err()
    );
}

// ── Counting across replicas ──────────────────────────────

/// The defect this exists to prevent: an attacker spreading requests over
/// the replicas behind a load balancer. Neither instance reaches the limit
/// on its own, so a per-instance count never fires.
#[tokio::test]
async fn test_two_replicas_share_one_ip_budget() {
    let (a, b) = replica_pair(ShieldConfig {
        enabled: true,
        auth_rate: 4,
        ..Default::default()
    });
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
    let path = "/v1/auth/opaque/login/start";

    // Two each: four requests, the whole budget, and no single instance
    // has seen more than two.
    for _ in 0..2 {
        assert!(a.check(ip, path).await.is_ok());
        assert!(b.check(ip, path).await.is_ok());
    }

    // The fifth is over the limit wherever it lands.
    assert_eq!(
        a.check(ip, path).await.unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// The same for the limit that guards one account against brute force,
/// which is the one a distributed attacker aims at.
#[tokio::test]
async fn test_two_replicas_share_one_principal_budget() {
    let (a, b) = replica_pair(ShieldConfig {
        enabled: true,
        principal_rate: 2,
        ..Default::default()
    });
    let path = "/v1/auth/opaque/login/start";

    assert!(
        a.check_principal("alice@sid.example.com", path)
            .await
            .is_ok()
    );
    assert!(
        b.check_principal("alice@sid.example.com", path)
            .await
            .is_ok()
    );
    assert_eq!(
        b.check_principal("alice@sid.example.com", path)
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// Sharing a counter must not merge buckets that were separate: a limit
/// reached on one IP or one account says nothing about another.
#[tokio::test]
async fn test_a_shared_counter_keeps_buckets_apart() {
    let (a, b) = replica_pair(ShieldConfig {
        enabled: true,
        auth_rate: 2,
        principal_rate: 2,
        ..Default::default()
    });
    let path = "/v1/auth/opaque/login/start";
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    assert!(a.check(ip1, path).await.is_ok());
    assert!(b.check(ip1, path).await.is_ok());
    assert!(a.check(ip1, path).await.is_err(), "ip1 is spent");
    assert!(b.check(ip2, path).await.is_ok(), "ip2 has its own budget");

    assert!(
        a.check_principal("alice@sid.example.com", path)
            .await
            .is_ok()
    );
    assert!(
        b.check_principal("alice@sid.example.com", path)
            .await
            .is_ok()
    );
    assert!(
        a.check_principal("alice@sid.example.com", path)
            .await
            .is_err()
    );
    assert!(b.check_principal("bob@sid.example.com", path).await.is_ok());
}

/// An unreachable cache must not take the service down with it: the local
/// window still limits, which is where this started.
#[tokio::test]
async fn test_an_unreachable_cache_leaves_the_local_limit_standing() {
    let shield = Shield::new(
        ShieldConfig {
            enabled: true,
            auth_rate: 2,
            ..Default::default()
        },
        Arc::new(UnreachableCache),
    );
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let path = "/v1/auth/opaque/login/start";

    assert!(shield.check(ip, path).await.is_ok());
    assert!(shield.check(ip, path).await.is_ok());
    assert_eq!(
        shield.check(ip, path).await.unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS,
        "the per-instance window still applies"
    );
}

struct UnreachableCache;

#[async_trait::async_trait]
impl CacheBackend for UnreachableCache {
    async fn get(&self, _k: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn set(
        &self,
        _k: &str,
        _v: &[u8],
        _t: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn delete(&self, _k: &str) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn take(&self, _k: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn incr(&self, _k: &str, _t: std::time::Duration) -> sid_plugin::cache::CacheResult<u64> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn publish(&self, _c: &str, _m: &[u8]) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn subscribe(
        &self,
        _c: &str,
    ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
}

#[test]
fn test_extract_principal_from_body() {
    let body = br#"{"principal": "alice@sid.example.com"}"#;
    assert_eq!(
        extract_principal_from_body(body),
        Some("alice@sid.example.com".to_string())
    );

    let body = br#"{"other_field": "value"}"#;
    assert_eq!(extract_principal_from_body(body), None);

    let body = b"not json";
    assert_eq!(extract_principal_from_body(body), None);

    let body = b"";
    assert_eq!(extract_principal_from_body(body), None);
}
