// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_plugin::cache::NoCacheBackend;
use std::net::{Ipv4Addr, Ipv6Addr};

fn no_cache() -> Arc<dyn CacheBackend> {
    Arc::new(NoCacheBackend)
}

// ── IpLabel ──

#[test]
fn test_ip_label_as_str() {
    assert_eq!(IpLabel::TorExit.as_str(), "tor_exit");
    assert_eq!(IpLabel::Datacenter.as_str(), "datacenter");
    assert_eq!(IpLabel::Vpn.as_str(), "vpn");
    assert_eq!(IpLabel::Proxy.as_str(), "proxy");
    assert_eq!(IpLabel::Bot.as_str(), "bot");
    assert_eq!(IpLabel::Blocklisted.as_str(), "blocklisted");
}

// ── AggregatedClassification ──

#[test]
fn test_aggregated_classification_default() {
    let c = AggregatedClassification::default();
    assert!(c.labels.is_empty());
    assert!(c.risk_score.is_none());
    assert!(!c.is_tor_exit());
    assert!(!c.is_datacenter());
    assert!(!c.is_blocklisted());
}

#[test]
fn test_aggregated_classification_labels() {
    let mut c = AggregatedClassification::default();
    c.labels.insert(IpLabel::TorExit);
    c.labels.insert(IpLabel::Blocklisted);
    assert!(c.is_tor_exit());
    assert!(!c.is_datacenter());
    assert!(c.is_blocklisted());
    assert!(c.has_label(IpLabel::TorExit));
    assert!(!c.has_label(IpLabel::Vpn));
}

// ── parse_tor_exit_list ──

#[test]
fn test_parse_tor_exit_list_basic() {
    let text = "1.2.3.4\n5.6.7.8\n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 2);
    assert!(nodes.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    assert!(nodes.contains(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
}

#[test]
fn test_parse_tor_exit_list_with_comments() {
    let text = "# This is a comment\n1.2.3.4\n# Another comment\n5.6.7.8\n\n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 2);
}

#[test]
fn test_parse_tor_exit_list_with_whitespace() {
    let text = "  1.2.3.4  \n  5.6.7.8  \n  \n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 2);
}

#[test]
fn test_parse_tor_exit_list_invalid_lines_skipped() {
    let text = "1.2.3.4\nnot-an-ip\n5.6.7.8\n999.999.999.999\n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 2);
}

#[test]
fn test_parse_tor_exit_list_ipv6() {
    let text = "1.2.3.4\n2001:db8::1\n::1\n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 3);
    assert!(nodes.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_parse_tor_exit_list_empty() {
    let nodes = parse_tor_exit_list("");
    assert!(nodes.is_empty());
}

#[test]
fn test_parse_tor_exit_list_dedup() {
    let text = "1.2.3.4\n1.2.3.4\n1.2.3.4\n";
    let nodes = parse_tor_exit_list(text);
    assert_eq!(nodes.len(), 1);
}

// ── TorExitProvider ──

#[tokio::test]
async fn test_tor_provider_classify_empty() {
    let provider = TorExitProvider::new(no_cache());
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(provider.classify(ip).await.unwrap().is_none());
}

#[tokio::test]
async fn test_tor_provider_classify_after_load() {
    let provider = TorExitProvider::new(no_cache());
    provider.load_from_text("1.2.3.4\n5.6.7.8\n");

    let tor_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let classification = provider.classify(tor_ip).await.unwrap().unwrap();
    assert_eq!(classification.labels, vec![IpLabel::TorExit]);
    assert_eq!(classification.risk_score, Some(0.8));
    assert_eq!(classification.source, "tor_bulk_exit_list");

    let normal_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(provider.classify(normal_ip).await.unwrap().is_none());
}

#[tokio::test]
async fn test_tor_provider_node_count() {
    let provider = TorExitProvider::new(no_cache());
    assert_eq!(provider.node_count(), 0);

    provider.load_from_text("1.2.3.4\n5.6.7.8\n9.10.11.12\n");
    assert_eq!(provider.node_count(), 3);
}

#[test]
fn test_tor_provider_source_name() {
    let provider = TorExitProvider::new(no_cache());
    assert_eq!(provider.source_name(), "tor_exit");
}

// ── Aggregator ──

#[tokio::test]
async fn test_aggregator_no_providers() {
    let agg = IpIntelligenceAggregator::new(vec![], no_cache(), Duration::from_secs(60));
    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    assert!(result.labels.is_empty());
    assert!(result.risk_score.is_none());
}

#[tokio::test]
async fn test_aggregator_single_provider() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("1.2.3.4\n");

    let agg = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );

    // Tor exit IP.
    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    assert!(result.is_tor_exit());
    assert_eq!(result.risk_score, Some(0.8));
    assert_eq!(result.sources, vec!["tor_bulk_exit_list"]);

    // Normal IP.
    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .await
        .unwrap();
    assert!(!result.is_tor_exit());
    assert!(result.risk_score.is_none());
}

#[tokio::test]
async fn test_aggregator_merges_labels() {
    // Two providers both classify the same IP differently.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("1.2.3.4\n");

    // Stub provider that marks everything as blocklisted.
    struct BlocklistAll;
    #[async_trait]
    impl IpIntelligenceProvider for BlocklistAll {
        async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
            Ok(Some(IpClassification {
                labels: vec![IpLabel::Blocklisted],
                risk_score: Some(0.9),
                source: "test_blocklist".to_string(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            }))
        }
        async fn refresh(&self) -> Result<(), IpIntelError> {
            Ok(())
        }
        fn source_name(&self) -> &str {
            "test_blocklist"
        }
    }

    let agg = IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            Arc::new(BlocklistAll),
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    // Both labels present.
    assert!(result.is_tor_exit());
    assert!(result.is_blocklisted());
    // Max risk score.
    assert_eq!(result.risk_score, Some(0.9));
    // Both sources.
    assert_eq!(result.sources.len(), 2);
}

#[tokio::test]
async fn test_aggregator_risk_score_max() {
    struct ScoreProvider(f32);
    #[async_trait]
    impl IpIntelligenceProvider for ScoreProvider {
        async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
            Ok(Some(IpClassification {
                labels: vec![],
                risk_score: Some(self.0),
                source: format!("score_{}", self.0),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            }))
        }
        async fn refresh(&self) -> Result<(), IpIntelError> {
            Ok(())
        }
        fn source_name(&self) -> &str {
            "score"
        }
    }

    let agg = IpIntelligenceAggregator::new(
        vec![
            Arc::new(ScoreProvider(0.3)) as Arc<dyn IpIntelligenceProvider>,
            Arc::new(ScoreProvider(0.7)),
            Arc::new(ScoreProvider(0.5)),
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    assert_eq!(result.risk_score, Some(0.7));
}

/// A provider that cannot answer fails the whole classification: it never
/// reads as a clean IP (a blocklist whose store is down once let every IP
/// through).
#[tokio::test]
async fn test_aggregator_provider_error_fails_classification() {
    struct Down;
    #[async_trait]
    impl IpIntelligenceProvider for Down {
        async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
            Err(IpIntelError::Unavailable("store down".into()))
        }
        async fn refresh(&self) -> Result<(), IpIntelError> {
            Ok(())
        }
        fn source_name(&self) -> &str {
            "down"
        }
    }

    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("1.2.3.4\n");
    let agg = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>, Arc::new(Down)],
        no_cache(),
        Duration::from_secs(60),
    );
    assert!(
        agg.classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
            .await
            .is_err()
    );
}

/// A replica that is not the refresh leader still picks up the feed the
/// leader stored in the shared cache; it once kept its startup snapshot for
/// as long as it ran.
#[tokio::test]
async fn follower_replica_loads_the_leaders_feed() {
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    // Another replica holds the refresh lock and has stored a fresh list.
    cache
        .set_nx("ipintel:refresh:lock", b"1", Duration::from_secs(300))
        .await
        .unwrap();
    cache
        .set(
            "ipintel:tor:nodes",
            b"203.0.113.7\n",
            Duration::from_secs(7200),
        )
        .await
        .unwrap();

    let tor = Arc::new(TorExitProvider::new(cache.clone()));
    let follower = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );
    try_leader_refresh(&follower, &cache).await;

    let result = follower
        .classify("203.0.113.7".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(result.is_tor_exit(), "the follower kept a stale list");
}

/// Serves `body` once over plain HTTP and returns its URL.
async fn serve_once(body: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _read = socket.read(&mut request).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    format!("http://{addr}/list")
}

/// A cache that accepts reads and refuses writes.
struct ReadOnlyCache;

#[async_trait]
impl CacheBackend for ReadOnlyCache {
    async fn get(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn set(&self, _: &str, _: &[u8], _: Duration) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn delete(&self, _: &str) -> sid_plugin::cache::CacheResult<()> {
        Ok(())
    }
    async fn take(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn incr(&self, _: &str, _: Duration) -> sid_plugin::cache::CacheResult<u64> {
        Ok(1)
    }
    async fn publish(&self, _: &str, _: &[u8]) -> sid_plugin::cache::CacheResult<()> {
        Ok(())
    }
    async fn subscribe(
        &self,
        _: &str,
    ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
        Ok(())
    }
}

/// A refresh whose list could not be published fails: the other replicas
/// would keep their old list while this one reported success.
#[tokio::test]
async fn unpublished_refresh_is_an_error() {
    let url = serve_once("203.0.113.9\n").await;
    let provider = TorExitProvider::with_url(Arc::new(ReadOnlyCache), url);
    assert!(matches!(
        provider.refresh().await,
        Err(IpIntelError::Cache(_))
    ));
    // This replica still uses the list it fetched.
    assert!(
        provider
            .classify("203.0.113.9".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn test_aggregator_provider_count() {
    let agg = IpIntelligenceAggregator::new(
        vec![Arc::new(TorExitProvider::new(no_cache())) as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );
    assert_eq!(agg.provider_count(), 1);
}

// ── Serialization roundtrip ──

#[test]
fn test_classification_serialization_roundtrip() {
    let mut original = AggregatedClassification::default();
    original.labels.insert(IpLabel::TorExit);
    original.labels.insert(IpLabel::Blocklisted);
    original.risk_score = Some(0.8);
    original.sources = vec!["tor_exit".to_string(), "firehol".to_string()];

    let data = serialize_classification(&original).unwrap();
    let deserialized = deserialize_classification(&data).unwrap();

    assert_eq!(deserialized.labels, original.labels);
    assert_eq!(deserialized.risk_score, original.risk_score);
    assert_eq!(deserialized.sources, original.sources);
}

#[test]
fn test_classification_serialization_empty() {
    let original = AggregatedClassification::default();
    let data = serialize_classification(&original).unwrap();
    let deserialized = deserialize_classification(&data).unwrap();
    assert!(deserialized.labels.is_empty());
    assert!(deserialized.risk_score.is_none());
}

#[test]
fn test_deserialization_invalid_data() {
    assert!(deserialize_classification(b"invalid").is_none());
    assert!(deserialize_classification(b"").is_none());
}

// ── Allowlist wins ──

#[tokio::test]
async fn test_aggregator_allowlist_clears_negative_labels() {
    // Tor provider marks IP as tor_exit.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("1.2.3.4\n");

    // Allowlist provider marks ALL IPs as allowed.
    struct AllowAll;
    #[async_trait]
    impl IpIntelligenceProvider for AllowAll {
        async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
            Ok(Some(IpClassification {
                labels: vec![IpLabel::Allowed],
                risk_score: Some(0.0),
                source: "test_allowlist".to_string(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            }))
        }
        async fn refresh(&self) -> Result<(), IpIntelError> {
            Ok(())
        }
        fn source_name(&self) -> &str {
            "test_allowlist"
        }
    }

    let agg = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>, Arc::new(AllowAll)],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    // Allowlist wins: tor_exit label removed, only Allowed remains.
    assert!(!result.is_tor_exit());
    assert!(!result.is_blocklisted());
    assert!(result.has_label(IpLabel::Allowed));
    // Risk score reset to 0.
    assert_eq!(result.risk_score, Some(0.0));
}

#[tokio::test]
async fn test_aggregator_no_allowlist_keeps_labels() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("1.2.3.4\n");

    let agg = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        .await
        .unwrap();
    // Without allowlist, labels stay.
    assert!(result.is_tor_exit());
    assert!(!result.has_label(IpLabel::Allowed));
}

#[test]
fn test_ip_label_allowed_as_str() {
    assert_eq!(IpLabel::Allowed.as_str(), "allowed");
}

#[test]
fn test_classification_serialization_roundtrip_with_allowed() {
    let mut original = AggregatedClassification::default();
    original.labels.insert(IpLabel::Allowed);
    original.risk_score = Some(0.0);
    original.sources = vec!["admin_allowlist".to_string()];

    let data = serialize_classification(&original).unwrap();
    let deserialized = deserialize_classification(&data).unwrap();

    assert!(deserialized.has_label(IpLabel::Allowed));
    assert_eq!(deserialized.risk_score, Some(0.0));
}

// ── CidrSet ──

#[test]
fn test_cidr_set_contains_ipv4() {
    let set = CidrSet::from_nets(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
    assert!(set.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(set.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    assert!(!set.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    assert!(!set.contains(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
}

#[test]
fn test_cidr_set_contains_ipv6() {
    let set = CidrSet::from_nets(vec!["2600:1900::/32".parse::<IpNet>().unwrap()]);
    let inside: IpAddr = "2600:1900::1".parse().unwrap();
    let outside: IpAddr = "2600:1901::1".parse().unwrap();
    assert!(set.contains(inside));
    assert!(!set.contains(outside));
}

#[test]
fn test_cidr_set_multiple_ranges() {
    let set = CidrSet::from_nets(vec![
        "3.5.0.0/15".parse::<IpNet>().unwrap(),    // AWS
        "35.190.0.0/17".parse::<IpNet>().unwrap(), // GCP
        "104.16.0.0/13".parse::<IpNet>().unwrap(), // Cloudflare
    ]);
    // AWS range
    assert!(set.contains("3.5.1.1".parse::<IpAddr>().unwrap()));
    // GCP range
    assert!(set.contains("35.190.0.1".parse::<IpAddr>().unwrap()));
    // Cloudflare range
    assert!(set.contains("104.16.0.1".parse::<IpAddr>().unwrap()));
    // Outside all ranges
    assert!(!set.contains("192.168.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_cidr_set_single_ip() {
    let set = CidrSet::from_nets(vec!["1.2.3.4/32".parse::<IpNet>().unwrap()]);
    assert!(set.contains("1.2.3.4".parse::<IpAddr>().unwrap()));
    assert!(!set.contains("1.2.3.5".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_cidr_set_empty() {
    let set = CidrSet::default();
    assert!(set.is_empty());
    assert!(!set.contains("1.2.3.4".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_cidr_set_overlapping_ranges_merged() {
    // Two overlapping ranges should merge.
    let set = CidrSet::from_nets(vec![
        "10.0.0.0/16".parse::<IpNet>().unwrap(), // 10.0.0.0 - 10.0.255.255
        "10.0.128.0/17".parse::<IpNet>().unwrap(), // subset of above
    ]);
    // Should merge into single range.
    assert_eq!(set.len(), 1);
    assert!(set.contains("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(set.contains("10.0.200.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_cidr_set_adjacent_ranges() {
    let set = CidrSet::from_nets(vec![
        "10.0.0.0/24".parse::<IpNet>().unwrap(), // 10.0.0.0 - 10.0.0.255
        "10.0.1.0/24".parse::<IpNet>().unwrap(), // 10.0.1.0 - 10.0.1.255
    ]);
    // Adjacent ranges should merge.
    assert_eq!(set.len(), 1);
    assert!(set.contains("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(set.contains("10.0.1.1".parse::<IpAddr>().unwrap()));
}

// ── parse_cidr_text ──

#[test]
fn test_parse_cidr_text_basic() {
    let text = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n";
    let nets = parse_cidr_text(text);
    assert_eq!(nets.len(), 3);
}

#[test]
fn test_parse_cidr_text_with_comments() {
    let text =
        "# FireHOL Level 1\n# Updated: 2026-03-17\n\n10.0.0.0/8\n# Private range\n172.16.0.0/12\n";
    let nets = parse_cidr_text(text);
    assert_eq!(nets.len(), 2);
}

#[test]
fn test_parse_cidr_text_bare_ips() {
    let text = "1.2.3.4\n5.6.7.8\n";
    let nets = parse_cidr_text(text);
    assert_eq!(nets.len(), 2);
    // Bare IPs become /32.
    let set = CidrSet::from_nets(nets);
    assert!(set.contains("1.2.3.4".parse::<IpAddr>().unwrap()));
    assert!(!set.contains("1.2.3.5".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_parse_cidr_text_mixed_formats() {
    let text = "10.0.0.0/8\n1.2.3.4\n2001:db8::/32\n::1\n";
    let nets = parse_cidr_text(text);
    assert_eq!(nets.len(), 4);
}

#[test]
fn test_parse_cidr_text_invalid_lines_skipped() {
    let text = "10.0.0.0/8\nnot-a-cidr\ngarbage/999\n5.6.7.8/24\n";
    let nets = parse_cidr_text(text);
    assert_eq!(nets.len(), 2);
}

// ── parse_aws_ranges ──

#[test]
fn test_parse_aws_ranges() {
    let json = r#"{
            "syncToken": "1234",
            "createDate": "2026-03-17",
            "prefixes": [
                {"ip_prefix": "3.5.0.0/15", "region": "us-east-1", "service": "AMAZON"},
                {"ip_prefix": "52.0.0.0/11", "region": "us-east-1", "service": "AMAZON"}
            ],
            "ipv6_prefixes": [
                {"ipv6_prefix": "2600:1f00::/24", "region": "us-east-1", "service": "AMAZON"}
            ]
        }"#;
    let nets = parse_aws_ranges(json);
    assert_eq!(nets.len(), 3);
}

#[test]
fn test_parse_aws_ranges_empty_json() {
    let nets = parse_aws_ranges("{}");
    assert!(nets.is_empty());
}

#[test]
fn test_parse_aws_ranges_invalid_json() {
    let nets = parse_aws_ranges("not json");
    assert!(nets.is_empty());
}

// ── parse_gcp_ranges ──

#[test]
fn test_parse_gcp_ranges() {
    let json = r#"{
            "syncToken": "1234",
            "creationTime": "2026-03-17T00:00:00.000000",
            "prefixes": [
                {"ipv4Prefix": "35.190.0.0/17"},
                {"ipv6Prefix": "2600:1900::/32"},
                {"ipv4Prefix": "34.0.0.0/15"}
            ]
        }"#;
    let nets = parse_gcp_ranges(json);
    assert_eq!(nets.len(), 3);
}

#[test]
fn test_parse_gcp_ranges_empty() {
    let nets = parse_gcp_ranges(r#"{"prefixes": []}"#);
    assert!(nets.is_empty());
}

// ── parse_azure_ranges ──

#[test]
fn test_parse_azure_ranges() {
    let json = r#"{
            "changeNumber": 12345,
            "cloud": "Public",
            "values": [
                {
                    "name": "AzureCloud",
                    "id": "AzureCloud",
                    "properties": {
                        "changeNumber": 100,
                        "region": "",
                        "regionId": 0,
                        "platform": "Azure",
                        "systemService": "",
                        "addressPrefixes": [
                            "13.64.0.0/11",
                            "20.33.0.0/16",
                            "2603:1000::/24"
                        ]
                    }
                },
                {
                    "name": "AzureCloud.eastus",
                    "properties": {
                        "addressPrefixes": [
                            "20.42.0.0/17"
                        ]
                    }
                }
            ]
        }"#;
    let nets = parse_azure_ranges(json);
    assert_eq!(nets.len(), 4); // 3 from AzureCloud + 1 from eastus
}

#[test]
fn test_parse_azure_ranges_empty() {
    let nets = parse_azure_ranges(r#"{"values": []}"#);
    assert!(nets.is_empty());
}

#[test]
fn test_parse_azure_ranges_invalid_json() {
    let nets = parse_azure_ranges("not json");
    assert!(nets.is_empty());
}

// ── CloudRangeProvider ──

#[tokio::test]
async fn test_cloud_provider_classify_empty() {
    let provider = CloudRangeProvider::new(no_cache());
    let ip = IpAddr::V4(Ipv4Addr::new(3, 5, 1, 1));
    assert!(provider.classify(ip).await.unwrap().is_none());
}

#[tokio::test]
async fn test_cloud_provider_classify_after_load() {
    let provider = CloudRangeProvider::new(no_cache());
    provider.load_from_text("3.5.0.0/15\n35.190.0.0/17\n");

    // AWS range.
    let aws_ip = IpAddr::V4(Ipv4Addr::new(3, 5, 1, 1));
    let classification = provider.classify(aws_ip).await.unwrap().unwrap();
    assert_eq!(classification.labels, vec![IpLabel::Datacenter]);
    assert_eq!(classification.risk_score, Some(0.4));
    assert_eq!(classification.source, "cloud_ranges");

    // GCP range.
    let gcp_ip = IpAddr::V4(Ipv4Addr::new(35, 190, 0, 1));
    assert!(provider.classify(gcp_ip).await.unwrap().is_some());

    // Normal IP.
    let normal_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert!(provider.classify(normal_ip).await.unwrap().is_none());
}

#[test]
fn test_cloud_provider_source_name() {
    let provider = CloudRangeProvider::new(no_cache());
    assert_eq!(provider.source_name(), "cloud_ranges");
}

#[tokio::test]
async fn test_cloud_provider_range_count() {
    let provider = CloudRangeProvider::new(no_cache());
    assert_eq!(provider.range_count(), 0);

    provider.load_from_text("10.0.0.0/8\n172.16.0.0/12\n");
    assert_eq!(provider.range_count(), 2);
}

// ── FireholProvider ──

#[tokio::test]
async fn test_firehol_provider_classify_empty() {
    let provider = FireholProvider::new(no_cache());
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(provider.classify(ip).await.unwrap().is_none());
}

#[tokio::test]
async fn test_firehol_provider_classify_after_load() {
    let provider = FireholProvider::new(no_cache());
    provider.load_from_text("# FireHOL Level 1\n\n45.95.147.0/24\n185.220.100.0/24\n");

    // Blocklisted IP.
    let bad_ip = IpAddr::V4(Ipv4Addr::new(45, 95, 147, 10));
    let classification = provider.classify(bad_ip).await.unwrap().unwrap();
    assert_eq!(classification.labels, vec![IpLabel::Blocklisted]);
    assert_eq!(classification.risk_score, Some(0.9));
    assert_eq!(classification.source, "firehol_level1");

    // Normal IP.
    let normal_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert!(provider.classify(normal_ip).await.unwrap().is_none());
}

// FireHOL level1 carries the bogon ranges (private, loopback, CGNAT, link
// local): addresses that must not appear on the public internet, not
// attackers. A client on the LAN, behind CGNAT or on the same host is never
// denied for them; a public entry still counts.
#[tokio::test]
async fn test_firehol_provider_ignores_bogon_hits() {
    let provider = FireholProvider::new(no_cache());
    provider.load_from_text(
        "0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n\
         172.16.0.0/12\n192.168.0.0/16\n::1/128\nfc00::/7\nfe80::/10\n\
         ::ffff:0.0.0.0/96\n45.95.147.0/24\n",
    );
    for ip in [
        "127.0.0.1",
        "10.1.2.3",
        "100.64.1.1",
        "169.254.1.1",
        "172.16.5.5",
        "192.168.1.10",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:192.168.1.10",
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(
            provider.classify(ip).await.unwrap().is_none(),
            "{ip} is not a threat"
        );
    }
    let public: IpAddr = "45.95.147.10".parse().unwrap();
    assert!(provider.classify(public).await.unwrap().is_some());
}

#[test]
fn test_firehol_provider_source_name() {
    let provider = FireholProvider::new(no_cache());
    assert_eq!(provider.source_name(), "firehol_level1");
}

#[tokio::test]
async fn test_firehol_provider_range_count() {
    let provider = FireholProvider::new(no_cache());
    assert_eq!(provider.range_count(), 0);

    provider.load_from_text("45.95.147.0/24\n185.220.100.0/24\n");
    assert_eq!(provider.range_count(), 2);
}

// ── Aggregator with cloud + firehol ──

#[tokio::test]
async fn test_aggregator_cloud_and_firehol_together() {
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("3.5.0.0/15\n");

    let firehol = Arc::new(FireholProvider::new(no_cache()));
    firehol.load_from_text("45.95.147.0/24\n");

    let agg = IpIntelligenceAggregator::new(
        vec![
            cloud as Arc<dyn IpIntelligenceProvider>,
            firehol as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    // Cloud IP → Datacenter.
    let result = agg
        .classify("3.5.1.1".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(result.is_datacenter());
    assert!(!result.is_blocklisted());

    // Blocklisted IP → Blocklisted.
    let result = agg
        .classify("45.95.147.10".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(result.is_blocklisted());
    assert!(!result.is_datacenter());

    // Normal IP → nothing.
    let result = agg
        .classify("192.168.1.1".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(!result.is_datacenter());
    assert!(!result.is_blocklisted());
}

#[tokio::test]
async fn test_aggregator_ip_in_both_cloud_and_firehol() {
    // IP is in a cloud range AND a firehol blocklist → both labels.
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("45.95.147.0/24\n"); // Same range as firehol

    let firehol = Arc::new(FireholProvider::new(no_cache()));
    firehol.load_from_text("45.95.147.0/24\n");

    let agg = IpIntelligenceAggregator::new(
        vec![
            cloud as Arc<dyn IpIntelligenceProvider>,
            firehol as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify("45.95.147.10".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    // Both labels present.
    assert!(result.is_datacenter());
    assert!(result.is_blocklisted());
    // Risk score = max(0.4, 0.9) = 0.9.
    assert_eq!(result.risk_score, Some(0.9));
}

// ── ip_to_u128 ──

#[test]
fn test_ip_to_u128_ipv4() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let val = ip_to_u128(ip);
    // 10.0.0.1 = 0x0A000001
    assert_eq!(val, 0x0A000001);
}

#[test]
fn test_ip_to_u128_ipv6() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let val = ip_to_u128(ip);
    assert_eq!(val, 0x20010db8_00000000_00000000_00000001);
}

// ── SelfLearnedReputationProvider ──
// Unit tests use stub IpIntelligenceProvider to test classify() logic.
// SelfLearnedReputationProvider requires StorageBackend (100+ methods) which
// can't be mocked in sid-authn. classify() logic is tested via set_suspicious()
// and the aggregator stub approach. Integration tests with real PostgreSQL
// test the full record → refresh → classify pipeline.

/// Stub that simulates SelfLearnedReputationProvider's classify() behavior
/// using a pre-loaded HashMap. Avoids needing StorageBackend.
struct SelfLearnedStub {
    suspicious: std::collections::HashMap<IpAddr, f32>,
}

#[async_trait]
impl IpIntelligenceProvider for SelfLearnedStub {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(self.suspicious.get(&ip).map(|&score| IpClassification {
            labels: vec![IpLabel::Blocklisted],
            risk_score: Some(score),
            source: "self_learned".to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }

    fn source_name(&self) -> &str {
        "self_learned"
    }
}

#[tokio::test]
async fn test_self_learned_classify_empty() {
    let stub = SelfLearnedStub {
        suspicious: std::collections::HashMap::new(),
    };
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(stub.classify(ip).await.unwrap().is_none());
}

#[tokio::test]
async fn test_self_learned_classify_suspicious_ip() {
    let mut map = std::collections::HashMap::new();
    map.insert(IpAddr::V4(Ipv4Addr::new(45, 95, 147, 10)), 0.85_f32);
    map.insert(IpAddr::V4(Ipv4Addr::new(185, 220, 100, 1)), 0.92_f32);

    let stub = SelfLearnedStub { suspicious: map };

    // Suspicious IP → Blocklisted.
    let classification = stub
        .classify(IpAddr::V4(Ipv4Addr::new(45, 95, 147, 10)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(classification.labels, vec![IpLabel::Blocklisted]);
    assert_eq!(classification.risk_score, Some(0.85));
    assert_eq!(classification.source, "self_learned");

    // Normal IP → None.
    assert!(
        stub.classify(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_self_learned_source_name() {
    let stub = SelfLearnedStub {
        suspicious: std::collections::HashMap::new(),
    };
    assert_eq!(stub.source_name(), "self_learned");
}

#[tokio::test]
async fn test_self_learned_in_aggregator() {
    let mut map = std::collections::HashMap::new();
    map.insert(IpAddr::V4(Ipv4Addr::new(45, 95, 147, 10)), 0.85_f32);

    let stub = Arc::new(SelfLearnedStub { suspicious: map });

    let agg = IpIntelligenceAggregator::new(
        vec![stub as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );

    // Suspicious IP → Blocklisted.
    let result = agg
        .classify("45.95.147.10".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(result.is_blocklisted());
    assert_eq!(result.risk_score, Some(0.85));

    // Normal IP → nothing.
    let result = agg
        .classify("192.168.1.1".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(!result.is_blocklisted());
}

#[tokio::test]
async fn test_self_learned_combined_with_other_providers() {
    // Self-learned + Tor: IP flagged by self-learned but also Tor exit.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("45.95.147.10\n");

    let mut map = std::collections::HashMap::new();
    map.insert(IpAddr::V4(Ipv4Addr::new(45, 95, 147, 10)), 0.85_f32);
    let stub = Arc::new(SelfLearnedStub { suspicious: map });

    let agg = IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            stub as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify("45.95.147.10".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    // Both labels present.
    assert!(result.is_tor_exit());
    assert!(result.is_blocklisted());
    // Risk score = max(0.8 from Tor, 0.85 from self-learned).
    assert_eq!(result.risk_score, Some(0.85));
}

// ── AllowlistProvider ──
// Uses CidrSet-based stub (same pattern as existing AllowAll stub tests above).
// AllowlistProvider requires StorageBackend — tested via integration tests with PostgreSQL.
// Unit tests verify classify() logic via stub provider.

/// Stub that simulates AllowlistProvider's classify() using pre-loaded CidrSet.
struct AllowlistStub {
    cidrs: CidrSet,
}

#[async_trait]
impl IpIntelligenceProvider for AllowlistStub {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(self.cidrs.contains(ip).then(|| IpClassification {
            labels: vec![IpLabel::Allowed],
            risk_score: Some(0.0),
            source: "admin_allowlist".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }))
    }
    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }
    fn source_name(&self) -> &str {
        "admin_allowlist"
    }
}

#[tokio::test]
async fn test_allowlist_classify_empty() {
    let stub = AllowlistStub {
        cidrs: CidrSet::default(),
    };
    assert!(
        stub.classify("1.2.3.4".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_allowlist_classify_matching_cidr() {
    let stub = AllowlistStub {
        cidrs: CidrSet::from_nets(vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "172.16.0.0/12".parse::<IpNet>().unwrap(),
        ]),
    };

    let c = stub
        .classify("10.0.0.1".parse::<IpAddr>().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.labels, vec![IpLabel::Allowed]);
    assert_eq!(c.risk_score, Some(0.0));
    assert_eq!(c.source, "admin_allowlist");

    assert!(
        stub.classify("8.8.8.8".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_allowlist_overrides_blocklist_in_aggregator() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("10.0.0.1\n");

    let stub = Arc::new(AllowlistStub {
        cidrs: CidrSet::from_nets(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]),
    });

    let agg = IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            stub as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    );

    let result = agg
        .classify("10.0.0.1".parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(!result.is_tor_exit());
    assert!(result.has_label(IpLabel::Allowed));
    assert_eq!(result.risk_score, Some(0.0));
}
