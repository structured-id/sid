// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// A call through the proxy carries its resolved address: forwarding headers
/// and the connection, which behind a sidecar is the pod's own address, are
/// not read again.
#[test]
fn a_proxied_call_has_the_address_the_proxy_resolved() {
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
    request
        .extensions_mut()
        .insert(ClientAddress::from_peer(Some(
            "203.0.113.7:5000".parse().unwrap(),
        )));
    assert_eq!(client_ip(&request).unwrap(), "203.0.113.7".parse().ok());
}

/// A proxy that resolved no address refuses the call: without an address it
/// would pass every check that keys on one.
#[test]
fn a_call_the_proxy_could_not_resolve_is_refused() {
    let mut request = tonic::Request::new(());
    request
        .extensions_mut()
        .insert(ClientAddress::from_peer(None));
    assert_eq!(
        client_ip(&request).unwrap_err().code(),
        tonic::Code::Internal
    );
}

/// A direct call has no resolved address and no peer here: nothing is made up
/// from a header a client wrote.
#[test]
fn a_direct_call_believes_no_forwarding_header() {
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
    assert_eq!(client_ip(&request).unwrap(), None);
}

/// Trusted proxies make the address required, so one they report unreadably
/// is refused; without any, every peer is the client.
#[test]
fn edge_trust_reads_the_list_and_requires_an_address_behind_proxies() {
    let trust = edge_trust(" 10.42.0.14, 192.0.2.0/24 ,");
    assert_eq!(
        trust["trusted_proxies"],
        serde_json::json!(["10.42.0.14", "192.0.2.0/24"])
    );
    assert_eq!(trust["required"], true);
    let none = edge_trust("");
    assert_eq!(none["trusted_proxies"], serde_json::json!([]));
    assert_eq!(none["required"], false);
}

/// The transcoder takes the trust; a second source in its file is refused.
#[test]
fn the_edge_trust_reaches_the_transcoder_from_one_source() {
    let mut config = listening_on("127.0.0.1:0");
    with_edge_trust(&mut config, "10.42.0.14", EdgeReport::Chain).unwrap();
    let proxy = embedded_transcoder(&config, &[], |_| true).unwrap();
    assert_eq!(
        proxy.config().client_address.trusted_proxies,
        ["10.42.0.14"]
    );
    assert!(proxy.config().client_address.required);
    assert!(with_edge_trust(&mut config, "10.42.0.15", EdgeReport::Chain).is_err());
}

/// Behind a reporter that resolved the address, the transcoder reads its one
/// value instead of walking a chain.
#[test]
fn a_resolved_report_is_read_from_its_one_header() {
    let mut config = listening_on("127.0.0.1:0");
    with_edge_trust(&mut config, "10.42.0.14", EdgeReport::Resolved).unwrap();
    let proxy = embedded_transcoder(&config, &[], |_| true).unwrap();
    assert_eq!(
        proxy.config().client_address.header,
        structured_proxy::config::ForwardingHeader::CleanedReport
    );
    assert_eq!(
        EdgeReport::parse("x-real-ip").unwrap(),
        EdgeReport::Resolved
    );
    assert_eq!(
        EdgeReport::parse("x-forwarded-for").unwrap(),
        EdgeReport::Chain
    );
    assert!(EdgeReport::parse("forwarded").is_err());
}

/// An entry that is no address stops startup.
#[test]
fn the_edge_layer_refuses_an_unreadable_proxy() {
    assert!(edge_layer("10.42.0.14").is_ok());
    assert!(edge_layer("proxy.local").is_err());
}

/// The transcoder forwards the headers the RPCs read whatever the operator
/// listed, keeps its listen address and names no upstream of its own.
#[test]
fn forwards_the_headers_the_rpcs_read() {
    let config: serde_json::Value = serde_saphyr::from_str(
        "listen: { http: \"127.0.0.1:8080\" }\nforwarded_headers: [x-request-id]\n",
    )
    .unwrap();
    let proxy = embedded_transcoder(
        &config,
        &["authorization", "dpop", "x-request-id"],
        |name| name == sid_proto::FORWARD_AUTH_PROTO,
    )
    .unwrap();
    let forwarded = &proxy.config().forwarded_headers;
    for name in ["x-request-id", "authorization", "dpop"] {
        assert_eq!(forwarded.iter().filter(|h| *h == name).count(), 1, "{name}");
    }
    assert_eq!(proxy.config().listen.http, "127.0.0.1:8080");
    assert!(proxy.config().upstream.is_none());
}

/// An `upstream` in the configuration would send the service's own RPCs
/// elsewhere; it is refused instead of silently ignored.
#[test]
fn an_upstream_in_the_configuration_is_refused() {
    let config: serde_json::Value =
        serde_saphyr::from_str("upstream: { default: \"http://elsewhere:1\" }\n").unwrap();
    let error = embedded_transcoder(&config, &[], |_| true)
        .err()
        .expect("an upstream is refused");
    assert!(error.to_string().contains("names no upstream"), "{error}");
}

/// The annotated RPCs of an added descriptor set are mounted beside the
/// selected ones: a route only the added set holds is answered by the
/// process (UNIMPLEMENTED with no service registered, 501), and is not
/// found without it. The added set repeats files the selected ones hold
/// (`google/api/http.proto` and the like), which load once.
#[tokio::test]
async fn an_added_set_mounts_its_annotated_rpcs() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const ADDED: &str = "sid/v1/authn/issuer.proto";
    let discovery = || {
        Request::get("/i/0123456789abcdef0123456789abcdef/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap()
    };
    let selected = |name: &str| name == sid_proto::FORWARD_AUTH_PROTO;
    let added = sid_proto::descriptor_set_of(|name| name == ADDED);

    let with =
        embedded_transcoder_with_sets(&listening_on("127.0.0.1:0"), &[], selected, &[&added])
            .unwrap()
            .service(tonic::service::Routes::default())
            .unwrap();
    assert_eq!(
        with.oneshot(discovery()).await.unwrap().status(),
        StatusCode::NOT_IMPLEMENTED
    );
    let without = embedded_transcoder(&listening_on("127.0.0.1:0"), &[], selected)
        .unwrap()
        .service(tonic::service::Routes::default())
        .unwrap();
    assert_eq!(
        without.oneshot(discovery()).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

/// An added set that is not a file descriptor set stops the transcoder from
/// being built.
#[test]
fn an_undecodable_added_set_is_refused() {
    assert!(
        embedded_transcoder_with_sets(
            &listening_on("127.0.0.1:0"),
            &[],
            |_| true,
            &[&[0xff, 0x01]]
        )
        .is_err()
    );
}

/// Configuration that is not a mapping is refused.
#[test]
fn non_mapping_config_is_refused() {
    let config = serde_json::Value::String("listen".into());
    assert!(embedded_transcoder(&config, &[], |_| true).is_err());
}

/// A listen address that is not an address stops the server with that
/// address in the error, before anything is bound.
#[tokio::test]
async fn an_unparsable_listen_address_is_named() {
    let proxy = embedded_transcoder(&listening_on("not-an-address"), &[], |_| true).unwrap();
    let error = serve(
        &proxy,
        tonic::service::Routes::default(),
        std::future::pending(),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect_err("an unparsable address stops serve");
    assert!(error.to_string().contains("not-an-address"), "{error}");
}

/// The shutdown signal stops the listener gracefully: serving ends on its
/// own within the drain interval and the port refuses new connections.
#[tokio::test]
async fn shutdown_closes_the_listener_and_returns() {
    let proxy = embedded_transcoder(&listening_on("127.0.0.1:0"), &[], |_| true).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        serve_on(
            &proxy,
            tonic::service::Routes::default(),
            listener,
            async {
                stopped.await.ok();
            },
            std::time::Duration::from_secs(5),
        )
        .await
    });
    tokio::net::TcpStream::connect(addr)
        .await
        .expect("serving before the signal");
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), serving)
        .await
        .expect("serving ends within the drain")
        .unwrap()
        .unwrap();
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}
