// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// The transcoder forwards the headers the RPCs read whatever the operator
/// listed, keeps its listen address and names no upstream of its own.
#[test]
fn forwards_the_headers_the_rpcs_read() {
    let config: serde_yaml::Value = serde_yaml::from_str(
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
    let config: serde_yaml::Value =
        serde_yaml::from_str("upstream: { default: \"http://elsewhere:1\" }\n").unwrap();
    let error = embedded_transcoder(&config, &[], |_| true)
        .err()
        .expect("an upstream is refused");
    assert!(error.to_string().contains("names no upstream"), "{error}");
}

/// Configuration that is not a mapping is refused.
#[test]
fn non_mapping_config_is_refused() {
    let config = serde_yaml::Value::String("listen".into());
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
