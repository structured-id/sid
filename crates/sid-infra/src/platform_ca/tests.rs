use super::*;
use sid_proto::sid::v1::federation::platform_ca_service_server::{
    PlatformCaService, PlatformCaServiceServer,
};
use sid_proto::sid::v1::{GetPlatformCasRequest, PlatformCa, PlatformCaState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A client without TLS for the loopback servers of these tests, with the
/// redirect policy of [`PlatformCaPublication::new`].
fn loopback(endpoint: &str) -> PlatformCaPublication {
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        sid_crypto::tls::aws_lc::provider()
            .install_default()
            .expect("the test process's only TLS provider");
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    PlatformCaPublication::with_client(client, endpoint.parse().unwrap()).unwrap()
}

fn published() -> PlatformCas {
    PlatformCas {
        revision: 6,
        generations: vec![
            PlatformCa {
                generation: 2,
                certificate: vec![2; 600],
                state: PlatformCaState::Active as i32,
                overlap_end: None,
                // The generation's CRL travels as bytes (base64 in the JSON).
                crl: vec![0x30, 0x82, 0xff, 0x00, 0x7f],
            },
            PlatformCa {
                generation: 1,
                certificate: vec![1; 600],
                state: PlatformCaState::VerificationOnly as i32,
                overlap_end: Some(prost_types::Timestamp {
                    seconds: 1_900_000_000,
                    nanos: 0,
                }),
                crl: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            },
        ],
        roots: vec![vec![9; 400]],
        issued_at: Some(prost_types::Timestamp {
            seconds: 1_800_000_000,
            nanos: 0,
        }),
        next_update: Some(prost_types::Timestamp {
            seconds: 1_800_003_600,
            nanos: 0,
        }),
    }
}

struct Publishing(PlatformCas);

#[tonic::async_trait]
impl PlatformCaService for Publishing {
    async fn get_platform_cas(
        &self,
        _: tonic::Request<GetPlatformCasRequest>,
    ) -> Result<tonic::Response<PlatformCas>, tonic::Status> {
        Ok(tonic::Response::new(self.0.clone()))
    }
}

// The publication as the HTTP transcoder serves it (its proto3 JSON, the
// 64-bit revision as a string, bytes as base64, enums by name) reads back to
// exactly the published message.
#[tokio::test]
async fn the_served_publication_reads_back() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    let proxy = crate::http::embedded_transcoder(&crate::http::listening_on(&bind), &[], |file| {
        file == PUBLICATION_FILE
    })
    .unwrap();
    let routes = tonic::service::Routes::new(PlatformCaServiceServer::new(Publishing(published())));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        crate::http::serve_on(
            &proxy,
            routes,
            listener,
            async {
                let _ = stopped.await;
            },
            Duration::from_secs(1),
        )
        .await
    });
    let fetched = loopback(&format!("http://{bind}/.well-known/sid-ca/index.json"))
        .fetch()
        .await
        .unwrap();
    assert_eq!(fetched, published());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// A server answering one request with `answer`, at the publication's path.
async fn answering(answer: Vec<u8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await;
        stream.write_all(&answer).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    format!("http://{bind}/.well-known/sid-ca/index.json")
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}

// Only an https endpoint is configured.
#[test]
fn an_endpoint_that_is_not_https_is_refused() {
    assert!(matches!(
        PlatformCaPublication::new(
            "http://platform.sid.example.com/.well-known/sid-ca/index.json"
                .parse()
                .unwrap()
        ),
        Err(PublicationError::NotHttps)
    ));
}

// A redirect is not followed: its target would be an endpoint the
// deployment did not configure.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let endpoint = answering(response(
        "302 Found",
        "location: https://elsewhere.example/.well-known/sid-ca/index.json\r\n",
        b"",
    ))
    .await;
    assert!(matches!(
        loopback(&endpoint).fetch().await,
        Err(PublicationError::Status(302))
    ));
}

// An answer other than success carries its status.
#[tokio::test]
async fn a_failed_answer_carries_its_status() {
    let endpoint = answering(response("503 Service Unavailable", "", b"")).await;
    assert!(matches!(
        loopback(&endpoint).fetch().await,
        Err(PublicationError::Status(503))
    ));
}

// An answer over the bound is refused, announced by its length or not.
#[tokio::test]
async fn an_oversized_answer_is_refused() {
    let body = vec![b' '; MAX_BODY + 1];
    let endpoint = answering(response("200 OK", "", &body)).await;
    assert!(matches!(
        loopback(&endpoint).fetch().await,
        Err(PublicationError::TooLarge)
    ));

    let mut chunked =
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec();
    chunked.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    chunked.extend_from_slice(&body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let endpoint = answering(chunked).await;
    assert!(matches!(
        loopback(&endpoint).fetch().await,
        Err(PublicationError::TooLarge)
    ));
}

// What is not the publication's JSON is refused: other JSON, a field the
// message lacks, trailing content.
#[tokio::test]
async fn a_malformed_answer_is_refused() {
    for body in [
        &b"not json"[..],
        b"{\"revision\":\"6\",\"unknownField\":1}",
        b"{\"revision\":\"six\"}",
        b"{\"revision\":\"6\"} {}",
    ] {
        let endpoint = answering(response("200 OK", "", body)).await;
        assert!(
            matches!(
                loopback(&endpoint).fetch().await,
                Err(PublicationError::Malformed(_))
            ),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}
