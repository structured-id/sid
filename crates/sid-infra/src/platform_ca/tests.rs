use super::*;
use sid_proto::sid::v1::federation::platform_ca_service_server::{
    PlatformCaService, PlatformCaServiceServer,
};
use sid_proto::sid::v1::{GetPlatformCasRequest, PlatformCa, PlatformCaState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The TLS provider an HTTPS client is built with, selected as a host
/// selects it.
fn select_tls() {
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        sid_crypto::tls::aws_lc::provider()
            .install_default()
            .expect("the test process's only TLS provider");
    });
}

/// A client without TLS for the loopback servers of these tests, with the
/// redirect policy of [`PlatformCaPublication::new`].
fn loopback(endpoint: &str) -> PlatformCaPublication {
    select_tls();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    PlatformCaPublication::with_client(client, endpoint.parse().unwrap()).unwrap()
}

#[path = "../../build_platform.rs"]
mod build_platform;

/// The build asks the same publication the installation later refreshes
/// from, whether or not the origin was written with a trailing slash.
/// Bug prevented: an origin ending in `/` asked at `//.well-known/...`,
/// where a platform answers 404 or its page and the build carries no set.
#[test]
fn the_build_asks_the_published_path() {
    for origin in ["https://sid.example.com", "https://sid.example.com/"] {
        assert_eq!(
            build_platform::publication_of(origin),
            publication_of(origin).unwrap().as_str()
        );
    }
}

/// Only a 200 with the publication's JSON is a set to carry; a 200 with
/// anything else is a platform that publishes none yet; any other status
/// stops the build.
/// Bug prevented: a redirect's JSON error body compiled in as the platform
/// CA set, giving a binary that fails at start.
#[test]
fn only_an_ok_json_answer_is_a_set() {
    use build_platform::{Answer, answer};
    assert_eq!(answer("200", "application/json"), Ok(Answer::Set));
    assert_eq!(
        answer("200", "application/json; charset=utf-8"),
        Ok(Answer::Set)
    );
    assert_eq!(answer("200", "text/html"), Ok(Answer::NoSetYet));
    assert_eq!(answer("200", ""), Ok(Answer::NoSetYet));
    for status in ["302", "301", "204", "000"] {
        assert!(answer(status, "application/json").is_err(), "{status}");
    }
}

/// The one flag of a local publication selects the platform: off is
/// production, on is the development platform, absent is no platform. Both
/// origins are ones a build can name, and an origin given beside the flag
/// must be the one the flag selects.
/// Bug prevented: a closed test build signing its site in to production, a
/// flag left unset inventing a platform, or a build naming two platforms.
#[test]
fn the_dev_flag_selects_the_platform() {
    use build_platform::{DEVELOPMENT, PRODUCTION, selected};
    assert_eq!(selected(None, None).unwrap(), None);
    assert_eq!(
        selected(None, Some("false")).unwrap().as_deref(),
        Some(PRODUCTION)
    );
    assert_eq!(
        selected(None, Some("true")).unwrap().as_deref(),
        Some(DEVELOPMENT)
    );
    assert_eq!(PRODUCTION, "https://structured.id");
    assert_eq!(DEVELOPMENT, "https://dev.structured.id");
    for origin in [PRODUCTION, DEVELOPMENT] {
        let host = url::Url::parse(origin)
            .unwrap()
            .host_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            publication_of(origin).unwrap().as_str(),
            format!("https://{host}/.well-known/sid-ca/index.json")
        );
    }
    // An official build names the origin itself, with or without the flag.
    assert_eq!(
        selected(Some("https://sid.example.com"), None)
            .unwrap()
            .as_deref(),
        Some("https://sid.example.com")
    );
    assert_eq!(
        selected(Some(DEVELOPMENT), Some("true"))
            .unwrap()
            .as_deref(),
        Some(DEVELOPMENT)
    );
    assert!(selected(Some(PRODUCTION), Some("true")).is_err());
    assert!(selected(Some(DEVELOPMENT), Some("false")).is_err());
    for other in ["1", "yes", "TRUE", "dev"] {
        assert!(selected(None, Some(other)).is_err(), "{other}");
    }
}

/// The platform a build names is its public https origin, and its
/// publication is the published path below it. Anything else a build could
/// be given (plain http, a path, a query, credentials, text that is no URL)
/// names no platform. Bug prevented: a build asking some other address, or
/// an unprotected one, for the certificates it will trust.
#[test]
fn a_build_names_its_platform_by_origin() {
    for platform in ["https://sid.example.com", "https://sid.example.com/"] {
        assert_eq!(
            publication_of(platform).unwrap().as_str(),
            "https://sid.example.com/.well-known/sid-ca/index.json"
        );
    }
    for other in [
        "http://sid.example.com",
        "https://sid.example.com/platform",
        "https://sid.example.com/?a=1",
        "https://sid.example.com/#f",
        "https://u:p@sid.example.com",
        "sid.example.com",
        "",
    ] {
        assert!(
            matches!(publication_of(other), Err(PublicationError::NotHttps)),
            "{other}"
        );
    }
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
            },
            PlatformCa {
                generation: 1,
                certificate: vec![1; 600],
                state: PlatformCaState::VerificationOnly as i32,
                overlap_end: Some(prost_types::Timestamp {
                    seconds: 1_900_000_000,
                    nanos: 0,
                }),
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

/// What a build carries is the platform's publication as it was fetched:
/// it states the same set the publication states. A build that carries
/// nothing states none, and a file that is no publication (a site's HTML
/// page answered at that address) is refused rather than read as no set.
/// Bug prevented: a delivery going out with a platform named and nothing to
/// verify under, unnoticed.
#[test]
fn a_build_carries_the_publication_it_fetched() {
    let message = publication_message().unwrap();
    let dynamic =
        prost_reflect::DynamicMessage::decode(message, published().encode_to_vec().as_slice())
            .unwrap();
    let body = serde_json::to_vec(&dynamic).unwrap();
    assert_eq!(carried(&body).unwrap(), Some(set_of(published()).unwrap()));
    assert_eq!(carried(b"").unwrap(), None);
    for other in [&b"<!doctype html><html></html>"[..], b"{\"revision\":"] {
        assert!(matches!(
            carried(other),
            Err(PublicationError::Malformed(_))
        ));
    }
    let oversized = vec![b' '; MAX_BODY + 1];
    assert!(matches!(
        carried(&oversized),
        Err(PublicationError::TooLarge)
    ));
}

/// Whatever this very build carries reads as a set with at least one
/// generation, or the build carries nothing. In a build made for a platform
/// this is the check that the fetched publication is one.
#[test]
fn what_this_build_carries_is_a_set() {
    select_tls();
    let platform = build_platform().unwrap();
    let carried = build_platform_cas().unwrap();
    // The run's record of which platform this very build was made for.
    eprintln!(
        "build platform: {}; publication: {}; site admissions: {}; carried generations: {}",
        platform.as_ref().map_or("none", |p| p.as_str()),
        build_publication()
            .unwrap()
            .as_ref()
            .map_or("none", |p| p.as_str()),
        site_admission::PlatformAdmissions::of_build()
            .unwrap()
            .as_ref()
            .map_or("none", |p| p.endpoint()),
        carried.as_ref().map_or(0, |set| set.generations.len()),
    );
    if let Some(set) = carried {
        assert!(!set.generations.is_empty());
        assert!(platform.is_some());
    }
}

struct Publishing(PlatformCas);

/// The DER bytes the test publication serves as generation 2's CRL.
const SERVED_CRL: &[u8] = &[0x30, 0x82, 0xff, 0x00, 0x7f];

#[tonic::async_trait]
impl PlatformCaService for Publishing {
    async fn get_platform_cas(
        &self,
        _: tonic::Request<GetPlatformCasRequest>,
    ) -> Result<tonic::Response<PlatformCas>, tonic::Status> {
        Ok(tonic::Response::new(self.0.clone()))
    }

    async fn get_platform_ca_crl(
        &self,
        request: tonic::Request<sid_proto::sid::v1::GetPlatformCaCrlRequest>,
    ) -> Result<tonic::Response<sid_proto::google::api::HttpBody>, tonic::Status> {
        if request.into_inner().generation != 2 {
            return Err(tonic::Status::not_found("no such generation"));
        }
        Ok(tonic::Response::new(sid_proto::google::api::HttpBody {
            content_type: CRL_TYPE.into(),
            data: SERVED_CRL.to_vec(),
            extensions: vec![],
        }))
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
    let publication = loopback(&format!("http://{bind}/.well-known/sid-ca/index.json"));
    let fetched = publication.fetch().await.unwrap();
    assert_eq!(fetched, published());
    // A generation's CRL is read apart, as the DER the service answered.
    assert_eq!(publication.fetch_crl(2).await.unwrap(), SERVED_CRL);
    assert!(matches!(
        publication.fetch_crl(7).await,
        Err(PublicationError::Status(404))
    ));
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

// A published message reads to the set its holder applies: states by their
// meaning, an overlap end and the times in seconds. Bug prevented: an
// unknown state or a missing freshness time read as some default, so a
// holder would apply a set that never said it.
#[test]
fn a_published_message_states_the_set() {
    use sid_plugin::platform_ca as held;
    let set = set_of(published()).unwrap();
    assert_eq!(set.revision, 6);
    assert_eq!(
        (set.issued_at, set.next_update),
        (1_800_000_000, 1_800_003_600)
    );
    assert_eq!(
        set.generations,
        vec![
            held::PlatformCa {
                generation: 2,
                certificate: vec![2; 600],
                state: held::PlatformCaState::Active,
                overlap_end: None,
            },
            held::PlatformCa {
                generation: 1,
                certificate: vec![1; 600],
                state: held::PlatformCaState::VerificationOnly,
                overlap_end: Some(1_900_000_000),
            },
        ]
    );

    let mut stateless = published();
    stateless.generations[0].state = 0;
    assert_eq!(set_of(stateless).unwrap_err().field, "generations.state");
    let mut undated = published();
    undated.next_update = None;
    assert_eq!(set_of(undated).unwrap_err().field, "next_update");
}

// Discovery records never replace the publication: whatever they say of a
// fetched set (announce it, name another, or fail to resolve), the set taken
// is the one the configured endpoint answered. Bug prevented: a DNS failure
// or mismatch stopping the refresh, or DNS content standing in for the set.
#[test]
fn discovery_only_qualifies_the_fetched_set() {
    let endpoint: url::Url = "https://platform.sid.example.com/.well-known/sid-ca/index.json"
        .parse()
        .unwrap();
    let expected = set_of(published()).unwrap();
    // The record announcing `generation` with `certificate` at the endpoint.
    let announced = |generation: u32, certificate: &[u8]| {
        use sha2::Digest;
        discovery::DiscoveryRecord {
            generation,
            algorithms: vec![
                discovery::KeyAlgorithm::EcdsaP256,
                discovery::KeyAlgorithm::MlDsa65,
            ],
            fingerprint: sha2::Sha256::digest(certificate).into(),
            publication: endpoint.clone(),
        }
    };
    // Both anchoring generations of the published set, exactly.
    let exact = vec![announced(2, &[2; 600]), announced(1, &[1; 600])];
    for (records, step) in [
        (None, RefreshStep::Publication),
        // A set the secure records announce exactly is taken on the DNS step.
        (Some(Ok(exact)), RefreshStep::Discovery),
        // Records that cannot be read, name no generation, or announce
        // another certificate reject the DNS candidate: the HTTPS
        // publication still supplies the set.
        (Some(Err("NXDOMAIN".to_owned())), RefreshStep::Publication),
        (Some(Ok(Vec::new())), RefreshStep::Publication),
        (
            Some(Ok(vec![
                announced(2, b"another certificate"),
                announced(1, &[1; 600]),
            ])),
            RefreshStep::Publication,
        ),
    ] {
        assert_eq!(
            PublishedPlatformCas::taken(published(), records, &endpoint).unwrap(),
            (expected.clone(), step)
        );
    }
}

/// Discovery records answering with `answer`, counting the reads.
struct Discovery {
    answer: Result<Vec<discovery::DiscoveryRecord>, String>,
    reads: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl DiscoverySource for Discovery {
    async fn records(&self, _: &url::Url) -> Result<Vec<discovery::DiscoveryRecord>, String> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.answer.clone()
    }
}

// The source reads the records once beside each fetch, and a publication it
// cannot reach fails the fetch whatever the records say: DNS never supplies
// a set.
#[tokio::test]
async fn the_records_are_read_beside_the_fetch_and_never_replace_it() {
    let discovery = std::sync::Arc::new(Discovery {
        answer: Ok(Vec::new()),
        reads: std::sync::atomic::AtomicUsize::new(0),
    });
    let source = PublishedPlatformCas::new().with_discovery(discovery.clone());
    // Nothing listens on the discard port of the loopback.
    let endpoint: url::Url = "https://127.0.0.1:9/.well-known/sid-ca/index.json"
        .parse()
        .unwrap();
    // The process's TLS provider, as the other tests install it.
    let _ = loopback(endpoint.as_str());
    assert!(source.fetch(&endpoint).await.is_err());
    assert_eq!(discovery.reads.load(std::sync::atomic::Ordering::SeqCst), 1);
}
