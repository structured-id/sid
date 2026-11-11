use super::*;
use sid_proto::sid::v1::PlatformCa;

const PUBLICATION: &str = "https://platform.sid.example.com/.well-known/sid-ca/index.json";

fn publication() -> url::Url {
    PUBLICATION.parse().unwrap()
}

fn fingerprint_b64(certificate: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(certificate))
}

fn text(generation: u32, certificate: &[u8]) -> String {
    format!(
        "v=1;gen={generation};alg=ecdsa-p256+ml-dsa-65;sha256={};url={PUBLICATION}",
        fingerprint_b64(certificate)
    )
}

fn generation(generation: u32, certificate: &[u8], state: PlatformCaState) -> PlatformCa {
    PlatformCa {
        generation,
        certificate: certificate.to_vec(),
        state: state as i32,
        overlap_end: None,
    }
}

/// Generation 3 active, 2 verification-only, 1 withdrawn.
fn set() -> PlatformCas {
    PlatformCas {
        revision: 9,
        generations: vec![
            generation(3, &[3; 64], PlatformCaState::Active),
            generation(2, &[2; 64], PlatformCaState::VerificationOnly),
            generation(1, &[1; 64], PlatformCaState::Withdrawn),
        ],
        roots: vec![],
        issued_at: None,
        next_update: None,
    }
}

fn records_of(texts: &[String]) -> Vec<DiscoveryRecord> {
    parse_records(texts).unwrap()
}

// A record reads to its generation, algorithms, fingerprint and publication.
#[test]
fn a_record_reads_back() {
    let record: DiscoveryRecord = text(3, &[3; 64]).parse().unwrap();
    assert_eq!(record.generation, 3);
    assert_eq!(
        record.algorithms,
        vec![KeyAlgorithm::EcdsaP256, KeyAlgorithm::MlDsa65]
    );
    assert_eq!(
        record.fingerprint,
        <[u8; 32]>::from(Sha256::digest([3; 64]))
    );
    assert_eq!(record.publication, publication());
}

// Version 1 comes first; anything else is another version's record.
#[test]
fn another_version_is_refused() {
    let fp = fingerprint_b64(&[3; 64]);
    for text in [
        format!("v=2;gen=3;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
        format!("gen=3;v=1;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
        String::new(),
    ] {
        assert_eq!(
            text.parse::<DiscoveryRecord>(),
            Err(RecordError::Version),
            "{text}"
        );
    }
}

// Each field must be present, well formed, once, and known to version 1.
#[test]
fn a_malformed_record_is_refused() {
    let fp = fingerprint_b64(&[3; 64]);
    let short = base64::engine::general_purpose::STANDARD.encode([3; 31]);
    let cases = [
        (
            format!("v=1;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
            RecordError::Missing("gen"),
        ),
        (
            format!("v=1;gen=3;sha256={fp};url={PUBLICATION}"),
            RecordError::Missing("alg"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256;url={PUBLICATION}"),
            RecordError::Missing("sha256"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256;sha256={fp}"),
            RecordError::Missing("url"),
        ),
        (
            format!("v=1;gen=0;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
            RecordError::Malformed("gen"),
        ),
        (
            format!("v=1;gen=+3;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
            RecordError::Malformed("gen"),
        ),
        (
            format!("v=1;gen=3;alg=rsa;sha256={fp};url={PUBLICATION}"),
            RecordError::Malformed("alg"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256+ecdsa-p256;sha256={fp};url={PUBLICATION}"),
            RecordError::Malformed("alg"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256;sha256={short};url={PUBLICATION}"),
            RecordError::Malformed("sha256"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256;sha256={fp};url=http://platform.sid.example.com/x"),
            RecordError::Malformed("url"),
        ),
        (
            format!("v=1;gen=3;gen=4;alg=ecdsa-p256;sha256={fp};url={PUBLICATION}"),
            RecordError::Malformed("field"),
        ),
        (
            format!("v=1;gen=3;alg=ecdsa-p256;sha256={fp};url={PUBLICATION};retire=1"),
            RecordError::Malformed("field"),
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            text.parse::<DiscoveryRecord>(),
            Err(expected.clone()),
            "{text}"
        );
    }
}

// A generation is announced once, and the number of records is bounded.
#[test]
fn duplicate_and_excess_records_are_refused() {
    assert_eq!(
        parse_records(&[text(3, &[3; 64]), text(3, &[4; 64])]),
        Err(RecordError::DuplicateGeneration(3))
    );
    let many: Vec<String> = (1..=MAX_RECORDS as u32 + 1)
        .map(|g| text(g, &[1; 8]))
        .collect();
    assert_eq!(parse_records(&many), Err(RecordError::TooMany));
}

// A set whose anchoring generations are exactly the announced certificates
// passes; its withdrawn generation needs no record.
#[test]
fn a_matching_set_passes() {
    let records = records_of(&[text(3, &[3; 64]), text(2, &[2; 64])]);
    assert_eq!(check(&set(), &records, &publication()), Ok(()));
}

// Every way a set can differ from the records fails this step.
#[test]
fn a_set_that_differs_from_the_records_fails() {
    let publication = publication();
    // No records: DNS supplies nothing to hold the set to.
    assert_eq!(
        check(&set(), &[], &publication),
        Err(DiscoveryMismatch::NoRecords)
    );
    // An anchoring generation without a record.
    assert_eq!(
        check(&set(), &records_of(&[text(3, &[3; 64])]), &publication),
        Err(DiscoveryMismatch::Unlisted(2))
    );
    // Another certificate under an announced generation number.
    assert_eq!(
        check(
            &set(),
            &records_of(&[text(3, &[9; 64]), text(2, &[2; 64])]),
            &publication
        ),
        Err(DiscoveryMismatch::Fingerprint(3))
    );
    // A record for a generation the set does not anchor: withdrawn there, or
    // absent from it.
    for extra in [text(1, &[1; 64]), text(4, &[4; 64])] {
        let records = records_of(&[text(3, &[3; 64]), text(2, &[2; 64]), extra]);
        assert!(matches!(
            check(&set(), &records, &publication),
            Err(DiscoveryMismatch::NotInSet(1 | 4))
        ));
    }
    // A record naming another publication.
    let other = text(3, &[3; 64]).replace(PUBLICATION, "https://elsewhere.example/index.json");
    assert_eq!(
        check(
            &set(),
            &records_of(&[other, text(2, &[2; 64])]),
            &publication
        ),
        Err(DiscoveryMismatch::OtherPublication(3))
    );
}

// The records live under the publication's host; an address has no name.
#[test]
fn the_platform_name_is_the_publications_host() {
    assert_eq!(
        platform_name(&publication()),
        Some("platform.sid.example.com")
    );
    assert_eq!(
        platform_name(
            &"https://192.0.2.1/.well-known/sid-ca/index.json"
                .parse()
                .unwrap()
        ),
        None
    );
}

#[cfg(feature = "platform-ca-dns")]
mod resolving {
    use std::net::SocketAddr;

    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
    };
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::rdata::TXT;
    use hickory_resolver::proto::rr::{RData, Record, RecordType};

    use super::*;

    /// A name server on loopback answering every TXT query with `answer`,
    /// unsigned, and everything else with an empty answer.
    async fn unsigned_server(answer: String) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.authoritative = true;
                for q in &query.queries {
                    response.add_query(q.clone());
                    if q.query_type() == RecordType::TXT {
                        response.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::TXT(TXT::new(vec![answer.clone()])),
                        ));
                    }
                }
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        address
    }

    // An answer not proven by DNSSEC from the root yields no records, even
    // when its content is a well-formed record.
    #[tokio::test]
    async fn an_unsigned_answer_yields_no_records() {
        let address = unsigned_server(text(3, &[3; 64])).await;
        let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
        connection.port = address.port();
        let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
            address.ip(),
            true,
            vec![connection],
        )]);
        let resolver =
            DiscoveryResolver::from_builder(hickory_resolver::Resolver::builder_with_config(
                config,
                TokioRuntimeProvider::default(),
            ))
            .unwrap();
        let result = resolver.records(&publication()).await;
        assert!(
            matches!(
                result,
                Err(DiscoveryError::NotSecure(_) | DiscoveryError::Unavailable(_))
            ),
            "{result:?}"
        );
    }

    // Each validation outcome but a secure one is named, so an operator can
    // tell a missing delegation from failing signatures.
    #[test]
    fn every_unproven_outcome_is_named() {
        use hickory_resolver::proto::dnssec::Proof;

        assert_eq!(NotProven::of(Proof::Secure), None);
        assert_eq!(NotProven::of(Proof::Insecure), Some(NotProven::Insecure));
        assert_eq!(NotProven::of(Proof::Bogus), Some(NotProven::Bogus));
        assert_eq!(
            NotProven::of(Proof::Indeterminate),
            Some(NotProven::Indeterminate)
        );
        assert!(
            DiscoveryError::NotSecure(NotProven::Insecure)
                .to_string()
                .contains("no chain of trust from the root")
        );
    }

    // The validator rejecting the chain ends the lookup itself with an
    // error; that is a bogus answer (RFC 4033 §5), not an unreachable
    // resolver, so the operator is told why the record is not secure.
    #[test]
    fn a_failed_validation_is_bogus_not_unavailable() {
        use hickory_resolver::net::{DnsError, NetError};

        assert!(matches!(
            DiscoveryError::of_lookup(NetError::Dns(DnsError::DnssecBogus)),
            DiscoveryError::NotSecure(NotProven::Bogus)
        ));
        assert!(matches!(
            DiscoveryError::of_lookup(NetError::Timeout),
            DiscoveryError::Unavailable(_)
        ));
    }
}
