// SPDX-License-Identifier: AGPL-3.0-only
//! The composition the server delivers refuses what a method's access rule
//! does not admit, before the method's handler runs. The server is started
//! from its settings as its binary starts it; the test sets process
//! settings, so it is the only test of its binary.
#![cfg(all(feature = "http", feature = "storage-pg"))]

use prost_reflect::DescriptorPool;
use sid_core::models::{AuditEntry, Profile, ProfileStatus, Session};
use sid_infra::authn::access::{AccessRule, AccessRules, CredentialKind};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

/// Bytes sent and received as they are: the walk calls methods whose
/// messages it does not know.
#[derive(Clone, Default)]
struct Raw;

impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Raw;
    type Decoder = Raw;

    fn encoder(&mut self) -> Self::Encoder {
        Raw
    }

    fn decoder(&mut self) -> Self::Decoder {
        Raw
    }
}

impl Encoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        use prost_reflect::bytes::BufMut as _;
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        use prost_reflect::bytes::Buf as _;
        let mut read = vec![0; src.remaining()];
        src.copy_to_slice(&mut read);
        Ok(Some(read))
    }
}

/// A request body no message decodes from: an unterminated varint. A served
/// method decodes its request before its handler runs, so a call that got
/// past the guard answers with the decoding failure and never with a
/// handler's own decision.
const UNDECODABLE: [u8; 1] = [0xff];

/// The status of calling `path` with the undecodable body, as `bearer`.
async fn call(channel: &Channel, path: &str, bearer: Option<&str>) -> Status {
    let mut client = tonic::client::Grpc::new(channel.clone());
    client.ready().await.expect("the server accepts calls");
    let mut request = Request::new(UNDECODABLE.to_vec());
    // Every call names a new command, as a client does: a changing method
    // asks for it before anything else, a reading one ignores it.
    sid_infra::authn::operation::insert_context(
        request.metadata_mut(),
        &sid_core::models::OperationContext::new(
            sid_core::models::OperationKey::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
            sid_core::models::OperationPeriod::new(1),
        ),
    );
    if let Some(token) = bearer {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    client
        .unary(request, path.parse().expect("a method path"), Raw)
        .await
        .map(|_: tonic::Response<Vec<u8>>| ())
        .expect_err("an undecodable request is never answered with a message")
}

/// Every method whose access rule is `protected`, read from the schema the
/// server serves, refuses an anonymous call and a genuine credential of a
/// kind its rule does not admit, and does so before its handler: both are
/// answered by the guard, where a call the guard lets through fails at the
/// decoding of its request. A method list is not kept here: a service added
/// to the server is walked because the schema declares it.
/// Bug prevented: a service served without the guard, or a guard that
/// stopped enforcing a kind, which every per-service test would still pass.
#[test]
fn every_protected_method_refuses_what_its_rule_does_not_admit() {
    let data = tempfile::tempdir().unwrap();
    let http = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let settings = [
        (
            "SID_DATABASE_URL",
            std::env::var("SID_TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into()),
        ),
        // A schema of this run's own: the installation is opened from empty.
        (
            "SID_STORAGE_POSTGRESQL_SCHEMA",
            format!("admission_walk_{}", uuid::Uuid::new_v4().simple()),
        ),
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", "https://sid.example.com".to_owned()),
        ("SID_BIND", http.to_string()),
        ("SID_NATS_URL", "in-process".to_owned()),
    ];
    for (name, value) in settings {
        // SAFETY: the test's only thread so far; the runtime starts below.
        unsafe { std::env::set_var(name, value) };
    }
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .expect("no TLS provider is installed yet");
    sid_crypto::jwt::install_jwt_provider().unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = grpc.local_addr().unwrap();
        let c = sid_server::init::init_ce_with(Default::default())
            .await
            .unwrap();

        // A genuine credential of the own-session kind: a stored account's
        // stored session, signed by the installation.
        let mut account = Profile::new(Some("walker"));
        account.status = ProfileStatus::Active;
        c.storage
            .create_profile(&account, AuditEntry::system("test", "account").into())
            .await
            .unwrap();
        let session = Session::new(
            account.id,
            None,
            jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
        );
        c.storage
            .create_session(&session, AuditEntry::system("test", "session").into())
            .await
            .unwrap();
        let own_session = c
            .jwt
            .issue_access_token(
                &account.id.to_string(),
                Some(&account.id.to_string()),
                &account.roles,
                &session,
                &["openid".to_string()],
                None,
                None,
            )
            .unwrap();
        // The credential is genuine: the installation's own verifier and
        // its record of ended sessions accept it, so a refusal below is the
        // rule's and not a broken token's.
        sid_authn::caller::authenticate_token(
            &own_session,
            c.jwt.verifier(),
            c.revocation_cache.as_ref(),
        )
        .await
        .expect("the installation accepts its own session token");

        // A genuine credential of another kind: the account API's token, as
        // the installation's issuer signs it for the account's own pages.
        let issuer = c
            .storage
            .list_oidc_issuers()
            .await
            .unwrap()
            .into_iter()
            .find(|i| i.canonical_url == c.issuer)
            .expect("the installation has its base issuer");
        let account_api = c
            .jwt
            .access_token_signed_by(
                c.issuers.signer(&issuer).await.unwrap().as_ref(),
                sid_authn::jwt::TokenAudience::Resource {
                    indicator: sid_authn::system_integration::account_api_indicator(&c.issuer)
                        .unwrap()
                        .as_str(),
                    client_id: "account-pages",
                    grant: sid_authn::jwt::UserGrant::AccountApi,
                },
                &account.id.to_string(),
                None,
                &account.roles,
                &session,
                &["openid".to_string()],
                None,
                None,
            )
            .unwrap();
        let verified = sid_authn::caller::authenticate_token(
            &account_api,
            c.jwt.verifier(),
            c.revocation_cache.as_ref(),
        )
        .await
        .expect("the installation accepts its account API token");
        assert_eq!(verified.source, sid_authn::caller::TokenSource::AccountApi);

        let services = sid_server::serve::CeServices::new(&c, Default::default())
            .await
            .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(sid_server::serve::serve_on(grpc, c, services, async {
            stopped.await.ok();
        }));
        let channel = loop {
            match Channel::from_shared(format!("http://{address}"))
                .unwrap()
                .connect()
                .await
            {
                Ok(channel) => break channel,
                Err(_) => tokio::task::yield_now().await,
            }
        };

        let rules = AccessRules::from_descriptors(sid_proto::FILE_DESCRIPTOR_SET).unwrap();
        let pool = DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET).unwrap();
        let mut walked = 0;
        let mut foreign_kind = 0;
        let mut let_through = 0;
        let mut failures = Vec::new();
        let mut health = tonic_health::pb::health_client::HealthClient::new(channel.clone());
        for service in pool.services() {
            // The server reports every service it serves on its health
            // service; one it does not serve is unknown there.
            let serving = health
                .check(tonic_health::pb::HealthCheckRequest {
                    service: service.full_name().to_owned(),
                })
                .await;
            match serving {
                Ok(_) => {}
                Err(unknown) if unknown.code() == Code::NotFound => continue,
                Err(other) => panic!("health of {}: {other:?}", service.full_name()),
            }
            for method in service.methods() {
                let path = format!("/{}/{}", service.full_name(), method.name());
                let Some(AccessRule::Protected { .. }) = rules.rule(&path) else {
                    continue;
                };
                let rule = rules.rule(&path).unwrap();
                let anonymous = call(&channel, &path, None).await;
                walked += 1;
                if anonymous.code() != Code::Unauthenticated {
                    failures.push(format!("{path}: anonymous answered {anonymous:?}"));
                }
                for (kind, token) in [
                    (CredentialKind::OwnSession, &own_session),
                    (CredentialKind::AccountApi, &account_api),
                ] {
                    if !rule.admits(kind) {
                        foreign_kind += 1;
                        let refused = call(&channel, &path, Some(token)).await;
                        if refused.code() != Code::PermissionDenied {
                            failures.push(format!(
                                "{path}: {kind:?}, which its rule does not admit, answered {refused:?}"
                            ));
                        }
                    } else if kind == CredentialKind::OwnSession {
                        // The own session carries every scope, so the guard
                        // lets it through: the request is decoded, which
                        // fails. The body therefore does tell the guard from
                        // the handler.
                        let_through += 1;
                        let passed = call(&channel, &path, Some(token)).await;
                        if matches!(passed.code(), Code::Unauthenticated | Code::PermissionDenied)
                        {
                            failures
                                .push(format!("{path}: an admitted credential answered {passed:?}"));
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {walked} methods, the first:\n{}",
            failures.len(),
            failures
                .iter()
                .take(4)
                .map(|f| f.chars().take(260).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        );
        // The walk met methods of each case: an empty walk proves nothing.
        assert!(walked > 0, "no protected method is served");
        assert!(let_through > 0, "no method admits the own session");
        assert!(
            foreign_kind > 0,
            "every protected method admits both credentials: no kind was refused"
        );

        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    });
    runtime.shutdown_background();
}
