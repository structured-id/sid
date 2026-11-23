// SPDX-License-Identifier: AGPL-3.0-only
//! Email sign-in codes through the installation as it runs: the RPCs commit
//! the code and its mail work in PostgreSQL, the engine's work runner with
//! the CE work handlers the server registers sends the mail through the
//! templated mail to the email channel, and the code read from that mail
//! signs in through VerifyOtp.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use std::sync::Arc;
use std::time::Duration;

use sid::auth_mail::CodeMail;
use sid::work::{CeMail, CeWork, CeWorkParts};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, EmailLabel, Principal, PrincipalType, Profile, ProfileEmail, ProfileEmailId,
};
use sid_plugin::StorageBackend;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use sid_server::auth_mail::{MailTransport, TemplatedMail};
use tonic::Request;

/// The email channel at the edge of the installation: records each mail
/// instead of handing it to a provider.
#[derive(Default)]
struct Recorded {
    sent: std::sync::Mutex<Vec<(String, RenderedMessage)>>,
}

#[async_trait::async_trait]
impl NotificationChannel for Recorded {
    fn channel_id(&self) -> &str {
        "email"
    }

    async fn deliver(
        &self,
        recipient: &Recipient,
        message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.sent.lock().unwrap().push((
            recipient.email.clone().expect("an email recipient"),
            message.clone(),
        ));
        Ok(DeliveryReceipt {
            message_id: uuid::Uuid::now_v7().to_string(),
            channel: "email".into(),
            timestamp: jiff::Timestamp::now(),
            provider: "recorded".into(),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        unreachable!("the mail handler never probes its channel")
    }
}

/// The configured provider's channel, here the recording one.
struct Transport(Arc<Recorded>);

#[async_trait::async_trait]
impl MailTransport for Transport {
    async fn channel(&self) -> Result<Arc<dyn NotificationChannel>, String> {
        Ok(self.0.clone())
    }
}

/// The installation: its authentication service and the engine that runs
/// its owed work, both over `storage`, mail going to `recorded`.
struct Installation {
    storage: Arc<dyn StorageBackend>,
    /// The schema's pool, for reading the state of its work rows, which the
    /// work store's interface does not list.
    pool: sqlx::PgPool,
    auth: Arc<sid_server::grpc::auth_service::AuthServiceImpl>,
    engine: Option<sid::Engine>,
    recorded: Arc<Recorded>,
}

fn select_tls() {
    // The back-channel logout handler's HTTPS client needs the process's TLS
    // provider, as the server installs it at start.
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        sid_crypto::tls::aws_lc::provider()
            .install_default()
            .expect("the test process's only TLS provider");
    });
}

fn installation(storage: Arc<dyn StorageBackend>, pool: sqlx::PgPool) -> Installation {
    select_tls();
    let recorded = Arc::new(Recorded::default());
    let auth = common::auth_service_over(
        storage.clone(),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        None,
    );
    let keys = common::test_key_manager();
    let codes = Arc::new(sid_authn::otp::OtpService::new(
        storage.clone(),
        sid_authn::otp::CodeDelivery { keys: keys.clone() },
    ));
    let revocation = Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ));
    // The work the server assembles, with the mail delivery it builds
    // ([`sid_server::init::stored_mail`]) over this channel.
    let CeWork {
        handlers,
        maintenance,
    } = CeWork::assemble(CeWorkParts {
        storage: storage.clone(),
        organization: sid_core::models::OrgId::generate(),
        issuers: Arc::new(sid_authn::issuer::IssuerRegistry::new(
            storage.clone(),
            keys.clone(),
        )),
        closures: Arc::new(sid_authn::account_closure::AccountClosureService::new(
            storage.clone(),
            Arc::new(
                sid_authn::revocation_cascade::RevocationCascadeService::new(
                    storage.clone(),
                    revocation.clone(),
                ),
            ),
        )),
        revocation,
        event_bus: Arc::new(sid_plugin::event_bus::InProcessEventBus::new()),
        required_receivers: Vec::new(),
        history_evaluation: None,
        issuer: "https://sid.example.com".into(),
        mail: CeMail {
            codes: Arc::new(CodeMail::new(
                codes,
                Arc::new(TemplatedMail::new(Arc::new(Transport(recorded.clone())))),
            )),
            magic_links: None,
            resets: None,
        },
        site_admissions: Arc::new(sid::federation_site::AdmissionPublications::new(
            Arc::new(sid::federation_site::FederationSite::new(
                storage.clone(),
                keys.clone(),
                Arc::new(sid_fed::recipient::Recipient::new(
                    storage.clone(),
                    sid_fed::recipient::ClassicalVerdict,
                )),
                sid_core::models::OrgId::generate(),
            )),
            None,
        )),
        audit_retention: sid::AuditRetention::default(),
        migration_deadline_days: sid::maintenance::DEFAULT_MIGRATION_DEADLINE_DAYS,
        source: "test".into(),
    })
    .expect("the CE work");
    let engine = sid::Engine::new(sid::EngineParts {
        storage: storage.clone(),
        worker: format!("test-{}", uuid::Uuid::now_v7()),
        handlers,
        runner: sid_authn::work_runner::RunnerConfig::default(),
        maintenance,
    })
    .expect("the engine");
    Installation {
        storage,
        pool,
        auth,
        engine: Some(engine),
        recorded,
    }
}

impl Installation {
    /// A Profile whose email key `key` routes to the contact `mailbox`, as
    /// registration binds them.
    async fn holder(&self, key: &str, mailbox: &str) -> Profile {
        // Named after its key, so the scenarios' holders in the suite's one
        // database are distinct accounts.
        let holder = Profile::new(Some(key.split('@').next().unwrap()));
        self.storage
            .create_profile(&holder, AuditEntry::system("test", "profile").into())
            .await
            .unwrap();
        let contact = ProfileEmail {
            id: ProfileEmailId::new(),
            profile_id: holder.id,
            email: mailbox.to_string(),
            label: EmailLabel::Personal,
            custom_label: None,
            is_primary: true,
            verified: true,
            verified_at: Some(jiff::Timestamp::now()),
            created_at: jiff::Timestamp::now(),
            updated_at: jiff::Timestamp::now(),
        };
        self.storage
            .create_profile_email(&contact, AuditEntry::system("test", "contact").into())
            .await
            .unwrap();
        let mut principal = Principal::new(holder.id, PrincipalType::Email, key);
        principal.source_email_id = Some(contact.id);
        self.storage
            .save_principal(&principal, AuditEntry::system("test", "principal").into())
            .await
            .unwrap();
        holder
    }

    async fn request(&self, address: &str) -> RequestOtpResponse {
        self.auth
            .request_otp(Request::new(RequestOtpRequest {
                principal: address.to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    async fn resend(&self, pending: &RequestOtpResponse) {
        self.auth
            .resend_otp(Request::new(ResendOtpRequest {
                otp_session_id: pending.otp_session_id.clone(),
            }))
            .await
            .unwrap();
    }

    async fn verify(&self, pending: &RequestOtpResponse, code: &str) -> VerifyOtpResponse {
        self.auth
            .verify_otp(Request::new(VerifyOtpRequest {
                code: code.to_string(),
                otp_session_id: pending.otp_session_id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    /// The code mail work rows in `state`: of the sign-in `pending` when
    /// given, of every sign-in otherwise. A code mail's payload starts with
    /// its sign-in's id.
    async fn code_mails(&self, state: &str, pending: Option<&RequestOtpResponse>) -> i64 {
        let query = sqlx::query_scalar(
            "SELECT count(*) FROM durable_work WHERE kind = $1 AND state = $2
             AND ($3::bytea IS NULL OR substring(payload from 1 for 16) = $3)",
        )
        .bind(sid_authn::otp::OTP_EMAIL_KIND)
        .bind(state)
        .bind(pending.map(|p| {
            sid_ids_proto::required(p.otp_session_id.as_ref())
                .unwrap()
                .into_uuid()
                .as_bytes()
                .to_vec()
        }));
        query.fetch_one(&self.pool).await.unwrap()
    }

    /// Run the engine until it has no code mail left to attempt, then drain
    /// it; the mails it sent.
    async fn run_owed_mail(&mut self) -> Vec<(String, RenderedMessage)> {
        let running = self.engine.take().expect("the engine runs once").start();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if self.code_mails("pending", None).await + self.code_mails("claimed", None).await == 0
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the code mail was not attempted"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        running.drain().await.expect("the engine drains");
        self.recorded.sent.lock().unwrap().clone()
    }
}

/// The sign-in code a mail carries.
fn code_in(message: &RenderedMessage) -> String {
    let digits: Vec<char> = message.body.chars().collect();
    digits
        .windows(8)
        .find(|w| w.iter().all(char::is_ascii_digit))
        .map(|w| w.iter().collect())
        .unwrap_or_else(|| panic!("no code in the mail: {}", message.body))
}

/// The suite's database: one PostgreSQL installation of its own, a copy of
/// the run's template, so the runner sees this suite's work alone. Each
/// scenario runs on a new installation (service and engine) over it with
/// data of its own; the copy is removed at the end, also after a failed
/// scenario.
#[tokio::test]
async fn sign_in_codes_through_the_servers_work() {
    sid_storage::testing::in_isolated_postgres(|backend| async move {
        let pool = backend.pool().clone();
        let storage: Arc<dyn StorageBackend> = Arc::new(backend);
        storage
            .ensure_system_project(AuditEntry::system("test", "system").into())
            .await
            .unwrap();
        requested_code_reaches_the_mailbox_and_signs_in(installation(
            storage.clone(),
            pool.clone(),
        ))
        .await;
        resent_code_replaces_the_mail_of_the_first(installation(storage.clone(), pool.clone()))
            .await;
        the_sign_in_page_resends_a_code_and_signs_in_with_it(installation(storage, pool)).await;
    })
    .await;
}

/// A requested code reaches the account's stored mailbox (spelled unlike the
/// key the request was looked up by) through the work the installation runs,
/// and that code signs the account in. Bug prevented: a code committed with
/// no handler registered to send it, or sent to the lookup key instead of
/// the bound mailbox.
async fn requested_code_reaches_the_mailbox_and_signs_in(mut i: Installation) {
    let mailbox = "John.Smith+id@sid.example.com";
    let holder = i.holder("johnsmith@sid.example.com", mailbox).await;
    let pending = i.request("J.O.H.N.Smith@sid.example.com").await;

    let sent = i.run_owed_mail().await;

    assert_eq!(i.code_mails("completed", Some(&pending)).await, 1);
    assert_eq!(sent.len(), 1, "one mail per requested code");
    assert_eq!(sent[0].0, mailbox);
    let verified = i.verify(&pending, &code_in(&sent[0].1)).await;
    assert!(verified.verified);
    let sessions = i.storage.list_sessions(&holder.id).await.unwrap();
    assert_eq!(sessions.len(), 1, "the holder was not signed in");
}

/// `message` as the sign-in page sends it: its Origin, no session of its own.
fn from_sign_in_page<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("origin", common::SIGN_IN_ORIGIN.parse().unwrap());
    request
}

/// The sign-in page asks for a code and asks for it again before verifying,
/// as its code page's resend does with the challenge reference it holds:
/// one mail is delivered, with the resent code, and nothing is signed in
/// before the verify; the verify with that code signs in, the session
/// arriving as a cookie, never as a bearer token in the answer. RPC calls
/// with the page's metadata.
async fn the_sign_in_page_resends_a_code_and_signs_in_with_it(mut i: Installation) {
    let mailbox = "Kim.Park+page@sid.example.com";
    let holder = i.holder("kimpark@sid.example.com", mailbox).await;
    let pending = i
        .auth
        .request_otp(from_sign_in_page(RequestOtpRequest {
            principal: "K.I.M.Park@sid.example.com".to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    i.auth
        .resend_otp(from_sign_in_page(ResendOtpRequest {
            otp_session_id: pending.otp_session_id.clone(),
        }))
        .await
        .expect("the code page resends by its challenge reference");
    assert!(
        i.storage
            .list_sessions(&holder.id)
            .await
            .unwrap()
            .is_empty(),
        "nothing signs in before the verify"
    );

    let sent = i.run_owed_mail().await;
    assert_eq!(sent.len(), 1, "only the resent code is mailed");
    assert_eq!(sent[0].0, mailbox);

    let verified = i
        .auth
        .verify_otp(from_sign_in_page(VerifyOtpRequest {
            code: code_in(&sent[0].1),
            otp_session_id: pending.otp_session_id.clone(),
        }))
        .await
        .expect("the resent code signs in");
    assert!(verified.metadata().get("authorization").is_none());
    assert!(
        verified.metadata().get("set-cookie").is_some(),
        "the browser's session is a cookie"
    );
    assert!(verified.into_inner().verified);
    assert_eq!(i.storage.list_sessions(&holder.id).await.unwrap().len(), 1);
}

/// A resent code replaces the requested one before either mail goes out:
/// the replaced code's mail sends nothing, the new code goes to the stored
/// mailbox and signs in within the original sign-in. Bug prevented: a
/// superseded code still mailed (two live-looking codes in the inbox), or
/// the resent code going anywhere but the bound mailbox.
async fn resent_code_replaces_the_mail_of_the_first(mut i: Installation) {
    let mailbox = "Ann.Lee+login@sid.example.com";
    let holder = i.holder("annlee@sid.example.com", mailbox).await;
    let pending = i.request("A.N.N.Lee@sid.example.com").await;
    i.resend(&pending).await;

    let sent = i.run_owed_mail().await;

    // Both mails were attempted and ended; only the resent code's sent.
    assert_eq!(i.code_mails("completed", Some(&pending)).await, 2);
    assert_eq!(sent.len(), 1, "the replaced code's mail sent a code");
    assert_eq!(sent[0].0, mailbox);
    let verified = i.verify(&pending, &code_in(&sent[0].1)).await;
    assert!(verified.verified);
    let sessions = i.storage.list_sessions(&holder.id).await.unwrap();
    assert_eq!(sessions.len(), 1, "the holder was not signed in");
}
