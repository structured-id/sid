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
use sid_storage::PostgresBackend;
use tonic::Request;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

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
            timestamp: chrono::Utc::now(),
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
        let holder = Profile::new(Some("mail-holder"));
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
            verified_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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

    /// The code mail work rows in `state`.
    async fn code_mails(&self, state: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM durable_work WHERE kind = $1 AND state = $2")
            .bind(sid_authn::otp::OTP_EMAIL_KIND)
            .bind(state)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Run the engine until it has no code mail left to attempt, then drain
    /// it; the mails it sent.
    async fn run_owed_mail(&mut self) -> Vec<(String, RenderedMessage)> {
        let running = self.engine.take().expect("the engine runs once").start();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if self.code_mails("pending").await + self.code_mails("claimed").await == 0 {
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

/// Run `scenario` on an installation in a PostgreSQL schema of its own, so
/// the runner sees this test's work alone, and drop the schema afterwards.
async fn in_own_schema<F, Fut>(scenario: F)
where
    F: FnOnce(Installation) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let schema = format!("otp_mail_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    storage
        .ensure_system_project(AuditEntry::system("test", "system").into())
        .await
        .unwrap();
    let outcome = tokio::spawn(scenario(installation(storage, pool.clone()))).await;
    // The migrations also create the schema's database-wide reader role.
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// A requested code reaches the account's stored mailbox (spelled unlike the
/// key the request was looked up by) through the work the installation runs,
/// and that code signs the account in. Bug prevented: a code committed with
/// no handler registered to send it, or sent to the lookup key instead of
/// the bound mailbox.
#[tokio::test]
async fn requested_code_reaches_the_mailbox_and_signs_in() {
    in_own_schema(|mut i| async move {
        let mailbox = "John.Smith+id@sid.example.com";
        let holder = i.holder("johnsmith@sid.example.com", mailbox).await;
        let pending = i.request("J.O.H.N.Smith@sid.example.com").await;

        let sent = i.run_owed_mail().await;

        assert_eq!(i.code_mails("completed").await, 1);
        assert_eq!(sent.len(), 1, "one mail per requested code");
        assert_eq!(sent[0].0, mailbox);
        let verified = i.verify(&pending, &code_in(&sent[0].1)).await;
        assert!(verified.verified);
        let sessions = i.storage.list_sessions(&holder.id).await.unwrap();
        assert_eq!(sessions.len(), 1, "the holder was not signed in");
    })
    .await;
}

/// A resent code replaces the requested one before either mail goes out:
/// the replaced code's mail sends nothing, the new code goes to the stored
/// mailbox and signs in within the original sign-in. Bug prevented: a
/// superseded code still mailed (two live-looking codes in the inbox), or
/// the resent code going anywhere but the bound mailbox.
#[tokio::test]
async fn resent_code_replaces_the_mail_of_the_first() {
    in_own_schema(|mut i| async move {
        let mailbox = "Ann.Lee+login@sid.example.com";
        let holder = i.holder("annlee@sid.example.com", mailbox).await;
        let pending = i.request("A.N.N.Lee@sid.example.com").await;
        i.resend(&pending).await;

        let sent = i.run_owed_mail().await;

        // Both mails were attempted and ended; only the resent code's sent.
        assert_eq!(i.code_mails("completed").await, 2);
        assert_eq!(sent.len(), 1, "the replaced code's mail sent a code");
        assert_eq!(sent[0].0, mailbox);
        let verified = i.verify(&pending, &code_in(&sent[0].1)).await;
        assert!(verified.verified);
        let sessions = i.storage.list_sessions(&holder.id).await.unwrap();
        assert_eq!(sessions.len(), 1, "the holder was not signed in");
    })
    .await;
}
