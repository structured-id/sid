use std::collections::BTreeSet;

use super::*;
use crate::auth_mail::{AuthMailDelivery, MailError, OwedMail};
use crate::test_support::{keys, storage};

/// A delivery the assembly never calls.
struct Unused;

#[async_trait::async_trait]
impl AuthMailDelivery for Unused {
    async fn deliver(&self, _: &OwedMail) -> Result<String, MailError> {
        unreachable!("assembling the work sends no mail")
    }
}

/// The TLS provider the logout client is built with, selected as a host
/// selects it; each test runs in its own process.
fn select_tls() {
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .expect("the process selects its TLS provider once");
}

fn parts(storage: Arc<dyn StorageBackend>, links: bool) -> CeWorkParts {
    let delivery: Arc<dyn AuthMailDelivery> = Arc::new(Unused);
    let page = url::Url::parse("https://id.sid.example.com/account/verify").unwrap();
    let revocation = Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ));
    let codes = Arc::new(sid_authn::otp::OtpService::new(
        storage.clone(),
        sid_authn::otp::CodeDelivery { keys: keys() },
    ));
    let mail = CeMail {
        codes: Arc::new(CodeMail::new(codes, delivery.clone())),
        magic_links: links.then(|| {
            Arc::new(MagicLinkMail::new(
                Arc::new(sid_authn::magic_link::MagicLinkService::new(
                    storage.clone(),
                    keys(),
                )),
                page.clone(),
                delivery.clone(),
            ))
        }),
        resets: links.then(|| {
            Arc::new(ResetMail::new(
                Arc::new(sid_authn::password_reset::PasswordResetService::new(
                    storage.clone(),
                    keys(),
                )),
                page.clone(),
                delivery.clone(),
            ))
        }),
    };
    CeWorkParts {
        issuers: Arc::new(IssuerRegistry::new(storage.clone(), keys())),
        closures: Arc::new(AccountClosureService::new(
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
        issuer: "https://id.sid.example.com".into(),
        mail,
        audit_retention: AuditRetention::default(),
        migration_deadline_days: crate::maintenance::DEFAULT_MIGRATION_DEADLINE_DAYS,
        source: "test".into(),
        storage,
    }
}

fn kinds(work: &CeWork) -> BTreeSet<String> {
    work.handlers
        .iter()
        .map(|h| h.kind().as_str().to_owned())
        .collect()
}

/// Every kind of work a CE installation commits has its handler: an engine
/// started without one would leave that work owed forever. Sign-in and reset
/// links are owed only where they are enabled; codes always.
#[tokio::test]
async fn every_owed_kind_has_its_handler() {
    use sid_core::models::*;
    select_tls();
    let storage: Arc<dyn StorageBackend> = storage().await;
    let always = [
        LOGOUT_DELIVERY_KIND,
        event::EVENT_RELAY_KIND,
        event::EVENT_FANOUT_KIND,
        event::EVENT_DELIVERY_KIND,
        PRINCIPAL_CONTEST_CHECK_KIND,
        SESSION_REVOCATION_KIND,
        ENROLLMENT_ADMISSION_KIND,
        OWNER_PURGE_KIND,
        sid_authn::otp::OTP_EMAIL_KIND,
    ];
    let without = CeWork::assemble(parts(storage.clone(), false)).unwrap();
    assert_eq!(
        kinds(&without),
        always.iter().map(|k| k.to_string()).collect()
    );
    let with = CeWork::assemble(parts(storage, true)).unwrap();
    let mut all: BTreeSet<String> = always.iter().map(|k| k.to_string()).collect();
    all.insert(MAGIC_LINK_EMAIL_KIND.into());
    all.insert(PASSWORD_RESET_EMAIL_KIND.into());
    assert_eq!(kinds(&with), all);
    assert_eq!(with.handlers.len(), all.len(), "a kind has two handlers");
}

/// The maintenance is the CE maintenance with the purge of ended
/// authentication mail.
#[tokio::test]
async fn the_maintenance_purges_ended_mail() {
    select_tls();
    let work = CeWork::assemble(parts(storage().await, false)).unwrap();
    let names = work.maintenance.job_names();
    assert_eq!(names.last(), Some(&"authentication_mail_purge"));
    assert!(names.contains(&"principal_expiry"));
}
