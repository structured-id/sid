// SPDX-License-Identifier: AGPL-3.0-only
//! Delivery of the site's statements to the platform: owed with the change
//! that makes the held statements stale, made from the settings and the
//! certificate as they stand when the work runs.

use std::sync::Mutex;

use sid_core::models::{ClaimedWork, WorkId};
use sid_proto::sid::v1::admin::UpdateLoginSettingsRequest;

use super::*;
use crate::login_settings::LoginSettingsAdmin;
use crate::test_support::operation;

/// The platform: records what it is handed, answering `answer`.
struct Platform {
    published: Mutex<Vec<Vec<u8>>>,
    answer: fn() -> Result<Published, PublishError>,
}

impl Platform {
    fn answering(answer: fn() -> Result<Published, PublishError>) -> Arc<Self> {
        Arc::new(Self {
            published: Mutex::new(Vec::new()),
            answer,
        })
    }
}

#[async_trait::async_trait]
impl AdmissionPublisher for Platform {
    async fn publish(&self, statement: &[u8]) -> Result<Published, PublishError> {
        self.published.lock().unwrap().push(statement.to_vec());
        (self.answer)()
    }
}

/// The publication work owed now, claimed.
async fn owed(storage: &dyn StorageBackend) -> Vec<ClaimedWork> {
    storage
        .claim_work(
            &[WorkKind::new(SITE_ADMISSION_PUBLICATION_KIND).unwrap()],
            "test",
            100,
            Duration::from_secs(60),
        )
        .await
        .unwrap()
}

/// A claimed attempt the handler runs; it reads nothing from it.
fn attempt() -> ClaimedWork {
    ClaimedWork {
        id: WorkId::new(),
        kind: WorkKind::new(SITE_ADMISSION_PUBLICATION_KIND).unwrap(),
        payload: Vec::new(),
        attempt: 1,
        max_attempts: 5,
        generation: 1,
        expires_at: None,
        created_at: jiff::Timestamp::now(),
        due_at: jiff::Timestamp::now(),
    }
}

/// The handler of `i`'s site over `platform`.
fn handler(i: &Installed, platform: Option<Arc<Platform>>) -> AdmissionPublications {
    AdmissionPublications::new(
        Arc::new(FederationSite::new(
            i.storage.clone(),
            crate::test_support::keys(),
            i.recipient.clone(),
            i.organization,
        )),
        platform.map(|p| p as Arc<dyn AdmissionPublisher>),
    )
}

// Holding a certificate and every change of the login settings owe one
// publication each, committed with the change; a command that changes
// nothing owes none, and holding the same certificate again owes nothing
// new. Bug prevented: a settings change the platform never learns of (a
// closed switch or a removed source organization still offered there), or
// a delivery lost because it was not stored with the change.
#[tokio::test]
async fn changes_owe_their_publication() {
    let i = installed().await;
    let certificate = i
        .certificate(i.organization.into_uuid(), &[i.mount.as_str()])
        .await;
    i.site
        .hold(&i.admin, certificate.clone(), vec![])
        .await
        .unwrap();
    i.site.hold(&i.admin, certificate, vec![]).await.unwrap();
    assert_eq!(owed(i.storage.as_ref()).await.len(), 1, "the hold");

    let settings = LoginSettingsAdmin::new(i.storage.clone());
    let open = UpdateLoginSettingsRequest {
        allow_personal_profiles: Some(true),
        ..Default::default()
    };
    settings
        .update(
            &i.admin,
            operation(i.storage.as_ref(), "open").await,
            open.clone(),
        )
        .await
        .unwrap();
    assert_eq!(owed(i.storage.as_ref()).await.len(), 1, "the change");
    settings
        .update(&i.admin, operation(i.storage.as_ref(), "again").await, open)
        .await
        .unwrap();
    assert!(
        owed(i.storage.as_ref()).await.is_empty(),
        "a command changing nothing"
    );
}

// The work hands the platform the statement of every entry the certificate
// lists, made from the settings stored when it runs: a later change is in
// it even though an earlier one owed the work. A newer revision already
// standing there ends the work; a platform that is away retries it; a
// statement the platform refuses fails it. Bug prevented: a delivery of
// stale conditions, a superseded statement retried for two weeks, or an
// outage read as a final refusal that drops the delivery.
#[tokio::test]
async fn the_work_delivers_the_current_statements() {
    let i = installed().await;
    let platform = Platform::answering(|| Ok(Published::Held));
    // Not enrolled: nothing to state and nobody asked.
    assert!(matches!(
        handler(&i, Some(platform.clone())).handle(&attempt()).await,
        WorkOutcome::Done(_)
    ));
    assert!(platform.published.lock().unwrap().is_empty());

    let certificate = i
        .certificate(i.organization.into_uuid(), &[i.mount.as_str()])
        .await;
    i.site.hold(&i.admin, certificate, vec![]).await.unwrap();
    let settings = LoginSettings {
        allow_personal_profiles: true,
        revision: 3,
        ..LoginSettings::default()
    };
    assert!(
        i.storage
            .set_login_settings(
                &settings,
                None,
                AuditEntry::system("test", "settings").into()
            )
            .await
            .unwrap()
    );
    assert!(matches!(
        handler(&i, Some(platform.clone())).handle(&attempt()).await,
        WorkOutcome::Done(_)
    ));
    let published = platform.published.lock().unwrap().clone();
    assert_eq!(published.len(), 1, "one entry, one statement");
    let stated = i
        .recipient
        .accept_admission(&published[0], &StatusPolicy::default(), SystemTime::now())
        .await
        .unwrap()
        .admission;
    assert_eq!(stated.revision, 3);
    assert!(stated.allow_personal_profiles);
    assert_eq!(stated.mount, Mount::parse(&i.mount).unwrap());

    let superseded = Platform::answering(|| Ok(Published::Superseded));
    assert!(matches!(
        handler(&i, Some(superseded)).handle(&attempt()).await,
        WorkOutcome::Done(_)
    ));
    let away = Platform::answering(|| Err(PublishError::Unavailable("away".into())));
    assert!(matches!(
        handler(&i, Some(away)).handle(&attempt()).await,
        WorkOutcome::Retry(_)
    ));
    let refused = Platform::answering(|| Err(PublishError::Refused("forged".into())));
    assert!(matches!(
        handler(&i, Some(refused)).handle(&attempt()).await,
        WorkOutcome::Permanent(_)
    ));
    // A build that names no platform has nobody to tell.
    assert!(matches!(
        handler(&i, None).handle(&attempt()).await,
        WorkOutcome::Done(_)
    ));
}
