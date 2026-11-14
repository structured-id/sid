// SPDX-License-Identifier: AGPL-3.0-only
//! A recipient over a real store (SQLite, in memory): what it accepts under
//! the platform set it holds, and what the published status takes back.

use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use serde_json::json;
use sid_core::models::OfflineLimits;
use sid_plugin::platform_ca::PlatformCa;
use sid_storage::sqlite::SqliteBackend;

use super::*;
use crate::binding_passport::{AssuranceLevel, DEVELOPMENT_PASSPORT};
use crate::presentation::signing_input;
use crate::purpose::DEVELOPMENT_PURPOSES;
use crate::test_certificates::{
    Stated, StatedList, authority, current, key, key_id, name, permits, purposes, signs,
    signs_certificates,
};

const ROOT: u8 = 1;
const INTERMEDIATE: u8 = 2;
const ORGANIZATION: u8 = 3;
const HOLDER: u8 = 4;

const ROOT_NAME: &str = "CN=SID Root";
const INTERMEDIATE_NAME: &str = "CN=SID Platform Intermediate";

/// The serials the test certificates carry.
const ORGANIZATION_SERIAL: u32 = 3;
const PASSPORT_SERIAL: u32 = 9;

const CHALLENGE: &str = "nonce-of-the-pending-entry";
const DOMAIN: &str = "https://recipient.sid.example.com/auth/federation/callback";

fn source() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0a0a)
}

fn recipient_org() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0b0b)
}

fn binding() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_7c1e_7b2a_9d4e_3f5a_6b7c_8d9e)
}

/// The certificates of the tests, built once per process: a certificate is
/// named by its exact bytes (its issuer's status, an accepted path's key),
/// so every use of one must be the same certificate, not one built again a
/// second later with other validity times.
struct Chain {
    intermediate: Vec<u8>,
    organization_ca: Vec<u8>,
    personal: Vec<u8>,
    corporate: Vec<u8>,
}

fn chain() -> &'static Chain {
    static CHAIN: std::sync::OnceLock<Chain> = std::sync::OnceLock::new();
    CHAIN.get_or_init(|| Chain {
        intermediate: build_intermediate(),
        organization_ca: build_organization_ca(),
        personal: issued(&stated(None), INTERMEDIATE_NAME, INTERMEDIATE),
        corporate: issued(
            &stated(Some(source())),
            &format!("O={}", source()),
            ORGANIZATION,
        ),
    })
}

fn intermediate() -> Vec<u8> {
    chain().intermediate.clone()
}

fn organization_ca() -> Vec<u8> {
    chain().organization_ca.clone()
}

/// A Personal passport: issued by the platform intermediate itself.
fn personal() -> Vec<u8> {
    chain().personal.clone()
}

/// A Corporate passport: issued by the source organization's authority.
fn corporate() -> Vec<u8> {
    chain().corporate.clone()
}

/// The platform intermediate under the Root: it signs certificates and
/// revocation lists and names its key `[2; 20]`.
fn build_intermediate() -> Vec<u8> {
    Stated {
        subject: name(INTERMEDIATE_NAME),
        serial: 2,
        validity: current(),
        extensions: vec![
            authority(Some(1)),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.platform_intermediate]),
            key_id(&[2; 20]),
        ],
    }
    .signed(&key(INTERMEDIATE), &name(ROOT_NAME), &key(ROOT))
}

/// The authority of the source organization under the intermediate, naming
/// its key `[3; 20]`.
fn build_organization_ca() -> Vec<u8> {
    Stated {
        subject: name(&format!("O={}", source())),
        serial: ORGANIZATION_SERIAL,
        validity: current(),
        extensions: vec![
            authority(Some(0)),
            signs_certificates(),
            purposes(&[DEVELOPMENT_PURPOSES.organization_ca]),
            permits(&[&format!("O={}", source())], true),
            key_id(&[3; 20]),
        ],
    }
    .signed(
        &key(ORGANIZATION),
        &name(INTERMEDIATE_NAME),
        &key(INTERMEDIATE),
    )
}

fn stated(source_org: Option<Uuid>) -> Passport {
    Passport {
        binding_id: binding(),
        source_org,
        recipient_org: recipient_org(),
        merkle_root: [7; 32],
        instance_id: "instance.sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa2,
    }
}

fn issued(passport: &Passport, issuer: &str, issuer_key: u8) -> Vec<u8> {
    let mut extensions = vec![signs(), purposes(&[DEVELOPMENT_PASSPORT.key_usage])];
    extensions.extend(passport.extensions(&DEVELOPMENT_PASSPORT).unwrap());
    Stated {
        subject: passport.subject().unwrap(),
        serial: PASSPORT_SERIAL,
        validity: current(),
        extensions,
    }
    .signed(&key(HOLDER), &name(issuer), &key(issuer_key))
}

/// The intermediate's list `number`, revoking `serials`.
fn platform_list(number: u8, serials: &[u32]) -> Vec<u8> {
    StatedList::new(INTERMEDIATE_NAME, &[2; 20], number, serials).signed(&key(INTERMEDIATE))
}

/// The organization authority's list `number`, revoking `serials`.
fn organization_list(number: u8, serials: &[u32]) -> Vec<u8> {
    StatedList::new(&format!("O={}", source()), &[3; 20], number, serials)
        .signed(&key(ORGANIZATION))
}

fn epoch(at: SystemTime) -> i64 {
    at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// The platform's set at `revision`: the intermediate as generation 1 in
/// `state`. Its status is read apart: see [`hold`].
fn set(revision: u64, state: PlatformCaState) -> PlatformCaSet {
    let now = SystemTime::now();
    PlatformCaSet {
        revision,
        generations: vec![PlatformCa {
            generation: 1,
            certificate: intermediate(),
            state,
            overlap_end: None,
        }],
        issued_at: epoch(now) - 60,
        next_update: epoch(now) + 3600,
    }
}

/// Have `recipient` hold the set at `revision` in `state` and, read apart
/// from it as a recipient reads it, the generation's list `crl` when given.
async fn hold(
    recipient: &Recipient,
    revision: u64,
    state: PlatformCaState,
    crl: Option<Vec<u8>>,
) -> Result<(), RecipientError> {
    let set = set(revision, state);
    recipient.record_platform_cas(&set).await?;
    if let Some(crl) = crl {
        recipient
            .record_platform_ca_crl(&set.generations[0], &crl)
            .await?;
    }
    Ok(())
}

async fn store() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

async fn recipient() -> Recipient {
    Recipient::new(store().await, ClassicalVerdict)
}

/// Every absence of status permitted: for the tests whose subject is the
/// path, the anchors or the publication, not what is known of withdrawals.
const RELAXED: StatusPolicy = StatusPolicy {
    issuer: StatusRequirement::Offline(OfflineLimits::ANY),
    authorities: StatusRequirement::Offline(OfflineLimits::ANY),
};

/// A list in its time required of the passport's issuer and of every
/// authority above it.
const STRICT: StatusPolicy = StatusPolicy {
    issuer: StatusRequirement::Fresh,
    authorities: StatusRequirement::Fresh,
};

async fn accept_under(
    recipient: &Recipient,
    certificate: &[u8],
    chain: &[Vec<u8>],
    policy: &StatusPolicy,
) -> Result<Accepted, RecipientError> {
    recipient
        .accept_passport(
            certificate,
            chain,
            recipient_org(),
            policy,
            SystemTime::now(),
        )
        .await
}

/// The passport accepted with no status required: see [`RELAXED`].
async fn accept(
    recipient: &Recipient,
    certificate: &[u8],
    chain: &[Vec<u8>],
) -> Result<Passport, RecipientError> {
    accept_under(recipient, certificate, chain, &RELAXED)
        .await
        .map(|accepted| accepted.passport)
}

/// The passport accepted only on lists in their time: see [`STRICT`].
async fn accept_strict(
    recipient: &Recipient,
    certificate: &[u8],
    chain: &[Vec<u8>],
) -> Result<Passport, RecipientError> {
    accept_under(recipient, certificate, chain, &STRICT)
        .await
        .map(|accepted| accepted.passport)
}

async fn record_organization_list(recipient: &Recipient, crl: &[u8]) -> Result<(), RecipientError> {
    recipient
        .record_issuer_status(
            ContextAllocation::Development,
            source(),
            &organization_ca(),
            &[],
            crl,
            SystemTime::now(),
        )
        .await
}

/// Bug prevented: an installation that was never given the platform's set
/// accepting whatever chain it is shown. Without a held set nothing is
/// accepted, and that is evidence missing, not the identity refused.
#[tokio::test]
async fn nothing_is_accepted_without_a_held_set() {
    let recipient = recipient().await;
    let refused = accept(&recipient, &personal(), &[]).await.unwrap_err();
    assert!(matches!(
        refused,
        RecipientError::Platform(PlatformCaError::NotProvisioned)
    ));
    assert!(refused.undecided());
}

/// A Personal passport, issued by a platform intermediate the held set
/// admits, is accepted; and the recipient reads from its held anchors which
/// identifier allocation to verify under.
#[tokio::test]
async fn a_personal_passport_is_accepted_under_the_held_set() {
    let recipient = recipient().await;
    assert_eq!(
        recipient
            .record_platform_cas(&set(1, PlatformCaState::Active))
            .await
            .unwrap(),
        Applied::Current
    );
    assert_eq!(
        recipient
            .platform_allocation(SystemTime::now())
            .await
            .unwrap(),
        Some(ContextAllocation::Development)
    );
    let passport = accept(&recipient, &personal(), &[]).await.unwrap();
    assert_eq!(passport, stated(None));
    // The same passport again is answered from the accepted path.
    assert_eq!(
        accept(&recipient, &personal(), &[]).await.unwrap(),
        passport
    );
}

/// What a Corporate passport is accepted on is the installation's policy,
/// and each case has its own outcome.
///
/// The strict policy needs a list in its time from both issuers: the
/// platform generation's of the organization's authority, and that
/// authority's of the passport. Each missing list is evidence missing, not
/// a refusal. The default needs only the passport issuer's list and takes
/// the authorities above on what is held. The offline policy admits with
/// neither, and says so: the status is reported unknown, never fresh.
///
/// Bug prevented: a Corporate passport accepted on its signatures alone
/// when the installation requires status; an installation that cannot
/// reach the platform refusing everyone although its policy permits it;
/// unknown status reported as shown good.
#[tokio::test]
async fn a_corporate_passport_is_accepted_as_the_policy_says() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    let default = StatusPolicy::default();
    hold(&recipient, 1, PlatformCaState::Active, None)
        .await
        .unwrap();

    // Nothing held of either issuer.
    let refused = accept_strict(&recipient, &corporate(), &chain)
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        RecipientError::Status(StatusRefusal::Unavailable)
    ));
    assert!(refused.undecided());
    let refused = accept_under(&recipient, &corporate(), &chain, &default)
        .await
        .unwrap_err();
    assert!(matches!(refused, RecipientError::PassportStatusUnavailable));
    assert!(refused.undecided());
    let offline = accept_under(&recipient, &corporate(), &chain, &RELAXED)
        .await
        .unwrap();
    assert_eq!(offline.passport, stated(Some(source())));
    assert_eq!(offline.issuer, StatusEvidence::Unknown);
    assert_eq!(offline.authorities, Some(StatusEvidence::Unknown));

    // An offline policy that does not permit a missing list admits nothing
    // on one: nothing is permitted by not being mentioned.
    let stale_only = StatusPolicy {
        issuer: StatusRequirement::Offline(OfflineLimits {
            missing: false,
            max_stale: None,
        }),
        authorities: RELAXED.authorities,
    };
    assert!(matches!(
        accept_under(&recipient, &corporate(), &chain, &stale_only).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));

    // The platform's list arrives: the organization's authority stands.
    hold(
        &recipient,
        2,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let refused = accept_strict(&recipient, &corporate(), &chain)
        .await
        .unwrap_err();
    assert!(matches!(refused, RecipientError::PassportStatusUnavailable));
    assert!(refused.undecided());

    // The organization's list arrives: every policy accepts, as fresh.
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    for policy in [&STRICT, &default, &RELAXED, &stale_only] {
        let accepted = accept_under(&recipient, &corporate(), &chain, policy)
            .await
            .unwrap();
        assert_eq!(accepted.passport, stated(Some(source())));
        assert_eq!(accepted.issuer, StatusEvidence::Fresh);
        assert_eq!(accepted.authorities, Some(StatusEvidence::Fresh));
    }
}

/// A correctly signed list issued later than now is not yet its issuer's
/// status: it is refused, nothing is held, and the passport stays
/// undecided. Bug prevented: a list from an issuer whose clock runs ahead
/// counted as fresh, and by its higher number kept the current list out.
#[tokio::test]
async fn a_list_issued_in_the_future_is_not_held() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let mut early = StatedList::new(&format!("O={}", source()), &[3; 20], 5, &[]);
    early.this_update = SystemTime::now() + Duration::from_secs(600);
    let refused = record_organization_list(&recipient, &early.signed(&key(ORGANIZATION))).await;
    assert!(
        matches!(refused, Err(RecipientError::Invalid { field: "crl", .. })),
        "{refused:?}"
    );
    assert!(matches!(
        accept_strict(&recipient, &corporate(), &chain).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
    // The current list is still taken after it.
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    accept_strict(&recipient, &corporate(), &chain)
        .await
        .unwrap();
}

/// What an organization's installation publishes: its CA generations and,
/// served apart, generation 1's list.
#[derive(Clone)]
struct OrganizationPublished {
    set: PlatformCaSet,
    crl: Vec<u8>,
}

/// An issuing organization's publication as a test serves it: one answer,
/// and how often it was read (the set and its list together count once).
struct Published {
    answer: std::sync::Mutex<Result<Option<OrganizationPublished>, String>>,
    reads: AtomicUsize,
}

impl Published {
    fn of(answer: Result<Option<OrganizationPublished>, String>) -> Arc<Self> {
        Arc::new(Self {
            answer: std::sync::Mutex::new(answer),
            reads: AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl OrganizationPublications for Published {
    async fn fetch(&self, organization: Uuid) -> Result<Option<PlatformCaSet>, String> {
        assert_eq!(organization, source(), "the passport's own organization");
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.answer
            .lock()
            .unwrap()
            .clone()
            .map(|published| published.map(|p| p.set))
    }

    async fn crl(&self, organization: Uuid, generation: u32) -> Result<Option<Vec<u8>>, String> {
        assert_eq!(organization, source(), "the passport's own organization");
        assert_eq!(generation, 1, "the generation that issued the passport");
        self.answer
            .lock()
            .unwrap()
            .clone()
            .map(|published| published.map(|p| p.crl))
    }
}

/// The organization's publication: its authority as generation 1, and
/// that generation's list `crl` served apart.
fn organization_publication(crl: Vec<u8>) -> OrganizationPublished {
    let now = epoch(SystemTime::now());
    OrganizationPublished {
        set: PlatformCaSet {
            revision: 1,
            generations: vec![PlatformCa {
                generation: 1,
                certificate: organization_ca(),
                state: PlatformCaState::Active,
                overlap_end: None,
            }],
            issued_at: now,
            next_update: now + 3600,
        },
        crl,
    }
}

/// An offline allowance does not stop a reachable list from being read: a
/// recipient whose policy admits missing issuer status still reads the
/// organization's publication when it holds no current list, and the list
/// revoking the passport refuses it. Bug prevented: a recipient under an
/// offline policy admitting a revoked passport indefinitely because it never
/// looked at a list it could read.
#[tokio::test]
async fn an_offline_policy_still_reads_a_reachable_list() {
    let chain = [organization_ca()];
    let offline = StatusPolicy {
        issuer: StatusRequirement::Offline(OfflineLimits::ANY),
        authorities: StatusRequirement::Offline(OfflineLimits::ANY),
    };
    let revoking = Published::of(Ok(Some(organization_publication(organization_list(
        1,
        &[PASSPORT_SERIAL],
    )))));
    let recipient = recipient()
        .await
        .with_organization_publications(revoking.clone());
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    assert!(matches!(
        accept_under(&recipient, &corporate(), &chain, &offline).await,
        Err(RecipientError::PassportRevoked)
    ));
    assert_eq!(revoking.reads(), 1);
}

/// A Corporate passport whose organization's list is not held is decided
/// on the list the organization publishes now, read where the installation
/// knows its publication: a list without the passport admits it as fresh
/// and is held from then on, one revoking it refuses it. Where no
/// publication is known, or reading it fails, the passport stays undecided,
/// and a failing publication is not read again at once. Bug prevented: the
/// default policy never admitting another organization's employee, because
/// nothing ever brought that organization's list to the recipient.
#[tokio::test]
async fn an_organizations_list_is_read_from_its_publication() {
    let chain = [organization_ca()];
    let with = |published: Arc<Published>| async move {
        let recipient = recipient().await.with_organization_publications(published);
        hold(
            &recipient,
            1,
            PlatformCaState::Active,
            Some(platform_list(1, &[])),
        )
        .await
        .unwrap();
        recipient
    };

    let published = Published::of(Ok(Some(organization_publication(organization_list(
        1,
        &[],
    )))));
    let recipient = with(published.clone()).await;
    let accepted = accept_under(&recipient, &corporate(), &chain, &STRICT)
        .await
        .unwrap();
    assert_eq!(accepted.issuer, StatusEvidence::Fresh);
    // Held now: the next sign-in reads nothing.
    accept_strict(&recipient, &corporate(), &chain)
        .await
        .unwrap();
    assert_eq!(published.reads(), 1);

    let revoking = Published::of(Ok(Some(organization_publication(organization_list(
        2,
        &[PASSPORT_SERIAL],
    )))));
    let recipient = with(revoking).await;
    assert!(matches!(
        accept_strict(&recipient, &corporate(), &chain).await,
        Err(RecipientError::PassportRevoked)
    ));

    let unknown = Published::of(Ok(None));
    let recipient = with(unknown).await;
    assert!(matches!(
        accept_strict(&recipient, &corporate(), &chain).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));

    let failing = Published::of(Err("unreachable".into()));
    let recipient = with(failing.clone()).await;
    for _ in 0..2 {
        assert!(matches!(
            accept_strict(&recipient, &corporate(), &chain).await,
            Err(RecipientError::PassportStatusUnavailable)
        ));
    }
    assert_eq!(
        failing.reads(),
        1,
        "a failing publication is not read at once again"
    );
}

/// A Personal passport is issued by the platform generation itself, so its
/// status is that generation's list. The default asks for it in its time;
/// without one the passport is not decided, and the offline policy admits
/// it as unknown. A passport the generation withdrew is refused under every
/// policy. Bug prevented: a withdrawn Personal passport signing in because
/// only Corporate passports were ever checked against a list.
#[tokio::test]
async fn a_personal_passport_stands_by_its_generations_list() {
    let recipient = recipient().await;
    let default = StatusPolicy::default();
    hold(&recipient, 1, PlatformCaState::Active, None)
        .await
        .unwrap();
    let undecided = accept_under(&recipient, &personal(), &[], &default)
        .await
        .unwrap_err();
    assert!(matches!(
        undecided,
        RecipientError::PassportStatusUnavailable
    ));
    assert!(undecided.undecided());
    let offline = accept_under(&recipient, &personal(), &[], &RELAXED)
        .await
        .unwrap();
    assert_eq!(offline.issuer, StatusEvidence::Unknown);

    hold(
        &recipient,
        2,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let fresh = accept_under(&recipient, &personal(), &[], &default)
        .await
        .unwrap();
    assert_eq!(fresh.passport, stated(None));
    assert_eq!(fresh.issuer, StatusEvidence::Fresh);

    // The generation withdraws the passport.
    hold(
        &recipient,
        3,
        PlatformCaState::Active,
        Some(platform_list(2, &[PASSPORT_SERIAL])),
    )
    .await
    .unwrap();
    for policy in [&STRICT, &default, &RELAXED] {
        let refused = accept_under(&recipient, &personal(), &[], policy)
            .await
            .unwrap_err();
        assert!(matches!(refused, RecipientError::PassportRevoked));
        assert!(!refused.undecided());
    }
}

/// A list past its time is no evidence under the strict requirement, and
/// under the offline one it admits only within the age the policy names:
/// stale, never fresh. What it revoked stays revoked at any age.
#[tokio::test]
async fn an_expired_list_admits_only_within_the_policys_age() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    // The fixture's lists are evidence for an hour; this is two hours on,
    // and the certificates are valid for a day.
    let later = SystemTime::now() + Duration::from_secs(2 * 3600);
    let at = |policy: StatusPolicy| {
        let (recipient, chain) = (&recipient, &chain);
        async move {
            recipient
                .accept_passport(&corporate(), chain, recipient_org(), &policy, later)
                .await
        }
    };
    let aged = |max_stale| StatusPolicy {
        issuer: StatusRequirement::Offline(OfflineLimits {
            missing: false,
            max_stale,
        }),
        authorities: RELAXED.authorities,
    };
    assert!(matches!(
        at(StatusPolicy::default()).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
    // Stale by about an hour: within a day's limit, beyond a minute's.
    let stale = at(aged(Some(86_400))).await.unwrap();
    assert_eq!(stale.issuer, StatusEvidence::Stale);
    assert_eq!(stale.authorities, Some(StatusEvidence::Stale));
    assert_eq!(at(aged(None)).await.unwrap().issuer, StatusEvidence::Stale);
    assert!(matches!(
        at(aged(Some(60))).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
}

/// The platform's set past its refresh time still anchors under a policy
/// that takes the authorities on what is held, and is not decided on under
/// one that requires a current set. Bug prevented: the certificates an
/// installation was shipped with ceasing to verify an hour after its last
/// contact with the platform.
#[tokio::test]
async fn a_set_past_its_refresh_time_anchors_by_policy() {
    let recipient = recipient().await;
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let later = SystemTime::now() + Duration::from_secs(2 * 3600);
    let at = |policy: StatusPolicy| {
        let recipient = &recipient;
        async move {
            recipient
                .accept_passport(&personal(), &[], recipient_org(), &policy, later)
                .await
        }
    };
    let offline = at(RELAXED).await.unwrap();
    assert_eq!(offline.passport, stated(None));
    assert_eq!(offline.authorities, Some(StatusEvidence::Stale));
    let strict = at(STRICT).await.unwrap_err();
    assert!(matches!(strict, RecipientError::PlatformSetStale));
    assert!(strict.undecided());
}

/// Bug prevented: a passport still accepted after its organization's
/// authority was revoked by the platform. The authority's passports are
/// refused, a new one included, and so is a list it publishes.
#[tokio::test]
async fn a_revoked_organization_authority_takes_its_passports_along() {
    let recipient = recipient().await;
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[ORGANIZATION_SERIAL])),
    )
    .await
    .unwrap();
    let refused = accept(&recipient, &corporate(), &[organization_ca()])
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        RecipientError::Status(StatusRefusal::Revoked)
    ));
    assert!(!refused.undecided());
    assert!(matches!(
        record_organization_list(&recipient, &organization_list(1, &[])).await,
        Err(RecipientError::Status(StatusRefusal::Revoked))
    ));
}

/// Bug prevented: an accepted path reused after its passport was revoked.
/// New status drops what was accepted before, and the revocation stays when
/// an older list without it is shown again.
#[tokio::test]
async fn a_revoked_passport_is_refused_though_accepted_before() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    accept(&recipient, &corporate(), &chain).await.unwrap();

    record_organization_list(&recipient, &organization_list(2, &[PASSPORT_SERIAL]))
        .await
        .unwrap();
    let refused = accept(&recipient, &corporate(), &chain).await.unwrap_err();
    assert!(matches!(refused, RecipientError::PassportRevoked));
    assert!(!refused.undecided());

    // The older list replayed brings nothing back.
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    assert!(matches!(
        accept(&recipient, &corporate(), &chain).await,
        Err(RecipientError::PassportRevoked)
    ));
}

/// Bug prevented: a list accepted for where it came from. One signed with
/// another key than the organization authority's is not recorded.
#[tokio::test]
async fn a_list_of_another_key_is_not_recorded() {
    let recipient = recipient().await;
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let forged = StatedList::new(&format!("O={}", source()), &[3; 20], 9, &[]).signed(&key(HOLDER));
    assert!(matches!(
        record_organization_list(&recipient, &forged).await,
        Err(RecipientError::List(StatusError::Signature))
    ));
    // Nothing was taken from it: no status of the passport is held.
    assert!(matches!(
        accept_strict(&recipient, &corporate(), &[organization_ca()]).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
}

/// Bug prevented: a path accepted before a platform generation was
/// withdrawn staying accepted. A newer set that withdraws the generation
/// leaves no anchor, in this process at once.
#[tokio::test]
async fn a_withdrawn_generation_anchors_nothing() {
    let recipient = recipient().await;
    recipient
        .record_platform_cas(&set(1, PlatformCaState::Active))
        .await
        .unwrap();
    accept(&recipient, &personal(), &[]).await.unwrap();
    recipient
        .record_platform_cas(&set(2, PlatformCaState::Withdrawn))
        .await
        .unwrap();
    assert!(matches!(
        accept(&recipient, &personal(), &[]).await,
        Err(RecipientError::Path(PathError::NoAnchor))
    ));
    assert_eq!(
        recipient
            .platform_allocation(SystemTime::now())
            .await
            .unwrap(),
        None
    );
    // An older set listing it active again changes nothing.
    assert_eq!(
        recipient
            .record_platform_cas(&set(1, PlatformCaState::Active))
            .await
            .unwrap(),
        Applied::Stale
    );
    assert!(accept(&recipient, &personal(), &[]).await.is_err());
}

/// A set whose generation is no authority is refused whole, and a list that
/// is not that generation's is not recorded as its status.
#[tokio::test]
async fn a_malformed_set_is_not_held() {
    let recipient = recipient().await;
    let mut leaf = set(1, PlatformCaState::Active);
    leaf.generations[0].certificate = personal();
    assert!(matches!(
        recipient.record_platform_cas(&leaf).await,
        Err(RecipientError::Invalid {
            field: "generations.certificate",
            ..
        })
    ));
    let generation = &set(1, PlatformCaState::Active).generations[0];
    assert!(matches!(
        recipient
            .record_platform_ca_crl(generation, &organization_list(1, &[]))
            .await,
        Err(RecipientError::Invalid { field: "crl", .. })
    ));
    assert!(matches!(
        accept(&recipient, &personal(), &[]).await,
        Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
    ));
}

/// The statement the holder signs for the pending entry, presenting
/// `certificate` with `chain`, after `edit`.
fn statement(
    certificate: &[u8],
    chain: &[Vec<u8>],
    edit: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let holder = format!("did:sid:{}", binding());
    let x5c: Vec<String> = std::iter::once(certificate)
        .chain(chain.iter().map(Vec::as_slice))
        .map(|der| STANDARD.encode(der))
        .collect();
    let mut value = json!({
        "type": "SIDBindingPresentation",
        "version": 1,
        "purpose": "authentication",
        "recipient_org": recipient_org().to_string(),
        "created": epoch(SystemTime::now()),
        "challenge": CHALLENGE,
        "domain": DOMAIN,
        "holder": holder,
        "credential": {
            "subject": holder,
            "disclosed_fields": {},
            "attestations": {},
            "merkle_root": format!("0x{}", hex::encode([7u8; 32])),
            "proof": { "type": "X509CertificateChain", "x5c": x5c }
        }
    });
    edit(&mut value);
    value.to_string().into_bytes()
}

/// The presentation of `payload` with the ES256 proof of `signer`.
fn presented(payload: &[u8], signer: &SigningKey) -> Vec<u8> {
    let protected =
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"sid-binding-presentation+jws"}"#);
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    let signature: p256::ecdsa::Signature = signer.sign(&signing_input(&protected, &encoded));
    json!({
        "payload": encoded,
        "signatures": [{
            "protected": protected,
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }]
    })
    .to_string()
    .into_bytes()
}

fn expected() -> Expected<'static> {
    Expected {
        recipient: recipient_org(),
        challenge: CHALLENGE,
        domain: DOMAIN,
    }
}

/// Bug prevented: a copied passport signing someone in. The presentation
/// is accepted only signed by the passport's holder, for this pending
/// request, on a passport the recipient accepts. Asked through the trait a
/// service holds it by.
#[tokio::test]
async fn a_presentation_answers_one_pending_request() {
    let recipient = recipient().await;
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let identities: &dyn PresentedIdentities = &recipient;
    let accept = |jws: Vec<u8>| async move {
        identities
            .accept_presentation(
                &jws,
                &expected(),
                &StatusPolicy::default(),
                SystemTime::now(),
            )
            .await
    };
    let payload = statement(&personal(), &[], |_| {});
    let accepted = accept(presented(&payload, &key(HOLDER))).await.unwrap();
    assert_eq!(accepted.passport, stated(None));
    assert_eq!(accepted.issuer, StatusEvidence::Fresh);
    // Signed by another key than the passport certifies.
    assert!(matches!(
        accept(presented(&payload, &key(ORGANIZATION))).await,
        Err(RecipientError::Presentation(PresentationError::Signature))
    ));
    // The holder's answer to another request.
    let other = statement(&personal(), &[], |s| {
        s["challenge"] = json!("another-entry")
    });
    assert!(matches!(
        accept(presented(&other, &key(HOLDER))).await,
        Err(RecipientError::Presentation(PresentationError::Context(
            "request"
        )))
    ));
    // A Corporate passport whose issuers' status is not held is not decided,
    // whoever signed.
    let corporate = statement(&corporate(), &[organization_ca()], |_| {});
    let undecided = accept(presented(&corporate, &key(HOLDER)))
        .await
        .unwrap_err();
    assert!(undecided.undecided());
}

/// The configured publication, as a test answers it: the set, and generation
/// 1's list read apart, revoking nothing.
struct Publication {
    answer: Result<PlatformCaSet, String>,
    asked: AtomicUsize,
}

impl Publication {
    fn of(answer: Result<PlatformCaSet, String>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            asked: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl PlatformCaSource for Publication {
    async fn fetch(&self, _endpoint: &url::Url) -> Result<PlatformCaSet, String> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        self.answer.clone()
    }

    async fn crl(&self, _endpoint: &url::Url, generation: u32) -> Result<Vec<u8>, String> {
        assert_eq!(generation, 1, "only a published generation's list is read");
        Ok(platform_list(1, &[]))
    }
}

const PUBLICATION: &str = "https://platform.sid.example.com/.well-known/sid-ca/index.json";

/// A recipient over a fresh store that refreshes from `publication`.
async fn sourced(publication: &Arc<Publication>) -> Recipient {
    Recipient::new(store().await, ClassicalVerdict)
        .with_source(PUBLICATION.parse().unwrap(), publication.clone())
        .unwrap()
}

/// An installation holding no set asks the platform's publication on the
/// first request and accepts under what it published, with the
/// generation's list read apart from the set: a Personal passport is then
/// decided on fresh status. One composed without a publication asks nothing
/// and decides on what it holds alone, and a publication that is not
/// `https` is not taken.
#[tokio::test]
async fn the_platforms_publication_supplies_the_set() {
    let publication = Publication::of(Ok(set(1, PlatformCaState::Active)));
    let alone = recipient().await;
    assert!(matches!(
        accept(&alone, &personal(), &[]).await,
        Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
    ));
    // What it holds decides, with nothing to refresh from.
    alone
        .record_platform_cas(&set(1, PlatformCaState::Active))
        .await
        .unwrap();
    accept(&alone, &personal(), &[]).await.unwrap();
    assert!(matches!(
        Recipient::new(store().await, ClassicalVerdict).with_source(
            "http://platform.sid.example.com/".parse().unwrap(),
            publication.clone()
        ),
        Err(RecipientError::Invalid {
            field: "publication",
            ..
        })
    ));
    assert_eq!(publication.asked.load(Ordering::Relaxed), 0);

    let recipient = sourced(&publication).await;
    let fresh = accept_under(&recipient, &personal(), &[], &StatusPolicy::default())
        .await
        .unwrap();
    assert_eq!(fresh.issuer, StatusEvidence::Fresh);
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
    // The held set is current: the next request asks nothing.
    accept(&recipient, &personal(), &[]).await.unwrap();
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// Halfway through the held set's freshness the publication is asked for a
/// newer set, and the newer set is what is held after it: a withdrawal it
/// states takes the generation out. Bug prevented: a set relied on to its
/// last second while the platform had already withdrawn a generation.
#[tokio::test]
async fn a_set_halfway_through_its_freshness_is_renewed() {
    let publication = Publication::of(Ok(set(2, PlatformCaState::Withdrawn)));
    let recipient = sourced(&publication).await;
    // Issued 2000 s ago and current for an hour: past its halfway point.
    let mut aged = set(1, PlatformCaState::Active);
    aged.issued_at = epoch(SystemTime::now()) - 2_000;
    aged.next_update = aged.issued_at + 3_600;
    recipient.record_platform_cas(&aged).await.unwrap();
    assert!(matches!(
        accept(&recipient, &personal(), &[]).await,
        Err(RecipientError::Path(PathError::NoAnchor))
    ));
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// What the publication states is held only if it states a set: a
/// generation that is no CA certificate is refused whole and nothing is
/// anchored.
#[tokio::test]
async fn a_publication_that_states_no_set_is_not_held() {
    let mut stated = set(1, PlatformCaState::Active);
    stated.generations[0].certificate = vec![0x30, 0x00];
    let publication = Publication::of(Ok(stated));
    let recipient = sourced(&publication).await;
    assert!(matches!(
        accept(&recipient, &personal(), &[]).await,
        Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
    ));
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// Bug prevented: a failing publication asked on every request. After a
/// failure it is left alone for the backoff, and the held answer (none
/// here) decides.
#[tokio::test]
async fn a_failing_publication_is_not_asked_on_every_request() {
    let publication = Publication::of(Err("unreachable".into()));
    let recipient = sourced(&publication).await;
    for _ in 0..3 {
        assert!(matches!(
            accept(&recipient, &personal(), &[]).await,
            Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
        ));
    }
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// The installation's own authority, as a test answers for it: the
/// certificates installed here, and whether its record shows the passport
/// standing.
struct Own {
    installed: Vec<Vec<u8>>,
    stands: bool,
}

#[async_trait::async_trait]
impl OwnIssuer for Own {
    fn organization(&self) -> Uuid {
        source()
    }

    async fn authorities(&self) -> Result<Vec<Vec<u8>>, RecipientError> {
        Ok(self.installed.clone())
    }

    async fn standing(
        &self,
        issuer: &[u8],
        serial: &[u8],
        now: i64,
    ) -> Result<Option<i64>, RecipientError> {
        assert_eq!(issuer, organization_ca());
        assert_eq!(serial, [PASSPORT_SERIAL as u8]);
        if self.stands {
            Ok(Some(now + 3600))
        } else {
            Err(RecipientError::PassportRevoked)
        }
    }
}

/// An organization accepts a passport it issued from its own installed
/// authority and its own record, with nothing else: the store holds no
/// platform set, no list was ever published or fetched, and the strictest
/// policy changes nothing, because none of it is consulted. A passport its
/// record withdrew is refused all the same.
///
/// The own path is chosen by the certificates installed here. A passport
/// whose issuer is not one of them goes the platform's way (and with no
/// platform set is not decided), and one that names the installed
/// authority without that authority's signature is refused.
///
/// Bug prevented: an installation cut off from the platform unable to sign
/// its own people in; a withdrawn own passport passing because its issuer
/// is local; a stranger's certificate accepted as the installation's own.
#[tokio::test]
async fn an_organization_accepts_its_own_passport_offline() {
    let chain = [organization_ca()];
    let with = |installed: Vec<Vec<u8>>, stands: bool| async move {
        Recipient::new(store().await, ClassicalVerdict)
            .with_own_issuer(Arc::new(Own { installed, stands }))
    };
    let own = with(vec![organization_ca()], true).await;
    for policy in [&STRICT, &StatusPolicy::default(), &RELAXED] {
        let accepted = accept_under(&own, &corporate(), &chain, policy)
            .await
            .unwrap();
        assert_eq!(accepted.passport, stated(Some(source())));
        assert_eq!(accepted.issuer, StatusEvidence::Fresh);
        // Nothing above its own authority was relied on.
        assert_eq!(accepted.authorities, None);
    }

    let withdrawn = with(vec![organization_ca()], false).await;
    let refused = accept_under(&withdrawn, &corporate(), &chain, &RELAXED)
        .await
        .unwrap_err();
    assert!(matches!(refused, RecipientError::PassportRevoked));
    assert!(!refused.undecided());

    // The issuer presented is not installed here: the platform's way.
    let elsewhere = with(vec![intermediate()], true).await;
    assert!(matches!(
        accept_under(&elsewhere, &corporate(), &chain, &RELAXED).await,
        Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
    ));

    // Names the installed authority as its issuer, signed by another key.
    let forged = issued(&stated(Some(source())), &format!("O={}", source()), HOLDER);
    assert!(matches!(
        accept_under(&own, &forged, &chain, &RELAXED).await,
        Err(RecipientError::Path(_))
    ));
}

/// The evidence a kept acceptance rests on bounds it: a day of certificate
/// validity is not reused past the hour its issuer's list is evidence. Bug
/// prevented: a passport accepted once answered from the kept result after
/// the list it rested on ran out.
#[tokio::test]
async fn an_acceptance_is_kept_no_longer_than_its_status() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    hold(
        &recipient,
        1,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    let at = |later: Duration| {
        let recipient = &recipient;
        let chain = &chain;
        async move {
            recipient
                .accept_passport(
                    &corporate(),
                    chain,
                    recipient_org(),
                    &StatusPolicy::default(),
                    SystemTime::now() + later,
                )
                .await
        }
    };
    at(Duration::ZERO).await.unwrap();
    // Two hours on the organization's list is past its time.
    assert!(matches!(
        at(Duration::from_secs(2 * 3600)).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
}

const SITE: u8 = 5;
const SITE_SERIAL: u32 = 11;
const MOUNT: &str = "https://hosted.sid.example.com/i/0123456789abcdef0123456789abcdef";

fn site() -> Uuid {
    Uuid::from_u128(0x0192_f3a4_0000_7000_8000_0000_0000_0c0c)
}

/// The participant certificate of the recipient organization's site, under
/// the platform intermediate.
fn enrolled() -> Vec<u8> {
    use der::oid::AssociatedOid;
    use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};
    let mounts = [crate::participant::Mount::parse(MOUNT).unwrap()];
    Stated {
        subject: crate::participant::participant_subject(recipient_org(), site()).unwrap(),
        serial: SITE_SERIAL,
        validity: crate::test_certificates::current(),
        extensions: vec![
            crate::test_certificates::extension(
                BasicConstraints::OID,
                true,
                &BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                },
            ),
            signs(),
            purposes(&[DEVELOPMENT_PURPOSES.federation_participant]),
            crate::test_certificates::extension(
                SubjectAltName::OID,
                false,
                &crate::participant::mounts_name(&mounts).unwrap(),
            ),
        ],
    }
    .signed(&key(SITE), &name(INTERMEDIATE_NAME), &key(INTERMEDIATE))
}

/// The site's statement admitting the source organization, signed by the
/// key of `seed`.
fn admission_by(seed: u8) -> Vec<u8> {
    let now = epoch(SystemTime::now());
    let admission = Admission {
        recipient_org: recipient_org(),
        site: site(),
        mount: crate::participant::Mount::parse(MOUNT).unwrap(),
        revision: 4,
        allow_personal_profiles: false,
        allow_foreign_corporate_profiles: true,
        admitted_sources: vec![source()],
        not_before: now - 60,
        not_after: now + 3600,
        certificate: enrolled(),
        chain: vec![],
    };
    let signer: SigningKey = key(seed);
    crate::admission::sealed(&admission.payload(), |input| {
        let signature: p256::ecdsa::Signature = signer.sign(input);
        Ok::<_, std::convert::Infallible>(signature.to_bytes().into())
    })
    .unwrap()
}

/// An enrolled site and its statement are accepted under the held set as
/// the policy says of withdrawals: undecided without the generation's list
/// under the default policy, accepted under it once the list is held or
/// under a policy that asks for none, and refused under every policy once
/// the generation withdrew the site's certificate. A statement another key
/// signed is refused whatever is held. Bug prevented: a site whose
/// enrollment the platform withdrew still naming where people are sent, or
/// a statement taken on the certificate alone without the site's signature.
#[tokio::test]
async fn an_enrolled_site_stands_by_its_generations_list() {
    let recipient = recipient().await;
    let default = StatusPolicy::default();
    let now = SystemTime::now;
    hold(&recipient, 1, PlatformCaState::Active, None)
        .await
        .unwrap();
    let undecided = recipient
        .accept_participant(&enrolled(), &[], &default, now())
        .await
        .unwrap_err();
    assert!(matches!(
        undecided,
        RecipientError::Status(StatusRefusal::Unavailable)
    ));
    assert!(undecided.undecided());
    let offline = recipient
        .accept_participant(&enrolled(), &[], &RELAXED, now())
        .await
        .unwrap();
    assert_eq!(offline.participant.organization, recipient_org());
    assert_eq!(offline.participant.site, site());

    hold(
        &recipient,
        2,
        PlatformCaState::Active,
        Some(platform_list(1, &[])),
    )
    .await
    .unwrap();
    let verified = recipient
        .accept_admission(&admission_by(SITE), &default, now())
        .await
        .unwrap();
    assert!(verified.admission.admits_source(source()));
    assert!(!verified.admission.admits_source(recipient_org()));
    assert_eq!(verified.participant.participant.site, site());
    let forged = recipient
        .accept_admission(&admission_by(HOLDER), &default, now())
        .await
        .unwrap_err();
    assert!(matches!(
        forged,
        RecipientError::Admission(crate::admission::AdmissionError::Envelope(
            PresentationError::Signature
        ))
    ));
    assert!(!forged.undecided());

    // The generation withdraws the site's certificate.
    hold(
        &recipient,
        3,
        PlatformCaState::Active,
        Some(platform_list(2, &[SITE_SERIAL])),
    )
    .await
    .unwrap();
    for policy in [&STRICT, &default, &RELAXED] {
        let refused = recipient
            .accept_admission(&admission_by(SITE), policy, now())
            .await
            .unwrap_err();
        assert!(matches!(
            refused,
            RecipientError::Status(StatusRefusal::Revoked)
        ));
        assert!(!refused.undecided());
    }
}
