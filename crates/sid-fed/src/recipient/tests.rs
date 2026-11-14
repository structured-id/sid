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
/// `state`, publishing `crl`.
fn set(revision: u64, state: PlatformCaState, crl: Option<Vec<u8>>) -> PlatformCaSet {
    let now = SystemTime::now();
    PlatformCaSet {
        revision,
        generations: vec![PlatformCa {
            generation: 1,
            certificate: intermediate(),
            state,
            overlap_end: None,
            crl,
        }],
        issued_at: epoch(now) - 60,
        next_update: epoch(now) + 3600,
    }
}

async fn store() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

async fn recipient() -> Recipient {
    Recipient::new(store().await, ClassicalVerdict)
}

async fn accept(
    recipient: &Recipient,
    certificate: &[u8],
    chain: &[Vec<u8>],
) -> Result<Passport, RecipientError> {
    recipient
        .accept_passport(
            ContextAllocation::Development,
            certificate,
            chain,
            recipient_org(),
            SystemTime::now(),
        )
        .await
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
            .record_platform_cas(&set(1, PlatformCaState::Active, None))
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

/// Bug prevented: a Corporate passport accepted on its signatures alone.
/// Both authorities above it must be shown standing: the organization's
/// authority by the platform generation's list, and the passport by the
/// organization authority's list. Each missing list is evidence missing.
#[tokio::test]
async fn a_corporate_passport_needs_the_status_of_both_issuers() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    recipient
        .record_platform_cas(&set(1, PlatformCaState::Active, None))
        .await
        .unwrap();
    let refused = accept(&recipient, &corporate(), &chain).await.unwrap_err();
    assert!(matches!(
        refused,
        RecipientError::Status(StatusRefusal::Unavailable)
    ));
    assert!(refused.undecided());

    recipient
        .record_platform_cas(&set(
            2,
            PlatformCaState::Active,
            Some(platform_list(1, &[])),
        ))
        .await
        .unwrap();
    let refused = accept(&recipient, &corporate(), &chain).await.unwrap_err();
    assert!(matches!(refused, RecipientError::PassportStatusUnavailable));
    assert!(refused.undecided());

    record_organization_list(&recipient, &organization_list(1, &[]))
        .await
        .unwrap();
    assert_eq!(
        accept(&recipient, &corporate(), &chain).await.unwrap(),
        stated(Some(source()))
    );
}

/// Bug prevented: a passport still accepted after its organization's
/// authority was revoked by the platform. The authority's passports are
/// refused, a new one included, and so is a list it publishes.
#[tokio::test]
async fn a_revoked_organization_authority_takes_its_passports_along() {
    let recipient = recipient().await;
    recipient
        .record_platform_cas(&set(
            1,
            PlatformCaState::Active,
            Some(platform_list(1, &[ORGANIZATION_SERIAL])),
        ))
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
    recipient
        .record_platform_cas(&set(
            1,
            PlatformCaState::Active,
            Some(platform_list(1, &[])),
        ))
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
    recipient
        .record_platform_cas(&set(
            1,
            PlatformCaState::Active,
            Some(platform_list(1, &[])),
        ))
        .await
        .unwrap();
    let forged = StatedList::new(&format!("O={}", source()), &[3; 20], 9, &[]).signed(&key(HOLDER));
    assert!(matches!(
        record_organization_list(&recipient, &forged).await,
        Err(RecipientError::List(StatusError::Signature))
    ));
    assert!(matches!(
        accept(&recipient, &corporate(), &[organization_ca()]).await,
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
        .record_platform_cas(&set(1, PlatformCaState::Active, None))
        .await
        .unwrap();
    accept(&recipient, &personal(), &[]).await.unwrap();
    recipient
        .record_platform_cas(&set(2, PlatformCaState::Withdrawn, None))
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
            .record_platform_cas(&set(1, PlatformCaState::Active, None))
            .await
            .unwrap(),
        Applied::Stale
    );
    assert!(accept(&recipient, &personal(), &[]).await.is_err());
}

/// A set whose generation is no authority, or whose list is not that
/// generation's, is refused whole.
#[tokio::test]
async fn a_malformed_set_is_not_held() {
    let recipient = recipient().await;
    let mut leaf = set(1, PlatformCaState::Active, None);
    leaf.generations[0].certificate = personal();
    assert!(matches!(
        recipient.record_platform_cas(&leaf).await,
        Err(RecipientError::Invalid {
            field: "generations.certificate",
            ..
        })
    ));
    let foreign = set(1, PlatformCaState::Active, Some(organization_list(1, &[])));
    assert!(matches!(
        recipient.record_platform_cas(&foreign).await,
        Err(RecipientError::Invalid {
            field: "generations.crl",
            ..
        })
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
    recipient
        .record_platform_cas(&set(1, PlatformCaState::Active, None))
        .await
        .unwrap();
    let identities: &dyn PresentedIdentities = &recipient;
    let accept = |jws: Vec<u8>| async move {
        identities
            .accept_presentation(
                ContextAllocation::Development,
                &jws,
                &expected(),
                SystemTime::now(),
            )
            .await
    };
    let payload = statement(&personal(), &[], |_| {});
    assert_eq!(
        accept(presented(&payload, &key(HOLDER))).await.unwrap(),
        stated(None)
    );
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

/// The configured publication, as a test answers it.
struct Publication {
    answer: Result<PlatformCaSet, String>,
    asked: AtomicUsize,
}

#[async_trait::async_trait]
impl PlatformCaSource for Publication {
    async fn fetch(&self, _endpoint: &url::Url) -> Result<PlatformCaSet, String> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        self.answer.clone()
    }
}

/// An installation holding no set asks its configured publication on the
/// first request and accepts under what it published; without a configured
/// publication nothing is asked.
#[tokio::test]
async fn the_configured_publication_supplies_the_set() {
    let publication = Arc::new(Publication {
        answer: Ok(set(1, PlatformCaState::Active, None)),
        asked: AtomicUsize::new(0),
    });
    let recipient =
        Recipient::new(store().await, ClassicalVerdict).with_source(publication.clone());
    assert!(matches!(
        accept(&recipient, &personal(), &[]).await,
        Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
    ));
    assert_eq!(publication.asked.load(Ordering::Relaxed), 0);

    let endpoint =
        url::Url::parse("https://platform.sid.example.com/.well-known/sid-ca/index.json").unwrap();
    assert!(matches!(
        recipient
            .configure_publication(&url::Url::parse("http://platform.sid.example.com/").unwrap())
            .await,
        Err(RecipientError::Invalid {
            field: "publication",
            ..
        })
    ));
    assert!(recipient.configure_publication(&endpoint).await.unwrap());
    accept(&recipient, &personal(), &[]).await.unwrap();
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
    // The held set is current: the next request asks nothing.
    accept(&recipient, &personal(), &[]).await.unwrap();
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// Bug prevented: a failing publication asked on every request. After a
/// failure it is left alone for the backoff, and the held answer (none
/// here) decides.
#[tokio::test]
async fn a_failing_publication_is_not_asked_on_every_request() {
    let publication = Arc::new(Publication {
        answer: Err("unreachable".into()),
        asked: AtomicUsize::new(0),
    });
    let recipient =
        Recipient::new(store().await, ClassicalVerdict).with_source(publication.clone());
    let endpoint =
        url::Url::parse("https://platform.sid.example.com/.well-known/sid-ca/index.json").unwrap();
    recipient.configure_publication(&endpoint).await.unwrap();
    for _ in 0..3 {
        assert!(matches!(
            accept(&recipient, &personal(), &[]).await,
            Err(RecipientError::Platform(PlatformCaError::NotProvisioned))
        ));
    }
    assert_eq!(publication.asked.load(Ordering::Relaxed), 1);
}

/// The installation's own authority, as a test answers for it.
struct Own(Option<bool>);

#[async_trait::async_trait]
impl OwnIssuer for Own {
    async fn standing(
        &self,
        issuer: &[u8],
        serial: &[u8],
        now: i64,
    ) -> Result<Option<i64>, RecipientError> {
        assert_eq!(issuer, organization_ca());
        assert_eq!(serial, [PASSPORT_SERIAL as u8]);
        match self.0 {
            None => Ok(None),
            Some(true) => Ok(Some(now + 3600)),
            Some(false) => Err(RecipientError::PassportRevoked),
        }
    }
}

/// A passport of the installation's own authority is answered from its own
/// record, never from a published list; an authority that is not its own
/// falls to the held list.
#[tokio::test]
async fn an_own_authority_answers_for_its_passports() {
    let chain = [organization_ca()];
    let with = |own: Own| async {
        let recipient =
            Recipient::new(store().await, ClassicalVerdict).with_own_issuer(Arc::new(own));
        recipient
            .record_platform_cas(&set(
                1,
                PlatformCaState::Active,
                Some(platform_list(1, &[])),
            ))
            .await
            .unwrap();
        recipient
    };
    let standing = with(Own(Some(true))).await;
    assert_eq!(
        accept(&standing, &corporate(), &chain).await.unwrap(),
        stated(Some(source()))
    );
    let revoked = with(Own(Some(false))).await;
    assert!(matches!(
        accept(&revoked, &corporate(), &chain).await,
        Err(RecipientError::PassportRevoked)
    ));
    let foreign = with(Own(None)).await;
    assert!(matches!(
        accept(&foreign, &corporate(), &chain).await,
        Err(RecipientError::PassportStatusUnavailable)
    ));
}

/// The evidence a kept acceptance rests on bounds it: a day of certificate
/// validity is not reused past the hour its issuers' lists are evidence.
#[tokio::test]
async fn an_acceptance_is_kept_no_longer_than_its_status() {
    let recipient = recipient().await;
    let chain = [organization_ca()];
    recipient
        .record_platform_cas(&set(
            1,
            PlatformCaState::Active,
            Some(platform_list(1, &[])),
        ))
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
                    ContextAllocation::Development,
                    &corporate(),
                    chain,
                    recipient_org(),
                    SystemTime::now() + later,
                )
                .await
        }
    };
    at(Duration::ZERO).await.unwrap();
    // Past the set's refresh time the held set itself is no evidence.
    assert!(matches!(
        at(Duration::from_secs(2 * 3600)).await,
        Err(RecipientError::Platform(PlatformCaError::Stale))
    ));
}
