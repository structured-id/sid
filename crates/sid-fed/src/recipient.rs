// SPDX-License-Identifier: AGPL-3.0-only
//! A recipient's acceptance of the identities presented to it.
//!
//! In plain words: someone signs in here with an identity issued elsewhere.
//! This installation accepts it only when these hold at once. The
//! identity's certificate (its Binding Passport) leads, signature by
//! signature, to a platform authority this installation admits. Nothing
//! the installation has seen withdrew the passport or an authority on the
//! way. The passport was issued for this very organization. And the holder
//! signed for this one sign-in, with the key the passport certifies.
//!
//! Whether more must be known of withdrawals is the installation's policy
//! ([`StatusPolicy`]): by default the passport's issuer must have published
//! a list still within its time, and the installation may instead choose to
//! admit without one, within limits it names. Each outcome is defined:
//!
//! | What is held | Strict requirement | Offline requirement |
//! |---|---|---|
//! | a list in its time, no withdrawal | accepted, fresh | accepted, fresh |
//! | no list, or one past its time | not decided | accepted only if that exact absence is permitted, as stale or unknown |
//! | a withdrawal seen of the passport or of an authority on the path | refused | refused |
//! | expired certificate, another recipient, bad signature or holder proof | refused | refused |
//! | the platform's set past its refresh time | not decided | its anchors still anchor; a withdrawn generation stays out |
//! | a list that is malformed, wrongly signed or another issuer's | not recorded; what is held decides | the same |
//!
//! An organization that issues passports itself accepts its own from its
//! own installed authority and its own record of what it withdrew: no
//! platform authority, published list or network takes part.
//!
//! The admitted platform authorities and the published status are held in
//! the installation's store ([`PlatformCaStore`]) and only ever narrow. A
//! path validated once is reused while every certificate on it, the held
//! answer, the policy and the status it rested on stay as they were; the
//! holder's signature is verified every time.
//!
//! How signatures are checked is the [`Verdict`] of the composition: the
//! [`ClassicalVerdict`] here checks ECDSA P-256 and says nothing of further
//! signatures the same certificates carry. Whether the recipient admits such
//! an identity at all is its caller's decision.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::SystemTime;

use der::Decode;
use sha2::{Digest, Sha256};
use sid_core::models::{
    AuditEntry, MutationContext, StatusEvidence, StatusPolicy, StatusRequirement,
};
use sid_plugin::platform_ca::{
    AnchorStatus, Applied, GenerationStatus, HeldAnchors, IssuerStatus, PlatformCaError,
    PlatformCaSet, PlatformCaSource, PlatformCaState, PlatformCaStore, StatusRefusal,
};
use uuid::Uuid;
use x509_cert::Certificate;

use crate::admission::{ADMISSION_TYP, Admission, VerifiedAdmission, verify_site_signature};
use crate::admitted_paths::{self, AnchorView};
use crate::allocation::ContextAllocation;
use crate::binding_passport::{Passport, PassportProfile};
use crate::passport_path::{
    AcceptedParticipant, Classical, PathError, PathPolicy, Trust, ValidatedPath,
    accept_organization_ca, accept_participant, accept_passport,
};
use crate::presentation::{ES256, Envelope, Expected, PresentationError, Statement, verify_es256};
use crate::purpose::{IssuerRole, PurposeProfile};
use crate::status::{IssuedStatus, StatusError, verify_status};

/// The wait after a failed fetch before the source is asked again.
const SOURCE_BACKOFF: i64 = 30;

/// How long a view of a set past its refresh time is kept before the store
/// is read again: another replica may have held a newer set meanwhile.
const STALE_SET_REREAD: i64 = 60;

/// An accepted passport, with what was known of withdrawals when it was
/// accepted. Stale or unknown status is an accepted passport the policy
/// admitted, never one shown good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub passport: Passport,
    /// Of the passport, by its issuer's status.
    pub issuer: StatusEvidence,
    /// Of the authorities above the issuer and of the platform's set; none
    /// when the path ended at the installation's own authority and nothing
    /// above it was relied on.
    pub authorities: Option<StatusEvidence>,
}

/// How a composition checks the signatures of what is presented: of a
/// certificate path, of a published revocation list, and of the holder over
/// a presentation. The admission rules around them are the same for every
/// verdict.
pub trait Verdict: Send + Sync {
    /// The policy a path's signatures are verified under.
    type Path<'a>: PathPolicy
    where
        Self: 'a;

    fn path(&self) -> Self::Path<'_>;

    /// The DER list `crl` accepted under the DER certificate `issuer`.
    fn status(&self, crl: &[u8], issuer: &[u8]) -> Result<IssuedStatus, StatusError>;

    /// The holder's proof in `envelope` verifies with the key of the passport
    /// `certificate` (DER).
    fn holder(&self, envelope: &Envelope, certificate: &[u8]) -> Result<(), PresentationError>;
}

/// The classical verdict: ECDSA P-256 signatures on the path and on a
/// revocation list, and the holder's `ES256` proof.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClassicalVerdict;

impl Verdict for ClassicalVerdict {
    type Path<'a> = Classical;

    fn path(&self) -> Classical {
        Classical
    }

    fn status(&self, crl: &[u8], issuer: &[u8]) -> Result<IssuedStatus, StatusError> {
        verify_status(crl, issuer)
    }

    fn holder(&self, envelope: &Envelope, certificate: &[u8]) -> Result<(), PresentationError> {
        let proof = envelope.required(ES256)?;
        verify_es256(
            certificate,
            &envelope.signing_input(proof),
            &proof.signature,
        )
    }
}

/// This installation's own authority, when its organization issues passports
/// itself: the certificates it installed after they were admitted, and its
/// own record of what it withdrew. A passport one of them issued is accepted
/// from that certificate and that record alone, never from a published list
/// or a platform authority.
#[async_trait::async_trait]
pub trait OwnIssuer: Send + Sync {
    /// The organization this installation issues for.
    fn organization(&self) -> Uuid;

    /// The authority certificates (DER) installed here that still issue or
    /// verify: every generation the installation holds, exactly as
    /// installed. A certificate presented with a passport is the
    /// installation's own only when it is one of these, byte for byte.
    async fn authorities(&self) -> Result<Vec<Vec<u8>>, RecipientError>;

    /// Until when (seconds since the epoch) the certificate with `serial`,
    /// issued by `issuer` (DER), is shown not revoked at `now`. `Ok(None)`
    /// when `issuer` is not this installation's own authority.
    async fn standing(
        &self,
        issuer: &[u8],
        serial: &[u8],
        now: i64,
    ) -> Result<Option<i64>, RecipientError>;
}

/// Why something presented was not accepted, or could not be decided.
#[derive(Debug, thiserror::Error)]
pub enum RecipientError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    /// The platform CA set: none held, or a generation arriving with
    /// another certificate than the one held.
    #[error(transparent)]
    Platform(PlatformCaError),
    /// The held platform CA set is past its refresh time and the policy
    /// requires a current one: its anchors are not relied on now.
    #[error("the platform CA set is past its refresh time and a current one is required")]
    PlatformSetStale,
    /// A presented passport is not accepted on a path to the held anchors.
    #[error(transparent)]
    Path(PathError),
    /// A CA certificate on the path is revoked by the platform generation
    /// that issued it, or no current status of it is held.
    #[error(transparent)]
    Status(StatusRefusal),
    /// The authority that issued the passport revoked it.
    #[error("the passport is revoked by the authority that issued it")]
    PassportRevoked,
    /// No status of the issuing authority's passports is held within its
    /// time: absence of a revocation is not shown.
    #[error("no current status of the issuing authority's passports is held")]
    PassportStatusUnavailable,
    /// A presentation is not its passport holder's answer to the pending
    /// request: its envelope, the holder's proof or what it states.
    #[error(transparent)]
    Presentation(PresentationError),
    /// A site's statement of whom it admits is not that site's own: its
    /// envelope, the site's signature, its scope or its time.
    #[error(transparent)]
    Admission(crate::admission::AdmissionError),
    /// A published revocation list is not its issuer's.
    #[error(transparent)]
    List(StatusError),
    #[error("store: {0}")]
    Store(sid_core::Error),
}

impl RecipientError {
    /// Whether the evidence to decide on is missing now, rather than the
    /// identity refused: the same request may be retried.
    pub const fn undecided(&self) -> bool {
        matches!(
            self,
            Self::Platform(_)
                | Self::PlatformSetStale
                | Self::PassportStatusUnavailable
                | Self::Status(StatusRefusal::Unavailable)
                | Self::Store(_)
        )
    }
}

impl From<PlatformCaError> for RecipientError {
    fn from(e: PlatformCaError) -> Self {
        match e {
            PlatformCaError::Storage(e) => Self::Store(e),
            other => Self::Platform(other),
        }
    }
}

/// What asking the platform's publication did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pulled {
    /// The recipient was composed with no publication to ask.
    Unconfigured,
    /// The held set is current: nothing was asked.
    Current,
    /// A set was fetched and applied (or found older than the one held).
    Applied,
    /// The fetch failed now or failed less than the backoff ago.
    Failed,
}

/// `at` in whole seconds since the epoch.
fn seconds(at: SystemTime) -> Result<i64, RecipientError> {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(RecipientError::Invalid {
            field: "time",
            reason: "seconds since the epoch".into(),
        })
}

fn no_profile(e: impl std::fmt::Display) -> RecipientError {
    RecipientError::Invalid {
        field: "allocation",
        reason: e.to_string(),
    }
}

/// The allocation's byte in an accepted path's key.
const fn allocation_tag(allocation: ContextAllocation) -> u8 {
    match allocation {
        ContextAllocation::Development => 0,
        ContextAllocation::Production => 1,
    }
}

/// The serial of the DER certificate `der`, as its INTEGER contents.
fn serial_of(der: &[u8]) -> Result<Vec<u8>, RecipientError> {
    Ok(Certificate::from_der(der)
        .map_err(|e| RecipientError::Path(PathError::Encoding(e.to_string())))?
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec())
}

/// The name an authority's status is held under: the SHA-256 of its exact
/// certificate (DER).
pub fn issuer_name(certificate: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate).into()
}

fn audit(action: &str) -> MutationContext {
    AuditEntry::system(action, "installation").into()
}

/// What is known, and until when, of the certificate with `serial` under the
/// `status` its issuer published, by `requirement` at `now`. A withdrawal
/// seen once refuses under every requirement; with none seen, the
/// requirement decides whether what is held suffices.
fn standing(
    status: &AnchorStatus,
    serial: &[u8],
    requirement: StatusRequirement,
    now: i64,
) -> Result<(StatusEvidence, Option<i64>), StatusRefusal> {
    if status.revoked.iter().any(|revoked| revoked == serial) {
        return Err(StatusRefusal::Revoked);
    }
    requirement
        .weigh(status.until, now)
        .ok_or(StatusRefusal::Unavailable)
}

/// The status the anchor of `path` holds of what its generation issued.
fn anchor_status<'a>(held: &'a HeldAnchors, path: &ValidatedPath) -> Option<&'a AnchorStatus> {
    held.anchors
        .iter()
        .position(|anchor| anchor == &path.anchor)
        .and_then(|i| held.status.get(i))
}

/// The less that is known of two things relied on together, and the earlier
/// end of the two answers.
fn weakest(
    a: (StatusEvidence, Option<i64>),
    b: (StatusEvidence, Option<i64>),
) -> (StatusEvidence, Option<i64>) {
    let until = match (a.1, b.1) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    (a.0.max(b.0), until)
}

/// What is known of the authorities a platform path relied on, by
/// `requirement` at `now`: the held set itself (past its refresh time its
/// withdrawals are no longer known to be current) and, when a CA stands
/// between the anchor and the certificate (`issued` when the certificate is
/// itself that CA), that CA by the status the anchor's generation
/// published. A revoked CA refuses the path, a leaf never seen before
/// included.
fn authorities_standing(
    held: &HeldAnchors,
    path: &ValidatedPath,
    issued: Option<&[u8]>,
    requirement: StatusRequirement,
    now: i64,
) -> Result<(StatusEvidence, Option<i64>), RecipientError> {
    let set = requirement
        .weigh(Some(held.refresh_at), now)
        .ok_or(RecipientError::PlatformSetStale)?;
    // The path's issuers are listed the certificate's own first, so the CA
    // the anchor issued is the last; a CA target is itself that CA when no
    // issuer stands between.
    let Some(ca) = path.issuers.last().map(Vec::as_slice).or(issued) else {
        return Ok(set);
    };
    let unknown = AnchorStatus::default();
    let status = anchor_status(held, path).unwrap_or(&unknown);
    let ca = standing(status, &serial_of(ca)?, requirement, now).map_err(RecipientError::Status)?;
    Ok(weakest(set, ca))
}

/// What a recipient asks of the identities presented to it, whatever the
/// verdict of its composition.
#[async_trait::async_trait]
pub trait PresentedIdentities: Send + Sync {
    /// The passport of the presentation `jws`, accepted as its holder's
    /// answer to `expected` under the installation's `policy`, with what
    /// was known of withdrawals; see [`Recipient::accept_presentation`].
    async fn accept_presentation(
        &self,
        jws: &[u8],
        expected: &Expected<'_>,
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError>;

    /// The enrolled site of the participant `certificate`, accepted under
    /// the installation's `policy`; see [`Recipient::accept_participant`].
    async fn accept_participant(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<AcceptedParticipant, RecipientError>;

    /// The statement `jws` of whom a site admits, accepted as that site's
    /// own; see [`Recipient::accept_admission`].
    async fn accept_admission(
        &self,
        jws: &[u8],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<VerifiedAdmission, RecipientError>;
}

/// Whether the list `verified` was issued by `at`: one whose thisUpdate is
/// still ahead is not yet the issuer's status (RFC 5280 §5.1.2.4, §6.3.3),
/// and holding it would both count as fresh and, by its number, keep the
/// current list out. Such a list is not recorded.
fn issued_by_now(
    verified: &IssuedStatus,
    at: SystemTime,
    field: &'static str,
) -> Result<(), RecipientError> {
    if verified.this_update > at {
        return Err(RecipientError::Invalid {
            field,
            reason: "a list issued later than now".into(),
        });
    }
    Ok(())
}

/// Where an organization's own publication is read from: its CA generations
/// and the list each publishes of the passports it issued
/// (`arch/auth/org-ca-architecture.md` §organization-status-publication),
/// in the platform publication's format. Where it is read grants nothing:
/// every certificate and list is checked as the recipient checks any.
#[async_trait::async_trait]
pub trait OrganizationPublications: Send + Sync {
    /// What `organization` publishes now; `Ok(None)` when no location of its
    /// publication is known to this installation.
    async fn fetch(&self, organization: Uuid) -> Result<Option<PlatformCaSet>, String>;
}

/// The recipient side of one installation over its store.
pub struct Recipient<V = ClassicalVerdict> {
    store: Arc<dyn PlatformCaStore>,
    verdict: V,
    /// The held platform anchors and the passports accepted under them,
    /// while that answer is current.
    view: tokio::sync::RwLock<Option<Arc<AnchorView>>>,
    /// The platform's publication and how it is fetched; none fetches
    /// nothing, and the held set alone decides.
    source: Option<(url::Url, Arc<dyn PlatformCaSource>)>,
    /// The installation's own authority, when it issues passports itself.
    own: Option<Arc<dyn OwnIssuer>>,
    /// When the last fetch failed (seconds since the epoch), so a failing
    /// source is not asked again on every request.
    failed_at: AtomicI64,
    /// Where issuing organizations' publications are read when a list of
    /// theirs is missing or past its time; none reads nothing, and only what
    /// is held decides.
    publications: Option<Arc<dyn OrganizationPublications>>,
    /// When reading an organization's publication last failed (seconds
    /// since the epoch), so a failing one is not asked on every sign-in.
    publication_failed_at: std::sync::Mutex<std::collections::HashMap<Uuid, i64>>,
}

impl<V: Verdict> Recipient<V> {
    pub fn new(store: Arc<dyn PlatformCaStore>, verdict: V) -> Self {
        Self {
            store,
            verdict,
            view: tokio::sync::RwLock::new(None),
            source: None,
            own: None,
            failed_at: AtomicI64::new(i64::MIN),
            publications: None,
            publication_failed_at: std::sync::Mutex::default(),
        }
    }

    /// The recipient reading an issuing organization's own publication
    /// through `publications` when what it holds of that organization's
    /// list is missing or past its time.
    pub fn with_organization_publications(
        mut self,
        publications: Arc<dyn OrganizationPublications>,
    ) -> Self {
        self.publications = Some(publications);
        self
    }

    /// Read `organization`'s publication and hold the list of its generation
    /// `issuer` (with `chain` above it): whether a list of that generation
    /// was found and recorded. A failure is logged and answers false; it is
    /// not asked again within [`SOURCE_BACKOFF`].
    async fn refresh_issuer_status(
        &self,
        allocation: ContextAllocation,
        organization: Uuid,
        issuer: &[u8],
        chain: &[Vec<u8>],
        at: SystemTime,
    ) -> bool {
        let Some(publications) = &self.publications else {
            return false;
        };
        let Ok(now) = seconds(at) else {
            return false;
        };
        let backoff = |failed_at: &mut std::collections::HashMap<Uuid, i64>| {
            failed_at.insert(organization, now);
        };
        {
            let failed_at = self
                .publication_failed_at
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if failed_at
                .get(&organization)
                // Both are seconds since the epoch: the sum stays in range.
                .is_some_and(|failed| now < failed + SOURCE_BACKOFF)
            {
                return false;
            }
        }
        let published = match publications.fetch(organization).await {
            Ok(Some(published)) => published,
            Ok(None) => return false,
            Err(reason) => {
                tracing::warn!(%organization, %reason, "organization publication not read");
                backoff(
                    &mut self
                        .publication_failed_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                return false;
            }
        };
        let Some(crl) = published
            .generations
            .iter()
            .find(|g| g.certificate == issuer)
            .and_then(|g| g.crl.as_deref())
        else {
            return false;
        };
        match self
            .record_issuer_status(allocation, organization, issuer, chain, crl, at)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(%organization, error = %e, "organization list not recorded");
                backoff(
                    &mut self
                        .publication_failed_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                false
            }
        }
    }

    /// The recipient refreshing its platform set from the platform's
    /// `publication` (an `https` URL) through `source`. The publication is
    /// the composing build's, held nowhere else: nothing stored or received
    /// replaces it.
    pub fn with_source(
        mut self,
        publication: url::Url,
        source: Arc<dyn PlatformCaSource>,
    ) -> Result<Self, RecipientError> {
        if publication.scheme() != "https" {
            return Err(RecipientError::Invalid {
                field: "publication",
                reason: "an https URL".into(),
            });
        }
        self.source = Some((publication, source));
        Ok(self)
    }

    /// The recipient answering for the passports of its own authority from
    /// `own`.
    pub fn with_own_issuer(mut self, own: Arc<dyn OwnIssuer>) -> Self {
        self.own = Some(own);
        self
    }

    /// The verdict signatures are checked with.
    pub fn verdict(&self) -> &V {
        &self.verdict
    }

    /// A platform set's generations are CA certificates, a verification-only
    /// one names its overlap end, and a list a generation publishes is its
    /// own, by this verdict. The authenticated lists are returned for the
    /// store.
    fn check_set(&self, set: &PlatformCaSet) -> Result<Vec<GenerationStatus>, RecipientError> {
        let mut status = Vec::new();
        for generation in &set.generations {
            let certificate = Certificate::from_der(&generation.certificate).map_err(|e| {
                RecipientError::Invalid {
                    field: "generations.certificate",
                    reason: format!("a DER certificate: {e}"),
                }
            })?;
            let is_ca = certificate
                .tbs_certificate()
                .get_extension::<x509_cert::ext::pkix::BasicConstraints>()
                .ok()
                .flatten()
                .is_some_and(|(_, constraints)| constraints.ca);
            if !is_ca {
                return Err(RecipientError::Invalid {
                    field: "generations.certificate",
                    reason: "a platform generation is a CA certificate".into(),
                });
            }
            if generation.state == PlatformCaState::VerificationOnly
                && generation.overlap_end.is_none()
            {
                return Err(RecipientError::Invalid {
                    field: "generations.overlap_end",
                    reason: "a verification-only generation names its overlap end".into(),
                });
            }
            if let Some(crl) = &generation.crl {
                let verified = self
                    .verdict
                    .status(crl, &generation.certificate)
                    .map_err(|e| RecipientError::Invalid {
                        field: "generations.crl",
                        reason: e.to_string(),
                    })?;
                issued_by_now(&verified, SystemTime::now(), "generations.crl")?;
                status.push(GenerationStatus {
                    generation: generation.generation,
                    certificate: generation.certificate.clone(),
                    number: verified.number,
                    next_update: seconds(verified.next_update)?,
                    revoked: verified.revoked,
                });
            }
        }
        Ok(status)
    }

    /// Hold the status and then the set: an anchor is never held ahead of
    /// what its generation revoked.
    async fn hold(&self, set: &PlatformCaSet) -> Result<Applied, RecipientError> {
        let status = self.check_set(set)?;
        if !status.is_empty() {
            self.store
                .record_platform_ca_status(&status, audit("platform_ca.record_status"))
                .await?;
        }
        Ok(self
            .store
            .apply_platform_cas(set, audit("platform_ca.apply"))
            .await?)
    }

    /// Hold the platform's admitted CA set `set`, after checking it.
    /// Authentication of the set is its carrier's: the managing service over
    /// an admitted channel, or the configured publication.
    pub async fn record_platform_cas(
        &self,
        set: &PlatformCaSet,
    ) -> Result<Applied, RecipientError> {
        let mut view = self.view.write().await;
        let applied = self.hold(set).await?;
        // The anchors and every path accepted under them are read again from
        // the set now held.
        *view = None;
        Ok(applied)
    }

    /// The held platform anchors at `now` (seconds since the epoch), from
    /// the view while it is current, else read once for every caller waiting
    /// on it. Past halfway through the held set's freshness, or with no
    /// set, the platform's publication is asked for a newer one first; a
    /// failed fetch leaves the held answer as it is (its anchors keep
    /// anchoring past its refresh time, which the policy weighs) and is not
    /// repeated for [`SOURCE_BACKOFF`] seconds.
    async fn view(&self, now: i64) -> Result<Arc<AnchorView>, RecipientError> {
        if let Some(view) = self.view.read().await.as_ref()
            && view.current(now)
        {
            return Ok(view.clone());
        }
        let mut slot = self.view.write().await;
        if let Some(view) = slot.as_ref()
            && view.current(now)
        {
            return Ok(view.clone());
        }
        let mut held = self.store.held_platform_cas(now).await;
        let due = match &held {
            Ok(held) => now >= held.renew_at,
            Err(PlatformCaError::NotProvisioned) => true,
            Err(_) => false,
        };
        let pulled = match &self.source {
            Some((publication, source)) if due => {
                self.pull(publication, source.as_ref(), now).await
            }
            Some(_) => Pulled::Current,
            None => Pulled::Unconfigured,
        };
        if due && pulled == Pulled::Applied {
            held = self.store.held_platform_cas(now).await;
        }
        let held = held?;
        // A configured source is asked again halfway through the set's
        // freshness, or after the backoff when it just failed.
        let stale = now > held.refresh_at;
        let until = match pulled {
            // Nothing in this process will replace a set past its refresh
            // time; another replica may have, so the store is read again.
            Pulled::Unconfigured | Pulled::Current | Pulled::Applied if stale => {
                held.until.min(now + STALE_SET_REREAD)
            }
            Pulled::Unconfigured => held.until,
            Pulled::Failed => held.until.min(now + SOURCE_BACKOFF),
            Pulled::Current | Pulled::Applied if held.renew_at > now => {
                held.until.min(held.renew_at)
            }
            Pulled::Current | Pulled::Applied => held.until,
        };
        let view = Arc::new(AnchorView::new(held, until));
        *slot = Some(view.clone());
        Ok(view)
    }

    /// Fetch the platform's `publication` and hold the set it states, unless
    /// the last fetch failed less than the backoff ago. The store applies
    /// it under its own rules, so a fetch can bring back neither an older
    /// set nor a withdrawn generation. A failure is logged, never answered:
    /// the held set decides.
    async fn pull(
        &self,
        publication: &url::Url,
        source: &dyn PlatformCaSource,
        now: i64,
    ) -> Pulled {
        // `failed_at` starts at i64::MIN, so the sum stays in range.
        if now < self.failed_at.load(Ordering::Relaxed) + SOURCE_BACKOFF {
            return Pulled::Failed;
        }
        let outcome = async {
            let set = source.fetch(publication).await?;
            let applied = self.hold(&set).await.map_err(|e| e.to_string())?;
            tracing::info!(
                revision = set.revision,
                ?applied,
                "platform CA set refreshed"
            );
            Ok::<Pulled, String>(Pulled::Applied)
        }
        .await;
        match outcome {
            Ok(pulled) => pulled,
            Err(reason) => {
                self.failed_at.store(now, Ordering::Relaxed);
                tracing::warn!(%reason, "platform CA publication not refreshed");
                Pulled::Failed
            }
        }
    }

    /// Accepts the Binding Passport `certificate` (DER), with the
    /// authorities `chain` presented above it, for the recipient
    /// organization `recipient` at `at`, under the installation's status
    /// `policy`.
    ///
    /// A passport issued by this installation's own authority (its issuer
    /// is, byte for byte, one of the certificates installed here) is
    /// accepted from that authority and its own record: see
    /// [`Self::accept_own`]. Every other passport is accepted on a complete
    /// path to a platform intermediate the held set admits: see
    /// [`Self::accept_under_platform`].
    ///
    /// A passport and chain accepted before are not validated again while
    /// every certificate of the path, the held answer, the policy and the
    /// status it rested on stay as they were; the holder's proof over a
    /// presentation is verified every time.
    pub async fn accept_passport(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        recipient: Uuid,
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError> {
        // Chosen by the certificates installed here, never by what the
        // passport or its presenter says of its source: a certificate
        // another organization presents is not one of them.
        if let Some(own) = &self.own
            && let Some(issuer) = chain.first()
        {
            let installed = own.authorities().await?;
            if installed.iter().any(|authority| authority == issuer) {
                return self
                    .accept_own(own.as_ref(), &installed, certificate, chain, recipient, at)
                    .await;
            }
        }
        self.accept_under_platform(certificate, chain, recipient, policy, at)
            .await
    }

    /// Accepts a passport this installation's own authority issued, from
    /// that authority alone: its signature under one of the `installed`
    /// certificates, its validity, purpose and recipient, and the
    /// installation's own record of what it withdrew. No platform set,
    /// published list or network is consulted, so an installation cut off
    /// from everything still signs its own people in. A passport the
    /// organization withdrew is refused all the same: being local excuses
    /// nothing.
    async fn accept_own(
        &self,
        own: &dyn OwnIssuer,
        installed: &[Vec<u8>],
        certificate: &[u8],
        chain: &[Vec<u8>],
        recipient: Uuid,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError> {
        let now = seconds(at)?;
        let allocation = allocation_of(installed, IssuerRole::OrganizationCa)?.ok_or(
            RecipientError::Invalid {
                field: "own authority",
                reason: "the installed certificates name no single allocation".into(),
            },
        )?;
        let accepted = accept_passport(
            &self.verdict.path(),
            &PassportProfile::of(allocation).map_err(no_profile)?,
            &PurposeProfile::of(allocation).map_err(no_profile)?,
            Trust::OwnOrganization(own.organization()),
            certificate,
            chain,
            installed,
            recipient,
            at,
        )
        .map_err(RecipientError::Path)?;
        // The installation's own record is the authority on its passports:
        // read on every acceptance, so a withdrawal is seen at once.
        own.standing(&accepted.path.anchor, &serial_of(certificate)?, now)
            .await?
            .ok_or(RecipientError::PassportStatusUnavailable)?;
        Ok(Accepted {
            passport: accepted.passport,
            issuer: StatusEvidence::Fresh,
            authorities: None,
        })
    }

    /// Accepts a passport issued elsewhere on a complete path to a platform
    /// intermediate the held set admits. What must be known of withdrawals
    /// is `policy`'s: of the passport by its issuer's status (the platform
    /// generation's for a Personal one, the organization authority's for a
    /// Corporate one), and of the authorities above by the platform's. A
    /// withdrawal seen of any of them refuses under every policy.
    async fn accept_under_platform(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        recipient: Uuid,
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError> {
        let now = seconds(at)?;
        let view = self.view(now).await?;
        // A held set whose every generation was withdrawn anchors nothing.
        if view.held.anchors.is_empty() {
            return Err(RecipientError::Path(PathError::NoAnchor));
        }
        let allocation = allocation_of(&view.held.anchors, IssuerRole::PlatformIntermediate)?
            .ok_or(RecipientError::Invalid {
                field: "platform CA set",
                reason: "its generations name no single allocation".into(),
            })?;
        let key = admitted_paths::key(
            allocation_tag(allocation),
            &policy.tag(),
            recipient,
            certificate,
            chain,
        );
        if let Some(accepted) = view.reused(&key, now).await {
            return Ok(accepted);
        }
        let path = accept_passport(
            &self.verdict.path(),
            &PassportProfile::of(allocation).map_err(no_profile)?,
            &PurposeProfile::of(allocation).map_err(no_profile)?,
            Trust::Platform,
            certificate,
            chain,
            &view.held.anchors,
            recipient,
            at,
        )
        .map_err(RecipientError::Path)?;
        let (authorities, authorities_until) =
            authorities_standing(&view.held, &path.path, None, policy.authorities, now)?;
        let serial = serial_of(certificate)?;
        let leaf = match path.path.issuers.first() {
            // Issued by an authority below the platform: its own published
            // status, as this installation holds it. Missing or past its
            // time, the organization's own publication is read once, where
            // the installation knows it, and the list it gives decides.
            Some(issuer) => {
                let mut status = self.store.held_issuer_status(&issuer_name(issuer)).await?;
                let mut decided = standing(&status, &serial, policy.issuer, now);
                if matches!(decided, Err(StatusRefusal::Unavailable))
                    && let Some(organization) = path.passport.source_org
                    && self
                        .refresh_issuer_status(
                            allocation,
                            organization,
                            issuer,
                            &path.path.issuers[1..],
                            at,
                        )
                        .await
                {
                    status = self.store.held_issuer_status(&issuer_name(issuer)).await?;
                    decided = standing(&status, &serial, policy.issuer, now);
                }
                decided
            }
            // Issued by the platform generation itself: that generation's.
            None => {
                let unknown = AnchorStatus::default();
                let status = anchor_status(&view.held, &path.path).unwrap_or(&unknown);
                standing(status, &serial, policy.issuer, now)
            }
        };
        let (issuer, issuer_until) = leaf.map_err(|refusal| match refusal {
            StatusRefusal::Revoked => RecipientError::PassportRevoked,
            StatusRefusal::Unavailable => RecipientError::PassportStatusUnavailable,
        })?;
        let until = [authorities_until, issuer_until]
            .into_iter()
            .flatten()
            .fold(seconds(path.until)?, i64::min);
        let accepted = Accepted {
            passport: path.passport,
            issuer,
            authorities: Some(authorities),
        };
        view.keep(key, accepted.clone(), until, now).await;
        Ok(accepted)
    }

    /// Accepts the Binding presentation `jws` as its holder's answer to the
    /// pending request `expected` at `at`: the passport it carries is
    /// accepted as [`Self::accept_passport`] accepts one; the holder's proof
    /// is verified with that passport's key every time; and the statement is
    /// the passport's own for exactly the pending challenge and verifier
    /// context. The caller consumes the challenge.
    pub async fn accept_presentation(
        &self,
        jws: &[u8],
        expected: &Expected<'_>,
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError> {
        let envelope = Envelope::parse(jws).map_err(RecipientError::Presentation)?;
        let statement = Statement::read(&envelope.payload).map_err(RecipientError::Presentation)?;
        let accepted = self
            .accept_passport(
                &statement.certificate,
                &statement.chain,
                expected.recipient,
                policy,
                at,
            )
            .await?;
        self.verdict
            .holder(&envelope, &statement.certificate)
            .map_err(RecipientError::Presentation)?;
        statement
            .admit(&accepted.passport, expected)
            .map_err(RecipientError::Presentation)?;
        Ok(accepted)
    }

    /// The identifier allocation the platform intermediates this
    /// installation holds at `at` were issued under, read from those
    /// certificates: the one whose purposes name every held anchor a
    /// platform intermediate. A recipient verifies what it is presented
    /// under the allocation of the anchors it admits. `None` while its
    /// anchors name no single allocation.
    pub async fn platform_allocation(
        &self,
        at: SystemTime,
    ) -> Result<Option<ContextAllocation>, RecipientError> {
        let view = self.view(seconds(at)?).await?;
        allocation_of(&view.held.anchors, IssuerRole::PlatformIntermediate)
    }

    /// Accepts the authority `certificate` (DER) of `organization`, with the
    /// `chain` presented above it, at `at`: on a complete path to a held
    /// platform anchor, scoped to exactly that organization, and not
    /// revoked by the generation that issued it. Whether the absence of a
    /// current list of that generation suffices is `requirement`'s; under
    /// the strict one it is [`RecipientError::Status`] with
    /// [`StatusRefusal::Unavailable`]: not shown either way.
    pub async fn accept_organization_ca(
        &self,
        allocation: ContextAllocation,
        organization: Uuid,
        certificate: &[u8],
        chain: &[Vec<u8>],
        requirement: StatusRequirement,
        at: SystemTime,
    ) -> Result<(), RecipientError> {
        let now = seconds(at)?;
        let view = self.view(now).await?;
        let path = accept_organization_ca(
            &self.verdict.path(),
            &PurposeProfile::of(allocation).map_err(no_profile)?,
            certificate,
            chain,
            &view.held.anchors,
            organization,
            at,
        )
        .map_err(RecipientError::Path)?;
        authorities_standing(&view.held, &path, Some(certificate), requirement, now)?;
        Ok(())
    }

    /// Accepts the participant certificate `certificate` (DER) of an
    /// enrolled site, with the `chain` presented above it, at `at`: on a
    /// complete path to a platform intermediate the held set admits, issued
    /// by that intermediate itself, in the participant profile, and not
    /// withdrawn by the generation that issued it. What must be known of
    /// withdrawals is `policy`'s, as for a passport the platform issued; a
    /// withdrawal seen refuses under every policy.
    pub async fn accept_participant(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<AcceptedParticipant, RecipientError> {
        let now = seconds(at)?;
        let view = self.view(now).await?;
        if view.held.anchors.is_empty() {
            return Err(RecipientError::Path(PathError::NoAnchor));
        }
        let allocation = allocation_of(&view.held.anchors, IssuerRole::PlatformIntermediate)?
            .ok_or(RecipientError::Invalid {
                field: "platform CA set",
                reason: "its generations name no single allocation".into(),
            })?;
        let accepted = accept_participant(
            &self.verdict.path(),
            &PurposeProfile::of(allocation).map_err(no_profile)?,
            certificate,
            chain,
            &view.held.anchors,
            at,
        )
        .map_err(RecipientError::Path)?;
        authorities_standing(&view.held, &accepted.path, None, policy.authorities, now)?;
        let unknown = AnchorStatus::default();
        let status = anchor_status(&view.held, &accepted.path).unwrap_or(&unknown);
        standing(status, &serial_of(certificate)?, policy.issuer, now)
            .map_err(RecipientError::Status)?;
        Ok(accepted)
    }

    /// Accepts the statement `jws` of whom a site admits as that site's own
    /// at `at`: its participant certificate as
    /// [`Self::accept_participant`] accepts one, the site's signature with
    /// that certificate's key, and that it speaks for exactly that
    /// organization and site at an entry the certificate lists, within its
    /// time. Which revision is the newest seen is the caller's.
    pub async fn accept_admission(
        &self,
        jws: &[u8],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<VerifiedAdmission, RecipientError> {
        let envelope = Envelope::parse_typed(jws, ADMISSION_TYP)
            .map_err(|e| RecipientError::Admission(e.into()))?;
        let admission = Admission::read(&envelope.payload).map_err(RecipientError::Admission)?;
        let participant = self
            .accept_participant(&admission.certificate, &admission.chain, policy, at)
            .await?;
        verify_site_signature(&envelope, &admission.certificate)
            .map_err(RecipientError::Admission)?;
        admission
            .within(&participant.participant, at)
            .map_err(RecipientError::Admission)?;
        Ok(VerifiedAdmission {
            admission,
            participant,
        })
    }

    /// Drop every path accepted so far: the caller changed status an
    /// acceptance may have rested on outside this recipient (its own
    /// authority revoked a passport). The next acceptance validates again.
    pub async fn forget(&self) {
        *self.view.write().await = None;
    }

    /// Hold the status `organization` published for the passports one of
    /// its authority's generations issued: that generation's `certificate`
    /// with the `chain` above it and its `crl`, all DER, as a resolver
    /// obtained them. Where they came from grants nothing: the certificate
    /// must be that organization's authority on a path to a held platform
    /// anchor whose generation has not revoked it, and the list must be
    /// issued by exactly that certificate. A list older than the one held
    /// changes only what it revokes. Recording a list only ever narrows
    /// what is relied on, so no current status of the authority itself is
    /// required to take it; a list that is malformed, wrongly signed or
    /// another issuer's is not recorded and what is held stays as it was.
    pub async fn record_issuer_status(
        &self,
        allocation: ContextAllocation,
        organization: Uuid,
        certificate: &[u8],
        chain: &[Vec<u8>],
        crl: &[u8],
        at: SystemTime,
    ) -> Result<(), RecipientError> {
        self.accept_organization_ca(
            allocation,
            organization,
            certificate,
            chain,
            StatusRequirement::Offline(sid_core::models::OfflineLimits::ANY),
            at,
        )
        .await?;
        let verified = self
            .verdict
            .status(crl, certificate)
            .map_err(RecipientError::List)?;
        issued_by_now(&verified, at, "crl")?;
        let mut slot = self.view.write().await;
        self.store
            .record_issuer_status(
                &IssuerStatus {
                    issuer: issuer_name(certificate),
                    number: verified.number,
                    next_update: seconds(verified.next_update)?,
                    revoked: verified.revoked,
                },
                audit("platform_ca.record_issuer_status"),
            )
            .await?;
        // Every passport accepted before is checked against it again.
        *slot = None;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<V: Verdict> PresentedIdentities for Recipient<V> {
    async fn accept_presentation(
        &self,
        jws: &[u8],
        expected: &Expected<'_>,
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<Accepted, RecipientError> {
        Recipient::accept_presentation(self, jws, expected, policy, at).await
    }

    async fn accept_participant(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<AcceptedParticipant, RecipientError> {
        Recipient::accept_participant(self, certificate, chain, policy, at).await
    }

    async fn accept_admission(
        &self,
        jws: &[u8],
        policy: &StatusPolicy,
        at: SystemTime,
    ) -> Result<VerifiedAdmission, RecipientError> {
        Recipient::accept_admission(self, jws, policy, at).await
    }
}

/// The identifier allocation `certificates` (DER) were issued under, read
/// from them: the one whose purposes name every one of them `role`. `None`
/// when there are none or they name no single allocation.
fn allocation_of(
    certificates: &[Vec<u8>],
    role: IssuerRole,
) -> Result<Option<ContextAllocation>, RecipientError> {
    if certificates.is_empty() {
        return Ok(None);
    }
    let read = certificates
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            RecipientError::Store(sid_core::Error::Storage(format!(
                "a held authority certificate: {e}"
            )))
        })?;
    Ok([
        ContextAllocation::Development,
        ContextAllocation::Production,
    ]
    .into_iter()
    .find(|allocation| {
        PurposeProfile::of(*allocation).is_ok_and(|purposes| {
            read.iter().all(|certificate| {
                purposes
                    .issuer_roles(certificate)
                    .is_ok_and(|roles| roles.contains(&role))
            })
        })
    }))
}

#[cfg(test)]
mod tests;
