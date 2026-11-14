// SPDX-License-Identifier: AGPL-3.0-only
//! A recipient's acceptance of the identities presented to it.
//!
//! In plain words: someone signs in here with an identity issued elsewhere.
//! This installation accepts it only when four things hold at once. The
//! identity's certificate (its Binding Passport) leads, signature by
//! signature, to a platform authority this installation currently admits.
//! None of the authorities on the way, nor the passport itself, was
//! withdrawn by its issuer, shown by a list still within its time. The
//! passport was issued for this very organization. And the holder signed
//! for this one sign-in, with the key the passport certifies.
//!
//! The admitted platform authorities and the published status are held in
//! the installation's store ([`PlatformCaStore`]) and only ever narrow. A
//! path validated once is reused while every certificate on it, the held
//! answer and the status it rested on stay valid; the holder's signature is
//! verified every time.
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
use sid_core::models::{AuditEntry, MutationContext};
use sid_plugin::platform_ca::{
    Applied, GenerationStatus, HeldAnchors, IssuerStatus, PlatformCaError, PlatformCaSet,
    PlatformCaSource, PlatformCaState, PlatformCaStore, StatusRefusal,
};
use uuid::Uuid;
use x509_cert::Certificate;

use crate::admitted_paths::{self, AnchorView};
use crate::allocation::ContextAllocation;
use crate::binding_passport::{Passport, PassportProfile};
use crate::passport_path::{
    Classical, PathError, PathPolicy, ValidatedPath, accept_organization_ca, accept_passport,
};
use crate::presentation::{ES256, Envelope, Expected, PresentationError, Statement, verify_es256};
use crate::purpose::{IssuerRole, PurposeProfile};
use crate::status::{IssuedStatus, StatusError, verify_status};

/// The wait after a failed fetch before the source is asked again.
const SOURCE_BACKOFF: i64 = 30;

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

/// The status of the passports this installation's own authority issued,
/// when it has one: answered from its own record, never from a published
/// list.
#[async_trait::async_trait]
pub trait OwnIssuer: Send + Sync {
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
    /// The platform CA set: none held, past its refresh time, or a
    /// generation arriving with another certificate than the one held.
    #[error(transparent)]
    Platform(PlatformCaError),
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

/// What asking the configured source did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pulled {
    /// No source or no publication is configured.
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

/// Whether the CA certificate directly under the anchor of `path` may be
/// relied on at `now`, by the status the anchor's generation published: a
/// revoked CA refuses the path, a leaf never seen before included. A path
/// with no CA below the anchor has none to check here; the end of the
/// status' evidence is returned for the reuse of the result.
fn issued_ca_status(
    held: &HeldAnchors,
    path: &ValidatedPath,
    issued: Option<&[u8]>,
    now: i64,
) -> Result<Option<i64>, RecipientError> {
    // The path's issuers are listed the certificate's own first, so the CA
    // the anchor issued is the last; a CA target is itself that CA when no
    // issuer stands between.
    let Some(ca) = path.issuers.last().map(Vec::as_slice).or(issued) else {
        return Ok(None);
    };
    let status = held
        .anchors
        .iter()
        .position(|anchor| anchor == &path.anchor)
        .and_then(|i| held.status.get(i))
        .ok_or(RecipientError::Status(StatusRefusal::Unavailable))?;
    status
        .admits(&serial_of(ca)?, now)
        .map_err(RecipientError::Status)?;
    Ok(status.until)
}

/// What a recipient asks of the identities presented to it, whatever the
/// verdict of its composition.
#[async_trait::async_trait]
pub trait PresentedIdentities: Send + Sync {
    /// The identifier allocation the held platform intermediates were issued
    /// under; see [`Recipient::platform_allocation`].
    async fn platform_allocation(
        &self,
        at: SystemTime,
    ) -> Result<Option<ContextAllocation>, RecipientError>;

    /// The passport of the presentation `jws`, accepted as its holder's
    /// answer to `expected`; see [`Recipient::accept_presentation`].
    async fn accept_presentation(
        &self,
        allocation: ContextAllocation,
        jws: &[u8],
        expected: &Expected<'_>,
        at: SystemTime,
    ) -> Result<Passport, RecipientError>;
}

/// The recipient side of one installation over its store.
pub struct Recipient<V = ClassicalVerdict> {
    store: Arc<dyn PlatformCaStore>,
    verdict: V,
    /// The held platform anchors and the passports accepted under them,
    /// while that answer is current.
    view: tokio::sync::RwLock<Option<Arc<AnchorView>>>,
    /// How the configured publication is fetched; none fetches nothing.
    source: Option<Arc<dyn PlatformCaSource>>,
    /// The installation's own authority, when it issues passports itself.
    own: Option<Arc<dyn OwnIssuer>>,
    /// When the last fetch failed (seconds since the epoch), so a failing
    /// source is not asked again on every request.
    failed_at: AtomicI64,
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
        }
    }

    /// The recipient refreshing its platform set from the configured
    /// publication through `source`.
    pub fn with_source(mut self, source: Arc<dyn PlatformCaSource>) -> Self {
        self.source = Some(source);
        self
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

    /// Configure the publication the platform set is refreshed from: an
    /// `https` URL, which a refresh never replaces with one it receives. A
    /// configured one is kept; whether this one was written.
    pub async fn configure_publication(&self, endpoint: &url::Url) -> Result<bool, RecipientError> {
        if endpoint.scheme() != "https" {
            return Err(RecipientError::Invalid {
                field: "publication",
                reason: "an https URL".into(),
            });
        }
        Ok(self
            .store
            .configure_platform_ca_publication(
                endpoint.as_str(),
                audit("platform_ca.configure_publication"),
            )
            .await?)
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
                status.push(GenerationStatus {
                    generation: generation.generation,
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
    /// current set, the configured source is asked for a newer one first; a
    /// failed fetch leaves the held answer as it is (refused once past its
    /// refresh time) and is not repeated for [`SOURCE_BACKOFF`] seconds.
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
            Err(PlatformCaError::NotProvisioned | PlatformCaError::Stale) => true,
            Err(_) => false,
        };
        let pulled = match &self.source {
            Some(source) if due => self.pull(source.as_ref(), now).await,
            Some(_) => Pulled::Current,
            None => Pulled::Unconfigured,
        };
        if due && pulled == Pulled::Applied {
            held = self.store.held_platform_cas(now).await;
        }
        let held = held?;
        // A configured source is asked again halfway through the set's
        // freshness, or after the backoff when it just failed.
        let until = match pulled {
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

    /// Fetch the configured publication and hold the set it states, unless
    /// none is configured or the last fetch failed less than the backoff
    /// ago. The store applies it under its own rules, so a fetch can bring
    /// back neither an older set nor a withdrawn generation. A failure is
    /// logged, never answered: the held set decides.
    async fn pull(&self, source: &dyn PlatformCaSource, now: i64) -> Pulled {
        // `failed_at` starts at i64::MIN, so the sum stays in range.
        if now < self.failed_at.load(Ordering::Relaxed) + SOURCE_BACKOFF {
            return Pulled::Failed;
        }
        let outcome = async {
            let Some(endpoint) = self
                .store
                .platform_ca_publication()
                .await
                .map_err(|e| e.to_string())?
            else {
                return Ok(Pulled::Unconfigured);
            };
            let endpoint = url::Url::parse(&endpoint).map_err(|e| e.to_string())?;
            let set = source.fetch(&endpoint).await?;
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
    /// organization `recipient` at `at`, on a complete path to a platform
    /// intermediate the held set admits, under the profiles of `allocation`.
    /// A passport and chain accepted before are not validated again while
    /// every certificate of the path and the held answer stay valid; the
    /// holder's proof over a presentation is verified every time.
    pub async fn accept_passport(
        &self,
        allocation: ContextAllocation,
        certificate: &[u8],
        chain: &[Vec<u8>],
        recipient: Uuid,
        at: SystemTime,
    ) -> Result<Passport, RecipientError> {
        let now = seconds(at)?;
        let view = self.view(now).await?;
        let key = admitted_paths::key(allocation_tag(allocation), recipient, certificate, chain);
        if let Some(passport) = view.reused(&key, now).await {
            return Ok(passport);
        }
        let accepted = accept_passport(
            &self.verdict.path(),
            &PassportProfile::of(allocation).map_err(no_profile)?,
            &PurposeProfile::of(allocation).map_err(no_profile)?,
            certificate,
            chain,
            &view.held.anchors,
            recipient,
            at,
        )
        .map_err(RecipientError::Path)?;
        // The path's CA under the platform anchor stands only while the
        // anchor's published status says so; the result is reused no longer
        // than that status is evidence.
        let status_until = issued_ca_status(&view.held, &accepted.path, None, now)?;
        // A Corporate passport stands only while its own issuer's published
        // status says so.
        let leaf_until = match (accepted.passport.source_org, accepted.path.issuers.first()) {
            (Some(_), Some(issuer)) => Some(self.leaf_status(issuer, certificate, now).await?),
            _ => None,
        };
        let until = [status_until, leaf_until]
            .into_iter()
            .flatten()
            .fold(seconds(accepted.until)?, i64::min);
        view.keep(key, accepted.passport.clone(), until, now).await;
        Ok(accepted.passport)
    }

    /// Accepts the Binding presentation `jws` as its holder's answer to the
    /// pending request `expected` at `at`: the passport it carries is
    /// accepted as [`Self::accept_passport`] accepts one; the holder's proof
    /// is verified with that passport's key every time; and the statement is
    /// the passport's own for exactly the pending challenge and verifier
    /// context. The caller consumes the challenge.
    pub async fn accept_presentation(
        &self,
        allocation: ContextAllocation,
        jws: &[u8],
        expected: &Expected<'_>,
        at: SystemTime,
    ) -> Result<Passport, RecipientError> {
        let envelope = Envelope::parse(jws).map_err(RecipientError::Presentation)?;
        let statement = Statement::read(&envelope.payload).map_err(RecipientError::Presentation)?;
        let passport = self
            .accept_passport(
                allocation,
                &statement.certificate,
                &statement.chain,
                expected.recipient,
                at,
            )
            .await?;
        self.verdict
            .holder(&envelope, &statement.certificate)
            .map_err(RecipientError::Presentation)?;
        statement
            .admit(&passport, expected)
            .map_err(RecipientError::Presentation)?;
        Ok(passport)
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
        if view.held.anchors.is_empty() {
            return Ok(None);
        }
        let anchors = view
            .held
            .anchors
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                RecipientError::Store(sid_core::Error::Storage(format!(
                    "a held platform certificate: {e}"
                )))
            })?;
        Ok([
            ContextAllocation::Development,
            ContextAllocation::Production,
        ]
        .into_iter()
        .find(|allocation| {
            PurposeProfile::of(*allocation).is_ok_and(|purposes| {
                anchors.iter().all(|anchor| {
                    purposes
                        .issuer_roles(anchor)
                        .is_ok_and(|roles| roles.contains(&IssuerRole::PlatformIntermediate))
                })
            })
        }))
    }

    /// Until when the passport `certificate`, issued by the authority
    /// certificate `issuer` (both DER), is shown not revoked at `now`. A
    /// passport of this installation's own authority is answered from its
    /// own record; another organization's from the status that organization
    /// published and this installation holds.
    async fn leaf_status(
        &self,
        issuer: &[u8],
        certificate: &[u8],
        now: i64,
    ) -> Result<i64, RecipientError> {
        let serial = serial_of(certificate)?;
        if let Some(own) = &self.own
            && let Some(until) = own.standing(issuer, &serial, now).await?
        {
            return Ok(until);
        }
        let status = self.store.held_issuer_status(&issuer_name(issuer)).await?;
        match status.admits(&serial, now) {
            // Admitted only under a list in its time, which names its end.
            Ok(()) => status
                .until
                .ok_or(RecipientError::PassportStatusUnavailable),
            Err(StatusRefusal::Revoked) => Err(RecipientError::PassportRevoked),
            Err(StatusRefusal::Unavailable) => Err(RecipientError::PassportStatusUnavailable),
        }
    }

    /// Accepts the authority `certificate` (DER) of `organization`, with the
    /// `chain` presented above it, at `at`: on a complete path to a held
    /// platform anchor, scoped to exactly that organization, and shown not
    /// revoked by the generation that issued it. No held status of it is
    /// [`RecipientError::Status`] with [`StatusRefusal::Unavailable`]: not
    /// shown either way.
    pub async fn accept_organization_ca(
        &self,
        allocation: ContextAllocation,
        organization: Uuid,
        certificate: &[u8],
        chain: &[Vec<u8>],
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
        issued_ca_status(&view.held, &path, Some(certificate), now)?;
        Ok(())
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
    /// changes only what it revokes.
    pub async fn record_issuer_status(
        &self,
        allocation: ContextAllocation,
        organization: Uuid,
        certificate: &[u8],
        chain: &[Vec<u8>],
        crl: &[u8],
        at: SystemTime,
    ) -> Result<(), RecipientError> {
        self.accept_organization_ca(allocation, organization, certificate, chain, at)
            .await?;
        let verified = self
            .verdict
            .status(crl, certificate)
            .map_err(RecipientError::List)?;
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
    async fn platform_allocation(
        &self,
        at: SystemTime,
    ) -> Result<Option<ContextAllocation>, RecipientError> {
        Recipient::platform_allocation(self, at).await
    }

    async fn accept_presentation(
        &self,
        allocation: ContextAllocation,
        jws: &[u8],
        expected: &Expected<'_>,
        at: SystemTime,
    ) -> Result<Passport, RecipientError> {
        Recipient::accept_presentation(self, allocation, jws, expected, at).await
    }
}

#[cfg(test)]
mod tests;
