// SPDX-License-Identifier: AGPL-3.0-only
//! This installation as a site of the federation: its key, its enrollment
//! by the platform, and what it states about whom it admits.
//!
//! In plain words: to receive employees of other organizations, an
//! installation first makes itself known to the platform. It creates one
//! key of its own and hands the public half, with the addresses it is
//! entered at, to its organization's manager, who has the platform certify
//! them. The installation keeps the certificate it gets back. From then on
//! it can state, signed with that key, whom it admits at each of its
//! entries, and another organization's installation can check that
//! statement before sending anyone here.
//!
//! Nothing here calls the platform: the request and the certificate travel
//! through the administrator. The installation never certifies anything and
//! decides nothing for anyone else: a signed statement repeats its own
//! stored login settings.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sid_authn::caller::{Caller, CallerError};
use sid_authn::instance_secret::{self, InstanceSecretError};
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::Error as SidError;
use sid_core::models::{
    AdmissionPublication, AuditEntry, InstanceSecret, IssuerAuthority, MutationContext, OrgId,
    SiteEnrollment,
};
use sid_core::models::{ClaimedWork, NewWork, SITE_ADMISSION_PUBLICATION_KIND, WorkKind};
use sid_fed::admission::{Admission, sealed};
use sid_fed::participant::{Mount, Participant, key_record};
use sid_fed::passport_path::AcceptedParticipant;
use sid_fed::recipient::{PresentedIdentities, RecipientError};
use sid_fed::site_key::{SiteKey, SiteKeyError};
use sid_keys::KeyManager;
use sid_plugin::site_admission::{AdmissionPublisher, PublishError, Published};
use sid_plugin::storage::StorageBackend;

/// How many times a certificate is held again when another one lands
/// between its read and its write.
const WRITE_ATTEMPTS: usize = 4;

/// Why a site operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum FederationSiteError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// The site's key could not be made, opened or used.
    #[error("site key: {0}")]
    Key(String),
    /// The certificate is not an enrolled site's on a path this installation
    /// admits, or its status forbids relying on it.
    #[error(transparent)]
    Refused(RecipientError),
    /// The certificate certifies another key than this site's.
    #[error("the certificate is for another key than this site's")]
    AnotherKey,
    /// The certificate enrolls a site of another organization.
    #[error("the certificate is for another organization than this installation's")]
    AnotherOrganization,
    /// The certificate lists an entry this installation does not serve, or
    /// a statement was asked for one its certificate does not list.
    #[error("{0} is not an entry of this site")]
    NotAnEntry(String),
    /// The installation holds no enrollment yet.
    #[error("this installation is not enrolled as a site")]
    NotEnrolled,
    /// Other certificates kept landing between this one's read and write.
    #[error("the site enrollment kept changing")]
    Contended,
}

impl FederationSiteError {
    /// Whether the evidence to decide on is missing now, rather than the
    /// request refused: the same request may be retried.
    pub fn undecided(&self) -> bool {
        match self {
            Self::Refused(refused) => refused.undecided(),
            Self::Store(_) | Self::Contended => true,
            _ => false,
        }
    }
}

impl From<SiteKeyError> for FederationSiteError {
    fn from(e: SiteKeyError) -> Self {
        Self::Key(e.to_string())
    }
}

impl From<InstanceSecretError<SiteKeyError>> for FederationSiteError {
    fn from(e: InstanceSecretError<SiteKeyError>) -> Self {
        match e {
            InstanceSecretError::Storage(e) => Self::Store(e),
            other => Self::Key(other.to_string()),
        }
    }
}

/// What the organization's manager takes to the platform to have this site
/// enrolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    /// The site's public key (DER `SubjectPublicKeyInfo`).
    pub public_key: Vec<u8>,
    /// The TXT value publishing that key under the organization's verified
    /// domain, at the `_sid-fed` name.
    pub key_record: String,
    /// The addresses this installation is entered at.
    pub mounts: Vec<Mount>,
}

/// The site of one installation.
pub struct FederationSite {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn KeyManager>,
    identities: Arc<dyn PresentedIdentities>,
    /// The organization this installation serves.
    organization: OrgId,
}

impl FederationSite {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        keys: Arc<dyn KeyManager>,
        identities: Arc<dyn PresentedIdentities>,
        organization: OrgId,
    ) -> Self {
        Self {
            storage,
            keys,
            identities,
            organization,
        }
    }

    /// The site's key, made and sealed on first use: every replica opens
    /// the one stored first.
    async fn key(&self) -> Result<SiteKey, FederationSiteError> {
        let sealed = instance_secret::load_or_create(
            self.storage.as_ref(),
            self.keys.as_ref(),
            InstanceSecret::FederationSiteKey,
            SiteKey::generate,
        )
        .await?;
        Ok(SiteKey::read(&sealed)?)
    }

    /// The addresses this installation is entered at: the exact URLs of the
    /// issuers it serves for its own organization.
    async fn served(&self) -> Result<Vec<Mount>, FederationSiteError> {
        let mut mounts = Vec::new();
        for issuer in self.storage.list_oidc_issuers().await? {
            if issuer.authority != IssuerAuthority::Local
                || issuer.recipient_org != self.organization
            {
                continue;
            }
            // An issuer URL that is not a mount (it would not be `https`)
            // is no entry another installation can be sent to.
            if let Some(mount) = Mount::parse(&issuer.canonical_url) {
                mounts.push(mount);
            }
        }
        Ok(mounts)
    }

    /// What to take to the platform to enroll this site, for an
    /// administrator. Asking again answers the same key.
    pub async fn enrollment_request(
        &self,
        caller: &Caller,
    ) -> Result<EnrollmentRequest, FederationSiteError> {
        caller.require_admin()?;
        let public_key = self.key().await?.public_key()?;
        Ok(EnrollmentRequest {
            key_record: key_record(&public_key),
            public_key,
            mounts: self.served().await?,
        })
    }

    /// `certificate` and the `chain` above it, accepted as this site's
    /// enrollment now: an enrolled site's certificate under the
    /// installation's status policy, for this site's key, this
    /// installation's organization and only entries it serves.
    async fn accept(
        &self,
        certificate: &[u8],
        chain: &[Vec<u8>],
        at: SystemTime,
    ) -> Result<AcceptedParticipant, FederationSiteError> {
        let policy = crate::login_settings::in_force(self.storage.as_ref())
            .await?
            .status_policy;
        let accepted = self
            .identities
            .accept_participant(certificate, chain, &policy, at)
            .await
            .map_err(FederationSiteError::Refused)?;
        if accepted.public_key != self.key().await?.public_key()? {
            return Err(FederationSiteError::AnotherKey);
        }
        if accepted.participant.organization != self.organization.into_uuid() {
            return Err(FederationSiteError::AnotherOrganization);
        }
        let served = self.served().await?;
        if let Some(elsewhere) = accepted
            .participant
            .mounts
            .iter()
            .find(|mount| !served.contains(mount))
        {
            return Err(FederationSiteError::NotAnEntry(elsewhere.to_string()));
        }
        Ok(accepted)
    }

    /// Hold the certificate the platform issued for this site, with the
    /// `chain` above it, for an administrator; a renewal replaces the one
    /// held. Holding the certificate already held changes nothing.
    pub async fn hold(
        &self,
        caller: &Caller,
        certificate: Vec<u8>,
        chain: Vec<Vec<u8>>,
    ) -> Result<Participant, FederationSiteError> {
        caller.require_admin()?;
        let accepted = self.accept(&certificate, &chain, SystemTime::now()).await?;
        let enrollment = SiteEnrollment { certificate, chain };
        for _ in 0..WRITE_ATTEMPTS {
            let held = self.storage.site_enrollment().await?;
            if held.as_ref() == Some(&enrollment) {
                return Ok(accepted.participant);
            }
            let mut audit = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "federation_site.hold_enrollment",
                "site_enrollment",
            ));
            // The platform holds statements signed under the certificate it
            // knows; a first or renewed one owes it the current statements.
            audit
                .work
                .push(AdmissionPublication::Enrollment(&enrollment).work());
            if self
                .storage
                .set_site_enrollment(&enrollment, held.as_ref(), audit)
                .await?
            {
                return Ok(accepted.participant);
            }
        }
        Err(FederationSiteError::Contended)
    }

    /// The site this installation is enrolled as, for an administrator;
    /// none before a certificate was held. The held certificate is accepted
    /// again now: one the platform withdrew since is an error, not a site.
    pub async fn enrolled(
        &self,
        caller: &Caller,
    ) -> Result<Option<Participant>, FederationSiteError> {
        caller.require_admin()?;
        let Some(held) = self.storage.site_enrollment().await? else {
            return Ok(None);
        };
        Ok(Some(
            self.accept(&held.certificate, &held.chain, SystemTime::now())
                .await?
                .participant,
        ))
    }

    /// The site's signed statement of whom this installation admits at its
    /// entry `mount`, for an administrator: the stored login settings as
    /// they are now, good while the site's certificate is. The statement
    /// decides nothing here: every arrival is decided again from the
    /// settings in force then.
    pub async fn admission(
        &self,
        caller: &Caller,
        mount: &Mount,
    ) -> Result<Vec<u8>, FederationSiteError> {
        caller.require_admin()?;
        let now = SystemTime::now();
        let held = self
            .storage
            .site_enrollment()
            .await?
            .ok_or(FederationSiteError::NotEnrolled)?;
        let accepted = self.accept(&held.certificate, &held.chain, now).await?;
        if !accepted.participant.admits(mount) {
            return Err(FederationSiteError::NotAnEntry(mount.to_string()));
        }
        self.signed(held, &accepted, mount, now).await
    }

    /// The statements of every entry the held certificate lists, signed now
    /// from the stored settings: what the platform is owed. None before a
    /// certificate is held.
    pub(crate) async fn statements(&self) -> Result<Vec<Vec<u8>>, FederationSiteError> {
        let now = SystemTime::now();
        let Some(held) = self.storage.site_enrollment().await? else {
            return Ok(Vec::new());
        };
        let accepted = self.accept(&held.certificate, &held.chain, now).await?;
        let mut statements = Vec::with_capacity(accepted.participant.mounts.len());
        for mount in &accepted.participant.mounts {
            statements.push(self.signed(held.clone(), &accepted, mount, now).await?);
        }
        Ok(statements)
    }

    /// The statement of `mount` under the held certificate `held`, accepted
    /// as `accepted`, signed at `now` from the settings stored now.
    async fn signed(
        &self,
        held: SiteEnrollment,
        accepted: &AcceptedParticipant,
        mount: &Mount,
        now: SystemTime,
    ) -> Result<Vec<u8>, FederationSiteError> {
        let settings = crate::login_settings::in_force(self.storage.as_ref()).await?;
        let second = |at: SystemTime| {
            at.duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
                .ok_or_else(|| FederationSiteError::Key("a time outside the epoch".into()))
        };
        let mut admitted_sources: Vec<uuid::Uuid> = settings
            .admitted_sources
            .as_slice()
            .iter()
            .map(|id| id.into_uuid())
            .collect();
        admitted_sources.sort_unstable();
        let statement = Admission {
            recipient_org: accepted.participant.organization,
            site: accepted.participant.site,
            mount: mount.clone(),
            revision: settings.revision,
            allow_personal_profiles: settings.allow_personal_profiles,
            allow_foreign_corporate_profiles: settings.allow_foreign_corporate_profiles,
            admitted_sources,
            not_before: second(now)?,
            // No longer than the certificate and its path stand.
            not_after: second(accepted.until)?,
            certificate: held.certificate,
            chain: held.chain,
        };
        let key = self.key().await?;
        sealed(&statement.payload(), |input| {
            Ok::<_, FederationSiteError>(key.sign(input))
        })
    }
}

/// Delivers the site's statements to the platform its build names, as the
/// login settings and the held certificate stand when the work runs: a
/// later change owes its own delivery, and a lost one is tried again.
/// Delivery never gates the site: it enforces its own settings meanwhile.
pub struct AdmissionPublications {
    kind: WorkKind,
    site: Arc<FederationSite>,
    /// The transport; none for a build that names no platform, which has
    /// nobody to tell.
    publisher: Option<Arc<dyn AdmissionPublisher>>,
}

impl AdmissionPublications {
    pub fn new(site: Arc<FederationSite>, publisher: Option<Arc<dyn AdmissionPublisher>>) -> Self {
        Self {
            kind: WorkKind::new(SITE_ADMISSION_PUBLICATION_KIND)
                .expect("the publication kind is valid"),
            site,
            publisher,
        }
    }
}

/// The delays between attempts: soon after a blip, then hourly while the
/// platform stays away.
const PUBLICATION_RETRIES: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(10),
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(900),
    Duration::from_secs(3600),
]);

#[async_trait::async_trait]
impl WorkHandler for AdmissionPublications {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        PUBLICATION_RETRIES
    }

    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, _work: &ClaimedWork) -> WorkOutcome {
        let Some(publisher) = &self.publisher else {
            return WorkOutcome::Done(Some("this build names no platform".into()));
        };
        let statements = match self.site.statements().await {
            Ok(statements) => statements,
            Err(e) if e.undecided() => return WorkOutcome::Retry(e.to_string()),
            // A certificate that no longer stands has nothing to state; a
            // renewal held later owes its own delivery.
            Err(e) => return WorkOutcome::Done(Some(format!("nothing to publish: {e}"))),
        };
        if statements.is_empty() {
            return WorkOutcome::Done(Some("not enrolled".into()));
        }
        for statement in &statements {
            match publisher.publish(statement).await {
                Ok(Published::Held | Published::Superseded) => {}
                Err(PublishError::Unavailable(why)) => return WorkOutcome::Retry(why),
                Err(PublishError::Refused(why)) => return WorkOutcome::Permanent(why),
            }
        }
        WorkOutcome::Done(Some(format!("{} entries published", statements.len())))
    }
}

#[cfg(test)]
mod tests;
