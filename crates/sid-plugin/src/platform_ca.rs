// SPDX-License-Identifier: AGPL-3.0-only
//! The admitted platform CA set an installation verifies SID credentials
//! under: the platform intermediates a certificate path may end at, as the
//! platform last published them, and the status each of them published of
//! the CA certificates it issued. A recipient of a federated sign-in holds
//! this set whether or not it issues anything itself.
//!
//! What a store keeps only ever narrows: a set older than the one held is
//! refused, a generation's state moves from active to verification-only to
//! withdrawn and never back, a generation number keeps the certificate it
//! was first published with, and a revocation seen once stays. A set past
//! its refresh time is not current evidence: anchors are refused rather than
//! read from it.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sid_core::models::MutationContext;

/// What the installation may anchor on a platform generation for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PlatformCaState {
    /// Currently issuing.
    Active,
    /// Replaced; paths through it are accepted until its overlap end.
    VerificationOnly,
    /// No path through it is accepted.
    Withdrawn,
}

impl PlatformCaState {
    /// The stored name of the state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::VerificationOnly => "verification_only",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// The narrowing order a store keeps: a state never moves to a lower one.
    pub const fn rank(self) -> i64 {
        match self {
            Self::Active => 0,
            Self::VerificationOnly => 1,
            Self::Withdrawn => 2,
        }
    }

    /// The state a store kept under `rank`.
    pub const fn from_rank(rank: i64) -> Option<Self> {
        match rank {
            0 => Some(Self::Active),
            1 => Some(Self::VerificationOnly),
            2 => Some(Self::Withdrawn),
            _ => None,
        }
    }
}

/// The held set's revision and freshness, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldSet {
    pub revision: u64,
    pub issued_at: i64,
    pub next_update: i64,
}

/// One generation as a store keeps it: the narrowest state it was ever
/// published in, and the revision that last listed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldGeneration {
    pub generation: u32,
    pub certificate: Vec<u8>,
    pub state: PlatformCaState,
    pub overlap_end: Option<i64>,
    pub listed_in: u64,
}

/// Everything a store holds, as stored, for a move to another store: the
/// generations and status in generation order, revoked serials in byte
/// order. A moved installation keeps every narrowing the source had seen.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PlatformCaArchive {
    pub publication: Option<String>,
    pub set: Option<HeldSet>,
    pub generations: Vec<HeldGeneration>,
    pub status: Vec<GenerationStatus>,
    /// The status held of the authorities below the platform, in the order
    /// of their names.
    pub issuers: Vec<IssuerStatus>,
}

impl PlatformCaArchive {
    /// How many stored records the archive carries.
    pub fn len(&self) -> usize {
        usize::from(self.publication.is_some())
            + usize::from(self.set.is_some())
            + self.generations.len()
            + self.status.len()
            + self.issuers.len()
    }

    /// Whether the source held nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One published platform generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCa {
    pub generation: u32,
    /// The intermediate's certificate (DER).
    pub certificate: Vec<u8>,
    pub state: PlatformCaState,
    /// End of a verification-only generation's overlap (seconds since the
    /// epoch); none for the other states.
    pub overlap_end: Option<i64>,
    /// The generation's CRL (DER) as published; none when it publishes none.
    /// A store does not keep it: its caller authenticates it and records
    /// what it says with [`PlatformCaStore::record_platform_ca_status`].
    pub crl: Option<Vec<u8>>,
}

/// A generation's CRL, authenticated under the generation's certificate: the
/// status of the CA certificates it issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationStatus {
    pub generation: u32,
    /// The CRL's number: a lower one than the one held changes nothing.
    pub number: u64,
    /// The CRL's nextUpdate (seconds since the epoch): after it the status is
    /// no evidence.
    pub next_update: i64,
    /// The serials it revokes, as their DER INTEGER contents.
    pub revoked: Vec<Vec<u8>>,
}

/// The CRL of an authority below the platform (an organization's CA),
/// authenticated under that authority's certificate: the status of the
/// certificates it issued. An issuer is one exact certificate, named by the
/// SHA-256 of its DER: a serial means something only under the key and
/// generation that issued it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerStatus {
    /// SHA-256 of the issuing certificate (DER).
    pub issuer: [u8; 32],
    /// The CRL's number: a lower one than the one held changes nothing.
    pub number: u64,
    /// The CRL's nextUpdate (seconds since the epoch): after it the status is
    /// no evidence.
    pub next_update: i64,
    /// The serials it revokes, as their DER INTEGER contents.
    pub revoked: Vec<Vec<u8>>,
}

/// What is known of the certificates one authority issued: a platform
/// generation's CA certificates, or an organization CA's passports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorStatus {
    /// Until when the held CRL is evidence (seconds since the epoch); none
    /// when no CRL of the generation was ever accepted.
    pub until: Option<i64>,
    /// Every serial the generation was seen to revoke, in byte order. A
    /// revocation seen once stays, whatever a later or older CRL lists.
    pub revoked: Vec<Vec<u8>>,
}

impl AnchorStatus {
    /// Whether the CA certificate with `serial`, issued by this anchor, may
    /// be relied on at `now`: not revoked, under a CRL still in its time.
    pub fn admits(&self, serial: &[u8], now: i64) -> Result<(), StatusRefusal> {
        if self.revoked.iter().any(|r| r.as_slice() == serial) {
            return Err(StatusRefusal::Revoked);
        }
        match self.until {
            Some(until) if now <= until => Ok(()),
            _ => Err(StatusRefusal::Unavailable),
        }
    }
}

/// Why an issued CA certificate is not relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StatusRefusal {
    /// Its issuer revoked it.
    #[error("the issuing platform generation revoked the CA certificate")]
    Revoked,
    /// No CRL of its issuer is held within its time: absence of a
    /// revocation is not shown.
    #[error("no current status of the CA certificate is held")]
    Unavailable,
}

/// A published set at one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCaSet {
    pub revision: u64,
    pub generations: Vec<PlatformCa>,
    /// When the platform made the statement, and by when it must be renewed
    /// (seconds since the epoch).
    pub issued_at: i64,
    pub next_update: i64,
}

/// The anchors of the held revision at one moment, and until when they are
/// that revision's current evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAnchors {
    pub revision: u64,
    /// The certificates (DER) a path may end at, newest generation first.
    pub anchors: Vec<Vec<u8>>,
    /// The status each anchor holds of the CA certificates it issued, in the
    /// anchors' order.
    pub status: Vec<AnchorStatus>,
    /// The earliest of the set's refresh time and the overlap ends of the
    /// verification-only generations among the anchors (seconds since the
    /// epoch): from then on the answer must be read again.
    pub until: i64,
    /// Halfway through the set's freshness: from then on a configured
    /// publication is asked for a newer set, while this one still holds.
    pub renew_at: i64,
}

/// What applying a set did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The set is held now (or was already).
    Current,
    /// A newer set is held; this one changed nothing.
    Stale,
}

/// Why the store refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PlatformCaError {
    #[error("platform CA store: {0}")]
    Storage(#[from] sid_core::Error),
    /// A generation number arrived with another certificate than the one held.
    #[error("platform generation {0} carries another certificate than the one held")]
    Conflict(u32),
    /// No platform set has been received.
    #[error("no platform CA set has been received")]
    NotProvisioned,
    /// The held set is past its refresh time; its states are not current.
    #[error("the platform CA set is past its refresh time")]
    Stale,
    /// A move met a store that already holds other platform CA state.
    #[error("the store already holds another platform CA set")]
    Occupied,
}

/// Where a newer platform CA set is fetched from: the publication the
/// installation configured, read by its transport. What it answers is only
/// transported: the holder checks and applies it under the store's rules.
#[async_trait]
pub trait PlatformCaSource: Send + Sync {
    /// The set the platform publishes at `endpoint` now.
    async fn fetch(&self, endpoint: &url::Url) -> Result<PlatformCaSet, String>;
}

/// The admitted platform CA set of one installation.
#[async_trait]
pub trait PlatformCaStore: Send + Sync {
    /// Hold `set` unless a newer one is held; concurrent applies end at the
    /// newest revision and the narrowest state of each generation. A
    /// generation keeps the revision that last listed it: only the held
    /// revision's generations anchor, while a generation a later set omits
    /// keeps its narrowed state. A generation number arriving with another
    /// certificate than the one held is [`PlatformCaError::Conflict`] and
    /// nothing of the set is held. A set older than the one held writes
    /// nothing, its audit entry included.
    async fn apply_platform_cas(
        &self,
        set: &PlatformCaSet,
        ctx: MutationContext,
    ) -> Result<Applied, PlatformCaError>;

    /// Hold the CRLs `status`, which the caller authenticated under their
    /// generations' certificates. Each replaces the generation's held one
    /// only with a number not lower, and every serial it revokes is kept
    /// from then on. Both only ever narrow what is relied on, so they are
    /// recorded whatever set they arrived with, an older one included.
    async fn record_platform_ca_status(
        &self,
        status: &[GenerationStatus],
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError>;

    /// The generations a path may end at, at `now` (seconds since the
    /// epoch): the active ones and the verification-only ones whose overlap
    /// has not ended, of one committed revision. Refused when no set is held
    /// ([`PlatformCaError::NotProvisioned`]) or the held one is past its
    /// refresh time ([`PlatformCaError::Stale`]).
    async fn held_platform_cas(&self, now: i64) -> Result<HeldAnchors, PlatformCaError>;

    /// The publication the set is refreshed from, when one is configured.
    async fn platform_ca_publication(&self) -> Result<Option<String>, PlatformCaError>;

    /// Configure the publication the set is refreshed from, unless one is
    /// configured already: a stored value is never replaced by a repeated
    /// provisioning. Whether it was written.
    async fn configure_platform_ca_publication(
        &self,
        publication: &str,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError>;

    /// Hold the CRL `status` of an authority below the platform, which the
    /// caller authenticated under that authority's certificate on an
    /// accepted path. It replaces the issuer's held one only with a number
    /// not lower, and every serial it revokes is kept from then on, whatever
    /// its number.
    async fn record_issuer_status(
        &self,
        status: &IssuerStatus,
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError>;

    /// What is held of the certificates `issuer` (the SHA-256 of its DER
    /// certificate) issued; nothing known of an issuer is the default
    /// status, which admits no certificate.
    async fn held_issuer_status(&self, issuer: &[u8; 32]) -> Result<AnchorStatus, PlatformCaError>;

    /// Everything the store holds, as stored.
    async fn export_platform_cas(&self) -> Result<PlatformCaArchive, PlatformCaError>;

    /// Hold `archive` exactly as its source did, in a store that holds no
    /// platform CA state. Whether it was written: a store already holding
    /// exactly `archive` (an interrupted move resumed) writes nothing, and
    /// one holding anything else is [`PlatformCaError::Occupied`].
    async fn import_platform_cas(
        &self,
        archive: &PlatformCaArchive,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError>;
}
