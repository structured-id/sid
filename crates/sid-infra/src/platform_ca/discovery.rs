// SPDX-License-Identifier: AGPL-3.0-only
//! The platform's CA discovery record, `_sid-ca.<platform name>` TXT, as a
//! verifier reads it: one record per published generation a path may end at,
//! `v=1;gen=<N>;alg=<algorithms>;sha256=<base64 DER fingerprint>;url=<the
//! publication>`.
//!
//! A record identifies a generation and the exact certificate it stands for,
//! and names the publication that states the set. It carries no revision,
//! state or freshness: those stay with the publication and with the holder
//! that applies it. Records are read only from a DNSSEC-secure answer
//! ([`DiscoveryResolver`], feature `platform-ca-dns`), and a fetched set is
//! taken on this step only when it matches them exactly ([`check`]).

use std::str::FromStr;

use base64::Engine;
use sha2::{Digest, Sha256};
use sid_proto::sid::v1::{PlatformCaState, PlatformCas};

/// The label the record is published under, below the platform name.
pub const RECORD_LABEL: &str = "_sid-ca";
/// The most records read: a few overlapping generations, with ample room.
pub const MAX_RECORDS: usize = 16;

/// A key algorithm a published generation's certificate carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    EcdsaP256,
    MlDsa65,
}

impl KeyAlgorithm {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "ecdsa-p256" => Some(Self::EcdsaP256),
            "ml-dsa-65" => Some(Self::MlDsa65),
            _ => None,
        }
    }

    /// The name a record writes the algorithm with.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }
}

/// One discovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub generation: u32,
    /// The generation's key algorithms, at least one, each once.
    pub algorithms: Vec<KeyAlgorithm>,
    /// SHA-256 of the generation's certificate (DER).
    pub fingerprint: [u8; 32],
    /// The publication that states the set.
    pub publication: url::Url,
}

/// Why a record was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("the discovery record is not version 1")]
    Version,
    #[error("the discovery record's {0} is missing")]
    Missing(&'static str),
    #[error("the discovery record's {0} is malformed")]
    Malformed(&'static str),
    #[error("the discovery record names generation {0} more than once")]
    DuplicateGeneration(u32),
    #[error("more than {MAX_RECORDS} discovery records")]
    TooMany,
}

impl FromStr for DiscoveryRecord {
    type Err = RecordError;

    /// A record's text. `v=1` comes first; every other field once, none
    /// unknown: a record with a field this version does not define is
    /// another version's.
    fn from_str(text: &str) -> Result<Self, RecordError> {
        let mut fields = text.split(';');
        if fields.next() != Some("v=1") {
            return Err(RecordError::Version);
        }
        let (mut generation, mut algorithms, mut fingerprint, mut publication) =
            (None, None, None, None);
        for field in fields {
            let (key, value) = field
                .split_once('=')
                .ok_or(RecordError::Malformed("field"))?;
            let slot_taken = match key {
                "gen" => generation.replace(parse_generation(value)?).is_some(),
                "alg" => algorithms.replace(parse_algorithms(value)?).is_some(),
                "sha256" => fingerprint.replace(parse_fingerprint(value)?).is_some(),
                "url" => publication.replace(parse_publication(value)?).is_some(),
                _ => return Err(RecordError::Malformed("field")),
            };
            if slot_taken {
                return Err(RecordError::Malformed("field"));
            }
        }
        Ok(Self {
            generation: generation.ok_or(RecordError::Missing("gen"))?,
            algorithms: algorithms.ok_or(RecordError::Missing("alg"))?,
            fingerprint: fingerprint.ok_or(RecordError::Missing("sha256"))?,
            publication: publication.ok_or(RecordError::Missing("url"))?,
        })
    }
}

fn parse_generation(value: &str) -> Result<u32, RecordError> {
    // Decimal digits only: `u32::from_str` would also take a sign.
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RecordError::Malformed("gen"));
    }
    match value.parse::<u32>() {
        Ok(0) | Err(_) => Err(RecordError::Malformed("gen")),
        Ok(generation) => Ok(generation),
    }
}

fn parse_algorithms(value: &str) -> Result<Vec<KeyAlgorithm>, RecordError> {
    let mut algorithms = Vec::new();
    for name in value.split('+') {
        let algorithm = KeyAlgorithm::parse(name).ok_or(RecordError::Malformed("alg"))?;
        if algorithms.contains(&algorithm) {
            return Err(RecordError::Malformed("alg"));
        }
        algorithms.push(algorithm);
    }
    Ok(algorithms)
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32], RecordError> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RecordError::Malformed("sha256"))
}

fn parse_publication(value: &str) -> Result<url::Url, RecordError> {
    url::Url::parse(value)
        .ok()
        .filter(|url| url.scheme() == "https")
        .ok_or(RecordError::Malformed("url"))
}

/// The records `texts` state: each read, no generation twice, at most
/// [`MAX_RECORDS`].
pub fn parse_records<S: AsRef<str>>(texts: &[S]) -> Result<Vec<DiscoveryRecord>, RecordError> {
    if texts.len() > MAX_RECORDS {
        return Err(RecordError::TooMany);
    }
    let mut records: Vec<DiscoveryRecord> = Vec::with_capacity(texts.len());
    for text in texts {
        let record: DiscoveryRecord = text.as_ref().parse()?;
        if records.iter().any(|r| r.generation == record.generation) {
            return Err(RecordError::DuplicateGeneration(record.generation));
        }
        records.push(record);
    }
    Ok(records)
}

/// How a fetched set disagrees with the discovery records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryMismatch {
    #[error("no discovery record is published")]
    NoRecords,
    #[error("the discovery record of generation {0} names another publication")]
    OtherPublication(u32),
    #[error("generation {0} of the set has no discovery record")]
    Unlisted(u32),
    #[error("generation {0} of the set is not the certificate its record names")]
    Fingerprint(u32),
    #[error("the discovery record names generation {0}, which the set does not anchor")]
    NotInSet(u32),
}

/// Whether `set`, fetched from `publication`, is exactly what `records`
/// announce: every record names `publication`, every generation a path may
/// end at (active or verification-only) has a record with its certificate's
/// fingerprint, and every record such a generation. A withdrawn generation
/// is announced by the set alone and needs no record.
pub fn check(
    set: &PlatformCas,
    records: &[DiscoveryRecord],
    publication: &url::Url,
) -> Result<(), DiscoveryMismatch> {
    if records.is_empty() {
        return Err(DiscoveryMismatch::NoRecords);
    }
    if let Some(record) = records.iter().find(|r| &r.publication != publication) {
        return Err(DiscoveryMismatch::OtherPublication(record.generation));
    }
    let anchoring = |state: i32| {
        matches!(
            PlatformCaState::try_from(state),
            Ok(PlatformCaState::Active | PlatformCaState::VerificationOnly)
        )
    };
    let anchors: Vec<_> = set
        .generations
        .iter()
        .filter(|g| anchoring(g.state))
        .collect();
    for generation in &anchors {
        let record = records
            .iter()
            .find(|r| r.generation == generation.generation)
            .ok_or(DiscoveryMismatch::Unlisted(generation.generation))?;
        let fingerprint: [u8; 32] = Sha256::digest(&generation.certificate).into();
        if fingerprint != record.fingerprint {
            return Err(DiscoveryMismatch::Fingerprint(generation.generation));
        }
    }
    if let Some(record) = records
        .iter()
        .find(|r| !anchors.iter().any(|g| g.generation == r.generation))
    {
        return Err(DiscoveryMismatch::NotInSet(record.generation));
    }
    Ok(())
}

/// The platform name the records of `publication` are published under: its
/// host, when that is a DNS name.
pub fn platform_name(publication: &url::Url) -> Option<&str> {
    match publication.host()? {
        url::Host::Domain(name) => Some(name),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
    }
}

#[cfg(feature = "platform-ca-dns")]
pub use resolver::{DiscoveryError, DiscoveryResolver};

#[cfg(feature = "platform-ca-dns")]
mod resolver {
    use std::time::Duration;

    use hickory_resolver::TokioResolver;
    use hickory_resolver::proto::dnssec::Proof;
    use hickory_resolver::proto::rr::{Name, RData, RecordType};

    use super::{DiscoveryRecord, RECORD_LABEL, RecordError, parse_records, platform_name};

    /// The longest wait for one server's answer, and for the whole lookup
    /// with its validation chain.
    const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
    const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

    /// Why no records were read.
    #[derive(Debug, thiserror::Error)]
    pub enum DiscoveryError {
        /// The publication's host is not a DNS name.
        #[error("the publication's host is not a DNS name")]
        NoName,
        /// The lookup failed: no answer, no such record, or a chain that does
        /// not validate.
        #[error("the discovery record did not resolve: {0}")]
        Unavailable(String),
        /// An answer was not proven by DNSSEC from the root.
        #[error("the discovery record is not DNSSEC-secure")]
        NotSecure,
        #[error(transparent)]
        Record(#[from] RecordError),
    }

    /// Reads discovery records through a validating resolver: the system's
    /// name servers, the IANA root trust anchors.
    pub struct DiscoveryResolver {
        resolver: TokioResolver,
    }

    impl DiscoveryResolver {
        /// The resolver over the system configuration.
        pub fn new() -> Result<Self, DiscoveryError> {
            let builder = TokioResolver::builder_tokio()
                .map_err(|e| DiscoveryError::Unavailable(e.to_string()))?;
            Self::from_builder(builder)
        }

        /// The resolver over `builder`'s name servers, validating.
        pub(super) fn from_builder(
            mut builder: hickory_resolver::ResolverBuilder<
                hickory_resolver::net::runtime::TokioRuntimeProvider,
            >,
        ) -> Result<Self, DiscoveryError> {
            let options = builder.options_mut();
            options.validate = true;
            options.timeout = QUERY_TIMEOUT;
            let resolver = builder
                .build()
                .map_err(|e| DiscoveryError::Unavailable(e.to_string()))?;
            Ok(Self { resolver })
        }

        /// The records announced for `publication`, from a secure answer only.
        pub async fn records(
            &self,
            publication: &url::Url,
        ) -> Result<Vec<DiscoveryRecord>, DiscoveryError> {
            let platform = platform_name(publication).ok_or(DiscoveryError::NoName)?;
            let name = Name::from_ascii(format!("{RECORD_LABEL}.{platform}."))
                .map_err(|_| DiscoveryError::NoName)?;
            let lookup = tokio::time::timeout(
                LOOKUP_TIMEOUT,
                self.resolver.lookup(name.clone(), RecordType::TXT),
            )
            .await
            .map_err(|_| DiscoveryError::Unavailable("timed out".into()))?
            .map_err(|e| DiscoveryError::Unavailable(e.to_string()))?;
            let mut texts = Vec::new();
            for record in lookup.answers() {
                let RData::TXT(txt) = &record.data else {
                    continue;
                };
                if record.name != name {
                    continue;
                }
                if record.proof != Proof::Secure {
                    return Err(DiscoveryError::NotSecure);
                }
                // One record's character-strings form one text (RFC 7208
                // §3.3 joins them the same way).
                let mut text = Vec::new();
                for part in &txt.txt_data {
                    text.extend_from_slice(part);
                }
                texts.push(String::from_utf8(text).map_err(|_| RecordError::Malformed("text"))?);
            }
            Ok(parse_records(&texts)?)
        }
    }
}

#[cfg(test)]
mod tests;
