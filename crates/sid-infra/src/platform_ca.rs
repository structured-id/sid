// SPDX-License-Identifier: AGPL-3.0-only
//! The client of the platform's public CA publication
//! (`GET /.well-known/sid-ca/index.json`, `sid.v1.federation.PlatformCaService`):
//! the admitted platform CA set as the platform last published it, fetched
//! from the one endpoint the deployment configured.
//!
//! The client transports and decodes. It follows no redirect and takes no
//! endpoint from what it receives, and it bounds the time and the size of an
//! answer. Whether the set is admitted (its revision, narrowing and
//! withdrawal) is decided by the holder that applies it.

use std::time::Duration;

use prost::Message;
use sid_plugin::platform_ca::{PlatformCa, PlatformCaSet, PlatformCaSource, PlatformCaState};
use sid_proto::sid::v1::PlatformCas;

pub mod discovery;

/// The proto file the publication's message is defined in.
const PUBLICATION_FILE: &str = sid_proto::PLATFORM_CA_PROTO;
/// The publication's message.
const MESSAGE: &str = "sid.v1.federation.PlatformCas";
/// The longest answer read: a few generations of hybrid certificates and
/// their Roots, with ample room.
pub const MAX_BODY: usize = 1 << 20;
/// The longest wait for a connection, and for the whole answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);

/// The platform this build was made for: the origin of its public site,
/// given to the compiler by the build that made it (`SID_BUILD_PLATFORM`).
/// The installation asks that platform, and no other, for the admitted
/// platform CA set. A build made without it names no platform.
const BUILD_PLATFORM: Option<&str> = option_env!("SID_BUILD_PLATFORM");

/// Where a platform publishes its admitted CA set, below its origin.
const PUBLICATION_PATH: &str = "/.well-known/sid-ca/index.json";

/// Below which a generation's CRL is read, at `{CRL_PATH}{generation}/crl`.
const CRL_PATH: &str = "/.well-known/sid-ca/";

/// The media type of a DER CRL (RFC 2585 section 4.2).
const CRL_TYPE: &str = "application/pkix-crl";

/// The publication of the platform this build was made for; `None` for a
/// build made for none, which then verifies no identity under a platform
/// set until one is supplied to its store otherwise.
pub fn build_publication() -> Result<Option<url::Url>, PublicationError> {
    // A build argument left empty is one not given.
    BUILD_PLATFORM
        .filter(|platform| !platform.is_empty())
        .map(publication_of)
        .transpose()
}

/// The platform CA set this build carries: the publication of its platform
/// as the build that made it fetched it (see the crate's build script).
/// Empty for a build made for no platform.
const BUILD_PLATFORM_CAS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/platform_cas.json"));

/// The platform CA set this build carries, for its holder to apply at
/// start: the installation then verifies under it with no network, and the
/// publication only brings a newer one sooner than the next build. Only
/// decoded here: the holder checks and applies it under the store's rules,
/// so it never brings back a generation a newer held set withdrew. `None`
/// for a build made for no platform.
pub fn build_platform_cas() -> Result<Option<PlatformCaSet>, PublicationError> {
    carried(BUILD_PLATFORM_CAS)
}

/// The set the carried publication `body` states; none when nothing is
/// carried.
fn carried(body: &[u8]) -> Result<Option<PlatformCaSet>, PublicationError> {
    if body.is_empty() {
        return Ok(None);
    }
    if body.len() > MAX_BODY {
        return Err(PublicationError::TooLarge);
    }
    let wire = decode(&publication_message()?, body)?;
    set_of(wire)
        .map(Some)
        .map_err(|e| PublicationError::Malformed(e.to_string()))
}

/// The descriptor of the publication's message.
fn publication_message() -> Result<prost_reflect::MessageDescriptor, PublicationError> {
    let pool = prost_reflect::DescriptorPool::decode(
        sid_proto::descriptor_set_of(|file| file == PUBLICATION_FILE).as_slice(),
    )
    .map_err(|e| PublicationError::Malformed(e.to_string()))?;
    pool.get_message_by_name(MESSAGE)
        .ok_or_else(|| PublicationError::Malformed(format!("no {MESSAGE} descriptor")))
}

/// The publication's JSON `body` read as its message, by the proto3 JSON
/// mapping the transcoder writes it with.
fn decode(
    message: &prost_reflect::MessageDescriptor,
    body: &[u8],
) -> Result<PlatformCas, PublicationError> {
    let mut json = serde_json::Deserializer::from_slice(body);
    let message = prost_reflect::DynamicMessage::deserialize(message.clone(), &mut json)
        .map_err(|e| PublicationError::Malformed(e.to_string()))?;
    json.end()
        .map_err(|e| PublicationError::Malformed(e.to_string()))?;
    PlatformCas::decode(message.encode_to_vec().as_slice())
        .map_err(|e| PublicationError::Malformed(e.to_string()))
}

/// The publication of the platform whose public origin is `platform`: an
/// `https` origin, nothing after its authority.
fn publication_of(platform: &str) -> Result<url::Url, PublicationError> {
    let origin = url::Url::parse(platform).map_err(|_| PublicationError::NotHttps)?;
    let bare = origin.scheme() == "https"
        && origin.host_str().is_some()
        && matches!(origin.path(), "" | "/")
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin.username().is_empty()
        && origin.password().is_none();
    if !bare {
        return Err(PublicationError::NotHttps);
    }
    origin
        .join(PUBLICATION_PATH)
        .map_err(|_| PublicationError::NotHttps)
}

/// The publication of the installation whose issuer is `issuer`: the same
/// path at that issuer's `https` origin, where an organization publishes its
/// CA generations and their lists
/// (`arch/auth/org-ca-architecture.md` §organization-status-publication).
pub fn publication_at(issuer: &url::Url) -> Result<url::Url, PublicationError> {
    if issuer.scheme() != "https" || issuer.host_str().is_none() {
        return Err(PublicationError::NotHttps);
    }
    publication_of(&issuer.origin().ascii_serialization())
}

/// Why the publication was not read.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    /// The configured endpoint is not an HTTPS URL.
    #[error("the platform CA publication endpoint must be an https URL")]
    NotHttps,
    /// No HTTP client could be built (no TLS provider installed).
    #[error("no HTTP client for the platform CA publication: {0}")]
    Client(String),
    /// The endpoint did not answer: connection, TLS or time.
    #[error("the platform CA publication did not answer: {0}")]
    Unreachable(String),
    /// The endpoint answered with a status other than success; a redirect
    /// is one of them.
    #[error("the platform CA publication answered {0}")]
    Status(u16),
    /// The answer is larger than [`MAX_BODY`].
    #[error("the platform CA publication is larger than {MAX_BODY} bytes")]
    TooLarge,
    /// The answer is not the publication's JSON.
    #[error("the platform CA publication is malformed: {0}")]
    Malformed(String),
}

/// The platform CA publication at one configured endpoint.
pub struct PlatformCaPublication {
    client: reqwest::Client,
    endpoint: url::Url,
    message: prost_reflect::MessageDescriptor,
}

impl PlatformCaPublication {
    /// The publication at `endpoint`, which must be an `https` URL.
    pub fn new(endpoint: url::Url) -> Result<Self, PublicationError> {
        if endpoint.scheme() != "https" {
            return Err(PublicationError::NotHttps);
        }
        let client = sid_plugin::client_builder()
            .map_err(|e| PublicationError::Client(e.to_string()))?
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| PublicationError::Client(e.to_string()))?;
        Self::with_client(client, endpoint)
    }

    /// The publication at `endpoint` over `client`, whose bounds and
    /// redirect policy are the caller's.
    fn with_client(client: reqwest::Client, endpoint: url::Url) -> Result<Self, PublicationError> {
        Ok(Self {
            client,
            endpoint,
            message: publication_message()?,
        })
    }

    /// The configured endpoint.
    pub fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    /// Fetch the publication: the set as the platform last published it.
    pub async fn fetch(&self) -> Result<PlatformCas, PublicationError> {
        let body = self.read(self.endpoint.clone(), "application/json").await?;
        decode(&self.message, &body)
    }

    /// Fetch the current CRL (DER) of generation `generation`, served apart
    /// from the set at `{origin}/.well-known/sid-ca/{generation}/crl` as
    /// `application/pkix-crl` (RFC 2585 section 4.2). Only transported: its
    /// holder authenticates it.
    pub async fn fetch_crl(&self, generation: u32) -> Result<Vec<u8>, PublicationError> {
        let crl = self
            .endpoint
            .join(&format!("{CRL_PATH}{generation}/crl"))
            .map_err(|_| PublicationError::NotHttps)?;
        self.read(crl, CRL_TYPE).await
    }

    /// The body of a successful answer to `GET url` accepting `accept`, at
    /// most [`MAX_BODY`] bytes; no redirect is followed.
    async fn read(&self, url: url::Url, accept: &str) -> Result<Vec<u8>, PublicationError> {
        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, accept)
            .send()
            .await
            .map_err(|e| PublicationError::Unreachable(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(PublicationError::Status(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY as u64)
        {
            return Err(PublicationError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| PublicationError::Unreachable(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(PublicationError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

/// Why a published message states no set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{field}: expected {reason}")]
pub struct WireError {
    pub field: &'static str,
    pub reason: &'static str,
}

/// The set a `PlatformCas` message states, as pushed by a managing service
/// or read from the publication. Only decoded: its holder checks it.
pub fn set_of(wire: PlatformCas) -> Result<PlatformCaSet, WireError> {
    use sid_proto::sid::v1::PlatformCaState as Wire;
    let generations = wire
        .generations
        .into_iter()
        .map(|g| {
            let state = match Wire::try_from(g.state) {
                Ok(Wire::Active) => PlatformCaState::Active,
                Ok(Wire::VerificationOnly) => PlatformCaState::VerificationOnly,
                Ok(Wire::Withdrawn) => PlatformCaState::Withdrawn,
                _ => {
                    return Err(WireError {
                        field: "generations.state",
                        reason: "active, verification-only or withdrawn",
                    });
                }
            };
            Ok(PlatformCa {
                generation: g.generation,
                certificate: g.certificate,
                state,
                overlap_end: g.overlap_end.map(|t| t.seconds),
            })
        })
        .collect::<Result<Vec<_>, WireError>>()?;
    let seconds = |field: &'static str, seconds: Option<i64>| {
        seconds.ok_or(WireError {
            field,
            reason: "a timestamp",
        })
    };
    Ok(PlatformCaSet {
        revision: wire.revision,
        generations,
        issued_at: seconds("issued_at", wire.issued_at.map(|t| t.seconds))?,
        next_update: seconds("next_update", wire.next_update.map(|t| t.seconds))?,
    })
}

/// The platform's records for a publication, read from a secure answer.
#[async_trait::async_trait]
pub trait DiscoverySource: Send + Sync {
    async fn records(
        &self,
        publication: &url::Url,
    ) -> Result<Vec<discovery::DiscoveryRecord>, String>;
}

#[cfg(feature = "platform-ca-dns")]
#[async_trait::async_trait]
impl DiscoverySource for discovery::DiscoveryResolver {
    async fn records(
        &self,
        publication: &url::Url,
    ) -> Result<Vec<discovery::DiscoveryRecord>, String> {
        discovery::DiscoveryResolver::records(self, publication)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The configured publication as the source an installation refreshes its
/// platform CA set from: the set is fetched over HTTPS from exactly the
/// configured endpoint, and with discovery configured the platform's DNS
/// records are read alongside. A set the records announce exactly is taken
/// on the DNS step; records that are not usable or do not match reject that
/// candidate, and the set is taken on the HTTPS step from the configured
/// endpoint. Either way its holder applies it under the same rules, so
/// neither step can bring back an older set or a withdrawn generation.
#[derive(Default)]
pub struct PublishedPlatformCas {
    discovery: Option<std::sync::Arc<dyn DiscoverySource>>,
}

impl PublishedPlatformCas {
    /// The source over HTTPS alone.
    pub fn new() -> Self {
        Self::default()
    }

    /// The source reading the platform's discovery records through
    /// `discovery` before it takes a fetched set.
    pub fn with_discovery(mut self, discovery: std::sync::Arc<dyn DiscoverySource>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// The set `wire`, fetched from `endpoint`, with what the discovery
    /// records said of it.
    fn taken(
        wire: PlatformCas,
        records: Option<Result<Vec<discovery::DiscoveryRecord>, String>>,
        endpoint: &url::Url,
    ) -> Result<(PlatformCaSet, RefreshStep), String> {
        let step = match records {
            None => RefreshStep::Publication,
            Some(Ok(records)) => match discovery::check(&wire, &records, endpoint) {
                Ok(()) => RefreshStep::Discovery,
                Err(mismatch) => {
                    tracing::warn!(
                        %mismatch,
                        "platform CA discovery candidate rejected; the HTTPS publication supplies the set"
                    );
                    RefreshStep::Publication
                }
            },
            Some(Err(reason)) => {
                tracing::warn!(
                    %reason,
                    "platform CA discovery not usable; the HTTPS publication supplies the set"
                );
                RefreshStep::Publication
            }
        };
        Ok((set_of(wire).map_err(|e| e.to_string())?, step))
    }
}

/// Which step of the refresh order supplied a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStep {
    /// The platform's DNSSEC-secure discovery records announced exactly the
    /// fetched set.
    Discovery,
    /// The configured HTTPS publication alone: no discovery is configured,
    /// its records were not usable, or they did not match the set.
    Publication,
}

#[async_trait::async_trait]
impl PlatformCaSource for PublishedPlatformCas {
    async fn fetch(&self, endpoint: &url::Url) -> Result<PlatformCaSet, String> {
        let publication =
            PlatformCaPublication::new(endpoint.clone()).map_err(|e| e.to_string())?;
        let (records, wire) = match &self.discovery {
            Some(discovery) => {
                let (records, wire) =
                    tokio::join!(discovery.records(endpoint), publication.fetch());
                (Some(records), wire)
            }
            None => (None, publication.fetch().await),
        };
        let (set, step) = Self::taken(wire.map_err(|e| e.to_string())?, records, endpoint)?;
        tracing::info!(revision = set.revision, ?step, "platform CA set fetched");
        Ok(set)
    }

    async fn crl(&self, endpoint: &url::Url, generation: u32) -> Result<Vec<u8>, String> {
        PlatformCaPublication::new(endpoint.clone())
            .map_err(|e| e.to_string())?
            .fetch_crl(generation)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests;
