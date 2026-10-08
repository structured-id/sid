// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's OIDC issuers as the protocol edge knows them.
//!
//! A request path or a token names an issuer by its handle; the edge asks the
//! installation's registry for that issuer's exact URL and public keys and
//! verifies its tokens from the answer. Only issuers of this installation are
//! known: a token naming any other `iss` is refused without fetching anything
//! for it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sid_authn::issuer::IssuerVerifier;

/// How long an answer from the registry is reused. Keys rotate rarely and a
/// new key is found sooner through the unknown-`kid` refresh.
const ANSWER_TTL: Duration = Duration::from_secs(300);
/// The shortest interval between two refreshes of one issuer caused by a
/// token naming a key the cached answer lacks, so unknown key ids cannot
/// drive a lookup per request.
const UNKNOWN_KEY_REFRESH: Duration = Duration::from_secs(30);
/// How long an answer about a registered resource is reused: a resource
/// deactivated in the registry stops opening its routes on every replica
/// within this interval.
const RESOURCE_TTL: Duration = Duration::from_secs(30);

/// The endpoint path of an issuer-scoped request: what follows
/// `/i/{handle}` (`/oauth2/token`, `/jwks`, `/.well-known/...`), or `None`
/// for a path outside every issuer.
pub fn issuer_endpoint(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/i/")?;
    rest.find('/').map(|slash| &rest[slash..])
}

/// An issuer as the registry describes it: its exact identifier and its
/// public keys as (`kid`, Ed25519 key), newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRecord {
    pub issuer: String,
    pub keys: Vec<(String, [u8; 32])>,
}

/// A registered protected resource as the registry describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Exact identifier of the issuer whose tokens it accepts.
    pub issuer: String,
    /// Its resource indicator, the `aud` of its access tokens.
    pub resource: String,
    /// Whether it accepts tokens now.
    pub active: bool,
    /// The registered resource: the target of permission questions about
    /// its requests.
    pub id: sid_core::models::ResourceId,
}

/// Where issuer and resource records come from.
#[async_trait::async_trait]
pub trait IssuerSource: Send + Sync {
    /// The issuer named by `handle`, or `None` when there is none.
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, tonic::Status>;

    /// The resource `resource` names under the issuer `handle`, or `None`
    /// when that issuer registered none under it.
    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, tonic::Status>;
}

/// The registry of the SID server, over gRPC.
pub struct GrpcIssuerSource {
    channel: tonic::transport::Channel,
}

impl GrpcIssuerSource {
    pub fn new(channel: tonic::transport::Channel) -> Self {
        Self { channel }
    }
}

#[async_trait::async_trait]
impl IssuerSource for GrpcIssuerSource {
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, tonic::Status> {
        let mut client =
            sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient::new(
                self.channel.clone(),
            );
        let answer = match client
            .get_oidc_issuer(sid_proto::sid::v1::GetOidcIssuerRequest {
                handle: handle.to_owned(),
            })
            .await
        {
            Ok(answer) => answer.into_inner(),
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(status) => return Err(status),
        };
        let keys = answer
            .keys
            .into_iter()
            .map(|key| {
                let public_key: [u8; 32] = key.public_key.as_slice().try_into().map_err(|_| {
                    sid_core::grpc_error::refuse::internal(
                        "read issuer key",
                        "not an Ed25519 public key",
                    )
                })?;
                Ok((key.key_id, public_key))
            })
            .collect::<Result<_, tonic::Status>>()?;
        Ok(Some(IssuerRecord {
            issuer: answer.issuer,
            keys,
        }))
    }

    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, tonic::Status> {
        let mut client =
            sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient::new(
                self.channel.clone(),
            );
        match client
            .get_protected_resource(sid_proto::sid::v1::GetProtectedResourceRequest {
                issuer_handle: handle.to_owned(),
                resource: resource.to_owned(),
            })
            .await
        {
            Ok(answer) => {
                let answer = answer.into_inner();
                // A registry answer names its resource; one that does not is
                // no answer.
                let id = answer
                    .id
                    .as_ref()
                    .and_then(|id| sid_core::models::ResourceId::try_from(id).ok())
                    .ok_or_else(|| {
                        sid_core::grpc_error::refuse::internal(
                            "read protected resource",
                            "the answer names no resource",
                        )
                    })?;
                Ok(Some(ResourceRecord {
                    issuer: answer.issuer,
                    resource: answer.resource,
                    active: answer.active,
                    id,
                }))
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status),
        }
    }
}

/// A known issuer with what the edge checks for it.
pub struct KnownIssuer {
    /// The exact issuer identifier.
    pub issuer: String,
    /// Verifies tokens this issuer signed, with its keys only.
    pub verifier: IssuerVerifier,
}

impl std::fmt::Debug for KnownIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownIssuer")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl KnownIssuer {
    fn from_record(record: IssuerRecord) -> Self {
        Self {
            verifier: IssuerVerifier::new(record.issuer.clone(), record.keys),
            issuer: record.issuer,
        }
    }
}

/// A known issuer and when the registry described it. Only known issuers are
/// kept: an unknown handle is asked about again, so handles a client makes up
/// cannot grow the cache.
struct Cached {
    fetched: Instant,
    issuer: Arc<KnownIssuer>,
}

/// The installation's issuers, looked up by handle and cached per replica.
///
/// The cache holds public data read from the registry; every replica reads
/// the same, so it holds no state a replica must agree on.
pub struct IssuerDirectory {
    /// `{base}/i/`: the prefix of every issuer URL of this installation.
    prefix: String,
    source: Arc<dyn IssuerSource>,
    cache: DashMap<String, Cached>,
    /// Registered resources by (issuer handle, indicator). Only resources the
    /// route configuration names are asked about, so the map stays bounded.
    resources: DashMap<(String, String), CachedResource>,
}

/// A registered resource and when the registry described it.
struct CachedResource {
    fetched: Instant,
    record: ResourceRecord,
}

impl std::fmt::Debug for IssuerDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerDirectory")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl IssuerDirectory {
    /// The issuers under `base`, the installation's public URL.
    pub fn new(base: &str, source: Arc<dyn IssuerSource>) -> Self {
        Self {
            prefix: format!("{}/i/", base.trim_end_matches('/')),
            source,
            cache: DashMap::new(),
            resources: DashMap::new(),
        }
    }

    /// The resource `resource` registered under the issuer `issuer` (its
    /// exact identifier), or `None` when this installation has no such
    /// issuer or the issuer no such resource. The answer must name exactly
    /// that issuer and indicator, or it names nothing here.
    pub async fn resource(
        &self,
        issuer: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, tonic::Status> {
        let Some(handle) = issuer.strip_prefix(&self.prefix) else {
            return Ok(None);
        };
        if sid_core::models::IssuerHandle::parse(handle).is_err() {
            return Ok(None);
        }
        let key = (handle.to_owned(), resource.to_owned());
        if let Some(cached) = self.resources.get(&key)
            && cached.fetched.elapsed() < RESOURCE_TTL
        {
            return Ok(Some(cached.record.clone()));
        }
        let record = self
            .source
            .resource(handle, resource)
            .await?
            .filter(|record| record.issuer == issuer && record.resource == resource);
        match &record {
            Some(record) => {
                self.resources.insert(
                    key,
                    CachedResource {
                        fetched: Instant::now(),
                        record: record.clone(),
                    },
                );
            }
            None => {
                self.resources.remove(&key);
            }
        }
        Ok(record)
    }

    /// The issuer a request path names by `handle`. The answer must name an
    /// issuer under this installation's base and end in this handle, or the
    /// handle names no issuer here.
    pub async fn by_handle(&self, handle: &str) -> Result<Option<Arc<KnownIssuer>>, tonic::Status> {
        // Text that cannot be a handle is not asked about.
        if sid_core::models::IssuerHandle::parse(handle).is_err() {
            return Ok(None);
        }
        if let Some(cached) = self.cache.get(handle)
            && cached.fetched.elapsed() < ANSWER_TTL
        {
            return Ok(Some(cached.issuer.clone()));
        }
        self.fetch(handle).await
    }

    /// The issuer a token names in `iss`, when it is one of this
    /// installation's, holding the key `kid` names. A key the cached answer
    /// lacks is looked up again, at most once per [`UNKNOWN_KEY_REFRESH`].
    pub async fn for_token(
        &self,
        iss: &str,
        kid: &str,
    ) -> Result<Option<Arc<KnownIssuer>>, tonic::Status> {
        let Some(handle) = iss.strip_prefix(&self.prefix) else {
            return Ok(None);
        };
        let Some(issuer) = self.by_handle(handle).await? else {
            return Ok(None);
        };
        if issuer.issuer != iss {
            return Ok(None);
        }
        if issuer.verifier.knows_key(kid) {
            return Ok(Some(issuer));
        }
        let recent = self
            .cache
            .get(handle)
            .is_some_and(|cached| cached.fetched.elapsed() < UNKNOWN_KEY_REFRESH);
        if recent {
            return Ok(Some(issuer));
        }
        Ok(self
            .fetch(handle)
            .await?
            .filter(|issuer| issuer.issuer == iss))
    }

    async fn fetch(&self, handle: &str) -> Result<Option<Arc<KnownIssuer>>, tonic::Status> {
        let issuer = self
            .source
            .issuer(handle)
            .await?
            .filter(|record| record.issuer.strip_prefix(&self.prefix) == Some(handle))
            .map(|record| Arc::new(KnownIssuer::from_record(record)));
        match &issuer {
            Some(known) => {
                self.cache.insert(
                    handle.to_owned(),
                    Cached {
                        fetched: Instant::now(),
                        issuer: known.clone(),
                    },
                );
            }
            None => {
                self.cache.remove(handle);
            }
        }
        Ok(issuer)
    }
}

#[cfg(test)]
mod tests;
