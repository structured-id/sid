// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's OIDC issuers as a receiver or a relying party knows
//! them: their exact identifiers, public keys and registered resources, read
//! from the installation's registry and cached per replica.
//!
//! A request path or a token names an issuer by its organization segment;
//! the directory asks the installation's registry for that issuer's exact URL
//! and public keys and verifies its tokens from the answer. Keys come only
//! from the registry, never from the host a token names
//! (oidc-issuer-model: never fetch keys for an arbitrary `iss`), and a token
//! whose `iss` is not exactly the registry's URL is refused.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::issuer::IssuerVerifier;
use crate::jwt::{AccessTokenClaims, IdTokenClaims, LogoutTokenClaims};

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

/// The endpoint path of a request to a scoped issuer: what follows
/// `/i/{handle}` (`/oauth2/token`, `/jwks`, `/.well-known/...`), or `None`
/// for a path outside every scoped issuer.
pub fn issuer_endpoint(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/i/")?;
    rest.find('/').map(|slash| &rest[slash..])
}

/// The registry could not answer; what was asked may still exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("issuer registry unavailable: {0}")]
pub struct RegistryUnavailable(pub String);

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
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable>;

    /// The resource `resource` names under the issuer `handle`, or `None`
    /// when that issuer registered none under it.
    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable>;
}

/// A known issuer with what is checked for it.
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

/// Why a token is not accepted as one a named issuer signed.
#[derive(Debug, thiserror::Error)]
pub enum IssuedTokenRefusal {
    /// Not a valid token of that issuer for this use.
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The registry could not be asked; the token may be valid.
    #[error(transparent)]
    Unavailable(#[from] RegistryUnavailable),
}

/// A known issuer and when the registry described it. Only known issuers are
/// kept: an unknown handle is asked about again, so handles a client makes up
/// cannot grow the cache.
struct Cached {
    fetched: Instant,
    issuer: Arc<KnownIssuer>,
}

/// A registered resource and when the registry described it.
struct CachedResource {
    fetched: Instant,
    record: ResourceRecord,
}

/// The installation's issuers, looked up by handle and cached per replica.
///
/// The cache holds public data read from the registry; every replica reads
/// the same, so it holds no state a replica must agree on.
pub struct IssuerDirectory {
    source: Arc<dyn IssuerSource>,
    cache: DashMap<String, Cached>,
    /// Registered resources by (issuer handle, indicator). Only resources the
    /// caller's configuration names are asked about, so the map stays bounded.
    resources: DashMap<(String, String), CachedResource>,
}

impl std::fmt::Debug for IssuerDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerDirectory").finish_non_exhaustive()
    }
}

impl IssuerDirectory {
    /// The issuers `source`, the installation's registry, describes.
    pub fn new(source: Arc<dyn IssuerSource>) -> Self {
        Self {
            source,
            cache: DashMap::new(),
            resources: DashMap::new(),
        }
    }

    /// Which issuer `issuer` selects in the registry, by its organization
    /// segment; whether it is exactly that issuer is checked against the
    /// registry's answer.
    fn selector_of(&self, issuer: &str) -> Option<crate::issuer::IssuerSelector> {
        crate::issuer::select_issuer(issuer)
    }

    /// The resource `resource` registered under the issuer `issuer` (its
    /// exact identifier), or `None` when this installation has no such
    /// issuer or the issuer no such resource. The answer must name exactly
    /// that issuer and indicator, or it names nothing here.
    pub async fn resource(
        &self,
        issuer: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        let Some(selector) = self.selector_of(issuer) else {
            return Ok(None);
        };
        let handle = selector.wire();
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

    /// The issuer a request path names by `handle`, the empty handle naming
    /// the root-addressed base issuer. The answer must be exactly the URL
    /// this installation gives that handle, or it names no issuer here.
    pub async fn by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<Arc<KnownIssuer>>, RegistryUnavailable> {
        use crate::issuer::IssuerSelector;
        // Text that cannot be a handle is not asked about, and never names
        // the base issuer.
        let selector = if handle.is_empty() {
            IssuerSelector::Root
        } else {
            match sid_core::models::IssuerHandle::parse(handle) {
                Ok(handle) => IssuerSelector::Scoped(handle),
                Err(_) => return Ok(None),
            }
        };
        self.known(&selector).await
    }

    /// The issuer `selector` names, from the cache while it is fresh.
    async fn known(
        &self,
        selector: &crate::issuer::IssuerSelector,
    ) -> Result<Option<Arc<KnownIssuer>>, RegistryUnavailable> {
        if let Some(cached) = self.cache.get(selector.wire())
            && cached.fetched.elapsed() < ANSWER_TTL
        {
            return Ok(Some(cached.issuer.clone()));
        }
        self.fetch(selector).await
    }

    /// The issuer a token names in `iss`, when it is one of this
    /// installation's, holding the key `kid` names. A key the cached answer
    /// lacks is looked up again, at most once per [`UNKNOWN_KEY_REFRESH`].
    pub async fn for_token(
        &self,
        iss: &str,
        kid: &str,
    ) -> Result<Option<Arc<KnownIssuer>>, RegistryUnavailable> {
        let Some(selector) = self.selector_of(iss) else {
            return Ok(None);
        };
        let Some(issuer) = self.known(&selector).await? else {
            return Ok(None);
        };
        // The token's `iss` must be exactly the issuer the registry answered
        // (OpenID Connect Core 1.0 §3.1.3.7, Discovery 1.0 §4.3).
        if issuer.issuer != iss {
            return Ok(None);
        }
        if issuer.verifier.knows_key(kid) {
            return Ok(Some(issuer));
        }
        let recent = self
            .cache
            .get(selector.wire())
            .is_some_and(|cached| cached.fetched.elapsed() < UNKNOWN_KEY_REFRESH);
        if recent {
            return Ok(Some(issuer));
        }
        Ok(self
            .fetch(&selector)
            .await?
            .filter(|issuer| issuer.issuer == iss))
    }

    /// The issuer that must have signed `token`: exactly `issuer`, whose keys
    /// alone are looked up, never those of whatever `iss` the token claims.
    pub async fn signer_of(
        &self,
        issuer: &str,
        token: &str,
    ) -> Result<Arc<KnownIssuer>, IssuedTokenRefusal> {
        let (iss, kid) = unverified_iss_and_kid(token)
            .ok_or_else(|| IssuedTokenRefusal::Invalid("malformed".into()))?;
        if iss != issuer {
            return Err(IssuedTokenRefusal::Invalid(
                "issued by another issuer".into(),
            ));
        }
        self.for_token(&iss, &kid)
            .await?
            .ok_or_else(|| IssuedTokenRefusal::Invalid("unknown issuer".into()))
    }

    /// An access token `issuer` issued for the resource `audience`: that
    /// issuer's exact `iss` and keys only, typed `at+jwt`, `aud` naming the
    /// resource (RFC 9068 §4).
    pub async fn issued_access_token(
        &self,
        issuer: &str,
        audience: &str,
        token: &str,
    ) -> Result<AccessTokenClaims, IssuedTokenRefusal> {
        self.signer_of(issuer, token)
            .await?
            .verifier
            .validate_access_token_for(token, audience)
            .map_err(|e| IssuedTokenRefusal::Invalid(e.to_string()))
    }

    /// The ID token `issuer` returned with a code redemption of `client_id`
    /// (OIDC Core 1.0 §3.1.3.7): that issuer's exact `iss` and keys only, for
    /// that client, carrying the `nonce` its sign-in sent.
    pub async fn issued_id_token(
        &self,
        issuer: &str,
        client_id: &str,
        nonce: &str,
        token: &str,
    ) -> Result<IdTokenClaims, IssuedTokenRefusal> {
        self.signer_of(issuer, token)
            .await?
            .verifier
            .validate_id_token(token, client_id, nonce)
            .map_err(|e| IssuedTokenRefusal::Invalid(e.to_string()))
    }

    /// The back-channel logout token `issuer` sent `client_id` (Back-Channel
    /// Logout 1.0 §2.6): that issuer's exact `iss` and keys only, for that
    /// client (see [`IssuerVerifier::validate_logout_token`]).
    pub async fn issued_logout_token(
        &self,
        issuer: &str,
        client_id: &str,
        token: &str,
    ) -> Result<LogoutTokenClaims, IssuedTokenRefusal> {
        self.signer_of(issuer, token)
            .await?
            .verifier
            .validate_logout_token(token, client_id)
            .map_err(|e| IssuedTokenRefusal::Invalid(e.to_string()))
    }

    async fn fetch(
        &self,
        selector: &crate::issuer::IssuerSelector,
    ) -> Result<Option<Arc<KnownIssuer>>, RegistryUnavailable> {
        let handle = selector.wire();
        // The answer stays bound to what was asked: the issuer the registry
        // answers must be one of this installation's and select exactly the
        // requested issuer, or the request named nothing here.
        let issuer = self
            .source
            .issuer(handle)
            .await?
            .filter(|record| self.selector_of(&record.issuer).as_ref() == Some(selector))
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

/// The `iss` a token claims and the `kid` its header names, read before the
/// signature is checked, only to choose who checks it.
fn unverified_iss_and_kid(token: &str) -> Option<(String, String)> {
    use base64::Engine;
    let kid = jsonwebtoken::decode_header(token)
        .ok()?
        .kid
        .unwrap_or_default();
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some((claims.get("iss")?.as_str()?.to_owned(), kid))
}

#[cfg(test)]
mod tests;
