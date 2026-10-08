// SPDX-License-Identifier: AGPL-3.0-only
//! Recipient resolution: profile_id → contact details via gRPC to sid-identity.
//!
//! When `SID_IDENTITY_GRPC_ADDRESS` is configured, resolves recipient contact
//! info (email, phone, locale) from the identity service. Falls back to
//! extracting contact info from event data when identity service is unavailable.
//!
//! Includes TTL cache to avoid per-event gRPC calls (default: 5 minutes).

use chrono::{DateTime, Utc};
use sid_plugin::notification::Recipient;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Default cache TTL: 5 minutes.
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Cached recipient contact info.
#[derive(Debug, Clone)]
struct CachedRecipient {
    email: Option<String>,
    phone: Option<String>,
    locale: String,
    cached_at: DateTime<Utc>,
}

/// Resolves recipient contact details from sid-identity via gRPC.
///
/// Falls back to event data extraction when identity service is unavailable
/// or profile_id is unknown.
pub(crate) struct RecipientResolver {
    /// gRPC client to sid-identity (None = event data only).
    identity_client: Option<
        Arc<
            RwLock<
                sid_proto::sid::v1::identity::identity_service_client::IdentityServiceClient<
                    tonic::transport::Channel,
                >,
            >,
        >,
    >,
    /// In-memory TTL cache: profile_id → contact info.
    cache: Arc<RwLock<HashMap<String, CachedRecipient>>>,
    /// Cache TTL duration.
    cache_ttl: Duration,
}

impl RecipientResolver {
    /// Create a resolver without identity service (event data extraction only).
    pub(crate) fn without_identity() -> Self {
        Self {
            identity_client: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        }
    }

    /// Create a resolver with gRPC connection to sid-identity.
    pub(crate) async fn with_identity(address: &str) -> anyhow::Result<Self> {
        let endpoint = tonic::transport::Channel::from_shared(address.to_string())
            .map_err(|e| anyhow::anyhow!("invalid identity address: {e}"))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(3));
        let channel = endpoint.connect_lazy();

        let client =
            sid_proto::sid::v1::identity::identity_service_client::IdentityServiceClient::new(
                channel,
            );

        Ok(Self {
            identity_client: Some(Arc::new(RwLock::new(client))),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        })
    }

    /// Resolve recipient from event.
    ///
    /// Strategy:
    /// 1. Extract profile_id from event.subject
    /// 2. Check TTL cache for contact info
    /// 3. If cache miss + identity client available → gRPC GetProfile + ListIdentifiers
    /// 4. Merge: gRPC result > event data fallback
    /// 5. Cache the result
    ///
    /// Without an identity service, or for an event naming no profile, the
    /// event data is the source. With one, a failed lookup is an error the
    /// caller retries (or, for a profile that no longer exists, gives up
    /// on); it never silently turns into event data.
    pub(crate) async fn resolve(
        &self,
        event: &sid_core::models::event::Event,
    ) -> Result<Recipient, ResolveError> {
        let Some(profile_id) = extract_profile_id(event) else {
            return Ok(build_recipient_from_event_data("unknown", event));
        };

        // Try cache first.
        if let Some(cached) = self.get_cached(&profile_id).await {
            debug!(profile_id = %profile_id, "Recipient resolved from cache");
            return Ok(build_recipient(
                &profile_id,
                cached.email.as_deref(),
                cached.phone.as_deref(),
                &cached.locale,
                event,
            ));
        }

        let Some(ref client) = self.identity_client else {
            debug!(profile_id = %profile_id, "Recipient resolved from event data");
            return Ok(build_recipient_from_event_data(&profile_id, event));
        };
        let cached = self.lookup(client, &profile_id).await?;
        debug!(
            profile_id = %profile_id,
            email = ?cached.email,
            phone = cached.phone.is_some(),
            "Recipient resolved via gRPC"
        );
        let recipient = build_recipient(
            &profile_id,
            cached.email.as_deref(),
            cached.phone.as_deref(),
            &cached.locale,
            event,
        );
        self.put_cache(profile_id, cached).await;
        Ok(recipient)
    }

    /// The addresses the identity service holds for `profile_id`, or `None`
    /// when no identity service is configured.
    pub(crate) async fn contact(&self, profile_id: &str) -> Result<Option<Contact>, ResolveError> {
        let Some(ref client) = self.identity_client else {
            return Ok(None);
        };
        let found = self.lookup(client, profile_id).await?;
        Ok(Some(Contact {
            email: found.email,
            phone: found.phone,
        }))
    }

    /// [`Self::resolve_via_grpc`] with its failure classified.
    async fn lookup(
        &self,
        client: &Arc<
            RwLock<
                sid_proto::sid::v1::identity::identity_service_client::IdentityServiceClient<
                    tonic::transport::Channel,
                >,
            >,
        >,
        profile_id: &str,
    ) -> Result<CachedRecipient, ResolveError> {
        self.resolve_via_grpc(client, profile_id)
            .await
            .map_err(|status| {
                if status.code() == tonic::Code::NotFound {
                    ResolveError::ProfileGone(profile_id.to_string())
                } else {
                    warn!(profile_id = %profile_id, error = %status, "recipient lookup failed");
                    ResolveError::Unavailable(status.message().to_string())
                }
            })
    }

    /// Check cache for non-expired entry.
    async fn get_cached(&self, profile_id: &str) -> Option<CachedRecipient> {
        let cache = self.cache.read().await;
        let entry = cache.get(profile_id)?;
        let age = Utc::now()
            .signed_duration_since(entry.cached_at)
            .to_std()
            .unwrap_or(Duration::MAX);
        if age < self.cache_ttl {
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Store in cache.
    async fn put_cache(&self, profile_id: String, entry: CachedRecipient) {
        self.cache.write().await.insert(profile_id, entry);
    }

    /// Resolve via gRPC GetProfile + ListIdentifiers.
    async fn resolve_via_grpc(
        &self,
        client: &Arc<
            RwLock<
                sid_proto::sid::v1::identity::identity_service_client::IdentityServiceClient<
                    tonic::transport::Channel,
                >,
            >,
        >,
        profile_id: &str,
    ) -> Result<CachedRecipient, tonic::Status> {
        let mut client = client.write().await;

        // GetProfile → email (denormalized).
        let profile_resp = client
            .get_profile(tonic::Request::new(
                sid_proto::sid::v1::identity::GetProfileRequest {
                    identifier: Some(
                        sid_proto::sid::v1::identity::get_profile_request::Identifier::Id(
                            profile_id.to_string(),
                        ),
                    ),
                },
            ))
            .await?;

        let profile = profile_resp
            .into_inner()
            .profile
            .ok_or_else(|| tonic::Status::internal("GetProfile returned empty profile"))?;

        let email = profile.email;

        // ListPrincipals → phone (first verified primary phone).
        let principals_resp = client
            .list_principals(tonic::Request::new(
                sid_proto::sid::v1::identity::ListPrincipalsRequest {
                    profile_id: profile_id.to_string(),
                },
            ))
            .await?;

        let principals = principals_resp.into_inner().principals;
        let phone = principals
            .iter()
            .filter(|p| {
                p.r#type == sid_proto::sid::v1::identity::PrincipalType::Phone as i32 && p.verified
            })
            .min_by_key(|p| !p.is_primary) // Primary first.
            .map(|p| p.value.clone());

        Ok(CachedRecipient {
            email,
            phone,
            locale: "en".to_string(), // TODO: resolve from profile preferences
            cached_at: Utc::now(),
        })
    }

    /// Invalidate cache entry for a profile (e.g., on user.updated event).
    pub(crate) async fn invalidate(&self, profile_id: &str) {
        self.cache.write().await.remove(profile_id);
    }

    /// Check if identity client is configured (used in tests and logging).
    #[cfg(test)]
    pub(crate) fn has_identity_client(&self) -> bool {
        self.identity_client.is_some()
    }
}

/// A profile's delivery addresses as the identity service holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Contact {
    pub(crate) email: Option<String>,
    /// The verified phone, primary first.
    pub(crate) phone: Option<String>,
}

/// Why a recipient could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ResolveError {
    /// The profile no longer exists: nothing can be delivered to it.
    #[error("profile {0} not found")]
    ProfileGone(String),
    /// The identity service did not answer usefully; worth another try.
    #[error("recipient lookup failed: {0}")]
    Unavailable(String),
}

/// Extract profile_id from event subject.
/// Subject format: "profile/{uuid}" or just the uuid.
fn extract_profile_id(event: &sid_core::models::event::Event) -> Option<String> {
    event
        .subject
        .as_deref()
        .map(|s| s.strip_prefix("profile/").unwrap_or(s).to_string())
}

/// Build Recipient merging gRPC-resolved contact info with event data fallback.
fn build_recipient(
    profile_id: &str,
    email: Option<&str>,
    phone: Option<&str>,
    locale: &str,
    event: &sid_core::models::event::Event,
) -> Recipient {
    // Prefer resolved data, fall back to event data.
    let email = email.map(String::from).or_else(|| {
        event
            .data
            .get("email")
            .and_then(|v| v.as_str())
            .map(String::from)
    });

    let phone = phone.map(String::from).or_else(|| {
        event
            .data
            .get("phone")
            .and_then(|v| v.as_str())
            .map(String::from)
    });

    Recipient {
        profile_id: profile_id.to_string(),
        email,
        phone,
        push_endpoint: None,
        device_token: None,
        locale: locale.to_string(),
    }
}

/// Fallback: build Recipient from event data only (no gRPC).
fn build_recipient_from_event_data(
    profile_id: &str,
    event: &sid_core::models::event::Event,
) -> Recipient {
    let email = event
        .data
        .get("email")
        .and_then(|v| v.as_str())
        .map(String::from);

    let phone = event
        .data
        .get("phone")
        .and_then(|v| v.as_str())
        .map(String::from);

    let locale = event
        .data
        .get("locale")
        .and_then(|v| v.as_str())
        .unwrap_or("en")
        .to_string();

    Recipient {
        profile_id: profile_id.to_string(),
        email,
        phone,
        push_endpoint: None,
        device_token: None,
        locale,
    }
}

#[cfg(test)]
mod tests;

/// Integration tests with mock gRPC identity server.
#[cfg(test)]
mod grpc_tests;
