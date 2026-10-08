// SPDX-License-Identifier: AGPL-3.0-only
//! The resource an application access token is issued for (RFC 8707).
//!
//! A token is issued for exactly one registered, active resource the client
//! was given explicit access to; its indicator becomes the token's `aud`.
//! A request naming no resource uses only the client's explicit default,
//! never a substitute such as the client id or the issuer. A grant (code,
//! refresh token, device code) keeps the target it was issued for.

use sid_core::Result as SidResult;
pub use sid_core::models::{IssuerId, ResourceIndicator};
use sid_core::models::{MachineUser, OAuth2Client, ProtectedResource, ResourceAccess, ResourceId};
use sid_plugin::storage::StorageBackend;

/// Why a request's target is refused. Every case is `invalid_target`
/// (RFC 8707 §2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetRefusal {
    /// More than one distinct resource: SID issues a token for one target.
    #[error("the request names more than one resource")]
    Several,
    /// Not an absolute URI without a fragment.
    #[error("resource is not a resource indicator: {0}")]
    Malformed(String),
    /// No resource of the issuer has this indicator.
    #[error("the resource is unknown")]
    Unknown,
    /// The resource is inactive or retired.
    #[error("the resource does not accept tokens now")]
    Inactive,
    /// The client has no access to the resource.
    #[error("the client may not obtain tokens for this resource")]
    NotPermitted,
    /// The request names no resource and the client has no default.
    #[error("no resource named and the client has no default resource")]
    NoneNamed,
    /// A grant presented for another resource than it was issued for.
    #[error("the grant was issued for another resource")]
    Different,
    /// A token exchange whose `resource` and `audience` name different
    /// targets (RFC 8693 §2.1).
    #[error("resource and audience name different targets")]
    Conflicting,
    /// A token exchange naming a target: it issues only the installation's
    /// own impersonation token.
    #[error("token exchange does not issue tokens for a named target")]
    NotExchangeable,
}

impl TargetRefusal {
    /// The OAuth `error` code of the refusal (RFC 8707 §2).
    pub fn oauth_error(&self) -> &'static str {
        "invalid_target"
    }
}

/// A resolved target: the resource and the client's access to it.
#[derive(Debug, Clone)]
pub struct Target {
    resource: ProtectedResource,
    access: ResourceAccess,
}

impl Target {
    /// A target from its parts, for unit tests of issuance.
    #[cfg(test)]
    pub(crate) fn from_parts(resource: ProtectedResource, access: ResourceAccess) -> Self {
        Self { resource, access }
    }

    /// The token audience: the resource indicator.
    pub fn audience(&self) -> &ResourceIndicator {
        &self.resource.indicator
    }

    /// The resource a grant binds to.
    pub fn resource_id(&self) -> ResourceId {
        self.resource.id
    }

    /// The requested scopes this target grants: allowed by the access and
    /// supported by the resource, in request order.
    pub fn granted_scopes(&self, requested: &[String]) -> Vec<String> {
        self.access.granted_scopes(&self.resource, requested)
    }

    /// Every scope this target grants, for a request naming none.
    pub fn scopes(&self) -> Vec<String> {
        self.granted_scopes(&self.access.scopes)
    }
}

/// The client asking for a token: an OAuth client, or a machine user acting
/// for itself, with the default resource it names when a request names none.
#[derive(Debug, Clone, Copy)]
pub struct Requester<'a> {
    pub client_id: &'a str,
    pub default_resource: Option<ResourceId>,
}

impl<'a> From<&'a OAuth2Client> for Requester<'a> {
    fn from(client: &'a OAuth2Client) -> Self {
        Self {
            client_id: &client.client_id,
            default_resource: client.default_resource,
        }
    }
}

impl<'a> From<&'a MachineUser> for Requester<'a> {
    /// A machine user has no default resource: it names its target.
    fn from(machine: &'a MachineUser) -> Self {
        Self {
            client_id: &machine.client_id,
            default_resource: None,
        }
    }
}

/// The one target a request's `resource` values name (RFC 8707 §2): `None`
/// when there is none. Repeated identical values name one target; distinct
/// ones are refused.
pub fn requested_indicator(values: &[String]) -> Result<Option<ResourceIndicator>, TargetRefusal> {
    let Some((first, rest)) = values.split_first() else {
        return Ok(None);
    };
    if rest.iter().any(|v| v != first) {
        return Err(TargetRefusal::Several);
    }
    ResourceIndicator::parse(first)
        .map(Some)
        .map_err(TargetRefusal::Malformed)
}

/// The one target a token exchange names through `resource` and `audience`
/// (RFC 8693 §2.1): `None` when neither is given. An audience is a resource
/// indicator, the only name a resource is registered under; when both are
/// given they must name the same resource.
pub fn exchange_indicator(
    resource: &[String],
    audience: &[String],
) -> Result<Option<ResourceIndicator>, TargetRefusal> {
    match (
        requested_indicator(resource)?,
        requested_indicator(audience)?,
    ) {
        (Some(r), Some(a)) if r != a => Err(TargetRefusal::Conflicting),
        (r, a) => Ok(r.or(a)),
    }
}

/// The target of a new grant for `requester` under `issuer`: the resource
/// `requested` names, or the requester's default when none is named.
pub async fn select_target<'r>(
    storage: &dyn StorageBackend,
    issuer: IssuerId,
    requester: impl Into<Requester<'r>>,
    requested: Option<&ResourceIndicator>,
) -> SidResult<Result<Target, TargetRefusal>> {
    let requester = requester.into();
    let resource = match requested {
        Some(indicator) => {
            storage
                .protected_resource_by_indicator(issuer, indicator)
                .await?
        }
        None => match requester.default_resource {
            Some(default) => storage
                .get_protected_resource(default)
                .await?
                .filter(|r| r.issuer_id == issuer),
            None => return Ok(Err(TargetRefusal::NoneNamed)),
        },
    };
    permitted(storage, requester.client_id, resource).await
}

/// The target of an existing grant of `requester` bound to `bound`,
/// re-checked against the registry: a `requested` indicator must name that
/// same resource, and the resource must still accept tokens from `issuer`
/// for this client.
pub async fn resume_target<'r>(
    storage: &dyn StorageBackend,
    issuer: IssuerId,
    requester: impl Into<Requester<'r>>,
    bound: ResourceId,
    requested: Option<&ResourceIndicator>,
) -> SidResult<Result<Target, TargetRefusal>> {
    let client_id = requester.into().client_id;
    let resource = storage
        .get_protected_resource(bound)
        .await?
        .filter(|r| r.issuer_id == issuer);
    if let (Some(resource), Some(requested)) = (&resource, requested)
        && &resource.indicator != requested
    {
        return Ok(Err(TargetRefusal::Different));
    }
    permitted(storage, client_id, resource).await
}

/// The target of a provisioning connector's token under `issuer`: its
/// `directory` resource, whether or not the request names it; any other
/// resource is refused. Its access comes from its grants, which the resource
/// checks on every request, not from a client access entry.
pub async fn connector_target(
    storage: &dyn StorageBackend,
    issuer: IssuerId,
    directory: &ResourceIndicator,
    requested: Option<&ResourceIndicator>,
) -> SidResult<Result<ProtectedResource, TargetRefusal>> {
    if requested.is_some_and(|r| r != directory) {
        return Ok(Err(TargetRefusal::NotPermitted));
    }
    let Some(resource) = storage
        .protected_resource_by_indicator(issuer, directory)
        .await?
    else {
        return Ok(Err(TargetRefusal::Unknown));
    };
    if !resource.is_target() {
        return Ok(Err(TargetRefusal::Inactive));
    }
    Ok(Ok(resource))
}

/// `resource` as a target of `client_id`: active, with access.
async fn permitted(
    storage: &dyn StorageBackend,
    client_id: &str,
    resource: Option<ProtectedResource>,
) -> SidResult<Result<Target, TargetRefusal>> {
    let Some(resource) = resource else {
        return Ok(Err(TargetRefusal::Unknown));
    };
    if !resource.is_target() {
        return Ok(Err(TargetRefusal::Inactive));
    }
    let Some(access) = storage.resource_access(client_id, resource.id).await? else {
        return Ok(Err(TargetRefusal::NotPermitted));
    };
    Ok(Ok(Target { resource, access }))
}

#[cfg(test)]
mod tests;
