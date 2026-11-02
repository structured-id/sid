// SPDX-License-Identifier: AGPL-3.0-only
//! Applications and their protected-resource role.
//!
//! An application is the managed registration of a product or integration in
//! a project. It has an OAuth client role (an [`super::OAuth2Client`] that
//! names it), a protected-resource role (a [`ProtectedResource`]), or both.
//! A client obtains tokens only for resources it is explicitly given access
//! to ([`ResourceAccess`]); project membership, a shared issuer or an equal
//! subject grant nothing.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use sid_ids::{ApplicationId, ResourceId};

use super::{IssuerId, ProjectId};

/// A managed application: the container of its client and resource roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Application {
    pub id: ApplicationId,
    pub project_id: ProjectId,
    /// Name shown to administrators.
    pub name: String,
    /// The installation's own integration this application is, which SID
    /// provisions and keeps; `None` for an administrator's application.
    #[serde(default)]
    pub system: Option<SystemIntegration>,
    /// Stored revision: 0 for a new application, moved on by every update.
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An integration of the installation with itself, provisioned by SID rather
/// than registered by an administrator. Each exists at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemIntegration {
    /// SID's own account UI: its web client, the account API and the
    /// client's access to it.
    Account,
}

impl SystemIntegration {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
        }
    }
}

parse_stored!(SystemIntegration, "system integration", [Account]);

/// The public identifier of a protected resource and the `aud` of tokens
/// issued for it: an absolute URI without a fragment (RFC 8707 §2).
///
/// An identifier, not a URL to fetch. Only the canonical spelling is
/// accepted, so equal resources have equal strings and a comparison is exact.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceIndicator(String);

impl ResourceIndicator {
    /// Longest accepted identifier, in bytes.
    pub const MAX_LEN: usize = 2048;

    /// A resource indicator in canonical form; anything else is refused with
    /// the reason, naming the canonical spelling when that is the only fault.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > Self::MAX_LEN {
            return Err(format!(
                "resource indicator is longer than {} bytes",
                Self::MAX_LEN
            ));
        }
        // RFC 8707 §2: "MUST be an absolute URI, as specified by Section 4.3
        // of [RFC3986]"; `Url::parse` refuses relative references.
        let url = url::Url::parse(text)
            .map_err(|e| format!("resource indicator is not an absolute URI: {e}"))?;
        // RFC 8707 §2: "MUST NOT include a fragment component".
        if url.fragment().is_some() {
            return Err("resource indicator must not include a fragment".to_owned());
        }
        // The indicator is copied into every token's `aud`.
        if !url.username().is_empty() || url.password().is_some() {
            return Err("resource indicator must not include credentials".to_owned());
        }
        if url.as_str() != text {
            return Err(format!(
                "resource indicator is not in canonical form; use {}",
                url.as_str()
            ));
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResourceIndicator({})", self.0)
    }
}

impl fmt::Display for ResourceIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ResourceIndicator {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ResourceIndicator> for String {
    fn from(indicator: ResourceIndicator) -> Self {
        indicator.0
    }
}

/// Lifecycle of a protected resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// Tokens are issued for it and accepted by it.
    Active,
    /// Temporarily not a target; can be activated again.
    Inactive,
    /// Its application was removed. The identifier stays reserved and is
    /// never reassigned or reactivated.
    Retired,
}

impl ResourceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Retired => "retired",
        }
    }

    /// Whether a resource in this state may be moved to `next`.
    pub const fn may_become(self, next: Self) -> bool {
        !matches!((self, next), (Self::Retired, Self::Active | Self::Inactive))
    }
}

parse_stored!(ResourceState, "resource state", [Active, Inactive, Retired]);

/// The protected-resource role of an application: an API or application at
/// which access is enforced. It needs no client, secret or callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub id: ResourceId,
    /// The application holding this role; `None` once retired.
    pub application_id: Option<ApplicationId>,
    /// The issuer whose tokens this resource accepts. Fixed at registration;
    /// within it `indicator` names this resource only, for ever.
    pub issuer_id: IssuerId,
    pub indicator: ResourceIndicator,
    /// Scopes this resource understands; access grants no others.
    pub scopes: Vec<String>,
    pub state: ResourceState,
    /// Stored revision: 0 for a new resource, moved on by every update.
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProtectedResource {
    /// Whether tokens may be issued for this resource.
    pub fn is_target(&self) -> bool {
        self.state == ResourceState::Active
    }
}

/// `scopes` as a stored scope list: each a scope token, each once, in order.
/// A value that is not a scope token is refused with the reason.
pub fn scope_list(scopes: &[String]) -> Result<Vec<String>, String> {
    let mut list: Vec<String> = Vec::with_capacity(scopes.len());
    for scope in scopes {
        // RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
        let token = !scope.is_empty()
            && scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b));
        if !token {
            return Err(format!("{scope:?} is not a scope token (RFC 6749 §3.3)"));
        }
        if !list.contains(scope) {
            list.push(scope.clone());
        }
    }
    Ok(list)
}

/// An explicit permission for one client to obtain tokens for one resource,
/// limited to `scopes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAccess {
    pub client_id: String,
    pub resource_id: ResourceId,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl ResourceAccess {
    /// The requested scopes this access grants at `resource`: allowed here
    /// and supported by the resource, in request order.
    pub fn granted_scopes(
        &self,
        resource: &ProtectedResource,
        requested: &[String],
    ) -> Vec<String> {
        requested
            .iter()
            .filter(|s| self.scopes.contains(s) && resource.scopes.contains(s))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests;
