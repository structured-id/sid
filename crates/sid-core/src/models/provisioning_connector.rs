// SPDX-License-Identifier: AGPL-3.0-only
//! Provisioning connectors: one directory source sending SCIM to this
//! installation, or one downstream target SID provisions, acting as its own
//! non-human actor with its own credentials and grants. Neither a Profile, a
//! machine user nor a login-handle principal.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::OrgId;
use super::machine_user::{CredentialStatus, MAX_ACTIVE_CREDENTIALS, ROTATION_GRACE_PERIOD_HOURS};

/// Validated UUIDv7 identifiers of a provisioning connector and of one of
/// its credentials (the reference audit records and listings show, never the
/// secret).
pub use sid_ids::{ProvisioningConnectorId, ProvisioningCredentialId};

parse_stored!(
    ProvisioningDirection,
    "provisioning direction",
    [Inbound, Outbound]
);
parse_stored!(
    ConnectorState,
    "provisioning connector state",
    [Active, Disabled, Retired]
);

/// Which way a connector's SCIM requests go, fixed at its creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningDirection {
    /// An external SCIM client (an HR system or IdP) calls this installation.
    Inbound,
    /// This installation calls a downstream application's SCIM server.
    Outbound,
}

impl ProvisioningDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Where a connector is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorState {
    /// Provisions through its credentials and grants.
    Active,
    /// Provisions nothing until enabled again; its users are untouched.
    Disabled,
    /// Retired for good; its identity and history stay, nothing provisions.
    Retired,
}

impl ConnectorState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Retired => "retired",
        }
    }

    /// Whether a change from this state to `to` is a lifecycle step: active
    /// and disabled switch, both retire, and nothing leaves retired.
    pub fn may_become(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Active, Self::Disabled)
                | (Self::Disabled, Self::Active)
                | (Self::Active | Self::Disabled, Self::Retired)
        )
    }
}

/// One provisioning connection of an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningConnector {
    pub id: ProvisioningConnectorId,
    /// The organization whose directory it provisions; fixed at creation.
    pub org_id: OrgId,
    /// Fixed at creation: another direction is another connector.
    pub direction: ProvisioningDirection,
    /// The connector's OAuth `client_id` at the token endpoint: the protocol
    /// name of this same actor, distinct from its ID (the token's `sub`).
    /// Random, fixed at creation.
    pub client_id: String,
    /// Administrator-chosen label; renaming keeps the identity.
    pub display_name: String,
    pub state: ConnectorState,
    /// Advances with every change, so a check made against an older revision
    /// can be fenced at the write it authorizes.
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProvisioningConnector {
    /// A new active connector of `org_id` in `direction`.
    pub fn new(
        org_id: OrgId,
        direction: ProvisioningDirection,
        display_name: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: ProvisioningConnectorId::generate(),
            org_id,
            direction,
            client_id: new_client_id(),
            display_name: display_name.into(),
            state: ConnectorState::Active,
            revision: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Whether it may provision now.
    pub fn is_active(&self) -> bool {
        self.state == ConnectorState::Active
    }
}

/// Prefix of a connector's OAuth `client_id`.
pub const CONNECTOR_CLIENT_ID_PREFIX: &str = "pc_";

/// A fresh connector `client_id`: the prefix and 24 random base62 characters
/// (about 143 bits).
fn new_client_id() -> String {
    use rand::RngExt as _;
    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let body: String = (0..24)
        .map(|_| BASE62[rng.random_range(0..BASE62.len())] as char)
        .collect();
    format!("{CONNECTOR_CLIENT_ID_PREFIX}{body}")
}

/// Prefix of an inbound connector's SCIM bearer secret, by which the SCIM
/// endpoint recognises it before any lookup.
pub const SCIM_BEARER_PREFIX: &str = "sidscim_";

/// Prefix of a connector's OAuth client secret. Distinct from the bearer's,
/// so neither is accepted where the other is expected.
pub const CONNECTOR_CLIENT_SECRET_PREFIX: &str = "sidpcs_";

parse_stored!(
    ConnectorCredentialKind,
    "connector credential kind",
    [ScimBearer, ClientSecret]
);

/// What a connector credential authenticates, fixed at its issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCredentialKind {
    /// Presented as the bearer of a SCIM request.
    ScimBearer,
    /// Presented as the OAuth client secret at the token endpoint, for an
    /// access token of the SCIM resource. Never a bearer itself.
    ClientSecret,
}

impl ConnectorCredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ScimBearer => "scim_bearer",
            Self::ClientSecret => "client_secret",
        }
    }

    /// The prefix its secrets are issued with.
    pub fn secret_prefix(&self) -> &'static str {
        match self {
            Self::ScimBearer => SCIM_BEARER_PREFIX,
            Self::ClientSecret => CONNECTOR_CLIENT_SECRET_PREFIX,
        }
    }
}

/// Usable credentials a connector may hold at once: the current one and,
/// during a rotation, its predecessor.
pub const MAX_USABLE_CONNECTOR_CREDENTIALS: usize = MAX_ACTIVE_CREDENTIALS;

/// How long a rotated-out credential keeps working.
pub fn rotation_grace() -> Duration {
    Duration::hours(i64::from(ROTATION_GRACE_PERIOD_HOURS))
}

/// One credential of a connector, stored only as the verifier of its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningCredential {
    pub id: ProvisioningCredentialId,
    pub connector_id: ProvisioningConnectorId,
    pub kind: ConnectorCredentialKind,
    pub status: CredentialStatus,
    /// SHA-256 of the secret, lowercase hex; unique, the lookup key.
    pub verifier: String,
    /// When it stops working: its own expiry, or the end of the grace a
    /// rotation gave it.
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ProvisioningCredential {
    /// A new active credential of `connector_id` of `kind` with `verifier`.
    pub fn new(
        connector_id: ProvisioningConnectorId,
        kind: ConnectorCredentialKind,
        verifier: impl Into<String>,
    ) -> Self {
        Self {
            id: ProvisioningCredentialId::generate(),
            connector_id,
            kind,
            status: CredentialStatus::Active,
            verifier: verifier.into(),
            expires_at: None,
            created_at: Utc::now(),
        }
    }

    /// Whether it authenticates at `now`: active or in its grace, and not
    /// past its expiry.
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.status.is_usable() && self.expires_at.is_none_or(|end| now < end)
    }
}

#[cfg(test)]
mod tests;
