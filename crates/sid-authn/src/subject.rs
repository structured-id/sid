// SPDX-License-Identifier: AGPL-3.0-only
//! Subject resolution: the `sub` an application's tokens carry.
//!
//! The hop decides it, not the client's `subject_type` metadata: which
//! authority issues ([`OidcIssuer`]), which Profile the user selected and how
//! that Profile stands to the recipient application's organization
//! ([`SubjectRule`]).
//!
//! - **Managed Profile**: the recipient's own organization manages the
//!   selected Profile and the issuer is its own authority in base mode; `sub`
//!   is the local ProfileId.
//! - **Organization Binding**: the selected identity is outside the recipient
//!   organization's management; `sub` is the BindingId of the Profile's
//!   stored binding to that organization, an opaque UUIDv7 allocated on the
//!   first visit and unlinkable across organizations.
//!
//! A token carries this subject and no other identifier of the user: moving
//! an application's accounts to another subject is a dedicated continuity
//! flow, never an extra claim in ordinary tokens.
//!
//! Reference: Prudnikov, D. (2026). "Client-Side Verifiable Presentation System
//! with Passkey-Derived Persistent Keys and Pairwise Service Bindings."
//! doi:[10.5281/zenodo.19387768](https://doi.org/10.5281/zenodo.19387768)

use sid_core::models::oidc_issuer::IssuerAuthority;
use sid_core::models::{AuditEntry, BindingScope, OAuth2Client, OidcIssuer, ProfileId};
use sid_plugin::storage::StorageBackend;

/// Which subject the selected Profile gets at a recipient application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectRule {
    /// The recipient's organization manages the selected Profile: its local
    /// ProfileId.
    ManagedProfile,
    /// The selected identity is outside the recipient organization's
    /// management: its binding to that organization.
    OrganizationBinding,
}

impl SubjectRule {
    /// The rule of the hop from `issuer` to `client`, for a Profile the
    /// issuing authority manages. A client that is not a recipient of the
    /// issuer has no rule: the association is never guessed.
    ///
    /// A local issuer serves its installation's own organization, whose
    /// Profiles it manages, so its applications get the ProfileId; CE has no
    /// opt-in for internal application isolation.
    pub fn for_hop(issuer: &OidcIssuer, client: &OAuth2Client) -> sid_core::Result<Self> {
        if client.org_id != Some(issuer.recipient_org) {
            return Err(sid_core::Error::Validation(format!(
                "client {} is not a recipient of issuer {}",
                client.client_id, issuer.canonical_url
            )));
        }
        match issuer.authority {
            IssuerAuthority::Local => Ok(Self::ManagedProfile),
        }
    }

    /// The rule of the hop from `issuer` to one of its registered resources,
    /// which belong to its recipient organization: the same as for that
    /// organization's clients.
    pub fn for_resource(issuer: &OidcIssuer) -> Self {
        match issuer.authority {
            IssuerAuthority::Local => Self::ManagedProfile,
        }
    }
}

/// Resolve the `sub` a token for `client` carries under `rule`, allocating
/// the Profile's binding to the client's organization on its first visit.
pub async fn resolve_subject(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    client: &OAuth2Client,
    rule: SubjectRule,
) -> sid_core::Result<String> {
    match rule {
        SubjectRule::ManagedProfile => Ok(profile_id.to_string()),
        SubjectRule::OrganizationBinding => {
            let binding = storage
                .service_binding(
                    profile_id,
                    &binding_scope(client)?,
                    AuditEntry::user(
                        profile_id.to_string(),
                        "service_binding.allocate",
                        client.client_id.clone(),
                    )
                    .into(),
                )
                .await?;
            Ok(binding.binding_id.to_string())
        }
    }
}

/// The `sub` `client` already received for `profile_id` under `rule`,
/// without allocating: `None` for an organization the Profile never visited.
pub async fn known_subject(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
    client: &OAuth2Client,
    rule: SubjectRule,
) -> sid_core::Result<Option<String>> {
    match rule {
        SubjectRule::ManagedProfile => Ok(Some(profile_id.to_string())),
        SubjectRule::OrganizationBinding => Ok(storage
            .find_service_binding(profile_id, &binding_scope(client)?)
            .await?
            .map(|binding| binding.binding_id.to_string())),
    }
}

/// The scope of a client's organization bindings: its organization, so every
/// client of one organization, in any project, sees the same subject
/// whatever its domains, never split by a user's department or group. A
/// client in no
/// organization has none: the scope is never inferred from a host or the
/// client id, which a registrant chooses.
pub fn binding_scope(client: &OAuth2Client) -> sid_core::Result<BindingScope> {
    let org_id = client.org_id.ok_or_else(|| {
        sid_core::Error::Validation(format!(
            "client {} belongs to no organization",
            client.client_id
        ))
    })?;
    BindingScope::try_from(org_id.to_string())
        .map_err(|e| sid_core::Error::Validation(format!("client {}: {e}", client.client_id)))
}

#[cfg(test)]
mod tests;
