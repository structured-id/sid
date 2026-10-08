// SPDX-License-Identifier: AGPL-3.0-only
//! CE Authorization Engine.
//!
//! Implements `AuthzEngine` for CE deployments using RBAC + Cedar.
//! Pipeline: RBAC role check → Cedar policy evaluation.
//! No graph traversal, no ReBAC — all checks are flat SQL queries.

use std::sync::Arc;

use async_trait::async_trait;
use sid_core::models::{
    AUTHZ_CHECK, AuthzPrincipal, MachineUserId, ProfileId, ProjectId, ProvisioningConnectorId,
    ResourceId, SCIM_ACTION_PREFIX, TOKEN_INTROSPECT,
};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzCheckResponse, AuthzEngine, AuthzError};
use uuid::Uuid;

use crate::cedar::CedarService;
use crate::rbac::RbacService;

/// Resource prefix naming one registered protected resource.
const OAUTH_RESOURCE: &str = "oauth_resource:";

/// CE authorization engine: RBAC + Cedar (ABAC).
///
/// Check pipeline:
/// 1. Parse subject → AuthzPrincipal (Profile, MachineUser or OAuthClient)
/// 2. A protected resource (`oauth_resource:<id>`) is decided by the
///    assignments scoped to exactly that resource; project policies do not
///    apply to it
/// 3. Otherwise, resource → ProjectId; RBAC: resolve effective roles, check
///    if any grants the permission
/// 4. If RBAC denies and Cedar policies exist: evaluate Cedar policies
/// 5. Return Allow/Deny with reason
///
/// `list_accessible_objects` and `list_subjects_with_access` require ReBAC
/// graph traversal — CE returns `NotSupported`.
pub struct CeAuthzEngine<S: StorageBackend + ?Sized> {
    rbac: RbacService<S>,
    cedar: CedarService,
    storage: Arc<S>,
}

impl<S: StorageBackend + ?Sized> CeAuthzEngine<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            rbac: RbacService::new(storage.clone()),
            cedar: CedarService::new(),
            storage,
        }
    }

    /// Parse subject string → AuthzPrincipal.
    /// Accepts: `user:<uuid>`, `machine:<uuid>`, `oauth_client:<client_id>`,
    /// `provisioning_connector:<uuid>`, or bare `<uuid>` (defaults to Profile).
    fn parse_subject(subject: &str) -> Result<AuthzPrincipal, AuthzError> {
        if let Some(id_str) = subject.strip_prefix("machine:") {
            MachineUserId::parse(id_str)
                .map(AuthzPrincipal::MachineUser)
                .map_err(|e| AuthzError::InvalidSubject(format!("{subject}: {e}")))
        } else if let Some(id_str) = subject.strip_prefix("provisioning_connector:") {
            ProvisioningConnectorId::parse(id_str)
                .map(AuthzPrincipal::ProvisioningConnector)
                .map_err(|e| AuthzError::InvalidSubject(format!("{subject}: {e}")))
        } else if let Some(client_id) = subject.strip_prefix("oauth_client:") {
            if client_id.is_empty() {
                return Err(AuthzError::InvalidSubject(format!(
                    "{subject}: empty client id"
                )));
            }
            Ok(AuthzPrincipal::OAuthClient(client_id.to_owned()))
        } else {
            let id_str = subject.strip_prefix("user:").unwrap_or(subject);
            ProfileId::parse(id_str)
                .map(AuthzPrincipal::Profile)
                .map_err(|e| AuthzError::InvalidSubject(format!("{subject}: {e}")))
        }
    }

    /// Parse resource string → ProjectId.
    /// Accepts: `project:<uuid>`, `<type>:<uuid>`, or bare `<uuid>`.
    fn parse_project(resource: &str) -> Result<ProjectId, AuthzError> {
        let id_str = if let Some(rest) = resource.strip_prefix("project:") {
            rest
        } else if let Some((_type, id)) = resource.split_once(':') {
            id
        } else {
            resource
        };
        Uuid::parse_str(id_str)
            .map(ProjectId)
            .map_err(|e| AuthzError::InvalidResource(format!("{resource}: {e}")))
    }

    /// The decision on one protected resource: only assignments scoped to it.
    async fn check_protected_resource(
        &self,
        principal: &AuthzPrincipal,
        resource: ResourceId,
        action: &str,
    ) -> Result<AuthzCheckResponse, AuthzError> {
        let granting = self
            .rbac
            .resource_granting_roles(principal, resource, action)
            .await
            .map_err(|e| AuthzError::Storage(e.to_string()))?;
        Ok(if granting.is_empty() {
            AuthzCheckResponse::Deny {
                reason: format!("no role on resource {resource} grants '{action}'"),
            }
        } else {
            AuthzCheckResponse::Allow {
                reason: format!(
                    "RBAC: roles [{}] on resource {resource} grant {action}",
                    granting.join(", ")
                ),
            }
        })
    }
}

#[async_trait]
impl<S: StorageBackend + ?Sized + 'static> AuthzEngine for CeAuthzEngine<S> {
    async fn check(&self, request: &AuthzCheckRequest) -> Result<AuthzCheckResponse, AuthzError> {
        let principal = Self::parse_subject(&request.subject)?;
        let protected = request.resource.strip_prefix(OAUTH_RESOURCE);
        // A provisioning connector acts only through SCIM on a protected
        // resource, whatever roles it was given.
        if matches!(principal, AuthzPrincipal::ProvisioningConnector(_))
            && (protected.is_none() || !request.action.starts_with(SCIM_ACTION_PREFIX))
        {
            return Ok(AuthzCheckResponse::Deny {
                reason: format!(
                    "a provisioning connector may only perform SCIM actions on a protected resource, not '{}' on {}",
                    request.action, request.resource
                ),
            });
        }
        // Inspecting tokens and asking about others' permissions are held by
        // a service identity only, whatever role a Profile or group was given
        // (D054): a role edited after its assignment cannot hand them out.
        let service_action = request.action == TOKEN_INTROSPECT || request.action == AUTHZ_CHECK;
        if service_action
            && !matches!(
                principal,
                AuthzPrincipal::MachineUser(_) | AuthzPrincipal::OAuthClient(_)
            )
        {
            return Ok(AuthzCheckResponse::Deny {
                reason: format!(
                    "'{}' is held by a machine user or an OAuth client only",
                    request.action
                ),
            });
        }
        if let Some(id) = protected {
            let resource = ResourceId::parse(id)
                .map_err(|e| AuthzError::InvalidResource(format!("{}: {e}", request.resource)))?;
            return self
                .check_protected_resource(&principal, resource, &request.action)
                .await;
        }
        let project_id = Self::parse_project(&request.resource)?;

        // Step 1: RBAC check — the principal's project roles, whatever kind
        // of principal it is.
        let granting_roles = self
            .rbac
            .project_granting_roles(&principal, project_id, &request.action)
            .await
            .map_err(|e| AuthzError::Storage(e.to_string()))?;
        if !granting_roles.is_empty() {
            return Ok(AuthzCheckResponse::Allow {
                reason: format!(
                    "RBAC: roles [{}] grant {}",
                    granting_roles.join(", "),
                    request.action
                ),
            });
        }

        // Step 2: Cedar policy evaluation — load project policies, evaluate.
        let cedar_policies = self
            .storage
            .list_cedar_policies(project_id)
            .await
            .map_err(|e| AuthzError::Storage(e.to_string()))?;

        let enabled_policies: Vec<(String, String)> = cedar_policies
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (p.id.0.to_string(), p.policy_text.clone()))
            .collect();

        if !enabled_policies.is_empty() {
            let cedar_subject = match &principal {
                AuthzPrincipal::Profile(id) => format!(r#"User::"{id}""#),
                AuthzPrincipal::MachineUser(id) => format!(r#"MachineUser::"{id}""#),
                AuthzPrincipal::OAuthClient(id) => format!(r#"OAuthClient::"{id}""#),
                AuthzPrincipal::ProvisioningConnector(id) => {
                    format!(r#"ProvisioningConnector::"{id}""#)
                }
            };
            let cedar_action = format!(r#"Action::"{}""#, request.action);
            let cedar_resource = format!(r#"Resource::"{}""#, project_id.0);

            match self.cedar.evaluate(
                &enabled_policies,
                &cedar_subject,
                &cedar_action,
                &cedar_resource,
                &request.context,
            ) {
                Ok(result) if result.allowed => {
                    let policy_ids: Vec<String> =
                        result.matches.iter().map(|m| m.policy_id.clone()).collect();
                    return Ok(AuthzCheckResponse::Allow {
                        reason: format!("Cedar: policies [{}] permit", policy_ids.join(", ")),
                    });
                }
                Ok(_) => {
                    // Cedar evaluated but denied — continue to final deny
                }
                Err(e) => {
                    // Cedar evaluation error — log but don't fail, fall through to deny
                    tracing::warn!("Cedar evaluation error: {e}");
                }
            }
        }

        Ok(AuthzCheckResponse::Deny {
            reason: format!(
                "no RBAC role grants '{}' and no Cedar policy permits",
                request.action
            ),
        })
    }

    async fn list_accessible_objects(
        &self,
        _subject: &str,
        _permission: &str,
        _object_type: &str,
    ) -> Result<Vec<String>, AuthzError> {
        Err(AuthzError::NotSupported(
            "list_accessible_objects requires relationship graph traversal".into(),
        ))
    }

    async fn list_subjects_with_access(
        &self,
        _permission: &str,
        _object: &str,
    ) -> Result<Vec<String>, AuthzError> {
        Err(AuthzError::NotSupported(
            "list_subjects_with_access requires relationship graph traversal".into(),
        ))
    }
}

#[cfg(test)]
mod tests;
