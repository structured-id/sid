// SPDX-License-Identifier: AGPL-3.0-only
//! CE Authorization Engine: the fixed RBAC + Cedar decision.
//!
//! Pipeline: RBAC role check → Cedar policy evaluation. No graph
//! traversal, no ReBAC: all checks are flat queries.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sid_core::models::{
    AUTHZ_CHECK, AuthzPrincipal, MachineUserId, PolicyScope, ProfileId, ProjectId,
    ProvisioningConnectorId, ResourceId, RoleAssignment, RoleId, SCIM_ACTION_PREFIX,
    TOKEN_INTROSPECT,
};
use sid_plugin::StorageBackend;

use crate::cedar::CedarService;
use crate::compiled::PolicySets;
use crate::decision::{AuthzCheckRequest, AuthzCheckResponse, AuthzError};
use crate::rbac::{self, GrantTarget, RbacService};

/// Resource prefix naming one registered protected resource.
const OAUTH_RESOURCE: &str = "oauth_resource:";

/// The policies that apply to a decision on one target, with the scopes they
/// were selected from.
#[derive(Debug, Clone)]
pub struct ApplicablePolicies {
    /// The scopes whose policies apply to the target.
    pub scopes: Vec<PolicyScope>,
    /// Every policy of `scopes`, enabled or not.
    pub policies: Vec<sid_core::models::CedarPolicy>,
}

/// CE authorization engine: RBAC + Cedar (ABAC).
///
/// Check pipeline:
/// 1. Parse subject → AuthzPrincipal (Profile, MachineUser or OAuthClient)
/// 2. A protected resource (`oauth_resource:<id>`) is decided by the
///    assignments scoped to exactly that resource, and by the installation's,
///    its registered parent project's and its own policies
/// 3. Otherwise, resource → ProjectId; RBAC: resolve effective roles, check
///    if any grants the permission; the installation's and the project's
///    policies apply
/// 4. Evaluate the applicable enabled Cedar policies: a satisfied `forbid`
///    denies whatever role grants; else a role grant allows; else a satisfied
///    `permit` allows; a policy set that cannot be evaluated denies
/// 5. Return Allow/Deny with reason
pub struct CeAuthzEngine<S: StorageBackend + ?Sized> {
    rbac: RbacService<S>,
    cedar: CedarService,
    /// The applicable sets, compiled once per distinct set of policies.
    policy_sets: PolicySets,
    storage: Arc<S>,
}

impl<S: StorageBackend + ?Sized> CeAuthzEngine<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            rbac: RbacService::new(storage.clone()),
            cedar: CedarService::new(),
            policy_sets: PolicySets::default(),
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
        ProjectId::parse(id_str)
            .map_err(|e| AuthzError::InvalidResource(format!("{resource}: {e}")))
    }

    /// The roles `principal` holds that grant `action` on `target`, read
    /// into `reads` when they are not there yet.
    async fn granting(
        &self,
        principal: &AuthzPrincipal,
        target: GrantTarget,
        action: &str,
        reads: &mut Reads,
    ) -> Result<Vec<String>, AuthzError> {
        let storage = |e: sid_core::Error| AuthzError::Storage(e.to_string());
        let picked = match reads.assignments.get(principal) {
            Some(assignments) => rbac::picks(assignments, target),
            None => {
                let assignments = self.rbac.assignments_of(principal).await.map_err(storage)?;
                let picked = rbac::picks(&assignments, target);
                reads.assignments.insert(principal.clone(), assignments);
                picked
            }
        };
        let unread: Vec<RoleId> = picked
            .iter()
            .flatten()
            .filter(|id| !reads.roles_read.contains(id))
            .copied()
            .collect();
        if !unread.is_empty() {
            reads
                .roles
                .extend(self.rbac.roles_by_id(&unread).await.map_err(storage)?);
            reads.roles_read.extend(unread);
        }
        Ok(rbac::granting(&picked, &reads.roles, action, target))
    }

    /// The enabled policies that apply to a decision on `target`, read into
    /// `reads` when they are not there yet.
    async fn applicable<'r>(
        &self,
        target: GrantTarget,
        reads: &'r mut Reads,
    ) -> Result<&'r [(String, String)], AuthzError> {
        match reads.policies.entry(target) {
            Entry::Occupied(read) => Ok(read.into_mut()),
            Entry::Vacant(unread) => {
                let scopes = self.scopes_for(target).await?;
                Ok(unread.insert(self.enabled_policies(&scopes).await?))
            }
        }
    }

    /// The project of the application `resource` belongs to; none for a
    /// resource of no application. An unknown resource, or one naming an
    /// application that does not exist, refuses the decision: it cannot
    /// select a smaller, less restrictive policy set.
    async fn parent_project(&self, resource: ResourceId) -> Result<Option<ProjectId>, AuthzError> {
        let registered = self
            .storage
            .get_protected_resource(resource)
            .await
            .map_err(|e| AuthzError::Storage(e.to_string()))?
            .ok_or_else(|| {
                AuthzError::InvalidResource(format!("resource {resource} is not registered"))
            })?;
        let Some(application) = registered.application_id else {
            return Ok(None);
        };
        let application = self
            .storage
            .get_application(application)
            .await
            .map_err(|e| AuthzError::Storage(e.to_string()))?
            .ok_or_else(|| {
                AuthzError::InvalidResource(format!(
                    "resource {resource} names application {application}, which does not exist"
                ))
            })?;
        Ok(Some(application.project_id))
    }

    /// The scopes whose policies apply to a decision on the protected
    /// `resource`: the installation's, its registered parent project's and
    /// its own.
    async fn resource_scopes(&self, resource: ResourceId) -> Result<Vec<PolicyScope>, AuthzError> {
        let mut scopes = vec![PolicyScope::Installation];
        if let Some(project) = self.parent_project(resource).await? {
            scopes.push(PolicyScope::Project(project));
        }
        scopes.push(PolicyScope::Resource(resource));
        Ok(scopes)
    }

    /// What `resource` names: a protected resource `oauth_resource:<id>`, or
    /// else a project.
    fn target_of(resource: &str) -> Result<GrantTarget, AuthzError> {
        match resource.strip_prefix(OAUTH_RESOURCE) {
            Some(id) => ResourceId::parse(id)
                .map(GrantTarget::Resource)
                .map_err(|e| AuthzError::InvalidResource(format!("{resource}: {e}"))),
            None => Self::parse_project(resource).map(GrantTarget::Project),
        }
    }

    /// The scopes whose policies apply to a decision on `target`.
    async fn scopes_for(&self, target: GrantTarget) -> Result<Vec<PolicyScope>, AuthzError> {
        match target {
            GrantTarget::Resource(id) => self.resource_scopes(id).await,
            GrantTarget::Project(project) => Ok(vec![
                PolicyScope::Installation,
                PolicyScope::Project(project),
            ]),
        }
    }

    /// The scopes that apply to a decision on `resource` and every policy of
    /// them, enabled or not, selected as enforcement selects it: what a dry
    /// run changes and evaluates under [`Self::check_under`].
    pub async fn applicable_policies(
        &self,
        resource: &str,
    ) -> Result<ApplicablePolicies, AuthzError> {
        let scopes = self.scopes_for(Self::target_of(resource)?).await?;
        let mut policies = Vec::new();
        for scope in &scopes {
            policies.extend(
                self.storage
                    .list_cedar_policies(*scope)
                    .await
                    .map_err(|e| AuthzError::Storage(e.to_string()))?,
            );
        }
        Ok(ApplicablePolicies { scopes, policies })
    }

    /// The enabled policies of `scopes`, as (id, text).
    async fn enabled_policies(
        &self,
        scopes: &[PolicyScope],
    ) -> Result<Vec<(String, String)>, AuthzError> {
        let mut enabled = Vec::new();
        for scope in scopes {
            enabled.extend(
                self.storage
                    .list_cedar_policies(*scope)
                    .await
                    .map_err(|e| AuthzError::Storage(e.to_string()))?
                    .into_iter()
                    .filter(|p| p.enabled)
                    .map(|p| (p.id.to_string(), p.policy_text)),
            );
        }
        Ok(enabled)
    }

    /// The decision on `request` for `principal` on the Cedar resource
    /// `target`, given the roles `granting` its action and the applicable
    /// `policies`: a satisfied `forbid` denies whatever role grants, as does
    /// a policy set that cannot be evaluated; otherwise a role grant allows,
    /// else a satisfied `permit` allows, else deny.
    fn combine(
        &self,
        principal: &AuthzPrincipal,
        request: &AuthzCheckRequest,
        target: &str,
        granting: &[String],
        policies: &[(String, String)],
    ) -> AuthzCheckResponse {
        let rbac_allow = || AuthzCheckResponse::Allow {
            reason: format!(
                "RBAC: roles [{}] grant {}",
                granting.join(", "),
                request.action
            ),
        };
        if policies.is_empty() {
            return if granting.is_empty() {
                AuthzCheckResponse::Deny {
                    reason: format!(
                        "no RBAC role grants '{}' and no Cedar policy permits",
                        request.action
                    ),
                }
            } else {
                rbac_allow()
            };
        }
        let (subject_type, subject_id) = match principal {
            AuthzPrincipal::Profile(id) => ("User", id.to_string()),
            AuthzPrincipal::MachineUser(id) => ("MachineUser", id.to_string()),
            AuthzPrincipal::OAuthClient(id) => ("OAuthClient", id.clone()),
            AuthzPrincipal::ProvisioningConnector(id) => ("ProvisioningConnector", id.to_string()),
        };
        let policy_ids = |result: &crate::cedar::CedarEvalResult| {
            result
                .matches
                .iter()
                .map(|m| m.policy_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        // Entities from their components: an identifier's quotes or
        // backslashes are part of it, never Cedar syntax.
        let evaluated = CedarService::entity(subject_type, &subject_id).and_then(|subject| {
            self.cedar.evaluate_compiled(
                &*self.policy_sets.get(policies)?,
                subject,
                CedarService::entity("Action", &request.action)?,
                CedarService::entity("Resource", target)?,
                &request.context,
            )
        });
        match evaluated {
            Ok(result) if result.forbidden() => AuthzCheckResponse::Deny {
                reason: format!("Cedar: policies [{}] forbid", policy_ids(&result)),
            },
            // A policy that fails to evaluate at runtime is skipped by
            // Cedar, and might be the prohibition that applies: deny,
            // whatever role grants.
            Ok(result) if !result.errors.is_empty() => {
                tracing::warn!("Cedar evaluation errors: {}", result.errors.join("; "));
                AuthzCheckResponse::Deny {
                    reason: format!(
                        "the applicable policies cannot be evaluated: {}",
                        result.errors.join("; ")
                    ),
                }
            }
            Ok(_) if !granting.is_empty() => rbac_allow(),
            Ok(result) if result.allowed => AuthzCheckResponse::Allow {
                reason: format!("Cedar: policies [{}] permit", policy_ids(&result)),
            },
            Ok(_) => AuthzCheckResponse::Deny {
                reason: format!(
                    "no RBAC role grants '{}' and no Cedar policy permits",
                    request.action
                ),
            },
            // A policy set that cannot be evaluated might hold the
            // prohibition that applies: deny, whatever role grants.
            Err(e) => {
                tracing::warn!("Cedar evaluation error: {e}");
                AuthzCheckResponse::Deny {
                    reason: format!("the applicable policies cannot be evaluated: {e}"),
                }
            }
        }
    }
}

impl<S: StorageBackend + ?Sized> CeAuthzEngine<S> {
    /// Decide whether the request's subject may perform its action on its
    /// resource.
    pub async fn check(
        &self,
        request: &AuthzCheckRequest,
    ) -> Result<AuthzCheckResponse, AuthzError> {
        self.decide(request, None, &mut Reads::default()).await
    }

    /// The decision [`Self::check`] would make if the project's enabled
    /// Cedar policies were `policies` (id, text): what a proposed policy
    /// change would decide, by the same precedence.
    pub async fn check_under(
        &self,
        request: &AuthzCheckRequest,
        policies: &[(String, String)],
    ) -> Result<AuthzCheckResponse, AuthzError> {
        self.decide(request, Some(policies), &mut Reads::default())
            .await
    }

    /// The decision on `request`, under `policies` instead of the stored
    /// ones when given, reading what it needs into `reads`.
    async fn decide(
        &self,
        request: &AuthzCheckRequest,
        policies: Option<&[(String, String)]>,
        reads: &mut Reads,
    ) -> Result<AuthzCheckResponse, AuthzError> {
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
        // Invites are managed by a machine user on the enrollment API only:
        // the invite RPCs admit no other caller, so no other is allowed here.
        if sid_core::models::is_invite_action(&request.action)
            && (protected.is_none() || !matches!(principal, AuthzPrincipal::MachineUser(_)))
        {
            return Ok(AuthzCheckResponse::Deny {
                reason: format!(
                    "'{}' is held by a machine user on a protected resource only",
                    request.action
                ),
            });
        }
        let target = Self::target_of(&request.resource)?;
        let action = request.action.as_str();
        // The principal's roles that grant the action on the target, whatever
        // kind of principal it is.
        let granting = self.granting(&principal, target, action, reads).await?;
        // Token inspection and permission checking need their assignment on
        // the resource whatever a policy permits.
        if let GrantTarget::Resource(resource) = target
            && granting.is_empty()
            && (action == TOKEN_INTROSPECT || action == AUTHZ_CHECK)
        {
            return Ok(AuthzCheckResponse::Deny {
                reason: format!("no role on resource {resource} grants '{action}'"),
            });
        }
        // The installation's, the project's and the resource's policies apply
        // to every decision on the target: a `forbid` prohibits whatever role
        // grants, a `permit` allows without one.
        let applicable = match policies {
            Some(policies) => policies,
            None => self.applicable(target, reads).await?,
        };
        let named = match target {
            GrantTarget::Resource(resource) => resource.to_string(),
            GrantTarget::Project(project) => project.to_string(),
        };
        Ok(self.combine(&principal, request, &named, &granting, applicable))
    }

    /// One decision per request, in order; the first check that cannot be
    /// decided fails the batch. Each subject's assignments and roles and each
    /// target's policies are read once for the whole batch.
    pub async fn batch_check(
        &self,
        requests: &[AuthzCheckRequest],
    ) -> Result<Vec<AuthzCheckResponse>, AuthzError> {
        let mut reads = Reads::default();
        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            results.push(self.decide(request, None, &mut reads).await?);
        }
        Ok(results)
    }
}

/// What the decisions of one call have read: each subject's assignments, the
/// roles they name and each target's enabled policies.
#[derive(Default)]
struct Reads {
    assignments: HashMap<AuthzPrincipal, Vec<RoleAssignment>>,
    roles: HashMap<RoleId, sid_core::models::Role>,
    /// The roles read, found or not: a role deleted since its assignment is
    /// not asked for again.
    roles_read: HashSet<RoleId>,
    policies: HashMap<GrantTarget, Vec<(String, String)>>,
}

#[cfg(test)]
mod tests;
