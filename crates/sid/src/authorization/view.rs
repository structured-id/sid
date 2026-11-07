// SPDX-License-Identifier: AGPL-3.0-only
//! Roles, groups, assignments and policies as the authorization API's
//! messages, and the administrative authorities a request asks for read back
//! from them, refused on the field they break.

use sid_core::models::{
    AdminEnvelope as DomainEnvelope, CedarPolicy, Group, PolicyAuthority as DomainPolicyAuthority,
    PolicyEffect as DomainPolicyEffect, PolicyScope, ResourceId, Role, RoleAssignment,
    RoleAssignmentPrincipal,
};
use sid_proto::sid::v1::authz::*;

use super::{AuthorizationError, invalid_field};
use crate::wire::{to_timestamp, wire_id};

pub(super) fn role_to_proto(r: &Role) -> sid_proto::sid::v1::Role {
    sid_proto::sid::v1::Role {
        id: Some(r.id.into()),
        project_id: Some(r.project_id.into()),
        name: r.key.clone(),
        description: r.description.clone(),
        permissions: r.permissions.clone(),
        created_at: Some(to_timestamp(r.created_at)),
        updated_at: Some(to_timestamp(r.updated_at)),
    }
}

pub(super) fn group_to_proto(g: &Group) -> sid_proto::sid::v1::Group {
    sid_proto::sid::v1::Group {
        id: Some(g.id.into()),
        project_id: Some(g.project_id.into()),
        name: g.name.clone(),
        description: g.description.clone(),
        created_at: Some(to_timestamp(g.created_at)),
        updated_at: Some(to_timestamp(g.updated_at)),
    }
}

pub(super) fn assignment_to_proto(a: &RoleAssignment) -> sid_proto::sid::v1::RoleAssignment {
    use role_assignment::Principal;
    let principal = match &a.principal {
        RoleAssignmentPrincipal::Profile(pid) => Principal::ProfileId((*pid).into()),
        RoleAssignmentPrincipal::Group(gid) => Principal::GroupId((*gid).into()),
        RoleAssignmentPrincipal::MachineUser(mid) => Principal::MachineUserId((*mid).into()),
        RoleAssignmentPrincipal::OAuthClient(client_id) => {
            Principal::OauthClientId(client_id.clone())
        }
        RoleAssignmentPrincipal::ProvisioningConnector(connector) => {
            Principal::ProvisioningConnectorId((*connector).into())
        }
    };
    sid_proto::sid::v1::RoleAssignment {
        id: Some(a.id.into()),
        principal: Some(principal),
        role_id: Some(a.role_id.into()),
        scope: a.scope.clone(),
        expires_at: a.expires_at.map(to_timestamp),
        created_at: Some(to_timestamp(a.created_at)),
        admin: a.admin.as_ref().map(envelope_to_proto),
        policy_admin: a.policy_admin.as_ref().map(policy_authority_to_proto),
        provenance: a.provenance.as_ref().map(|p| AssignmentProvenance {
            granted_by: p.granted_by.clone(),
            basis_assignment_id: p.basis.map(Into::into),
            depends_on_assignment_id: p.depends_on.map(Into::into),
            approved_ceiling: p
                .ceiling
                .as_ref()
                .map(|c| c.iter().cloned().collect())
                .unwrap_or_default(),
        }),
    }
}

fn policy_authority_to_proto(a: &DomainPolicyAuthority) -> PolicyAuthority {
    use sid_core::models::PolicyOperation as Op;
    PolicyAuthority {
        operations: a
            .operations
            .iter()
            .map(|op| match op {
                Op::Read => PolicyOperation::Read,
                Op::Edit => PolicyOperation::Edit,
                Op::Redelegate => PolicyOperation::Redelegate,
            } as i32)
            .collect(),
    }
}

/// The policy authority a request asks for, refused naming the field it breaks.
pub(super) fn policy_authority_from_proto(
    a: PolicyAuthority,
) -> Result<DomainPolicyAuthority, AuthorizationError> {
    use sid_core::models::PolicyOperation as Op;
    let operations = a
        .operations
        .iter()
        .map(|op| match PolicyOperation::try_from(*op) {
            Ok(PolicyOperation::Read) => Ok(Op::Read),
            Ok(PolicyOperation::Edit) => Ok(Op::Edit),
            Ok(PolicyOperation::Redelegate) => Ok(Op::Redelegate),
            Ok(PolicyOperation::Unspecified) | Err(_) => Err(invalid_field(
                "policy_admin.operations",
                "not a policy operation",
            )),
        })
        .collect::<Result<_, _>>()?;
    Ok(DomainPolicyAuthority { operations })
}

fn envelope_to_proto(e: &DomainEnvelope) -> AdminEnvelope {
    use sid_core::models::AdminOperation as Op;
    use sid_core::models::RecipientKind as Kind;
    AdminEnvelope {
        operations: e
            .operations
            .iter()
            .map(|op| match op {
                Op::Assign => AdminOperation::Assign,
                Op::Revoke => AdminOperation::Revoke,
                Op::EditRole => AdminOperation::EditRole,
                Op::Redelegate => AdminOperation::Redelegate,
            } as i32)
            .collect(),
        role_ids: e.roles.iter().map(|id| (*id).into()).collect(),
        permission_ceiling: e.permission_ceiling.iter().cloned().collect(),
        recipient_kinds: e
            .recipient_kinds
            .iter()
            .map(|kind| match kind {
                Kind::Profile => RecipientKind::Profile,
                Kind::Group => RecipientKind::Group,
                Kind::MachineUser => RecipientKind::MachineUser,
                Kind::OAuthClient => RecipientKind::OauthClient,
            } as i32)
            .collect(),
        recipient_group_id: e.recipient_group.map(Into::into),
        max_validity: Some(prost_types::Duration {
            seconds: e.max_validity_secs,
            nanos: 0,
        }),
    }
}

/// The envelope a request asks for, refused naming the field it breaks.
pub(super) fn envelope_from_proto(e: AdminEnvelope) -> Result<DomainEnvelope, AuthorizationError> {
    use sid_core::models::AdminOperation as Op;
    use sid_core::models::EnvelopeError;
    use sid_core::models::RecipientKind as Kind;
    let operations = e
        .operations
        .iter()
        .map(|op| match AdminOperation::try_from(*op) {
            Ok(AdminOperation::Assign) => Ok(Op::Assign),
            Ok(AdminOperation::Revoke) => Ok(Op::Revoke),
            Ok(AdminOperation::EditRole) => Ok(Op::EditRole),
            Ok(AdminOperation::Redelegate) => Ok(Op::Redelegate),
            Ok(AdminOperation::Unspecified) | Err(_) => Err(invalid_field(
                "admin.operations",
                "not an administration operation",
            )),
        })
        .collect::<Result<_, _>>()?;
    let roles = e
        .role_ids
        .iter()
        .map(|id| wire_id(Some(id), "admin.role_ids"))
        .collect::<Result<_, _>>()?;
    let recipient_kinds = e
        .recipient_kinds
        .iter()
        .map(|kind| match RecipientKind::try_from(*kind) {
            Ok(RecipientKind::Profile) => Ok(Kind::Profile),
            Ok(RecipientKind::Group) => Ok(Kind::Group),
            Ok(RecipientKind::MachineUser) => Ok(Kind::MachineUser),
            Ok(RecipientKind::OauthClient) => Ok(Kind::OAuthClient),
            Ok(RecipientKind::Unspecified) | Err(_) => Err(invalid_field(
                "admin.recipient_kinds",
                "not a recipient kind",
            )),
        })
        .collect::<Result<_, _>>()?;
    let recipient_group = e
        .recipient_group_id
        .as_ref()
        .map(|id| wire_id(Some(id), "admin.recipient_group_id"))
        .transpose()?;
    let max_validity_secs = match e.max_validity {
        Some(d) if d.nanos == 0 => d.seconds,
        Some(_) => {
            return Err(invalid_field(
                "admin.max_validity",
                "not a whole number of seconds",
            ));
        }
        None => return Err(AuthorizationError::MissingField("admin.max_validity")),
    };
    let envelope = DomainEnvelope {
        operations,
        roles,
        permission_ceiling: e.permission_ceiling.into_iter().collect(),
        recipient_kinds,
        recipient_group,
        max_validity_secs,
    };
    envelope.validate().map_err(|err| {
        let field = match err {
            EnvelopeError::NoOperations => "admin.operations",
            EnvelopeError::NoRoles => "admin.role_ids",
            EnvelopeError::NoPermissionCeiling => "admin.permission_ceiling",
            EnvelopeError::NoRecipientKinds => "admin.recipient_kinds",
            EnvelopeError::Validity => "admin.max_validity",
        };
        invalid_field(field, err.to_string())
    })?;
    Ok(envelope)
}

/// The effect a request names; an unspecified one permits.
pub(super) fn policy_effect(proto: i32) -> DomainPolicyEffect {
    match sid_proto::sid::v1::PolicyEffect::try_from(proto) {
        Ok(sid_proto::sid::v1::PolicyEffect::Forbid) => DomainPolicyEffect::Forbid,
        _ => DomainPolicyEffect::Permit,
    }
}

pub(super) fn policy_to_proto(p: &CedarPolicy) -> Policy {
    let effect = if p.effect == DomainPolicyEffect::Permit {
        sid_proto::sid::v1::PolicyEffect::Permit
    } else {
        sid_proto::sid::v1::PolicyEffect::Forbid
    };
    Policy {
        id: Some(p.id.into()),
        scope: Some(policy_scope_to_proto(p.scope)),
        name: p.name.clone(),
        description: p.description.clone(),
        policy_text: p.policy_text.clone(),
        effect: effect.into(),
        enabled: p.enabled,
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
        revision: p.revision,
    }
}

fn policy_scope_to_proto(scope: PolicyScope) -> sid_proto::sid::v1::PolicyScope {
    use sid_proto::sid::v1::policy_scope::Scope;
    sid_proto::sid::v1::PolicyScope {
        scope: Some(match scope {
            PolicyScope::Installation => Scope::Installation(()),
            PolicyScope::Project(id) => Scope::ProjectId(id.into()),
            PolicyScope::Resource(id) => Scope::Resource(id.into()),
        }),
    }
}

/// The scope `field` names; a missing or malformed one is refused.
pub(super) fn policy_scope_from_proto(
    scope: Option<&sid_proto::sid::v1::PolicyScope>,
    field: &'static str,
) -> Result<PolicyScope, AuthorizationError> {
    use sid_proto::sid::v1::policy_scope::Scope;
    match scope.and_then(|s| s.scope.as_ref()) {
        None => Err(AuthorizationError::MissingField(field)),
        Some(Scope::Installation(())) => Ok(PolicyScope::Installation),
        Some(Scope::ProjectId(id)) => Ok(PolicyScope::Project(wire_id(Some(id), field)?)),
        Some(Scope::Resource(id)) => ResourceId::try_from(id)
            .map(PolicyScope::Resource)
            .map_err(|_| invalid_field(field, "not a protected resource identifier")),
    }
}

#[cfg(test)]
mod tests;
