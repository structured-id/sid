// SPDX-License-Identifier: AGPL-3.0-only
//! Projects, applications with their client and resource roles, resource
//! access, project roles and initial access tokens as the management API
//! shows them.

use sid_core::models::{
    Application, ApplicationType, InitialAccessToken, OAuth2Client, Project, ProtectedResource,
    ResourceAccess, ResourceState, Role, SubjectType, TokenEndpointAuthMethod,
};
use sid_proto::sid::v1 as proto;

use crate::wire::to_timestamp;

pub(super) fn application_type_to_proto(kind: ApplicationType) -> proto::ApplicationType {
    match kind {
        ApplicationType::Web => proto::ApplicationType::Web,
        ApplicationType::Native => proto::ApplicationType::Native,
        ApplicationType::Api => proto::ApplicationType::Api,
        ApplicationType::Spa => proto::ApplicationType::Spa,
    }
}

fn auth_method_to_proto(method: TokenEndpointAuthMethod) -> proto::TokenEndpointAuthMethod {
    match method {
        TokenEndpointAuthMethod::ClientSecretPost => {
            proto::TokenEndpointAuthMethod::ClientSecretPost
        }
        TokenEndpointAuthMethod::ClientSecretBasic => {
            proto::TokenEndpointAuthMethod::ClientSecretBasic
        }
        TokenEndpointAuthMethod::None => proto::TokenEndpointAuthMethod::None,
        TokenEndpointAuthMethod::PrivateKeyJwt => proto::TokenEndpointAuthMethod::PrivateKeyJwt,
    }
}

pub(super) fn resource_state_to_proto(state: ResourceState) -> proto::ResourceState {
    match state {
        ResourceState::Active => proto::ResourceState::Active,
        ResourceState::Inactive => proto::ResourceState::Inactive,
        ResourceState::Retired => proto::ResourceState::Retired,
    }
}

/// The client role `c`, registered under `issuer`.
pub(super) fn client_to_proto(c: &OAuth2Client, issuer: &str) -> proto::OAuthClient {
    proto::OAuthClient {
        client_id: c.client_id.clone(),
        application_id: Some(c.application_id.into()),
        project_id: Some(c.project_id.into()),
        name: c.client_name.clone(),
        r#type: application_type_to_proto(c.application_type).into(),
        redirect_uris: c.redirect_uris.clone(),
        allowed_scopes: c.allowed_scopes.clone(),
        grant_types: c.grant_types.clone(),
        active: c.active,
        created_at: Some(to_timestamp(c.created_at)),
        token_endpoint_auth_method: auth_method_to_proto(c.token_endpoint_auth_method).into(),
        response_types: c.response_types.clone(),
        subject_type: match c.subject_type {
            SubjectType::Pairwise => proto::SubjectType::Pairwise,
            SubjectType::Public => proto::SubjectType::Public,
        }
        .into(),
        sector_identifier_uri: c.sector_identifier_uri.clone(),
        contacts: c.contacts.clone(),
        client_id_issued_at: Some(to_timestamp(c.client_id_issued_at)),
        client_secret_expires_at: c.client_secret_expires_at.map(to_timestamp),
        dynamically_registered: c.registration_iat.is_some(),
        org_id: c.org_id.map(Into::into),
        issuer: issuer.to_owned(),
        default_resource_id: c.default_resource.map(Into::into),
        revision: c.revision,
        jwks: c.jwks.as_ref().map(sid_core::models::ClientKeySet::to_json),
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
    }
}

/// The resource role `r`, whose tokens come from `issuer`.
pub(super) fn resource_to_proto(r: &ProtectedResource, issuer: &str) -> proto::ProtectedResource {
    proto::ProtectedResource {
        id: Some(r.id.into()),
        application_id: r.application_id.map(Into::into),
        indicator: r.indicator.to_string(),
        issuer: issuer.to_owned(),
        scopes: r.scopes.clone(),
        state: resource_state_to_proto(r.state).into(),
        revision: r.revision,
        created_at: Some(to_timestamp(r.created_at)),
        updated_at: Some(to_timestamp(r.updated_at)),
    }
}

pub(super) fn access_to_proto(a: &ResourceAccess) -> proto::ResourceAccess {
    proto::ResourceAccess {
        client_id: a.client_id.clone(),
        resource_id: Some(a.resource_id.into()),
        scopes: a.scopes.clone(),
        created_at: Some(to_timestamp(a.created_at)),
    }
}

pub(super) fn application_to_proto(
    app: &Application,
    client: Option<proto::OAuthClient>,
    resource: Option<proto::ProtectedResource>,
) -> proto::Application {
    proto::Application {
        id: Some(app.id.into()),
        project_id: Some(app.project_id.into()),
        name: app.name.clone(),
        client,
        resource,
        revision: app.revision,
        created_at: Some(to_timestamp(app.created_at)),
        updated_at: Some(to_timestamp(app.updated_at)),
        system_integration: match app.system {
            None => proto::SystemIntegration::Unspecified,
            Some(sid_core::models::SystemIntegration::Account) => proto::SystemIntegration::Account,
        }
        .into(),
    }
}

pub(super) fn project_to_proto(p: &Project) -> proto::Project {
    proto::Project {
        id: Some(p.id.into()),
        name: p.name.clone(),
        description: p.description.clone(),
        owner_profile_id: p.owner_id.map(Into::into),
        is_system: p.is_system,
        created_at: Some(to_timestamp(p.created_at)),
        updated_at: Some(to_timestamp(p.updated_at)),
    }
}

pub(super) fn role_to_proto(r: &Role) -> proto::Role {
    proto::Role {
        id: Some(r.id.into()),
        project_id: Some(r.project_id.into()),
        name: r.key.clone(),
        description: r.description.clone(),
        permissions: r.permissions.clone(),
        created_at: Some(to_timestamp(r.created_at)),
        updated_at: Some(to_timestamp(r.updated_at)),
    }
}

pub(super) fn iat_to_proto(t: &InitialAccessToken) -> proto::InitialAccessToken {
    proto::InitialAccessToken {
        id: Some(t.id.into()),
        project_id: Some(t.project_id.into()),
        max_clients: t.max_clients,
        clients_registered: t.clients_registered,
        allowed_scopes: t.allowed_scopes.clone(),
        allowed_grant_types: t.allowed_grant_types.clone(),
        allowed_redirect_patterns: t.allowed_redirect_patterns.clone(),
        expires_at: Some(to_timestamp(t.expires_at)),
        created_at: Some(to_timestamp(t.created_at)),
        created_by: Some(t.created_by.into()),
        revoked: t.revoked,
    }
}

#[cfg(test)]
mod tests;
