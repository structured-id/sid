// SPDX-License-Identifier: AGPL-3.0-only
//! Applications, their client and resource roles, and resource access as the
//! management API shows them.

use sid_core::models::{
    Application, ApplicationType, OAuth2Client, ProtectedResource, ResourceAccess, ResourceState,
    SubjectType, TokenEndpointAuthMethod,
};
use sid_proto::sid::v1 as proto;

use super::convert;

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
        application_id: c.application_id.to_string(),
        project_id: c.project_id.0.to_string(),
        name: c.client_name.clone(),
        r#type: application_type_to_proto(c.application_type).into(),
        redirect_uris: c.redirect_uris.clone(),
        allowed_scopes: c.allowed_scopes.clone(),
        grant_types: c.grant_types.clone(),
        active: c.active,
        created_at: Some(convert::to_timestamp(c.created_at)),
        token_endpoint_auth_method: auth_method_to_proto(c.token_endpoint_auth_method).into(),
        response_types: c.response_types.clone(),
        subject_type: match c.subject_type {
            SubjectType::Pairwise => proto::SubjectType::Pairwise,
            SubjectType::Public => proto::SubjectType::Public,
        }
        .into(),
        sector_identifier_uri: c.sector_identifier_uri.clone(),
        contacts: c.contacts.clone(),
        client_id_issued_at: Some(convert::to_timestamp(c.client_id_issued_at)),
        client_secret_expires_at: c.client_secret_expires_at.map(convert::to_timestamp),
        dynamically_registered: c.registration_iat.is_some(),
        org_id: c.org_id.map(|org| org.to_string()),
        issuer: issuer.to_owned(),
        default_resource_id: c.default_resource.map(|r| r.to_string()),
        revision: c.revision,
        jwks: c.jwks.as_ref().map(sid_core::models::ClientKeySet::to_json),
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
    }
}

/// The resource role `r`, whose tokens come from `issuer`.
pub(super) fn resource_to_proto(r: &ProtectedResource, issuer: &str) -> proto::ProtectedResource {
    proto::ProtectedResource {
        id: r.id.to_string(),
        application_id: r.application_id.map(|a| a.to_string()),
        indicator: r.indicator.to_string(),
        issuer: issuer.to_owned(),
        scopes: r.scopes.clone(),
        state: resource_state_to_proto(r.state).into(),
        revision: r.revision,
        created_at: Some(convert::to_timestamp(r.created_at)),
        updated_at: Some(convert::to_timestamp(r.updated_at)),
    }
}

pub(super) fn access_to_proto(a: &ResourceAccess) -> proto::ResourceAccess {
    proto::ResourceAccess {
        client_id: a.client_id.clone(),
        resource_id: a.resource_id.to_string(),
        scopes: a.scopes.clone(),
        created_at: Some(convert::to_timestamp(a.created_at)),
    }
}

pub(super) fn application_to_proto(
    app: &Application,
    client: Option<proto::OAuthClient>,
    resource: Option<proto::ProtectedResource>,
) -> proto::Application {
    proto::Application {
        id: app.id.to_string(),
        project_id: app.project_id.0.to_string(),
        name: app.name.clone(),
        client,
        resource,
        revision: app.revision,
        created_at: Some(convert::to_timestamp(app.created_at)),
        updated_at: Some(convert::to_timestamp(app.updated_at)),
        system_integration: match app.system {
            None => proto::SystemIntegration::Unspecified,
            Some(sid_core::models::SystemIntegration::Account) => proto::SystemIntegration::Account,
        }
        .into(),
    }
}

#[cfg(test)]
mod tests;
