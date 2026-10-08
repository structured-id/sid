// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's account integration (auth/session-management.md,
//! system account integration): SID's own account UI is an application of the
//! installation, provisioned automatically in the ordinary Application
//! registry. Its confidential web client (`private_key_jwt`, keys held by the
//! account BFF) obtains tokens for the account API, a registered resource,
//! through explicit access; nothing about it bypasses the normal flow.

use sid_core::models::{
    Application, ApplicationId, ApplicationType, AuditEntry, ClientKeySet, EnforcementMode,
    LoginStrategy, OAuth2Client, OidcIssuer, ProjectId, ProtectedResource, ResourceAccess,
    ResourceId, ResourceIndicator, ResourceState, SubjectType, SystemIntegration,
    TokenEndpointAuthMethod,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::storage::StorageBackend;

/// Scopes the account API understands; its access grants exactly these.
pub const ACCOUNT_SCOPES: [&str; 1] = ["account"];

/// Scopes the account web client may request: sign-in (OIDC Core 1.0 §3.1.2.1)
/// and the account API.
const CLIENT_SCOPES: [&str; 4] = ["openid", "profile", "email", "account"];

/// The path under the account URL the BFF receives authorization responses at.
pub const CALLBACK_PATH: &str = "/auth/callback";

/// Attempts at storing a changed client before giving up to a concurrent
/// writer that keeps changing it.
const UPDATE_ATTEMPTS: usize = 3;

/// The deployment's account integration settings, from trusted configuration.
#[derive(Debug, Clone)]
pub struct AccountSettings {
    account_url: url::Url,
    keys: ClientKeySet,
}

impl AccountSettings {
    /// Settings for an account UI served at `account_url`, whose BFF signs
    /// with `keys`. The URL is `https` (or `http` on a loopback host, for
    /// development), with no credentials, query or fragment: it supplies the
    /// exact callback, never a request's Host.
    pub fn new(account_url: &str, keys: ClientKeySet) -> Result<Self, String> {
        let url = url::Url::parse(account_url)
            .map_err(|e| format!("account URL {account_url:?} is not a URL: {e}"))?;
        let loopback = matches!(
            url.host(),
            Some(url::Host::Domain("localhost"))
                | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
        );
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(format!("account URL {account_url:?} must use https")),
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(format!(
                "account URL {account_url:?} must have no credentials, query or fragment"
            ));
        }
        Ok(Self {
            account_url: url,
            keys,
        })
    }

    /// The registered redirect URI of the account web client.
    pub fn callback(&self) -> String {
        format!(
            "{}{CALLBACK_PATH}",
            self.account_url.as_str().trim_end_matches('/')
        )
    }

    /// The account BFF's public keys.
    pub fn keys(&self) -> &ClientKeySet {
        &self.keys
    }
}

/// The account API's resource indicator at the installation served at
/// `installation_url` (RFC 8707 §2: an absolute URI naming the API).
pub fn account_api_indicator(installation_url: &str) -> SidResult<ResourceIndicator> {
    ResourceIndicator::parse(&format!(
        "{}/account",
        installation_url.trim_end_matches('/')
    ))
    .map_err(|e| SidError::Validation(format!("account API indicator: {e}")))
}

/// The stored account integration.
#[derive(Debug, Clone)]
pub struct AccountIntegration {
    pub application: Application,
    pub client: OAuth2Client,
    pub resource: ProtectedResource,
    /// The client's access to the account API; `None` until it is granted.
    pub access: Option<ResourceAccess>,
}

impl AccountIntegration {
    /// Whether the integration can serve sign-ins now: its client is active,
    /// the account API accepts tokens and the client may obtain them. An
    /// integration an administrator disabled stays disabled.
    pub fn is_ready(&self) -> bool {
        self.client.active && self.resource.is_target() && self.access.is_some()
    }
}

/// The installation's account integration as stored, if it was provisioned.
/// A provisioned integration missing its client or resource role is an
/// error: its roles are never removed separately.
pub async fn account_integration(
    storage: &dyn StorageBackend,
) -> SidResult<Option<AccountIntegration>> {
    let Some(application) = storage
        .system_application(SystemIntegration::Account)
        .await?
    else {
        return Ok(None);
    };
    let incomplete =
        |role: &str| SidError::InvalidState(format!("the account integration has no {role}"));
    let client = storage
        .oauth2_client_of_application(application.id)
        .await?
        .ok_or_else(|| incomplete("client role"))?;
    let resource = storage
        .protected_resource_of_application(application.id)
        .await?
        .ok_or_else(|| incomplete("resource role"))?;
    let access = storage
        .resource_access(&client.client_id, resource.id)
        .await?;
    Ok(Some(AccountIntegration {
        application,
        client,
        resource,
        access,
    }))
}

/// Provision the account integration under `issuer`, the installation
/// organization's local issuer, for the installation served at
/// `installation_url`: once, whatever replicas start together, and kept
/// matching `settings` (callback and keys) on every start. Its identifiers
/// never change, and an administrator's disabling of its client is kept.
pub async fn ensure_account_integration(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
    installation_url: &str,
    settings: &AccountSettings,
) -> SidResult<AccountIntegration> {
    storage
        .ensure_system_project(AuditEntry::system("project.ensure", "system").into())
        .await?;
    if storage
        .system_application(SystemIntegration::Account)
        .await?
        .is_none()
    {
        let (app, client, resource) = new_integration(issuer, installation_url, settings)?;
        // Replicas starting together race here: the first registration is
        // kept and every one of them reads that one back below.
        match storage
            .create_application(
                &app,
                Some(&client),
                Some(&resource),
                AuditEntry::system("account_integration.created", app.id.to_string()).into(),
            )
            .await
        {
            Ok(()) | Err(SidError::Conflict(_)) => {}
            Err(e) => return Err(e),
        }
    }
    let mut integration = account_integration(storage).await?.ok_or_else(|| {
        SidError::Storage("account integration missing right after it was stored".into())
    })?;
    integration.client = keep_client_current(storage, integration.client, settings).await?;
    if integration.access.is_none() {
        let access = ResourceAccess {
            client_id: integration.client.client_id.clone(),
            resource_id: integration.resource.id,
            scopes: ACCOUNT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
            created_at: chrono::Utc::now(),
        };
        storage
            .set_resource_access(
                &access,
                AuditEntry::system(
                    "account_integration.access",
                    integration.client.client_id.clone(),
                )
                .into(),
            )
            .await?;
        integration.access = Some(access);
    }
    Ok(integration)
}

/// A new account integration: its application, web client and account API.
fn new_integration(
    issuer: &OidcIssuer,
    installation_url: &str,
    settings: &AccountSettings,
) -> SidResult<(Application, OAuth2Client, ProtectedResource)> {
    let now = chrono::Utc::now();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: "Account".to_owned(),
        system: Some(SystemIntegration::Account),
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: account_api_indicator(installation_url)?,
        scopes: ACCOUNT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let client = OAuth2Client {
        // The whole UUIDv7, as every registered client id.
        client_id: format!("sid_{}", uuid::Uuid::now_v7().simple()),
        project_id: app.project_id,
        application_id: app.id,
        default_resource: Some(resource.id),
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: Some(settings.keys.clone()),
        redirect_uris: vec![settings.callback()],
        allowed_scopes: CLIENT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: app.name.clone(),
        logo_uri: None,
        active: true,
        // A browser UI's BFF is still a confidential client
        // (RFC 10017 §6.1.3.1); its key never leaves the BFF.
        token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: now,
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(issuer.recipient_org),
        revision: 0,
        created_at: now,
    };
    Ok((app, client, resource))
}

/// `client` with the callback and keys `settings` name, stored when they
/// differ. Only those change: its identity, activity and everything else
/// stay as they are.
async fn keep_client_current(
    storage: &dyn StorageBackend,
    mut client: OAuth2Client,
    settings: &AccountSettings,
) -> SidResult<OAuth2Client> {
    for _ in 0..UPDATE_ATTEMPTS {
        let callback = vec![settings.callback()];
        let keys = Some(settings.keys.clone());
        if client.redirect_uris == callback && client.jwks == keys {
            return Ok(client);
        }
        let mut current = client.clone();
        current.redirect_uris = callback;
        current.jwks = keys;
        if storage
            .update_oauth2_client(
                &current,
                AuditEntry::system("account_integration.updated", client.client_id.clone()).into(),
            )
            .await?
        {
            current.revision += 1;
            return Ok(current);
        }
        client = storage
            .get_oauth2_client(&client.client_id)
            .await?
            .ok_or_else(|| {
                SidError::InvalidState("the account integration's client was removed".into())
            })?;
    }
    Err(SidError::Conflict(
        "the account integration's client keeps changing concurrently".into(),
    ))
}

#[cfg(test)]
mod tests;
