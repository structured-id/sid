// SPDX-License-Identifier: AGPL-3.0-only
//! The provisioning service: an administrator registers an inbound
//! connector, grants it a role on the SCIM directory resource through the
//! authorization service, issues it a credential, and the SCIM endpoint then
//! serves it. Rotation keeps the old credential for its grace, revocation and
//! disabling stop it at once, retirement is final; a secret is shown only in
//! the response that issued it.

#![cfg(feature = "scim")]

mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token, test_profile};
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::{ProjectId, ProtectedResource, SCIM_PROVISIONER_ROLE};
use sid_proto::sid::v1::ScimListUsersRequest;
use sid_proto::sid::v1::admin as pb;
use sid_proto::sid::v1::admin::provisioning_service_server::ProvisioningService;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::authz::AssignRoleRequest;
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz_service_server::AuthzService;
use sid_proto::sid::v1::ids;
use sid_proto::sid::v1::scim_service_server::ScimService;
use sid_scim::grpc::{ScimDirectory, ScimServiceImpl};
use sid_server::grpc::provisioning_service::ProvisioningServiceImpl;
use tonic::{Code, Request};

const SCIM_BASE: &str = "https://sid.example.com/scim/v2";

struct Fixture {
    svc: TestServices,
    provisioning: ProvisioningServiceImpl,
    authz: AuthzServiceImpl,
    scim: ScimServiceImpl,
    directory: ProtectedResource,
    admin_token: String,
}

async fn fixture() -> Fixture {
    let svc = TestServices::new(MockStorage::new());
    let directory = sid_authn::issuer::ensure_scim_resource(svc.storage.as_ref(), &svc.issuer)
        .await
        .unwrap();
    let org = svc.issuer.recipient_org;
    let engine = Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone()));
    let provisioning = ProvisioningServiceImpl::new(
        svc.storage.clone(),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        svc.issuer.clone(),
        directory.clone(),
        SCIM_BASE.into(),
    );
    let tokens = sid_authn::resource_token::ResourceTokenVerifier::new(
        svc.issuers.clone(),
        svc.issuer.clone(),
        directory.indicator.clone(),
    )
    .await
    .unwrap();
    let authz = AuthzServiceImpl::new(
        engine.clone(),
        svc.storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        common::RecordingAuditLog::shared(),
    );
    let scim = ScimServiceImpl::new(
        svc.storage.clone(),
        sid_scim::mapping::ScimOrgContext {
            org_domain: "corp.sid.example.com".into(),
            project_id: ProjectId::system(),
        },
        "https://sid.example.com".into(),
        ScimDirectory {
            org,
            resource: directory.id,
        },
        engine,
        svc.revocation_cache.clone(),
    )
    .with_access_tokens(Arc::new(tokens));
    let admin_token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    Fixture {
        svc,
        provisioning,
        authz,
        scim,
        directory,
        admin_token,
    }
}

fn bearing<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

impl Fixture {
    fn admin<T>(&self, message: T) -> Request<T> {
        bearing(message, &self.admin_token)
    }

    fn keyed<T>(&self, message: T, key: &str) -> Request<T> {
        let mut request = self.admin(message);
        request
            .metadata_mut()
            .insert("idempotency-key", key.parse().unwrap());
        request
    }

    async fn create(&self, name: &str, key: &str) -> pb::ProvisioningConnector {
        self.provisioning
            .create_inbound_connector(self.keyed(
                pb::CreateInboundConnectorRequest {
                    display_name: name.into(),
                },
                key,
            ))
            .await
            .unwrap()
            .into_inner()
    }

    async fn grant(&self, connector: &pb::ProvisioningConnector) {
        let role = self
            .svc
            .storage
            .list_roles(ProjectId::system())
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.key == SCIM_PROVISIONER_ROLE)
            .unwrap();
        self.authz
            .assign_role(self.admin(AssignRoleRequest {
                principal: Some(Principal::ProvisioningConnectorId(
                    connector.id.clone().unwrap(),
                )),
                role_id: role.id.0.to_string(),
                scope: Some(format!("oauth_resource:{}", self.directory.id)),
                expires_at: None,
                admin: None,
            }))
            .await
            .unwrap();
    }

    async fn issue(
        &self,
        connector: &pb::ProvisioningConnector,
        key: &str,
    ) -> pb::IssuedConnectorCredential {
        self.issue_kind(connector, key, pb::ConnectorCredentialKind::ScimBearer)
            .await
    }

    async fn issue_kind(
        &self,
        connector: &pb::ProvisioningConnector,
        key: &str,
        kind: pb::ConnectorCredentialKind,
    ) -> pb::IssuedConnectorCredential {
        self.provisioning
            .create_connector_credential(self.keyed(
                pb::CreateConnectorCredentialRequest {
                    connector_id: connector.id.clone(),
                    expires_at: None,
                    kind: kind.into(),
                },
                key,
            ))
            .await
            .unwrap()
            .into_inner()
    }

    /// A client_credentials request of `client_id` with `secret` (Basic),
    /// for `resource` and `scope` when given.
    async fn token(
        &self,
        client_id: &str,
        secret: &str,
        scope: Option<&str>,
        resource: Option<&str>,
    ) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, tonic::Status> {
        self.svc
            .auth
            .o_auth2_token(common::as_client(
                sid_proto::sid::v1::OAuth2TokenRequest {
                    grant_type: "client_credentials".into(),
                    scope: scope.map(String::from),
                    resource: resource.map(String::from).into_iter().collect(),
                    issuer_handle: self.svc.issuer.handle.to_string(),
                    ..Default::default()
                },
                client_id,
                secret,
            ))
            .await
            .map(|r| r.into_inner())
    }

    async fn client_id(&self, connector: &pb::ProvisioningConnector) -> String {
        self.provisioning
            .get_scim_inbound_config(self.admin(pb::GetScimInboundConfigRequest {
                connector_id: connector.id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .client_id
    }

    async fn scim_code(&self, secret: &str) -> Code {
        match self
            .scim
            .list_users(bearing(ScimListUsersRequest::default(), secret))
            .await
        {
            Ok(_) => Code::Ok,
            Err(status) => status.code(),
        }
    }

    async fn set_state(
        &self,
        connector: &pb::ProvisioningConnector,
        state: pb::ProvisioningConnectorState,
    ) -> Result<pb::ProvisioningConnector, tonic::Status> {
        self.provisioning
            .change_provisioning_connector_state(self.admin(
                pb::ChangeProvisioningConnectorStateRequest {
                    connector_id: connector.id.clone(),
                    state: state.into(),
                },
            ))
            .await
            .map(|r| r.into_inner())
    }
}

/// The whole inbound lifecycle against the real SCIM endpoint.
#[tokio::test]
async fn an_inbound_connector_provisions_through_its_lifecycle() {
    let f = fixture().await;
    let connector = f.create("HR sync", "create-1").await;
    assert_eq!(connector.display_name, "HR sync");
    assert_eq!(
        connector.direction,
        pb::ProvisioningDirection::Inbound as i32
    );
    assert_eq!(
        connector.state,
        pb::ProvisioningConnectorState::Active as i32
    );

    // Configuration names the endpoint and the resource, holds no secret.
    let config = f
        .provisioning
        .get_scim_inbound_config(f.admin(pb::GetScimInboundConfigRequest {
            connector_id: connector.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(config.base_url, SCIM_BASE);
    assert_eq!(config.resource_indicator, f.directory.indicator.as_str());
    assert_eq!(
        config.authentication_methods,
        vec![
            pb::ScimAuthenticationMethod::StaticBearer as i32,
            pb::ScimAuthenticationMethod::OauthClientCredentials as i32,
        ]
    );
    assert!(config.client_id.starts_with("pc_"));
    assert_eq!(config.issuer, f.svc.issuer.canonical_url);
    assert_eq!(
        config.token_endpoint,
        format!("{}/oauth2/token", f.svc.issuer.canonical_url)
    );

    // A credential without a grant authenticates but may do nothing.
    let issued = f.issue(&connector, "cred-1").await;
    assert!(issued.secret.starts_with("sidscim_"));
    assert_eq!(f.scim_code(&issued.secret).await, Code::PermissionDenied);
    f.grant(&connector).await;
    assert_eq!(f.scim_code(&issued.secret).await, Code::Ok);

    // Rotation: the new secret works and so does the old one, for its grace.
    let old = issued.credential.clone().unwrap();
    let rotated = f
        .provisioning
        .rotate_connector_credential(f.keyed(
            pb::RotateConnectorCredentialRequest {
                connector_id: connector.id.clone(),
                credential_id: old.id.clone(),
            },
            "rotate-1",
        ))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(rotated.secret, issued.secret);
    assert_eq!(f.scim_code(&rotated.secret).await, Code::Ok);
    assert_eq!(f.scim_code(&issued.secret).await, Code::Ok);
    let listed = f
        .provisioning
        .list_connector_credentials(f.admin(pb::ListConnectorCredentialsRequest {
            connector_id: connector.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .credentials;
    let graced = listed.iter().find(|c| c.id == old.id).unwrap();
    assert_eq!(
        graced.status,
        pb::ConnectorCredentialStatus::GracePeriod as i32
    );
    assert!(graced.expires_at.is_some());

    // Revoking the old one ends it at once; revoking it again is a no-op.
    for _ in 0..2 {
        f.provisioning
            .revoke_connector_credential(f.admin(pb::RevokeConnectorCredentialRequest {
                connector_id: connector.id.clone(),
                credential_id: old.id.clone(),
            }))
            .await
            .unwrap();
    }
    assert_eq!(f.scim_code(&issued.secret).await, Code::Unauthenticated);
    assert_eq!(f.scim_code(&rotated.secret).await, Code::Ok);

    // Disabling stops the connector, enabling restores it; retiring is final.
    f.set_state(&connector, pb::ProvisioningConnectorState::Disabled)
        .await
        .unwrap();
    assert_eq!(f.scim_code(&rotated.secret).await, Code::Unauthenticated);
    let enabled = f
        .set_state(&connector, pb::ProvisioningConnectorState::Active)
        .await
        .unwrap();
    assert_eq!(enabled.state, pb::ProvisioningConnectorState::Active as i32);
    assert_eq!(f.scim_code(&rotated.secret).await, Code::Ok);
    f.set_state(&connector, pb::ProvisioningConnectorState::Retired)
        .await
        .unwrap();
    assert_eq!(f.scim_code(&rotated.secret).await, Code::Unauthenticated);
    let err = f
        .set_state(&connector, pb::ProvisioningConnectorState::Active)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

/// OAuth client credentials of a connector: its client_id and a client
/// secret get a token for the SCIM resource with the scopes its grants allow,
/// and the SCIM endpoint serves it within those scopes. A SCIM bearer is no
/// client secret and a client secret is no bearer; a token for no grant, for
/// another resource or with a DPoP proof is refused; disabling the connector
/// or revoking the credential stops tokens already issued.
#[tokio::test]
async fn a_connector_provisions_with_an_oauth_token() {
    let f = fixture().await;
    let connector = f.create("HR sync", "oauth-1").await;
    let client_id = f.client_id(&connector).await;
    let bearer = f.issue(&connector, "oauth-bearer").await.secret;
    let issued = f
        .issue_kind(
            &connector,
            "oauth-secret",
            pb::ConnectorCredentialKind::ClientSecret,
        )
        .await;
    assert!(issued.secret.starts_with("sidpcs_"));
    assert_eq!(
        issued.credential.as_ref().unwrap().kind,
        pb::ConnectorCredentialKind::ClientSecret as i32
    );

    // No grant yet: no scope to issue.
    let err = f
        .token(&client_id, &issued.secret, None, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    f.grant(&connector).await;

    // The client secret is no SCIM bearer, the bearer no client secret.
    assert_eq!(f.scim_code(&issued.secret).await, Code::Unauthenticated);
    let err = f.token(&client_id, &bearer, None, None).await.unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "{err:?}");

    let token = f
        .token(&client_id, &issued.secret, None, None)
        .await
        .unwrap();
    assert_eq!(token.token_type, "Bearer");
    let scopes: Vec<&str> = token.scope.as_deref().unwrap().split(' ').collect();
    assert!(scopes.contains(&"scim.user.read") && scopes.contains(&"scim.user.create"));
    assert_eq!(f.scim_code(&token.access_token).await, Code::Ok);

    // A token with a narrower scope is held to it.
    let reader = f
        .token(&client_id, &issued.secret, Some("scim.group.read"), None)
        .await
        .unwrap();
    assert_eq!(reader.scope.as_deref(), Some("scim.group.read"));
    assert_eq!(
        f.scim_code(&reader.access_token).await,
        Code::PermissionDenied
    );

    // Another resource, or a scope the resource does not have, is refused.
    let err = f
        .token(
            &client_id,
            &issued.secret,
            None,
            Some("https://resources.sid.example.com/other"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");
    let err = f
        .token(&client_id, &issued.secret, Some("openid"), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");

    // Disabling stops the token already issued; enabling restores it.
    f.set_state(&connector, pb::ProvisioningConnectorState::Disabled)
        .await
        .unwrap();
    assert_eq!(
        f.scim_code(&token.access_token).await,
        Code::Unauthenticated
    );
    let err = f
        .token(&client_id, &issued.secret, None, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "{err:?}");
    f.set_state(&connector, pb::ProvisioningConnectorState::Active)
        .await
        .unwrap();
    assert_eq!(f.scim_code(&token.access_token).await, Code::Ok);

    // Revoking the client secret stops its tokens at once.
    f.provisioning
        .revoke_connector_credential(f.admin(pb::RevokeConnectorCredentialRequest {
            connector_id: connector.id.clone(),
            credential_id: issued.credential.unwrap().id,
        }))
        .await
        .unwrap();
    assert_eq!(
        f.scim_code(&token.access_token).await,
        Code::Unauthenticated
    );
    assert_eq!(f.scim_code(&bearer).await, Code::Ok);
}

/// A retried create returns the same connector; a retried issue returns the
/// same credential without its secret; the same key on other inputs is a
/// conflict.
#[tokio::test]
async fn keyed_creates_answer_retries_without_the_secret() {
    let f = fixture().await;
    let first = f.create("HR sync", "k-create").await;
    let again = f.create("HR sync", "k-create").await;
    assert_eq!(first.id, again.id);
    assert_eq!(
        f.provisioning
            .list_provisioning_connectors(f.admin(pb::ListProvisioningConnectorsRequest {}))
            .await
            .unwrap()
            .into_inner()
            .connectors
            .len(),
        1
    );
    let err = f
        .provisioning
        .create_inbound_connector(f.keyed(
            pb::CreateInboundConnectorRequest {
                display_name: "Other".into(),
            },
            "k-create",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::AlreadyExists, "{err:?}");

    let issued = f.issue(&first, "k-cred").await;
    let replayed = f.issue(&first, "k-cred").await;
    assert!(!issued.secret.is_empty());
    assert!(replayed.secret.is_empty(), "a retry disclosed the secret");
    assert_eq!(issued.credential, replayed.credential);

    // A create without a key is refused before any effect.
    let err = f
        .provisioning
        .create_inbound_connector(f.admin(pb::CreateInboundConnectorRequest {
            display_name: "No key".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

/// Only an administrator manages connectors; anonymous callers and ordinary
/// users are refused, and a connector's own secret is no management
/// credential.
#[tokio::test]
async fn management_requires_an_administrator() {
    let f = fixture().await;
    let connector = f.create("HR sync", "admin-1").await;
    f.grant(&connector).await;
    let issued = f.issue(&connector, "admin-cred").await;
    let user = issue_token(&f.svc.jwt, &test_profile(), &["openid".to_string()]);

    let list = |token: Option<&str>| {
        let message = pb::ListProvisioningConnectorsRequest {};
        match token {
            Some(t) => bearing(message, t),
            None => Request::new(message),
        }
    };
    for (token, code) in [
        (None, Code::Unauthenticated),
        (Some(user.as_str()), Code::PermissionDenied),
        (Some(issued.secret.as_str()), Code::Unauthenticated),
    ] {
        let err = f
            .provisioning
            .list_provisioning_connectors(list(token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code);
    }
}

/// Unknown, foreign and malformed connectors, a rename of a stale revision
/// or of a retired connector, a fourth usable credential and an unknown
/// credential are refused with their own codes.
#[tokio::test]
async fn refusals_name_what_is_wrong() {
    let f = fixture().await;
    let connector = f.create("HR sync", "r-1").await;

    let unknown = Some(ids::ProvisioningConnectorId::from(
        sid_core::models::ProvisioningConnectorId::generate(),
    ));
    let err = f
        .provisioning
        .get_provisioning_connector(f.admin(pb::GetProvisioningConnectorRequest {
            connector_id: unknown,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    // A connector of another organization is not found here.
    let foreign = sid_core::models::ProvisioningConnector::new(
        sid_core::models::OrgId::generate(),
        sid_core::models::ProvisioningDirection::Inbound,
        "elsewhere",
    );
    f.svc
        .storage
        .create_provisioning_connector(
            &foreign,
            sid_core::models::AuditEntry::system("test", "foreign").into(),
        )
        .await
        .unwrap();
    let err = f
        .provisioning
        .get_provisioning_connector(f.admin(pb::GetProvisioningConnectorRequest {
            connector_id: Some(foreign.id.into()),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    let err = f
        .provisioning
        .get_provisioning_connector(f.admin(pb::GetProvisioningConnectorRequest {
            connector_id: Some(ids::ProvisioningConnectorId { value: vec![7; 16] }),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);

    let rename = |revision: i64| pb::RenameProvisioningConnectorRequest {
        connector_id: connector.id.clone(),
        revision,
        display_name: "Renamed".into(),
    };
    let renamed = f
        .provisioning
        .rename_provisioning_connector(f.admin(rename(connector.revision)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(renamed.display_name, "Renamed");
    assert_eq!(renamed.id, connector.id);
    let err = f
        .provisioning
        .rename_provisioning_connector(f.admin(rename(connector.revision)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Aborted, "stale revision");

    f.issue(&connector, "r-cred-1").await;
    f.issue(&connector, "r-cred-2").await;
    let err = f
        .provisioning
        .create_connector_credential(f.keyed(
            pb::CreateConnectorCredentialRequest {
                connector_id: connector.id.clone(),
                expires_at: None,
                kind: pb::ConnectorCredentialKind::ScimBearer.into(),
            },
            "r-cred-3",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);

    let err = f
        .provisioning
        .revoke_connector_credential(f.admin(pb::RevokeConnectorCredentialRequest {
            connector_id: connector.id.clone(),
            credential_id: Some(sid_core::models::ProvisioningCredentialId::generate().into()),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    f.set_state(&connector, pb::ProvisioningConnectorState::Retired)
        .await
        .unwrap();
    let current = f
        .provisioning
        .get_provisioning_connector(f.admin(pb::GetProvisioningConnectorRequest {
            connector_id: connector.id.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let err = f
        .provisioning
        .rename_provisioning_connector(f.admin(rename(current.revision)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition, "retired");
    let err = f
        .provisioning
        .create_connector_credential(f.keyed(
            pb::CreateConnectorCredentialRequest {
                connector_id: connector.id.clone(),
                expires_at: None,
                kind: pb::ConnectorCredentialKind::ScimBearer.into(),
            },
            "r-cred-4",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition, "retired");
}
