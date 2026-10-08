// SPDX-License-Identifier: AGPL-3.0-only
//! Who may ask whether another subject may act on a protected resource
//! (D054): the built-in permission checker role, assigned through the
//! ordinary role-assignment API to a service identity on one live resource.
//! It is never a Profile's, never project-wide, never a public client's, and
//! it is a separate capability from token inspection. A checker asks with its
//! own token, about a named installation service, a user named by the
//! target's issuer, or the subject of an original request established from
//! that request's own token.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, test_client, test_profile};
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;
use sid_core::models::audit::{ActorType, AuditOutcome};
use sid_core::models::{
    AUTHZ_CHECK, PERMISSION_CHECKER_ROLE, ProjectId, ResourceId, ResourceIndicator,
    TOKEN_INTROSPECT,
};
use sid_plugin::authz::{AuthzCheckRequest, AuthzEngine};
use sid_proto::sid::v1::authz::assign_role_request::Principal;
use sid_proto::sid::v1::authz::check_permission_request::Evaluation;
use sid_proto::sid::v1::authz::{
    AssignRoleRequest, BatchCheckPermissionRequest, CheckPermissionRequest,
    CheckPermissionResponse, IssuerSubject, PermissionOutcome, PermissionTarget,
    RequestConfirmation, RequestEvaluation, SenderProofProfile, SubjectReference,
    permission_target, subject_reference,
};
use sid_proto::sid::v1::authz_service_server::AuthzService;
use tonic::{Code, Request};

fn authz(svc: &TestServices) -> AuthzServiceImpl {
    authz_recording(svc, common::RecordingAuditLog::shared())
}

/// The service, recording its audit entries in `audit`.
fn authz_recording(svc: &TestServices, audit: Arc<common::RecordingAuditLog>) -> AuthzServiceImpl {
    AuthzServiceImpl::new(
        Arc::new(sid_authz::CeAuthzEngine::new(svc.storage.clone())),
        svc.storage.clone(),
        CedarService::new(),
        Arc::new(AtomicBool::new(false)),
        svc.jwt.clone(),
        svc.revocation_cache.clone(),
        audit,
    )
}

fn as_admin<T>(svc: &TestServices, message: T) -> Request<T> {
    let token = issue_admin_token(&svc.jwt, sid_core::models::ProfileId::generate());
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn checker_role(svc: &TestServices) -> String {
    svc.storage
        .list_roles(ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == PERMISSION_CHECKER_ROLE)
        .expect("provisioned at start")
        .id
        .0
        .to_string()
}

fn on(resource: impl std::fmt::Display) -> Option<String> {
    Some(format!("oauth_resource:{resource}"))
}

/// An administrator assigns the checker role to a confidential OAuth client
/// on one resource: the client may then ask there, and only there; the
/// assignment grants no token inspection.
#[tokio::test]
async fn a_service_is_assigned_permission_checking_on_one_resource() {
    let svc = TestServices::new(MockStorage::new().with_client(common::confidential_client()));
    let userinfo = common::userinfo_resource(&svc).await;
    authz(&svc)
        .assign_role(as_admin(
            &svc,
            AssignRoleRequest {
                principal: Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into())),
                role_id: checker_role(&svc).await,
                scope: on(userinfo),
                expires_at: None,
                admin: None,
            },
        ))
        .await
        .unwrap();

    let engine = sid_authz::CeAuthzEngine::new(svc.storage.clone());
    let asks = |action: &str, resource: ResourceId| AuthzCheckRequest {
        subject: format!("oauth_client:{}", common::CONFIDENTIAL_CLIENT),
        action: action.into(),
        resource: format!("oauth_resource:{resource}"),
        context: Default::default(),
    };
    assert!(
        engine
            .check(&asks(AUTHZ_CHECK, userinfo))
            .await
            .unwrap()
            .is_allowed()
    );
    assert!(
        !engine
            .check(&asks(AUTHZ_CHECK, ResourceId::generate()))
            .await
            .unwrap()
            .is_allowed(),
        "another resource"
    );
    assert!(
        !engine
            .check(&asks(TOKEN_INTROSPECT, userinfo))
            .await
            .unwrap()
            .is_allowed(),
        "checking grants no inspection"
    );
}

/// The checker role is refused to a Profile, without a resource scope,
/// project-wide, on an unknown resource, and to a public or unknown client;
/// nothing is stored.
#[tokio::test]
async fn permission_checking_is_assigned_only_to_a_service_on_one_resource() {
    let svc = TestServices::new(
        MockStorage::new()
            .with_client(test_client())
            .with_client(common::confidential_client()),
    );
    let authz = authz(&svc);
    let role = checker_role(&svc).await;
    let userinfo = common::userinfo_resource(&svc).await;
    let client = || Some(Principal::OauthClientId(common::CONFIDENTIAL_CLIENT.into()));
    let cases = [
        (
            Some(Principal::ProfileId(test_profile().id.to_string())),
            on(userinfo),
            Code::InvalidArgument,
        ),
        (client(), None, Code::InvalidArgument),
        (
            client(),
            Some(format!("project:{}", ProjectId::system().0)),
            Code::InvalidArgument,
        ),
        (client(), on(ResourceId::generate()), Code::NotFound),
        (
            Some(Principal::OauthClientId("test-client".into())),
            on(userinfo),
            Code::InvalidArgument,
        ),
        (
            Some(Principal::OauthClientId("nobody".into())),
            on(userinfo),
            Code::NotFound,
        ),
    ];
    for (i, (principal, scope, code)) in cases.into_iter().enumerate() {
        let err = authz
            .assign_role(as_admin(
                &svc,
                AssignRoleRequest {
                    principal,
                    role_id: role.clone(),
                    scope,
                    expires_at: None,
                    admin: None,
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "case {i}: {err:?}");
    }
    assert!(
        svc.storage
            .list_role_assignments_for_oauth_client(common::CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .is_empty()
    );
}

// ── Asking: the checker authenticates as itself ─────────────────────

/// A machine user able to obtain its own token for the authorization API,
/// with its client secret.
const CHECKER: &str = "mu_route_checker";
const CHECKER_SECRET: &str = "route-checker-secret";

/// A registered protected resource.
#[derive(Clone)]
struct Resource {
    id: ResourceId,
    indicator: ResourceIndicator,
}

/// An installation with an authorization API resource, a checker machine
/// user that may obtain tokens for it, two protected resources, a subject
/// machine user and a user's Profile, each allowed to read orders.
struct Asking {
    svc: TestServices,
    authz: AuthzServiceImpl,
    /// What the service recorded.
    audit: Arc<common::RecordingAuditLog>,
    checker: sid_core::models::MachineUser,
    orders: Resource,
    wiki: Resource,
    api: Resource,
    worker: sid_core::models::MachineUser,
    profile: sid_core::models::Profile,
    /// Verifies the checker's tokens for the authorization API.
    tokens: Arc<sid_authn::resource_token::ResourceTokenVerifier>,
}

async fn asking() -> Asking {
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
    let machine = |client_id: &str| {
        sid_core::models::MachineUser::new(
            ProjectId::system(),
            client_id,
            client_id,
            OwnerType::System,
            "system",
        )
    };
    let checker = machine(CHECKER);
    let worker = machine("mu_orders_worker");
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_machine_user(checker.clone())
            .with_machine_credential(MachineUserCredential::new(
                checker.id,
                "kid_checker",
                MachineCredentialType::ClientSecret,
                sid_authn::bearer_secret::verifier_of(CHECKER_SECRET),
            ))
            .with_machine_user(worker.clone())
            .with_profile(profile.clone())
            .with_client(test_client()),
    );
    let api =
        sid_authn::issuer::ensure_authorization_api_resource(svc.storage.as_ref(), &svc.issuer)
            .await
            .unwrap();
    let audit = || sid_core::models::AuditEntry::system("test", "checking").into();
    svc.storage
        .set_resource_access(
            &sid_core::models::ResourceAccess {
                client_id: CHECKER.into(),
                resource_id: api.id,
                scopes: vec![AUTHZ_CHECK.into()],
                created_at: chrono::Utc::now(),
            },
            audit(),
        )
        .await
        .unwrap();
    let resource = |path: &str| {
        let storage = svc.storage.clone();
        let issuer = svc.issuer.id;
        let path = path.to_owned();
        async move {
            let now = chrono::Utc::now();
            let app = sid_core::models::Application {
                id: sid_core::models::ApplicationId::generate(),
                project_id: ProjectId::system(),
                name: path.clone(),
                system: None,
                revision: 0,
                created_at: now,
                updated_at: now,
            };
            let resource = sid_core::models::ProtectedResource {
                id: ResourceId::generate(),
                application_id: Some(app.id),
                issuer_id: issuer,
                indicator: ResourceIndicator::parse(&format!("https://resources.example/{path}"))
                    .unwrap(),
                scopes: vec![],
                state: sid_core::models::ResourceState::Active,
                revision: 0,
                created_at: now,
                updated_at: now,
            };
            storage
                .create_application(
                    &app,
                    None,
                    Some(&resource),
                    sid_core::models::AuditEntry::system("test", "api").into(),
                )
                .await
                .unwrap();
            Resource {
                id: resource.id,
                indicator: resource.indicator,
            }
        }
    };
    let orders = resource("orders").await;
    let wiki = resource("wiki").await;
    // The subjects' own grants: each may read orders.
    let mut reader =
        sid_core::models::Role::new(ProjectId::system(), "orders-reader", "Orders reader");
    reader.permissions = vec!["orders.read".into()];
    svc.storage.create_role(&reader, audit()).await.unwrap();
    for principal in [
        sid_core::models::RoleAssignmentPrincipal::MachineUser(worker.id),
        sid_core::models::RoleAssignmentPrincipal::Profile(profile.id),
    ] {
        svc.storage
            .create_role_assignment(
                &sid_core::models::RoleAssignment::new(principal, reader.id).on_resource(orders.id),
                audit(),
            )
            .await
            .unwrap();
    }
    let tokens = Arc::new(
        sid_authn::resource_token::ResourceTokenVerifier::new(
            svc.issuers.clone(),
            svc.issuer.clone(),
            api.indicator.clone(),
        )
        .await
        .unwrap(),
    );
    let audit = common::RecordingAuditLog::shared();
    let authz = authz_recording(&svc, audit.clone()).with_service_tokens(tokens.clone());
    Asking {
        svc,
        authz,
        audit,
        checker,
        orders,
        wiki,
        api: Resource {
            id: api.id,
            indicator: api.indicator,
        },
        worker,
        profile,
        tokens,
    }
}

impl Asking {
    /// Configure the checker as the trusted verifier of DPoP proofs for
    /// requests to `resources`.
    fn trust_checker_on(&mut self, resources: &[&Resource]) {
        let listed: Vec<String> = resources
            .iter()
            .map(|r| format!("\"{}\"", r.indicator.as_str()))
            .collect();
        let verifiers = sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
            r#"{{"verifiers": [{{"subject": "machine:{}", "resources": [{}], "profiles": ["dpop"]}}]}}"#,
            self.checker.id,
            listed.join(", ")
        ))
        .unwrap();
        self.authz = authz_recording(&self.svc, self.audit.clone())
            .with_service_tokens(self.tokens.clone())
            .with_request_verifiers(verifiers);
    }

    /// Give the checker `role` on `resource`.
    async fn grant(&self, role: sid_core::models::Role, resource: &Resource) {
        self.svc
            .storage
            .create_role_assignment(
                &sid_core::models::RoleAssignment::new(
                    sid_core::models::RoleAssignmentPrincipal::MachineUser(self.checker.id),
                    role.id,
                )
                .on_resource(resource.id),
                sid_core::models::AuditEntry::system("test", "checking").into(),
            )
            .await
            .unwrap();
    }

    /// The checker's own token for the authorization API.
    async fn token(&self) -> String {
        use sid_proto::sid::v1::OAuth2TokenRequest;
        use sid_proto::sid::v1::auth_service_server::AuthService;
        self.svc
            .auth
            .o_auth2_token(Request::new(OAuth2TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: Some(CHECKER.into()),
                client_secret: Some(CHECKER_SECRET.into()),
                issuer_handle: self.svc.issuer.handle.to_string(),
                resource: vec![sid_authn::issuer::authorization_api_endpoint(
                    &self.svc.issuer.canonical_url,
                )],
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .access_token
    }

    /// The Profile's token for `resource`, from a stored sign-in; bound to the
    /// key `jkt` when given. Returns the token and its session.
    async fn profile_token(
        &self,
        resource: &Resource,
        jkt: Option<&str>,
    ) -> (String, sid_core::models::Session) {
        let session = sid_core::models::Session::new(
            self.profile.id,
            "127.0.0.1".into(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        self.svc
            .storage
            .create_session(
                &session,
                sid_core::models::AuditEntry::system("test", "session").into(),
            )
            .await
            .unwrap();
        let binding = jkt.map(sid_core::models::dpop::DPopBinding::new);
        let signer = self.svc.issuers.signer(&self.svc.issuer).await.unwrap();
        // A pairwise subject: never read as the ProfileId it stands for.
        let pairwise = uuid::Uuid::now_v7().to_string();
        let token = self
            .svc
            .jwt
            .access_token_signed_by(
                signer.as_ref(),
                sid_authn::jwt::TokenAudience::Resource {
                    indicator: resource.indicator.as_str(),
                    client_id: "test-client",
                },
                &pairwise,
                None,
                &self.profile,
                &session,
                &["orders.read".to_string()],
                binding.as_ref(),
                None,
            )
            .unwrap();
        (token, session)
    }

    fn named(&self, action: &str, resource: &Resource) -> CheckPermissionRequest {
        question(
            action,
            resource,
            Evaluation::NamedSubject(SubjectReference {
                kind: Some(subject_reference::Kind::MachineUserId(
                    self.worker.id.into(),
                )),
            }),
        )
    }

    fn request(&self, action: &str, resource: &Resource, token: &str) -> CheckPermissionRequest {
        question(
            action,
            resource,
            Evaluation::Request(RequestEvaluation {
                access_token: token.to_owned(),
                confirmation: None,
            }),
        )
    }
}

fn question(action: &str, resource: &Resource, evaluation: Evaluation) -> CheckPermissionRequest {
    CheckPermissionRequest {
        action: action.into(),
        consistency: 0,
        target: Some(PermissionTarget {
            scope: Some(permission_target::Scope::Resource(resource.id.into())),
            object: String::new(),
        }),
        evaluation: Some(evaluation),
    }
}

fn bearing<T>(token: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

fn outcome(answer: &CheckPermissionResponse) -> PermissionOutcome {
    PermissionOutcome::try_from(answer.outcome).unwrap()
}

/// A checker holding the checker role on a resource asks, with its own
/// token, whether a named subject may act there and gets that subject's
/// decision; on a resource it holds no checker role on, project-wide, or with
/// no such role at all, it is refused before any subject is evaluated.
#[tokio::test]
async fn a_checker_asks_about_a_subject_on_its_resource_only() {
    let a = asking().await;
    let token = a.token().await;

    let err = a
        .authz
        .check_permission(bearing(&token, a.named("orders.read", &a.orders)))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "no checker role yet: {err:?}"
    );

    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let allowed = a
        .authz
        .check_permission(bearing(&token, a.named("orders.read", &a.orders)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(outcome(&allowed), PermissionOutcome::Allowed);
    let denied = a
        .authz
        .check_permission(bearing(&token, a.named("orders.write", &a.orders)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        outcome(&denied),
        PermissionOutcome::Denied,
        "the subject's own grant decides"
    );
    assert!(
        denied.reason.is_none() && allowed.reason.is_none(),
        "no policy internals to a checker"
    );

    let err = a
        .authz
        .check_permission(bearing(&token, a.named("orders.read", &a.wiki)))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "another resource: {err:?}"
    );
    let mut project_wide = a.named("orders.read", &a.orders);
    project_wide.target = Some(PermissionTarget {
        scope: Some(permission_target::Scope::ProjectId(
            ProjectId::system().0.to_string(),
        )),
        object: String::new(),
    });
    let err = a
        .authz
        .check_permission(bearing(&token, project_wide))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "not a registered resource: {err:?}"
    );
}

/// Token inspection is no permission to ask about others.
#[tokio::test]
async fn an_inspector_cannot_ask() {
    let a = asking().await;
    a.grant(sid_core::models::Role::token_inspector(), &a.orders)
        .await;
    let token = a.token().await;
    let err = a
        .authz
        .check_permission(bearing(&token, a.named("orders.read", &a.orders)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

/// The checker role is permission to ask, nothing more (D054): its holder
/// cannot grant itself or anyone a role, revoke one, or list who may do
/// what; its token for the authorization API is no installation credential.
#[tokio::test]
async fn the_checker_role_grants_nothing_else() {
    use sid_proto::sid::v1::authz::{
        ListObjectsRequest, ListRoleAssignmentsRequest, ListSubjectsRequest, RevokeRoleRequest,
    };
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let held = || async {
        a.svc
            .storage
            .list_role_assignments_for_machine_user(a.checker.id)
            .await
            .unwrap()
            .into_iter()
            .map(|assignment| (assignment.id.0, assignment.scope))
            .collect::<Vec<_>>()
    };
    let before = held().await;

    let err = a
        .authz
        .assign_role(bearing(
            &token,
            AssignRoleRequest {
                principal: Some(Principal::MachineUserId(a.checker.id.to_string())),
                role_id: checker_role(&a.svc).await,
                scope: on(a.wiki.id),
                expires_at: None,
                admin: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "assign: {err:?}");
    let err = a
        .authz
        .revoke_role(bearing(
            &token,
            RevokeRoleRequest {
                assignment_id: before[0].0.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "revoke: {err:?}");
    assert_eq!(held().await, before, "no assignment changed");

    let err = a
        .authz
        .list_objects(bearing(
            &token,
            ListObjectsRequest {
                subject: format!("user:{}", a.profile.id),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "list objects: {err:?}");
    let err = a
        .authz
        .list_subjects(bearing(&token, ListSubjectsRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated, "list subjects: {err:?}");
    let err = a
        .authz
        .list_role_assignments(bearing(&token, ListRoleAssignmentsRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "list assignments: {err:?}"
    );
}

/// Every item of a batch is admitted before any subject is evaluated: one
/// item outside the checker's resource refuses the whole batch, whichever
/// order, and no result is returned; a batch beyond the bound is refused.
#[tokio::test]
async fn a_batch_is_admitted_whole_before_any_subject() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let mine = a.named("orders.read", &a.orders);
    let foreign = a.named("orders.read", &a.wiki);
    for checks in [
        vec![mine.clone(), foreign.clone()],
        vec![foreign.clone(), mine.clone()],
    ] {
        let err = a
            .authz
            .batch_check_permission(bearing(&token, BatchCheckPermissionRequest { checks }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
    }
    let results = a
        .authz
        .batch_check_permission(bearing(
            &token,
            BatchCheckPermissionRequest {
                checks: vec![mine.clone(), a.named("orders.write", &a.orders)],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .results;
    assert_eq!(
        results.iter().map(outcome).collect::<Vec<_>>(),
        [PermissionOutcome::Allowed, PermissionOutcome::Denied]
    );
    let err = a
        .authz
        .batch_check_permission(bearing(
            &token,
            BatchCheckPermissionRequest {
                checks: vec![mine; 101],
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Code::InvalidArgument,
        "unbounded batch: {err:?}"
    );
}

/// An abstract question naming a user by `issuer` and `subject` on
/// `resource`.
fn about_profile(
    action: &str,
    resource: &Resource,
    issuer: &str,
    subject: &str,
) -> CheckPermissionRequest {
    question(
        action,
        resource,
        Evaluation::NamedSubject(SubjectReference {
            kind: Some(subject_reference::Kind::IssuerSubject(IssuerSubject {
                issuer: issuer.into(),
                subject: subject.into(),
            })),
        }),
    )
}

/// A user is named by the subject the target's issuer gives the target's
/// organization, resolved under that hop's rule (CE local issuer to its own
/// organization's resource: the managed Profile's own identifier), never by
/// casting any identifier: that Profile's grant decides, and a subject naming
/// nobody is denied like one without a grant, so the answer reveals no
/// existence.
#[tokio::test]
async fn a_checker_names_a_user_by_the_targets_subject() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let issuer = a.svc.issuer.canonical_url.clone();
    let subject = a.profile.id.to_string();
    let ask = |action: &str, subject: &str| {
        a.authz.check_permission(bearing(
            &token,
            about_profile(action, &a.orders, &issuer, subject),
        ))
    };
    let read = ask("orders.read", &subject).await.unwrap().into_inner();
    assert_eq!(outcome(&read), PermissionOutcome::Allowed);
    let write = ask("orders.write", &subject).await.unwrap().into_inner();
    assert_eq!(outcome(&write), PermissionOutcome::Denied);
    let nobody = sid_core::models::ProfileId::generate().to_string();
    let unknown = ask("orders.read", &nobody).await.unwrap().into_inner();
    assert_eq!(
        outcome(&unknown),
        PermissionOutcome::Denied,
        "no existence oracle"
    );
}

/// A subject of another issuer, or one the target's hop never issues, is
/// no subject of this target and is refused, never evaluated.
#[tokio::test]
async fn a_user_is_named_only_by_the_targets_issuer() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let profile = a.profile.id.to_string();
    let issuer = a.svc.issuer.canonical_url.clone();
    for (case, issuer, subject) in [
        (
            "another issuer",
            "https://other.example/i/0123456789abcdef0123456789abcdef",
            profile.as_str(),
        ),
        ("not a subject of this hop", issuer.as_str(), "alice"),
    ] {
        let err = a
            .authz
            .check_permission(bearing(
                &token,
                about_profile("orders.read", &a.orders, issuer, subject),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{case}: {err:?}");
    }
}

// ── Request-bound evaluation: the original request's own token ─────

/// The subject of an original request is the Profile the request's own token
/// stands for, through its stored sign-in, whatever its `sub`: that Profile's
/// grant decides.
#[tokio::test]
async fn an_original_requests_token_names_its_subject() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    let read = a
        .authz
        .check_permission(bearing(
            &token,
            a.request("orders.read", &a.orders, &original),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(outcome(&read), PermissionOutcome::Allowed);
    let write = a
        .authz
        .check_permission(bearing(
            &token,
            a.request("orders.write", &a.orders, &original),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(outcome(&write), PermissionOutcome::Denied);
}

/// Questions about one original request share its verified evidence, each
/// with its own decision; a batch also carrying another request whose token
/// is no longer usable is refused whole, whichever comes first: one
/// request's evidence never stands in for another's.
#[tokio::test]
async fn a_batch_shares_one_requests_evidence_only() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    let (ended, session) = a.profile_token(&a.orders, None).await;
    end(&a, session).await;

    let results = a
        .authz
        .batch_check_permission(bearing(
            &token,
            BatchCheckPermissionRequest {
                checks: vec![
                    a.request("orders.read", &a.orders, &original),
                    a.request("orders.write", &a.orders, &original),
                    a.request("orders.read", &a.orders, &original),
                ],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .results;
    assert_eq!(
        results.iter().map(outcome).collect::<Vec<_>>(),
        [
            PermissionOutcome::Allowed,
            PermissionOutcome::Denied,
            PermissionOutcome::Allowed
        ]
    );
    for checks in [
        vec![
            a.request("orders.read", &a.orders, &original),
            a.request("orders.read", &a.orders, &ended),
        ],
        vec![
            a.request("orders.read", &a.orders, &ended),
            a.request("orders.read", &a.orders, &original),
        ],
    ] {
        let err = a
            .authz
            .batch_check_permission(bearing(&token, BatchCheckPermissionRequest { checks }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");
    }
}

/// A token for another resource, a token for the authorization API itself,
/// a token whose sign-in has ended and a token that is no token are no
/// evidence about the target's subject.
#[tokio::test]
async fn unusable_evidence_is_refused() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    a.grant(sid_core::models::Role::permission_checker(), &a.api)
        .await;
    let token = a.token().await;
    let (for_wiki, _) = a.profile_token(&a.wiki, None).await;
    let (ended, session) = a.profile_token(&a.orders, None).await;
    a.svc
        .storage
        .delete_session(
            session.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    for (case, resource, evidence) in [
        ("another resource's token", &a.orders, for_wiki.as_str()),
        ("an ended sign-in", &a.orders, ended.as_str()),
        ("not a token", &a.orders, "x.y.z"),
        ("the checker's own credential", &a.api, token.as_str()),
    ] {
        let err = a
            .authz
            .check_permission(bearing(
                &token,
                a.request("orders.read", resource, evidence),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{case}: {err:?}");
    }
}

/// A token bound to a key cannot act without a confirmed proof: with none
/// the answer is that evidence is required, never an allow; a confirmation
/// from a checker nobody trusts to confirm proofs is refused.
#[tokio::test]
async fn a_key_bound_token_needs_its_proof() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let (bound, _) = a.profile_token(&a.orders, Some(jkt)).await;
    let answer = a
        .authz
        .check_permission(bearing(&token, a.request("orders.read", &a.orders, &bound)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(outcome(&answer), PermissionOutcome::EvidenceRequired);

    let mut confirmed = a.request("orders.read", &a.orders, &bound);
    if let Some(Evaluation::Request(request)) = confirmed.evaluation.as_mut() {
        let now = chrono::Utc::now();
        request.confirmation = Some(RequestConfirmation {
            profile: SenderProofProfile::Dpop.into(),
            method: "GET".into(),
            uri: "https://resources.example/orders/items".into(),
            request_id: vec![7; 16],
            jkt: jkt.into(),
            verified_at: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: 0,
            }),
            valid_until: Some(prost_types::Timestamp {
                seconds: now.timestamp() + 30,
                nanos: 0,
            }),
        });
    }
    let err = a
        .authz
        .check_permission(bearing(&token, confirmed))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

/// A request-bound question about `token` carrying `confirmation`.
fn confirmed(
    a: &Asking,
    resource: &Resource,
    token: &str,
    confirmation: RequestConfirmation,
) -> CheckPermissionRequest {
    let mut question = a.request("orders.read", resource, token);
    if let Some(Evaluation::Request(request)) = question.evaluation.as_mut() {
        request.confirmation = Some(confirmation);
    }
    question
}

fn at(time: chrono::DateTime<chrono::Utc>) -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp {
        seconds: time.timestamp(),
        nanos: 0,
    })
}

/// A DPoP confirmation for key `jkt`, checked now and usable for 30 s.
fn dpop_confirmation(jkt: &str) -> RequestConfirmation {
    let now = chrono::Utc::now();
    RequestConfirmation {
        profile: SenderProofProfile::Dpop.into(),
        method: "GET".into(),
        uri: "https://resources.example/orders/items".into(),
        request_id: vec![7; 16],
        jkt: jkt.into(),
        verified_at: at(now),
        valid_until: at(now + chrono::Duration::seconds(30)),
    }
}

/// The configured verifier of a resource's requests confirms the proof it
/// checked, and the key-bound token's subject is decided on its grants.
#[tokio::test]
async fn a_configured_verifiers_confirmation_lets_a_bound_token_act() {
    let mut a = asking().await;
    a.trust_checker_on(&[&a.orders.clone()]);
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (bound, _) = a.profile_token(&a.orders, Some(JKT)).await;
    let answer = a
        .authz
        .check_permission(bearing(
            &token,
            confirmed(&a, &a.orders, &bound, dpop_confirmation(JKT)),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(outcome(&answer), PermissionOutcome::Allowed);
}

/// A checker configured as verifier only for another resource may still
/// ask about this one, but not testify about its requests.
#[tokio::test]
async fn a_verifier_of_another_resource_cannot_confirm() {
    let mut a = asking().await;
    a.trust_checker_on(&[&a.wiki.clone()]);
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (bound, _) = a.profile_token(&a.orders, Some(JKT)).await;
    let err = a
        .authz
        .check_permission(bearing(
            &token,
            confirmed(&a, &a.orders, &bound, dpop_confirmation(JKT)),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

/// A confirmation that does not fit the token or the request is refused,
/// never read as an allow or as a bearer token: another key, a token bound
/// to no key, an expired or overlong window, a check dated in the future,
/// a malformed request identifier or method/URI.
#[tokio::test]
async fn a_confirmation_that_does_not_fit_is_refused() {
    let mut a = asking().await;
    a.trust_checker_on(&[&a.orders.clone()]);
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (bound, _) = a.profile_token(&a.orders, Some(JKT)).await;
    let (unbound, _) = a.profile_token(&a.orders, None).await;
    let now = chrono::Utc::now();
    let cases: Vec<(&str, &str, RequestConfirmation)> = vec![
        (
            "another key",
            &bound,
            dpop_confirmation("another-thumbprint"),
        ),
        ("unbound token", &unbound, dpop_confirmation(JKT)),
        (
            "expired",
            &bound,
            RequestConfirmation {
                verified_at: at(now - chrono::Duration::seconds(40)),
                valid_until: at(now - chrono::Duration::seconds(10)),
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "overlong window",
            &bound,
            RequestConfirmation {
                valid_until: at(now + chrono::Duration::minutes(10)),
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "checked in the future",
            &bound,
            RequestConfirmation {
                verified_at: at(now + chrono::Duration::minutes(5)),
                valid_until: at(now + chrono::Duration::minutes(5) + chrono::Duration::seconds(20)),
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "short request id",
            &bound,
            RequestConfirmation {
                request_id: vec![7; 8],
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "no method",
            &bound,
            RequestConfirmation {
                method: String::new(),
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "uri with a query",
            &bound,
            RequestConfirmation {
                uri: "https://resources.example/orders/items?x=1".into(),
                ..dpop_confirmation(JKT)
            },
        ),
        (
            "unspecified profile",
            &bound,
            RequestConfirmation {
                profile: SenderProofProfile::Unspecified.into(),
                ..dpop_confirmation(JKT)
            },
        ),
    ];
    for (case, original, confirmation) in cases {
        let err = a
            .authz
            .check_permission(bearing(
                &token,
                confirmed(&a, &a.orders, original, confirmation),
            ))
            .await
            .expect_err(case);
        assert_eq!(err.code(), Code::InvalidArgument, "{case}: {err:?}");
    }
}

// ── Audit: denied questions are recorded ───────────────────────────

/// The recorded denials, as (chain, actor, actor type, metadata).
fn denials(a: &Asking) -> Vec<(String, String, ActorType, serde_json::Value)> {
    a.audit
        .entries()
        .into_iter()
        .filter(|(_, e)| e.action == "authz.permission_check")
        .map(|(chain, e)| {
            assert_eq!(e.outcome, AuditOutcome::Denied);
            assert_eq!(e.resource, chain, "the target is what was affected");
            (chain, e.actor_id, e.actor_type, e.metadata)
        })
        .collect()
}

/// A subject's denial is recorded with the asking checker as the actor and
/// the evaluated subject, its evaluation, client and delegated actor apart
/// from it; an allow records nothing (audit-log.md: denied checks only).
#[tokio::test]
async fn a_subject_denial_is_recorded_with_the_checker_as_actor() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let token = a.token().await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    for action in ["orders.read", "orders.write"] {
        a.authz
            .check_permission(bearing(&token, a.request(action, &a.orders, &original)))
            .await
            .unwrap();
    }
    let recorded = denials(&a);
    assert_eq!(recorded.len(), 1, "only the denial: {recorded:?}");
    let (chain, actor, actor_type, metadata) = &recorded[0];
    assert_eq!(chain, &format!("oauth_resource:{}", a.orders.id));
    assert_eq!(actor, &a.checker.id.to_string());
    assert_eq!(*actor_type, ActorType::Machine);
    assert_eq!(metadata["refused"], "subject");
    assert_eq!(metadata["action"], "orders.write");
    assert_eq!(metadata["subject"], format!("user:{}", a.profile.id));
    assert_eq!(metadata["evaluation"], "request");
    assert_eq!(metadata["client_id"], "test-client");
    assert!(metadata["delegated_actor"].is_null());
}

/// A checker refused before any subject is evaluated is recorded as the
/// caller's denial, naming only the target and the action asked about.
#[tokio::test]
async fn a_caller_refusal_is_recorded() {
    let a = asking().await;
    let token = a.token().await;
    a.authz
        .check_permission(bearing(&token, a.named("orders.read", &a.orders)))
        .await
        .unwrap_err();
    let recorded = denials(&a);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    let (chain, actor, _, metadata) = &recorded[0];
    assert_eq!(chain, &format!("oauth_resource:{}", a.orders.id));
    assert_eq!(actor, &a.checker.id.to_string());
    assert_eq!(metadata["refused"], "caller");
    assert_eq!(metadata["action"], "orders.read");
    assert!(
        metadata.get("subject").is_none(),
        "no subject was evaluated"
    );
}

// ── Forward auth asks as itself ─────────────────────────────────────

/// sid-auth deciding routes of Orders and Wiki that ask sid-authz, holding
/// the checker's own credential, against this server's token endpoint,
/// authorization API and registry over gRPC, as deployed. Counts the token
/// requests and records the permission questions that reach the server.
struct Guard {
    server: sid_auth::server::AuthServer,
    tokens: Arc<AtomicUsize>,
    questions: Arc<std::sync::Mutex<Vec<String>>>,
    /// Answers to permission questions still to be lost.
    lose: Arc<AtomicUsize>,
    /// The confirmation each permission question carried.
    confirmations: Confirmations,
    /// The route and credential files live as long as the guard.
    _files: Vec<tempfile::NamedTempFile>,
}

/// A file holding `content`.
fn file(content: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), content).unwrap();
    file
}

/// The checker authenticating with its client secret.
fn secret_authentication() -> (String, Vec<tempfile::NamedTempFile>) {
    let secret = file(CHECKER_SECRET);
    (
        format!(
            "{{ method: client_secret_basic, secret_file: {} }}",
            secret.path().display()
        ),
        vec![secret],
    )
}

async fn guard(a: &Asking, authentication: (String, Vec<tempfile::NamedTempFile>)) -> Guard {
    guard_trusting(a, authentication, Default::default()).await
}

/// The guard, with sid-authz trusting `verifiers` to confirm checks of
/// original requests.
async fn guard_trusting(
    a: &Asking,
    (authentication, mut files): (String, Vec<tempfile::NamedTempFile>),
    verifiers: sid_authz::request_verifier::RequestVerifiers,
) -> Guard {
    let Issuer {
        addr,
        tokens,
        questions,
        lose,
        confirmations,
    } = serve_issuer(a, verifiers).await;
    let issuer = &a.svc.issuer.canonical_url;
    let base = issuer.split("/i/").next().unwrap();
    let route_file = file(&format!(
        r#"
applications:
  - name: orders
    origin: https://orders.example
    issuer: {issuer}
    resource: {orders}
    routes:
      - match: {{ path: "/read/**" }}
        policy: {{ auth: required, check_authz: true, action: orders.read }}
      - match: {{ path: "/write/**" }}
        policy: {{ auth: required, check_authz: true, action: orders.write }}
  - name: wiki
    origin: https://wiki.example
    issuer: {issuer}
    resource: {wiki}
    routes:
      - match: {{ path: "/read/**" }}
        policy: {{ auth: required, check_authz: true, action: orders.read }}
"#,
        orders = a.orders.indicator,
        wiki = a.wiki.indicator,
    ));
    let config: sid_auth::config::AuthConfig = serde_yaml::from_str(&format!(
        "upstream: http://{addr}\nissuer_url: {base}\nroute_policy_path: {}\n\
         authz_checker:\n  issuer: {issuer}\n  client_id: {CHECKER}\n  authentication: {authentication}\n",
        route_file.path().display()
    ))
    .unwrap();
    files.push(route_file);
    let server = sid_auth::server::AuthServer::new(config, a.svc.cache.clone()).unwrap();
    Guard {
        server,
        tokens,
        questions,
        lose,
        confirmations,
        _files: files,
    }
}

/// This server's token endpoint, authorization API and issuer registry,
/// served over gRPC as a remote issuer.
struct Issuer {
    addr: std::net::SocketAddr,
    /// Token requests that reached it.
    tokens: Arc<AtomicUsize>,
    /// The checker token each permission question was asked with.
    questions: Arc<std::sync::Mutex<Vec<String>>>,
    /// Answers to permission questions still to be lost.
    lose: Arc<AtomicUsize>,
    /// The confirmation each permission question carried.
    confirmations: Confirmations,
}

/// The confirmation each permission question carried, in order.
type Confirmations = Arc<std::sync::Mutex<Vec<Option<RequestConfirmation>>>>;

/// The authorization API behind a link that loses answers: while `lose` is
/// above zero, a permission question is decided by sid-authz and its answer
/// never reaches the asker, as when a connection drops on the way back.
/// Records the confirmation every permission question carried.
#[derive(Clone)]
struct LosingAnswers<S> {
    inner: S,
    lose: Arc<AtomicUsize>,
    confirmations: Confirmations,
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for LosingAnswers<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> tower::Service<axum::http::Request<tonic::body::Body>> for LosingAnswers<S>
where
    S: tower::Service<
            axum::http::Request<tonic::body::Body>,
            Response = axum::http::Response<tonic::body::Body>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    type Response = axum::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::http::Request<tonic::body::Body>) -> Self::Future {
        use http_body_util::BodyExt;
        use prost::Message;
        // The ready service answers this call; its clone waits for the next.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let lose = self.lose.clone();
        let confirmations = self.confirmations.clone();
        Box::pin(async move {
            if !request.uri().path().ends_with("/CheckPermission") {
                return inner.call(request).await;
            }
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            // One gRPC message: a flag byte and a four-byte length first.
            let question = CheckPermissionRequest::decode(&bytes[5..]).unwrap();
            let confirmation = match question.evaluation {
                Some(Evaluation::Request(request)) => request.confirmation,
                _ => None,
            };
            confirmations.lock().unwrap().push(confirmation);
            let body = tonic::body::Body::new(http_body_util::Full::new(bytes));
            let answer = inner
                .call(axum::http::Request::from_parts(parts, body))
                .await?;
            let lost = lose
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if lost {
                drop(answer);
                return Ok(tonic::Status::unavailable("connection lost").into_http());
            }
            Ok(answer)
        })
    }
}

/// The issuer, with sid-authz trusting `verifiers` to confirm checks of
/// original requests.
async fn serve_issuer(
    a: &Asking,
    verifiers: sid_authz::request_verifier::RequestVerifiers,
) -> Issuer {
    use sid_proto::sid::v1::auth_service_server::AuthServiceServer;
    use sid_proto::sid::v1::authz_service_server::AuthzServiceServer;
    use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer;
    use tonic::service::interceptor::InterceptedService;

    let tokens = Arc::new(AtomicUsize::new(0));
    let questions: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let lose = Arc::new(AtomicUsize::new(0));
    let confirmations = Confirmations::default();
    let counting = {
        let tokens = tokens.clone();
        move |request: Request<()>| {
            tokens.fetch_add(1, Ordering::SeqCst);
            Ok(request)
        }
    };
    // The checker's token each question was asked with.
    let recording = {
        let questions = questions.clone();
        move |request: Request<()>| {
            let presented = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or_default()
                .to_owned();
            questions.lock().unwrap().push(presented);
            Ok(request)
        }
    };
    let service_tokens = Arc::new(
        sid_authn::resource_token::ResourceTokenVerifier::new(
            a.svc.issuers.clone(),
            a.svc.issuer.clone(),
            a.api.indicator.clone(),
        )
        .await
        .unwrap(),
    );
    let routes = tonic::service::Routes::new(InterceptedService::new(
        AuthServiceServer::from_arc(a.svc.auth.clone()),
        counting,
    ))
    .add_service(InterceptedService::new(
        LosingAnswers {
            inner: AuthzServiceServer::new(
                authz_recording(&a.svc, a.audit.clone())
                    .with_service_tokens(service_tokens)
                    .with_request_verifiers(verifiers),
            ),
            lose: lose.clone(),
            confirmations: confirmations.clone(),
        },
        recording,
    ))
    .add_service(OidcIssuerServiceServer::new(
        sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
            a.svc.issuers.clone(),
            a.svc.storage.clone(),
        ),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    Issuer {
        addr,
        tokens,
        questions,
        lose,
        confirmations,
    }
}

impl Guard {
    /// The verdict on `GET path` of `application` with `token`; `None` when
    /// the request is left without one.
    async fn decide(&self, application: &str, path: &str, token: &str) -> Option<u16> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        self.server
            .pdp()
            .decide(
                application,
                sid_auth::auth::decision::OriginalRequest {
                    method: &axum::http::Method::GET,
                    path,
                    headers: &headers,
                },
            )
            .await
            .ok()
            .map(|verdict| verdict.status.as_u16())
    }

    fn tokens(&self) -> usize {
        self.tokens.load(Ordering::SeqCst)
    }

    fn questions(&self) -> usize {
        self.presented().len()
    }

    /// The checker token each question reached sid-authz with, in order.
    fn presented(&self) -> Vec<String> {
        self.questions.lock().unwrap().clone()
    }
}

/// Forward auth asks sid-authz as the checker, with its own token, about the
/// subject of the request's own token: that Profile's grant decides, and one
/// token serves every question while it is fresh.
#[tokio::test]
async fn forward_auth_asks_as_its_own_checker() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let guard = guard(&a, secret_authentication()).await;
    let (original, _) = a.profile_token(&a.orders, None).await;

    assert_eq!(
        guard.decide("orders", "/read/1", &original).await,
        Some(200)
    );
    assert_eq!(
        guard.decide("orders", "/write/1", &original).await,
        Some(403),
        "the Profile may not write"
    );
    assert_eq!(
        guard.decide("orders", "/read/2", &original).await,
        Some(200)
    );
    assert_eq!(guard.tokens(), 1, "one token for every question");
    assert_eq!(guard.questions(), 3);
}

/// A token whose sign-in has ended still carries a valid signature, but the
/// authorization API refuses it as evidence: the request is unauthenticated
/// (RFC 6750 §3.1 invalid_token), not left without a verdict.
#[tokio::test]
async fn forward_auth_refuses_a_token_whose_sign_in_ended() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let guard = guard(&a, secret_authentication()).await;
    let (ended, session) = a.profile_token(&a.orders, None).await;
    end(&a, session).await;
    assert_eq!(guard.decide("orders", "/read/1", &ended).await, Some(401));
}

/// End `session` in the issuer's store.
async fn end(a: &Asking, session: sid_core::models::Session) {
    a.svc
        .storage
        .delete_session(
            session.id,
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
}

/// A checker the resource has not granted the checker role gets no answer,
/// so the request has no verdict and the proxy denies; the user's token
/// is never evaluated there.
#[tokio::test]
async fn forward_auth_without_the_checker_role_has_no_verdict() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let guard = guard(&a, secret_authentication()).await;
    let (for_wiki, _) = a.profile_token(&a.wiki, None).await;
    assert_eq!(guard.decide("wiki", "/read/1", &for_wiki).await, None);
}

/// The thumbprint of the ES256 test key `dpop_proof` signs with.
const TEST_KEY_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

impl Guard {
    /// The verdict on `GET path` of orders with the DPoP-bound `token` and
    /// `proof`; `None` when the request is left without one.
    async fn decide_bound(&self, path: &str, token: &str, proof: &str) -> Option<u16> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
        headers.insert("dpop", proof.parse().unwrap());
        self.server
            .pdp()
            .decide(
                "orders",
                sid_auth::auth::decision::OriginalRequest {
                    method: &axum::http::Method::GET,
                    path,
                    headers: &headers,
                },
            )
            .await
            .ok()
            .map(|verdict| verdict.status.as_u16())
    }
}

/// The deployment trusts forward auth to confirm DPoP proofs for orders:
/// a sender-bound request whose proof checked out here is decided on its
/// subject's grants. The same proof sent again is a new request and is
/// refused here, before anything is asked (RFC 9449 §11.1).
#[tokio::test]
async fn forward_auth_hands_over_a_bound_token_with_its_confirmation() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let verifiers = sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
        r#"{{"verifiers": [{{"subject": "machine:{}", "resources": ["{}"], "profiles": ["dpop"]}}]}}"#,
        a.checker.id, a.orders.indicator
    ))
    .unwrap();
    let guard = guard_trusting(&a, secret_authentication(), verifiers).await;
    let (bound, _) = a.profile_token(&a.orders, Some(TEST_KEY_JKT)).await;
    let proof = dpop_proof("GET", "https://orders.example/read/1", &bound);

    assert_eq!(
        guard.decide_bound("/read/1", &bound, &proof).await,
        Some(200)
    );
    assert_eq!(guard.questions(), 1);
    assert_eq!(
        guard.decide_bound("/read/1", &bound, &proof).await,
        Some(401),
        "a replayed proof"
    );
    assert_eq!(guard.questions(), 1, "a replay asks nothing");
    let write = dpop_proof("GET", "https://orders.example/write/1", &bound);
    assert_eq!(
        guard.decide_bound("/write/1", &bound, &write).await,
        Some(403),
        "the Profile may not write"
    );
}

/// The answer to a permission question is lost on its way back after
/// sid-authz decided it. Forward auth asks once more about the same pending
/// request, with the same confirmation, and the request is decided; the
/// original proof is not consumed again, so the same proof sent anew is
/// still refused. A second loss in a row leaves the request without a
/// verdict.
#[tokio::test]
async fn forward_auth_asks_again_when_an_answer_is_lost() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let verifiers = sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
        r#"{{"verifiers": [{{"subject": "machine:{}", "resources": ["{}"], "profiles": ["dpop"]}}]}}"#,
        a.checker.id, a.orders.indicator
    ))
    .unwrap();
    let guard = guard_trusting(&a, secret_authentication(), verifiers).await;
    let (bound, _) = a.profile_token(&a.orders, Some(TEST_KEY_JKT)).await;
    let proof = dpop_proof("GET", "https://orders.example/read/1", &bound);

    guard.lose.store(1, Ordering::SeqCst);
    assert_eq!(
        guard.decide_bound("/read/1", &bound, &proof).await,
        Some(200)
    );
    assert_eq!(guard.questions(), 2, "asked once more");
    let confirmations = guard.confirmations.lock().unwrap().clone();
    let first = confirmations[0]
        .as_ref()
        .expect("a bound token goes with its confirmation");
    assert_eq!(
        confirmations[1].as_ref(),
        Some(first),
        "the same pending request"
    );
    assert_eq!(
        guard.decide_bound("/read/1", &bound, &proof).await,
        Some(401),
        "the proof is used once"
    );
    assert_eq!(guard.questions(), 2, "a replay asks nothing");

    guard.lose.store(2, Ordering::SeqCst);
    let next = dpop_proof("GET", "https://orders.example/read/2", &bound);
    assert_eq!(
        guard.decide_bound("/read/2", &bound, &next).await,
        None,
        "asked again once, not until an answer arrives"
    );
    assert_eq!(guard.questions(), 4);
}

/// Without the deployment trusting forward auth to confirm proofs, a
/// sender-bound request has no verdict: the confirmation is refused and
/// the token is never decided as if it were a bearer one.
#[tokio::test]
async fn forward_auth_untrusted_to_confirm_has_no_verdict() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let guard = guard(&a, secret_authentication()).await;
    let (bound, _) = a.profile_token(&a.orders, Some(TEST_KEY_JKT)).await;
    let proof = dpop_proof("GET", "https://orders.example/read/1", &bound);
    assert_eq!(guard.decide_bound("/read/1", &bound, &proof).await, None);
}

/// A DPoP proof by the ES256 test key for `htm htu`, naming `token`
/// (RFC 9449 §4.2).
fn dpop_proof(htm: &str, htu: &str, token: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(jwk);
    let claims = serde_json::json!({
        "jti": uuid::Uuid::now_v7().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "ath": sid_authn::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// The checker's token is renewed when the authorization API stops accepting
/// it, and the question is asked again once.
#[tokio::test]
async fn forward_auth_renews_a_refused_checker_token() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let guard = guard(&a, secret_authentication()).await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    assert_eq!(
        guard.decide("orders", "/read/1", &original).await,
        Some(200)
    );

    // The token the guard asked with is revoked.
    let held = guard.presented().last().cloned().unwrap();
    let held = a
        .svc
        .issuers
        .verifier(&a.svc.issuer)
        .await
        .unwrap()
        .validate_access_token_for(&held, a.api.indicator.as_str())
        .unwrap();
    a.svc
        .revocation_cache
        .revoke_jti(held.jti, std::time::Duration::from_secs(60))
        .await
        .unwrap();

    assert_eq!(
        guard.decide("orders", "/read/2", &original).await,
        Some(200)
    );
    assert_eq!(guard.tokens(), 2, "a new token after the refusal");
    let presented = guard.presented();
    assert_eq!(
        presented.len(),
        3,
        "the refused question is asked again once"
    );
    assert_eq!(presented[0], presented[1]);
    assert_ne!(presented[1], presented[2]);
}

/// A machine checker authenticating with a signed assertion (RFC 7523)
/// asks the same way.
#[tokio::test]
async fn forward_auth_asks_with_a_key_credential() {
    use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential};
    const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";
    const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqK9dvWXRiLy73AXFvVRAMzmlQwKF6q/R/UJmjngfLLs=\n-----END PUBLIC KEY-----";
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let mut credential = MachineUserCredential::new(
        a.checker.id,
        "kid_checker_key",
        MachineCredentialType::PrivateKeyJwt,
        ED_PUBLIC_PEM,
    );
    credential.algorithm = Some("EdDSA".into());
    a.svc
        .storage
        .add_machine_credential(
            &credential,
            None,
            sid_core::models::AuditEntry::system("test", "credential").into(),
        )
        .await
        .unwrap();
    let key = file(ED_PRIVATE_PEM);
    let authentication = format!(
        "{{ method: private_key_jwt, key_file: {}, algorithm: EdDSA }}",
        key.path().display()
    );
    let guard = guard(&a, (authentication, vec![key])).await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    assert_eq!(
        guard.decide("orders", "/read/1", &original).await,
        Some(200)
    );
    assert_eq!(
        guard.decide("orders", "/write/1", &original).await,
        Some(403)
    );
}

/// The original request's token is only evidence: a user cannot ask with
/// it, and a user's Profile (even one asking about itself) cannot present
/// another's token as evidence.
#[tokio::test]
async fn only_a_checker_presents_request_evidence() {
    let a = asking().await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    let admin = common::issue_admin_token(&a.svc.jwt, a.profile.id);
    let err = a
        .authz
        .check_permission(bearing(
            &admin,
            a.request("orders.read", &a.orders, &original),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

// ── A gRPC service protected by a remote issuer ─────────────────────

/// Where callers address the protected service.
const SERVICE_ORIGIN: &str = "https://orders.example";
const READ: &str = "/orders.v1.OrderService/Read";
const WRITE: &str = "/orders.v1.OrderService/Write";

/// The protected service: answers OK and keeps every admitted call it saw.
#[derive(Clone, Default)]
struct OrderService(Arc<std::sync::Mutex<Vec<sid_auth::receiver::Admitted>>>);

impl tonic::server::NamedService for OrderService {
    const NAME: &'static str = "orders.v1.OrderService";
}

impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>> for OrderService {
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        if let Some(admitted) = request.extensions().get::<sid_auth::receiver::Admitted>() {
            self.0.lock().unwrap().push(admitted.clone());
        }
        std::future::ready(Ok(tonic::Status::ok("").into_http()))
    }
}

impl OrderService {
    fn admitted(&self) -> Vec<sid_auth::receiver::Admitted> {
        self.0.lock().unwrap().clone()
    }
}

/// The order service behind its receiver, which reaches the issuer only
/// over gRPC and keeps DPoP proof `jti`s in `cache_url`.
struct Protected {
    service: sid_auth::receiver::Guarded<OrderService>,
    reached: OrderService,
    issuer: Issuer,
    _secret: tempfile::NamedTempFile,
}

async fn protected_at(a: &Asking, issuer: Issuer, cache_url: Option<String>) -> Protected {
    let secret = file(CHECKER_SECRET);
    let canonical = a.svc.issuer.canonical_url.clone();
    let config = sid_auth::config::ReceiverConfig {
        upstream: format!("http://{}", issuer.addr),
        issuer_url: canonical.split("/i/").next().unwrap().to_owned(),
        resource: a.orders.indicator.as_str().to_owned(),
        origin: SERVICE_ORIGIN.into(),
        cache_url,
        checker: sid_auth::config::ClientCredentialConfig {
            issuer: canonical,
            client_id: CHECKER.into(),
            authentication: sid_auth::config::ClientAuthentication::ClientSecretBasic {
                secret_file: secret.path().display().to_string(),
            },
        },
    };
    let receiver = sid_auth::receiver::Receiver::connect("orders", &config)
        .await
        .unwrap();
    let reached = OrderService::default();
    let service = sid_auth::receiver::Guarded::new(
        reached.clone(),
        Arc::new(receiver),
        Arc::new(|path: &str| match path {
            READ => Some("orders.read"),
            WRITE => Some("orders.write"),
            _ => None,
        }),
    );
    Protected {
        service,
        reached,
        issuer,
        _secret: secret,
    }
}

async fn protected(a: &Asking) -> Protected {
    let issuer = serve_issuer(a, Default::default()).await;
    protected_at(a, issuer, None).await
}

impl Protected {
    /// The gRPC status of a call to `path` with `authorization` and, when
    /// given, a DPoP `proof`.
    async fn call(&mut self, path: &str, authorization: &str, proof: Option<&str>) -> Code {
        use tonic::codegen::Service;
        let mut request = tonic::codegen::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/grpc")
            .header("authorization", authorization);
        if let Some(proof) = proof {
            request = request.header("dpop", proof);
        }
        let response = self
            .service
            .call(request.body(tonic::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i32>().ok())
            .expect("a gRPC status");
        Code::from(status)
    }
}

/// A call whose token's subject holds the method's permission reaches the
/// service, which learns the subject the token names for this resource (a
/// pairwise identifier, never the ProfileId behind it). A call whose
/// subject lacks the permission does not reach it.
#[tokio::test]
async fn a_receiver_admits_a_permitted_call_with_its_subject() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let mut p = protected(&a).await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    let bearer = format!("Bearer {original}");

    assert_eq!(p.call(READ, &bearer, None).await, Code::Ok);
    assert_eq!(p.call(WRITE, &bearer, None).await, Code::PermissionDenied);
    let admitted = p.reached.admitted();
    assert_eq!(admitted.len(), 1, "only the permitted call reached it");
    assert_eq!(admitted[0].resource, a.orders.id);
    assert_ne!(admitted[0].claims.sub, a.profile.id.to_string());
    assert!(!admitted[0].claims.sub.is_empty());
}

/// A token whose sign-in ended still verifies by signature at the receiver,
/// which holds no issuer state: the issuer's answer makes it
/// unauthenticated.
#[tokio::test]
async fn a_receiver_refuses_a_token_whose_sign_in_ended() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let mut p = protected(&a).await;
    let (ended, session) = a.profile_token(&a.orders, None).await;
    end(&a, session).await;
    assert_eq!(
        p.call(READ, &format!("Bearer {ended}"), None).await,
        Code::Unauthenticated
    );
    assert!(p.reached.admitted().is_empty());
}

/// A token for another resource of the same issuer opens nothing here, and
/// the issuer is not even asked about it.
#[tokio::test]
async fn a_receiver_refuses_another_resources_token_without_asking() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let mut p = protected(&a).await;
    let (for_wiki, _) = a.profile_token(&a.wiki, None).await;
    assert_eq!(
        p.call(READ, &format!("Bearer {for_wiki}"), None).await,
        Code::Unauthenticated
    );
    assert!(p.issuer.questions.lock().unwrap().is_empty());
}

/// A receiver whose own client lacks the checker role on its resource gets
/// no decision, and serves nothing.
#[tokio::test]
async fn a_receiver_without_the_checker_role_serves_nothing() {
    let a = asking().await;
    let mut p = protected(&a).await;
    let (original, _) = a.profile_token(&a.orders, None).await;
    assert_eq!(
        p.call(READ, &format!("Bearer {original}"), None).await,
        Code::Unavailable
    );
    assert!(p.reached.admitted().is_empty());
}

/// The shared cache of the test stack.
fn test_redis_url() -> String {
    std::env::var("SID_TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:63799".to_string())
}

/// A key-bound token is admitted with a proof of its key for exactly this
/// call (POST, the service's origin and the RPC path), confirmed to the
/// issuer by the receiver it trusts for this resource. Replicas share the
/// proof record: the same proof sent to another replica is refused.
#[tokio::test]
async fn a_receiver_admits_a_bound_token_once_across_replicas() {
    let a = asking().await;
    a.grant(sid_core::models::Role::permission_checker(), &a.orders)
        .await;
    let verifiers = || {
        sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
            r#"{{"verifiers": [{{"subject": "machine:{}", "resources": ["{}"], "profiles": ["dpop"]}}]}}"#,
            a.checker.id, a.orders.indicator
        ))
        .unwrap()
    };
    let mut first = protected_at(
        &a,
        serve_issuer(&a, verifiers()).await,
        Some(test_redis_url()),
    )
    .await;
    let mut second = protected_at(
        &a,
        serve_issuer(&a, verifiers()).await,
        Some(test_redis_url()),
    )
    .await;
    let (bound, _) = a.profile_token(&a.orders, Some(TEST_KEY_JKT)).await;
    let dpop = format!("DPoP {bound}");

    let elsewhere = dpop_proof("POST", &format!("{SERVICE_ORIGIN}{WRITE}"), &bound);
    assert_eq!(
        first.call(READ, &dpop, Some(&elsewhere)).await,
        Code::Unauthenticated,
        "a proof for another method of the service"
    );
    let proof = dpop_proof("POST", &format!("{SERVICE_ORIGIN}{READ}"), &bound);
    assert_eq!(first.call(READ, &dpop, Some(&proof)).await, Code::Ok);
    assert_eq!(
        second.call(READ, &dpop, Some(&proof)).await,
        Code::Unauthenticated,
        "the proof was used at the other replica"
    );
    assert_eq!(
        first.call(READ, &format!("Bearer {bound}"), None).await,
        Code::Unauthenticated,
        "a bound token as a bearer token"
    );
    assert_eq!(first.reached.admitted().len(), 1);
    assert!(second.reached.admitted().is_empty());
}
