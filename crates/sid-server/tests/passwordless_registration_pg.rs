// SPDX-License-Identifier: AGPL-3.0-only
//! Passwordless self-registration through the AuthService over PostgreSQL:
//! an email code confirms the address, the registration's context (a cookie
//! with its CSRF token for the sign-in page, a bearer for a native client)
//! admits only its own first passkey, and the account then signs in with
//! that passkey.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use std::sync::Arc;
use std::time::Duration;

use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;
use sid_core::models::{
    AuditEntry, CredentialType, EnrollmentMode, Principal, PrincipalType, Profile, WorkKind,
};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use sid_server::grpc::auth_service::AuthServiceImpl;
use sid_storage::PostgresBackend;
use tonic::{Code, Request, Response, Status};
use tonic_types::StatusExt;

/// The relying party the test installation's passkeys are scoped to.
const WEBAUTHN_ORIGIN: &str = "https://sid.example.com";
const RP: &str = "sid.example.com";

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// An address no other scenario uses: the scenarios share one schema.
fn address(tag: &str) -> String {
    format!("{tag}{}@sid.example.com", uuid::Uuid::now_v7().simple())
}

/// The installation under test over `storage`.
struct Installation {
    storage: Arc<dyn StorageBackend>,
    auth: Arc<AuthServiceImpl>,
    codes: sid_authn::otp::OtpService,
}

fn installation(storage: Arc<dyn StorageBackend>) -> Installation {
    let auth = common::auth_service_over(
        storage.clone(),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        None,
    );
    let codes = sid_authn::otp::OtpService::new(
        storage.clone(),
        sid_authn::otp::CodeDelivery {
            keys: common::test_key_manager(),
        },
    );
    Installation {
        storage,
        auth,
        codes,
    }
}

/// How a client calls the registration RPCs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Client {
    /// The exact sign-in page.
    Page,
    /// A client without `Origin`.
    Native,
}

/// The context a verified registration delivered to its client.
#[derive(Clone)]
struct Context {
    client: Client,
    /// The `Cookie` header value a browser sends, or the bearer of a native
    /// client.
    credential: String,
    csrf: Option<String>,
}

impl Context {
    /// `message` sent with this context, as its client sends it.
    fn request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);
        let metadata = request.metadata_mut();
        match self.client {
            Client::Page => {
                metadata.insert("origin", common::SIGN_IN_ORIGIN.parse().unwrap());
                metadata.insert("cookie", self.credential.parse().unwrap());
                if let Some(csrf) = &self.csrf {
                    metadata.insert("x-csrf-token", csrf.parse().unwrap());
                }
            }
            Client::Native => {
                metadata.insert(
                    "authorization",
                    format!("Bearer {}", self.credential).parse().unwrap(),
                );
            }
        }
        request
    }
}

/// `message` as `client` sends it before it holds a context.
fn from<T>(client: Client, message: T) -> Request<T> {
    let mut request = Request::new(message);
    if client == Client::Page {
        request
            .metadata_mut()
            .insert("origin", common::SIGN_IN_ORIGIN.parse().unwrap());
    }
    request
}

/// The reason in `status`'s ErrorInfo.
fn reason(status: &Status) -> String {
    status
        .get_error_details()
        .error_info()
        .map(|info| info.reason.clone())
        .unwrap_or_default()
}

impl Installation {
    async fn start(
        &self,
        client: Client,
        principal: &str,
    ) -> Result<StartEmailRegistrationResponse, Status> {
        self.auth
            .start_email_registration(from(
                client,
                StartEmailRegistrationRequest {
                    principal: principal.to_string(),
                    ..Default::default()
                },
            ))
            .await
            .map(Response::into_inner)
    }

    /// The code mailed for the registration `started` began: read from the
    /// mail work it owes, as the mail handler reads it.
    async fn mailed_code(&self, started: &StartEmailRegistrationResponse) -> String {
        let session = sid_ids_proto::required(started.otp_session_id.as_ref())
            .unwrap()
            .into_uuid();
        self.codes_owed(session)
            .await
            .pop()
            .expect("the registration's code is mailed")
    }

    /// The codes mail work owes now for the code session `session`.
    async fn codes_owed(&self, session: uuid::Uuid) -> Vec<String> {
        let owed = self
            .storage
            .claim_work(
                &[WorkKind::new(sid_authn::otp::OTP_EMAIL_KIND).unwrap()],
                "test",
                1000,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let mut codes = Vec::new();
        for work in owed
            .iter()
            .filter(|work| work.payload[..16] == *session.as_bytes())
        {
            let issue = uuid::Uuid::from_slice(&work.payload[16..]).unwrap();
            if let Some(pending) = self
                .codes
                .pending_delivery(session, issue, jiff::Timestamp::now())
                .await
                .unwrap()
            {
                use secrecy::ExposeSecret;
                codes.push(pending.code.expose_secret().to_owned());
            }
        }
        codes
    }

    async fn verify(
        &self,
        client: Client,
        started: &StartEmailRegistrationResponse,
        code: &str,
    ) -> Result<Response<VerifyEmailRegistrationResponse>, Status> {
        self.auth
            .verify_email_registration(from(
                client,
                VerifyEmailRegistrationRequest {
                    otp_session_id: started.otp_session_id.clone(),
                    code: code.to_string(),
                },
            ))
            .await
    }

    /// Start, confirm and open the registration of `principal` for `client`.
    async fn open(&self, client: Client, principal: &str) -> Context {
        let started = self.start(client, principal).await.expect("admitted");
        let code = self.mailed_code(&started).await;
        let verified = self
            .verify(client, &started, &code)
            .await
            .expect("verified");
        let metadata = verified.metadata().clone();
        let body = verified.into_inner();
        match client {
            Client::Page => {
                assert!(metadata.get("authorization").is_none());
                let cookie = metadata
                    .get("set-cookie")
                    .expect("the context is a cookie")
                    .to_str()
                    .unwrap()
                    .to_owned();
                assert!(cookie.contains("HttpOnly"), "{cookie}");
                Context {
                    client,
                    credential: cookie.split(';').next().unwrap().to_owned(),
                    csrf: Some(body.browser_csrf.expect("the page's CSRF token")),
                }
            }
            Client::Native => {
                assert!(metadata.get("set-cookie").is_none());
                assert!(body.browser_csrf.is_none());
                let bearer = metadata
                    .get("authorization")
                    .expect("the context is authorization metadata")
                    .to_str()
                    .unwrap()
                    .strip_prefix("Bearer ")
                    .unwrap()
                    .to_owned();
                Context {
                    client,
                    credential: bearer,
                    csrf: None,
                }
            }
        }
    }

    async fn passkey_start(
        &self,
        context: &Context,
    ) -> Result<PasskeyRegistrationStartResponse, Status> {
        self.auth
            .passkey_registration_start(context.request(PasskeyRegistrationStartRequest::default()))
            .await
            .map(Response::into_inner)
    }

    async fn passkey_finish(
        &self,
        context: &Context,
        credential: Vec<u8>,
    ) -> Result<PasskeyRegistrationFinishResponse, Status> {
        self.auth
            .passkey_registration_finish(context.request(PasskeyRegistrationFinishRequest {
                credential,
                label: Some("Test key".to_string()),
            }))
            .await
            .map(Response::into_inner)
    }

    /// The profile the email `key` signs in to, if any.
    async fn holder(&self, key: &str) -> Option<sid_core::models::ProfileId> {
        self.storage
            .get_principal_by_value(PrincipalType::Email, key)
            .await
            .unwrap()
            .and_then(|principal| principal.assigned_profile_id)
    }

    /// Sign in with `key`'s passkey: by the address, then as a discoverable
    /// credential. The profile each sign-in's session belongs to.
    async fn sign_in(
        &self,
        principal: &str,
        key: &mut SoftAuthenticator,
    ) -> Vec<sid_core::models::ProfileId> {
        let mut signed_in = Vec::new();
        for named in [Some(principal.to_string()), None] {
            let start = self
                .auth
                .web_authn_authentication_start(Request::new(WebAuthnAuthenticationStartRequest {
                    principal: named.clone(),
                }))
                .await
                .expect("a passkey sign-in starts")
                .into_inner();
            let finished = self
                .auth
                .web_authn_authentication_finish(Request::new(
                    WebAuthnAuthenticationFinishRequest {
                        credential: key.assert(&start.options),
                        principal: named,
                    },
                ))
                .await
                .expect("the registered passkey signs in")
                .into_inner();
            let session = sid_ids_proto::required(finished.session_id.as_ref()).unwrap();
            signed_in.push(
                self.storage
                    .get_session(session)
                    .await
                    .unwrap()
                    .unwrap()
                    .profile_id,
            );
        }
        signed_in
    }
}

/// Store `mode` as the installation's enrollment mode, the rest at the
/// defaults, as an administrator sets it.
async fn store_mode(storage: &dyn StorageBackend, mode: EnrollmentMode) {
    storage
        .set_enrollment_policy(
            &sid_core::models::EnrollmentPolicy {
                mode,
                ..sid_core::models::SecurityPolicy::ce_default().enrollment
            },
            AuditEntry::system("test.enrollment", "installation").into(),
        )
        .await
        .unwrap();
}

/// The suite's database: one PostgreSQL schema of its own, migrated once.
/// Each scenario runs on a new installation over it with data of its own;
/// the schema is dropped at the end, also after a failed scenario.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passwordless_registration() {
    let schema = format!("pwless_reg_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    common::adopt_operation_period(&backend).await;
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    // A claimed installation: self-registration follows its policy, not the
    // instance claim.
    let administrator = Profile::new(Some("pwless_admin"));
    storage
        .create_profile(&administrator, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    common::assign_administrator(storage.as_ref(), administrator.id).await;
    let outcome = tokio::spawn(async move {
        the_page_registers_a_passkey_account_that_then_signs_in(installation(storage.clone()))
            .await;
        a_native_client_registers_with_its_bearer(installation(storage.clone())).await;
        a_held_address_is_refused_before_any_code(installation(storage.clone())).await;
        store_mode(storage.as_ref(), EnrollmentMode::AdminOnly).await;
        a_closed_policy_answers_held_and_free_addresses_alike(installation(storage.clone())).await;
        store_mode(storage.as_ref(), EnrollmentMode::Open).await;
        sign_in_and_registration_codes_do_not_cross(installation(storage.clone())).await;
        the_context_needs_its_csrf_token_and_the_page(installation(storage.clone())).await;
        the_context_opens_no_account_call(installation(storage.clone())).await;
        a_lost_finish_reply_answers_the_same_passkey(installation(storage.clone())).await;
        an_address_taken_meanwhile_commits_nothing(installation(storage.clone())).await;
        concurrent_finishes_commit_once(installation(storage)).await;
    })
    .await;
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// The page's whole registration: the code confirms the address, the
/// context arrives as an HttpOnly cookie with a CSRF token (never in the
/// body or as a bearer), its passkey commits the account with its confirmed
/// address and no session, and the account then signs in with that passkey
/// by its address and as a discoverable credential.
async fn the_page_registers_a_passkey_account_that_then_signs_in(i: Installation) {
    let principal = address("page");
    let context = i.open(Client::Page, &principal).await;
    assert!(
        i.holder(&principal).await.is_none(),
        "nothing before finish"
    );

    let mut key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&context).await.expect("the first passkey");
    let finished = i
        .passkey_finish(&context, key.register(&start.options))
        .await
        .expect("the account commits");
    assert!(finished.credential_id.is_some());

    let profile = i
        .holder(&principal)
        .await
        .expect("the account holds its address");
    let principals = i.storage.get_principals_by_profile(profile).await.unwrap();
    assert!(principals[0].verified, "the confirmed address is verified");
    assert!(
        i.storage
            .get_primary_profile_email(profile)
            .await
            .unwrap()
            .expect("its contact")
            .verified
    );
    let passkeys = i
        .storage
        .get_credentials_by_profile(profile, Some(CredentialType::WebAuthn))
        .await
        .unwrap();
    assert_eq!(passkeys.len(), 1);
    assert!(
        i.storage.list_sessions(&profile).await.unwrap().is_empty(),
        "registering a key opens no session"
    );

    assert_eq!(i.sign_in(&principal, &mut key).await, [profile, profile]);
}

/// A native client gets its context as `authorization` metadata, no cookie
/// and no CSRF token, and registers with it as its bearer.
async fn a_native_client_registers_with_its_bearer(i: Installation) {
    let principal = address("native");
    let context = i.open(Client::Native, &principal).await;
    let mut key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&context).await.unwrap();
    i.passkey_finish(&context, key.register(&start.options))
        .await
        .expect("the account commits");
    let profile = i.holder(&principal).await.expect("registered");
    assert_eq!(i.sign_in(&principal, &mut key).await, [profile, profile]);
}

/// An account at `principal`, as an earlier registration left it.
async fn held(i: &Installation, principal: &str) -> Profile {
    let profile = Profile::new(None::<&str>);
    i.storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    i.storage
        .save_principal(
            &Principal::new(profile.id, PrincipalType::Email, principal),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
    profile
}

/// When registration is admitted, a held address is refused as registered
/// before a code is created or mailed: the holder is not contacted, and an
/// email code can never add a key to an existing account.
async fn a_held_address_is_refused_before_any_code(i: Installation) {
    let principal = address("held");
    let holder = held(&i, &principal).await;

    let refused = i.start(Client::Page, &principal).await.unwrap_err();
    assert_eq!(refused.code(), Code::AlreadyExists, "{refused:?}");
    assert_eq!(reason(&refused), "EMAIL_ALREADY_REGISTERED");
    let owed = i
        .storage
        .claim_work(
            &[WorkKind::new(sid_authn::otp::OTP_EMAIL_KIND).unwrap()],
            "test",
            1000,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(owed.is_empty(), "a code was owed for a held address");
    assert!(
        i.storage
            .get_credentials_by_profile(holder.id, None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A policy that does not admit self-registration refuses a held and a free
/// address with the same answer, and mails neither a code.
async fn a_closed_policy_answers_held_and_free_addresses_alike(i: Installation) {
    let taken = address("closed_held");
    held(&i, &taken).await;
    let mut refusals = Vec::new();
    for principal in [taken, address("closed_free")] {
        refusals.push(i.start(Client::Page, &principal).await.unwrap_err());
    }
    assert_eq!(refusals[0].code(), Code::PermissionDenied);
    assert_eq!(refusals[0].code(), refusals[1].code());
    assert_eq!(reason(&refusals[0]), "REGISTRATION_RESTRICTED");
    assert_eq!(reason(&refusals[0]), reason(&refusals[1]));
    assert_eq!(refusals[0].message(), refusals[1].message());
}

/// A sign-in's code never confirms a registration and a registration's code
/// never signs in: each is unknown to the other ceremony, and the holder is
/// not signed in.
async fn sign_in_and_registration_codes_do_not_cross(i: Installation) {
    let holder_address = address("crossing_holder");
    let holder = held(&i, &holder_address).await;
    let sign_in = i
        .auth
        .request_otp(Request::new(RequestOtpRequest {
            principal: holder_address.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    let refused = i
        .auth
        .verify_email_registration(Request::new(VerifyEmailRegistrationRequest {
            otp_session_id: sign_in.otp_session_id.clone(),
            code: "00000000".into(),
        }))
        .await
        .unwrap_err();
    // Unknown to the registration ceremony: expired, as any lapsed one.
    assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
    assert_eq!(reason(&refused), "INVALID_STATE", "{refused:?}");

    let started = i.start(Client::Native, &address("crossing")).await.unwrap();
    let code = i.mailed_code(&started).await;
    let not_signed_in = i.auth.verify_otp(Request::new(VerifyOtpRequest {
        code,
        otp_session_id: started.otp_session_id.clone(),
    }));
    match not_signed_in.await {
        Ok(answer) => assert!(!answer.into_inner().verified),
        Err(refused) => assert_ne!(refused.code(), Code::Ok),
    }
    assert!(
        i.storage
            .list_sessions(&holder.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The page's context needs its CSRF token, and only the exact page may
/// present it: without the token, or from another origin, the passkey is
/// neither started nor registered.
async fn the_context_needs_its_csrf_token_and_the_page(i: Installation) {
    let principal = address("csrf");
    let context = i.open(Client::Page, &principal).await;

    let mut without_csrf = context.clone();
    without_csrf.csrf = None;
    let refused = i.passkey_start(&without_csrf).await.unwrap_err();
    assert_eq!(reason(&refused), "CSRF_TOKEN_INVALID", "{refused:?}");

    let mut wrong_csrf = context.clone();
    wrong_csrf.csrf = Some("AAAA".into());
    let refused = i.passkey_start(&wrong_csrf).await.unwrap_err();
    assert_eq!(reason(&refused), "CSRF_TOKEN_INVALID", "{refused:?}");

    let mut elsewhere = context.request(PasskeyRegistrationStartRequest::default());
    elsewhere
        .metadata_mut()
        .insert("origin", "https://evil.example.org".parse().unwrap());
    i.auth
        .passkey_registration_start(elsewhere)
        .await
        .expect_err("another origin presents no context");

    // The page's own requests still go through, and the refusals spent
    // nothing.
    let mut key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&context).await.unwrap();
    i.passkey_finish(&context, key.register(&start.options))
        .await
        .unwrap();
    assert!(i.holder(&principal).await.is_some());
}

/// The context is no session: as a bearer it authenticates no account call,
/// and an existing account's passkey methods refuse it.
async fn the_context_opens_no_account_call(i: Installation) {
    let context = i.open(Client::Native, &address("no_account")).await;
    let refused = i
        .auth
        .web_authn_registration_start(context.request(WebAuthnRegistrationStartRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated, "{refused:?}");
}

/// A finish whose reply was lost is answered again with the passkey it
/// committed: no second key, no second account and no session.
async fn a_lost_finish_reply_answers_the_same_passkey(i: Installation) {
    let principal = address("retry");
    let context = i.open(Client::Page, &principal).await;
    let mut key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&context).await.unwrap();
    let credential = key.register(&start.options);
    let first = i
        .passkey_finish(&context, credential.clone())
        .await
        .unwrap();

    let again = i.passkey_finish(&context, credential).await.unwrap();

    assert_eq!(again.credential_id, first.credential_id);
    let profile = i.holder(&principal).await.unwrap();
    assert_eq!(
        i.storage
            .get_credentials_by_profile(profile, Some(CredentialType::WebAuthn))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(i.storage.list_sessions(&profile).await.unwrap().is_empty());
}

/// An address another registration takes between this one's start and its
/// finish is refused as registered at the finish, and nothing of this
/// registration is written.
async fn an_address_taken_meanwhile_commits_nothing(i: Installation) {
    let principal = address("race");
    let late = i.open(Client::Page, &principal).await;
    let early = i.open(Client::Native, &principal).await;
    let mut early_key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&early).await.unwrap();
    i.passkey_finish(&early, early_key.register(&start.options))
        .await
        .unwrap();
    let holder = i.holder(&principal).await.unwrap();

    let mut late_key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&late).await.unwrap();
    let refused = i
        .passkey_finish(&late, late_key.register(&start.options))
        .await
        .unwrap_err();

    assert_eq!(refused.code(), Code::AlreadyExists, "{refused:?}");
    assert_eq!(i.holder(&principal).await, Some(holder));
    assert_eq!(
        i.storage
            .get_credentials_by_profile(holder, Some(CredentialType::WebAuthn))
            .await
            .unwrap()
            .len(),
        1,
        "the refused registration added a key"
    );
}

/// Of two concurrent finishes of one context exactly one account and one
/// passkey commit. Each answer is that passkey, or a retryable refusal
/// whose retry answers it: never an expired ceremony while the other
/// finish is committing.
async fn concurrent_finishes_commit_once(i: Installation) {
    let principal = address("concurrent");
    let context = i.open(Client::Native, &principal).await;
    let mut key = SoftAuthenticator::new(WEBAUTHN_ORIGIN, RP);
    let start = i.passkey_start(&context).await.unwrap();
    let credential = key.register(&start.options);

    let (a, b) = tokio::join!(
        i.passkey_finish(&context, credential.clone()),
        i.passkey_finish(&context, credential.clone()),
    );

    let mut committed = Vec::new();
    for answer in [a, b] {
        let answer = match answer {
            Ok(answer) => answer,
            Err(refused) => {
                assert_eq!(refused.code(), Code::Aborted, "{refused:?}");
                assert_eq!(reason(&refused), "CONCURRENT_MODIFICATION");
                tokio::time::sleep(Duration::from_millis(200)).await;
                i.passkey_finish(&context, credential.clone())
                    .await
                    .expect("the retry answers the committed finish")
            }
        };
        committed.push(answer.credential_id);
    }
    assert_eq!(committed[0], committed[1]);
    let profile = i.holder(&principal).await.unwrap();
    assert_eq!(
        i.storage
            .get_credentials_by_profile(profile, Some(CredentialType::WebAuthn))
            .await
            .unwrap()
            .len(),
        1
    );
}
