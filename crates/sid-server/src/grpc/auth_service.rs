// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AuthService implementation.
//!
//! Wraps the same OPAQUE, WebAuthn, OAuth2, and JWT services used by
//! the REST handlers.

use crate::feature_flags::FeatureFlagService;
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretBox};
use sid::sign_in::{AttemptContext, FirstFactor, FirstFactorSignedIn, LoginMethod};
use sid_authn::anomaly::AnomalyDetector;
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::device_auth;
use sid_authn::geoip::GeoIpChain;
use sid_authn::ip_intelligence::IpIntelligenceAggregator;
use sid_authn::jwt::JwtService;
use sid_authn::legacy_hash::BuiltinLegacyVerifier;
use sid_authn::magic_link::MagicLinkService;
use sid_authn::normalize::{NormalizedPrincipal, normalize_principal};
use sid_authn::oauth2::{OAuth2Server, TokenError};
use sid_authn::opaque::OpaqueRouter;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::otp::OtpService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::sign_in_delivery::{CeremonyClient, Delivery, SignedIn};
use sid_authn::webauthn::{
    AssertionPurpose, AssertionResponse, DiscoverableAssertionResponse, RegistrationResponse,
    VerifiedAssertion, WebAuthnServer,
};
use sid_core::models::WebAuthnUserHandle;
use sid_core::models::event::{Event, event_types};
use sid_core::models::principal::PrincipalType;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialId, CredentialType, ProfileId, ProfileType,
    Session, SessionId,
};
use sid_core::models::{
    HistoryCommit, MutationContext, OidcIssuer, OperationCompletion, RevocationReason,
};
use sid_infra::authn::ceremony::Respond;
use sid_infra::authn::operation::{context, run};
use sid_infra::authn::password_operation::{ClientListener, PasswordHistoryEvaluatorImpl};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};
use sid_infra::oauth_http::{
    client_refused, dpop_refusal, missing_parameter, target_refused, token_error, token_refusal,
};
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::StoredCredential;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

use super::native_session::NativeProof;
use super::password_operation::{Finish, OperationPurpose, PendingOperation};
use sid_authn::native_session::{NativePolicy, PROOF_METADATA, REFRESH_METADATA};
use sid_authn::password_operation::{
    CurrentPasswordCheck, OperationOwner, change_context, operation_id,
};
use sid_infra::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, maintenance,
    missing_field, not_configured, not_found, not_in_this_build, storage_failure,
};

mod authorize;
mod end_session;
mod refusal;
mod sign_in_security;
pub(crate) use authorize::{BrowserAuthorization, PendingAuthorization, REQUEST_URI_PREFIX};
pub(crate) use end_session::{EndSession, LogoutRequest};
use refusal::{
    anomaly_unavailable, authentication_failed, ceremony_expired, enrollment_requirement,
    mfa_not_enrolled, registration_restricted, session_ended, session_provisional,
    step_up_required, too_many_attempts,
};
use sid_authn::sign_in_security::device_id as compute_device_id;
use sign_in_security::sign_in_refusal;

/// Who binds a second factor: an interactive session, or a sign-in's pending
/// context owing its first.
enum Enroller {
    Session(sid_authn::caller::Caller),
    SignIn(Box<Session>),
}

impl Enroller {
    fn profile_id(&self) -> ProfileId {
        match self {
            Self::Session(caller) => caller.profile_id,
            Self::SignIn(pending) => pending.profile_id,
        }
    }
}

/// Who verifies a second factor.
enum FactorCaller {
    /// A sign-in's pending context, completed into its session for `client`.
    Pending(Session, CeremonyClient),
    /// An installation session stepping up.
    StepUp(Session),
}

/// Parse space-separated acr_values string into the highest requested AuthLevel.
///
/// Supports all formats recognized by `AuthLevel::from_acr_value()`:
/// - SID canonical: `urn:sid:acr:basic`, `urn:sid:acr:standard`, etc.
/// - Plain names: `basic`, `standard`, `elevated`, `critical`
///
/// Returns the highest (strictest) level found, or None if no recognizable values.
fn parse_acr_values(acr_values: &str) -> Option<sid_core::models::session::AuthLevel> {
    use sid_core::models::session::AuthLevel;

    let mut highest: Option<AuthLevel> = None;
    for val in acr_values.split_whitespace() {
        if let Some(l) = AuthLevel::from_acr_value(val) {
            highest = Some(highest.map_or(l, |h: AuthLevel| h.max(l)));
        }
    }
    highest
}

/// Extract User-Agent from gRPC metadata.
///
/// Checks `user-agent` header (standard HTTP) and `x-user-agent` (proxy-forwarded).
fn extract_user_agent(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    // x-user-agent (forwarded by proxy, takes priority)
    if let Some(ua) = metadata.get("x-user-agent")
        && let Ok(val) = ua.to_str()
        && !val.is_empty()
    {
        return Some(val.to_string());
    }
    // Standard user-agent header
    if let Some(ua) = metadata.get("user-agent")
        && let Ok(val) = ua.to_str()
        && !val.is_empty()
    {
        return Some(val.to_string());
    }
    None
}

/// The CAPTCHA pass a sign-in retry carries in `captcha-pass` metadata.
fn extract_captcha_pass(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("captcha-pass")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// Parse a principal string and determine its type.
///
/// Delegates to `sid_authn::normalize::normalize_principal` for full
/// NFC + IDNA + anti-homoglyph normalization. Returns `(PrincipalType, normalized_value)`.
fn parse_principal(identifier: &str) -> Result<(PrincipalType, String), tonic::Status> {
    let handle = parse_handle(identifier)?;
    Ok((handle.principal_type.to_principal_type(), handle.normalized))
}

/// [`parse_principal`] plus, for an email, the validated mailbox in the
/// spelling given (what a new contact stores and mail goes to) and the
/// policy revision its key was derived under.
fn parse_handle(identifier: &str) -> Result<NormalizedPrincipal, tonic::Status> {
    normalize_principal(identifier).map_err(|e| invalid_field("identifier", e.to_string()))
}

pub(crate) use sid::registration::PendingRegistration;

/// `ALREADY_EXISTS` with the error-model reason for the identifier kind.
fn already_registered(principal_type: PrincipalType) -> tonic::Status {
    let reason = match principal_type {
        PrincipalType::Email => ErrorReason::EmailAlreadyRegistered,
        PrincipalType::Username => ErrorReason::UsernameAlreadyTaken,
        PrincipalType::Phone => ErrorReason::PhoneAlreadyRegistered,
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag | PrincipalType::FederatedSubject => {
            ErrorReason::PrincipalAlreadyHeld
        }
    };
    ApiError::new(reason, "identifier is already registered")
        .with_resource("Principal", principal_type.as_str())
        .into()
}

/// INVALID_STATE: `method` cannot step up a session at `decay` (an older
/// session takes only phishing-resistant methods).
fn step_up_method_unavailable(method: StepUpMethod, decay: &str) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        format!(
            "{} cannot step up a session this old: phishing-resistant methods only",
            method.as_str_name()
        ),
    )
    .with_precondition("SESSION_DECAY", decay, "phishing-resistant methods only")
    .into()
}

use super::convert::wire_id;

/// A stored credential's id as an answer carries it.
#[allow(clippy::result_large_err)]
fn credential_wire(id: CredentialId) -> Result<Option<sid_ids_proto::CredentialId>, Status> {
    super::convert::stored_id::<sid_ids::CredentialId, _>(id.0)
}

/// The refusal of an email code request. The limit counts requests per
/// address, known or not, so it tells nothing about an account.
fn otp_refusal(e: sid_authn::otp::OtpError) -> Status {
    match e {
        sid_authn::otp::OtpError::RateLimited { wait_seconds } => ApiError::new(
            ErrorReason::RateLimitExceeded,
            "too many codes were requested for this address",
        )
        .with_quota_violation("email_codes", "codes requested per address")
        .with_retry_after(std::time::Duration::from_secs(wait_seconds))
        .into(),
        // The installation's bound of owed mails: the request is not
        // accepted rather than answered with a code nobody will send.
        sid_authn::otp::OtpError::Busy(_) => ApiError::new(
            ErrorReason::QuotaExceeded,
            "too many codes are waiting for delivery; try again shortly",
        )
        .with_quota_violation("email_deliveries", "codes waiting for delivery")
        .with_retry_after(std::time::Duration::from_secs(60))
        .into(),
        e @ (sid_authn::otp::OtpError::Internal(_) | sid_authn::otp::OtpError::Sealed(_)) => {
            internal("request email code", e)
        }
    }
}

/// A TOTP code is exactly six ASCII digits (RFC 6238 §5.3 with the default
/// `Digit` of 6); anything else is a malformed request, not a wrong code.
#[allow(clippy::result_large_err)]
fn require_totp_code_format(code: &str) -> Result<(), Status> {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(invalid_field("code", "six digits"))
    }
}

/// A retried GenerateRecoveryCodes whose set was issued: the codes were shown
/// once and only their hashes are kept, so the answer names the set
/// (`recorded`, its credential id) instead of codes. Replacing the set is a
/// new command with a new key.
fn recovery_codes_issued(recorded: &[u8]) -> Status {
    let set = match uuid::Uuid::from_slice(recorded) {
        Ok(id) => id.to_string(),
        Err(e) => return internal("read the issued recovery code set", e),
    };
    ApiError::new(
        ErrorReason::OperationResultUnavailable,
        "these recovery codes were issued once; generate a new set to replace them",
    )
    .with_precondition(
        "RECOVERY_CODES_ISSUED",
        set,
        "the codes are shown only once",
    )
    .into()
}

/// CREDENTIAL_NOT_FOUND for `id`: also the answer for a credential the caller
/// does not own, so a foreign id reveals nothing.
fn credential_not_found(id: CredentialId) -> Status {
    not_found(
        ErrorReason::CredentialNotFound,
        "Credential",
        id.0.to_string(),
    )
}

/// The answer to a refused or failed self-registration.
fn registration_refusal(e: sid::registration::RegistrationError) -> Status {
    use sid::registration::RegistrationError as E;
    match e {
        E::NotEnabled => not_configured("registration"),
        E::Restricted(requirement) => registration_restricted(requirement),
        E::AlreadyRegistered(principal_type) => already_registered(principal_type),
        E::InvalidIdentifier(detail) => invalid_field("identifier", detail),
        E::Identity(e) => super::identity_service::refusal(e),
        E::Operation(e) => e.into_status(),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

/// Whether `op` is a change of `credential_id` started by `caller`; any other
/// operation reads as not pending, so a caller learns nothing about others'.
#[allow(clippy::result_large_err)]
/// The attempt counter of the current-password sign-ins `profile`'s password
/// changes begin, apart from its sign-in counter.
fn current_password_guesses(profile: ProfileId) -> String {
    format!("current-password:{profile}")
}

/// Accept `op` as the caller's change of `credential` as it stands now. An
/// operation begun on a password another change has since replaced is
/// refused: its authority (a sign-in with that password, or a fresh session
/// then) is over the replaced one and must not overwrite the newer.
fn own_change(
    op: &PendingOperation,
    caller: ProfileId,
    credential: &Credential,
) -> Result<(), Status> {
    match op.purpose {
        OperationPurpose::Change {
            profile_id,
            credential_id,
            password,
        } if profile_id == caller && credential_id == credential.id => {
            if password == credential.opaque_credential_identifier() {
                Ok(())
            } else {
                Err(changed_concurrently())
            }
        }
        _ => Err(operation_not_pending()),
    }
}

/// The refusal of a password step whose operation is not pending for the
/// caller, the same whatever the reason.
fn operation_not_pending() -> Status {
    sid_authn::password_operation::PasswordOperationError::NotPending.into_status()
}

/// Server-side state for legacy password migration flow.
#[derive(serde::Serialize, serde::Deserialize)]
struct MigrationState {
    profile_id: ProfileId,
    /// The OPRF credential identifier of the password being registered.
    credential_identifier: [u8; 16],
}

/// Challenge-store key of a WebAuthn step-up: bound to the session that
/// requested it, so a completion on another session cannot consume it.
fn step_up_challenge_key(session_id: &str, challenge_id: &str) -> String {
    format!("step-up:{session_id}:{challenge_id}")
}

pub struct AuthServiceImpl {
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) oauth2: Arc<OAuth2Server>,
    pub(crate) webauthn: Arc<WebAuthnServer>,
    pub(crate) jwt: Arc<JwtService>,
    pub(crate) opaque_router: Arc<OpaqueRouter>,
    pub(crate) opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    pub(crate) revocation_cache: Arc<RevocationCache>,
    pub(crate) feature_flags: FeatureFlagService,
    /// Password registrations, changes and resets between their steps, and
    /// the history evaluator and checker they use.
    pub(crate) password_ops: Arc<super::password_operation::PasswordOperations>,
    /// The history evaluator, when it runs in this process.
    history_evaluation: Option<Arc<sid_authn::password_operation::HistoryEvaluation>>,
    /// Profile a WebAuthn ceremony was started for, keyed by its challenge:
    /// only that profile may finish it.
    webauthn_state: ChallengeStore<ProfileId>,
    /// WebAuthn ceremony of a pending step-up, keyed by session and step-up
    /// challenge id: only a completion on the same session consumes it.
    step_up_state: ChallengeStore<String>,
    /// Ephemeral legacy migration state: key → the migrating profile.
    migration_state: ChallengeStore<MigrationState>,
    /// Ephemeral TOTP enrollment state: enrollment_id → (profile_id, secret_bytes).
    totp_enrollment: ChallengeStore<(ProfileId, Vec<u8>)>,
    /// Magic links for Corporate Profiles; `None` when the instance has not enabled
    /// them, which is the default.
    pub(crate) magic_link: Option<Arc<MagicLinkService>>,
    /// OTP passwordless authentication (email/phone code).
    pub(crate) otp: Arc<OtpService>,
    /// Password resets by emailed link; `None` without the account UI page
    /// the links open.
    password_resets: Option<Arc<sid_authn::password_reset::PasswordResetService>>,
    /// The OAuth endpoints of this installation's issuers, and what sign-in
    /// shares with them: issuers, client authentication, targets, signers,
    /// sender proofs and the login requirements.
    oauth: sid::oauth::OAuth,
    /// Whether the login requirements are the host's, not
    /// `security_policy`'s fixed ones.
    host_login_policy: bool,
    /// The OIDC issuers whose endpoints the OAuth requests arrive at, and
    /// their signers.
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    /// Issuer URL (e.g., "https://sid.example.com").
    issuer: String,
    /// Its origin (scheme and authority): the prefix of every URI a sender
    /// proof names, never taken from a request.
    public_origin: String,
    /// Signing users in once a ceremony verified them: the sign-in rules,
    /// attempt counters, the security policy, the IdP session cookie and
    /// session delivery.
    sign_ins: sid::sign_in::SignIn,
    /// Field encryption for credential secrets the server reads back (TOTP seeds).
    key_manager: Arc<dyn sid_keys::KeyManager>,
    /// TOTP codes already accepted, shared by every replica.
    totp_replay: sid_authn::TotpReplayGuard,
    /// Ends a profile's sessions everywhere (tokens, RPs) on a password reset.
    cascade: Arc<RevocationCascadeService>,
    /// Origin of the browser sign-in page: a ceremony it runs sets the IdP
    /// session cookie. None sets no cookie.
    sign_in_origin: Option<url::Origin>,
    /// The enrollment mode the deployment pins over the stored one.
    /// Self-registration: its admission, held identifiers and the commit of
    /// a new account.
    registration: sid::registration::Registration,
    /// Browser authorization requests kept while the user signs in, by
    /// reference, shared by every replica.
    continuations: ChallengeStore<authorize::PendingAuthorization>,
    /// One-time values of the logout confirmation form, each naming the IdP
    /// session it ends and where the browser returns, shared by every replica.
    logout_confirmations: ChallengeStore<end_session::LogoutConfirmation>,
}

/// How the sign-in rules judge one sign-in.
#[derive(Clone, Copy)]
enum Judging {
    /// A new sign-in, recorded as evidence once admitted.
    Record,
    /// A repeat of a sign-in already admitted from `admitted_from`, recorded
    /// as no further sign-in.
    Repeat {
        admitted_from: Option<std::net::IpAddr>,
    },
}

/// The host's keyed operation an admitted sign-in completes: a repeat of it
/// is answered with the same session (see
/// [`AuthServiceImpl::complete_admitted_sign_in`]).
pub struct AdmittedCompletion<'a> {
    /// The operation's stable reference, its key.
    pub operation: &'a str,
    /// When the operation ends; nothing is delivered again after.
    pub deadline: chrono::DateTime<Utc>,
}

impl AdmittedCompletion<'_> {
    #[allow(clippy::result_large_err)]
    fn key(&self) -> Result<sid_core::models::OperationKey, Status> {
        sid_core::models::OperationKey::parse(self.operation)
            .map_err(|e| internal("the admitted sign-in's operation reference", e))
    }
}

/// What an upstream sign-in request tells about who completes it, read
/// before its state is consumed.
pub(crate) struct UpstreamCeremony {
    client: CeremonyClient,
    client_ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
    captcha_pass: Option<String>,
}

impl AuthServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        oauth2: Arc<OAuth2Server>,
        webauthn: Arc<WebAuthnServer>,
        jwt: Arc<JwtService>,
        opaque_router: Arc<OpaqueRouter>,
        opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
        revocation_cache: Arc<RevocationCache>,
        feature_flags: FeatureFlagService,
        magic_link: Option<Arc<MagicLinkService>>,
        otp: Arc<OtpService>,
        issuers: Arc<sid_authn::issuer::IssuerRegistry>,
        installation_org: sid_core::models::OrgId,
        issuer: String,
        captcha_provider: Arc<dyn sid_authn::captcha::CaptchaProvider>,
        cache_backend: Arc<dyn CacheBackend>,
        ip_intelligence: Arc<IpIntelligenceAggregator>,
        geoip: Arc<GeoIpChain>,
        key_manager: Arc<dyn sid_keys::KeyManager>,
        cascade: Arc<RevocationCascadeService>,
        authz: Arc<sid_authz::CeAuthzEngine<dyn StorageBackend>>,
        password_history: sid_authn::password_operation::PasswordHistoryAuthority,
    ) -> Self {
        let ttl = std::time::Duration::from_secs(300); // 5 minutes
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
        let captcha_gate =
            sid_authn::captcha::CaptchaGate::new(ceremonies.clone(), key_manager.clone());
        let (password_ops, history_evaluation) =
            super::password_operation::PasswordOperations::with_authority(
                storage.clone(),
                ceremonies.clone(),
                key_manager.clone(),
                installation_org,
                password_history,
            );
        let password_ops = Arc::new(password_ops);
        let oauth = sid::oauth::OAuth::new(sid::oauth::OAuthParts {
            storage: storage.clone(),
            oauth2: oauth2.clone(),
            jwt: jwt.clone(),
            issuers: issuers.clone(),
            installation_org,
            authz,
            revocation: revocation_cache.clone(),
            cascade: cascade.clone(),
            cache: cache_backend,
            login_policy: Arc::new(sid_authn::login_policy::FixedLoginPolicy::of(
                &SecurityPolicy::ce_default(),
            )),
            installation_url: issuer.clone(),
        });
        let registration = sid::registration::Registration::new(
            storage.clone(),
            key_manager.clone(),
            issuer.clone(),
        );
        let sign_ins = sid::sign_in::SignIn::new(sid::sign_in::SignInParts {
            storage: storage.clone(),
            jwt: jwt.clone(),
            revocation: revocation_cache.clone(),
            issuer: issuer.clone(),
            anomaly: Arc::new(AnomalyDetector::ce_default(ceremonies.clone())),
            ip_intelligence,
            geoip,
            captcha_gate,
            captcha_provider,
            opaque: opaque_router.clone(),
            keys: key_manager.clone(),
        });
        Self {
            storage,
            oauth2,
            webauthn,
            jwt,
            opaque_router,
            opaque_zkpp,
            revocation_cache,
            feature_flags,
            password_ops,
            history_evaluation,
            webauthn_state: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "webauthn-binding",
                ttl,
            ),
            step_up_state: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "webauthn-step-up",
                ttl,
            ),
            migration_state: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "legacy-migration",
                ttl,
            ),
            totp_enrollment: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "totp-enrollment",
                ttl,
            ),
            continuations: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "authorize-continuation",
                authorize::CONTINUATION_TTL,
            ),
            logout_confirmations: ChallengeStore::new(
                ceremonies.clone(),
                key_manager.clone(),
                "logout-confirmation",
                end_session::CONFIRMATION_TTL,
            ),
            magic_link,
            otp,
            password_resets: None,
            oauth,
            host_login_policy: false,
            issuers,
            public_origin: url::Url::parse(&issuer)
                .expect("the installation URL is validated at start-up")
                .origin()
                .ascii_serialization(),
            issuer,
            totp_replay: sid_authn::TotpReplayGuard::new(ceremonies.clone()),
            sign_ins,
            key_manager,
            cascade,
            sign_in_origin: None,
            registration,
        }
    }

    /// Set the IdP session cookie on ceremonies the sign-in page at
    /// `sign_in` runs.
    pub fn with_sign_in_page(mut self, sign_in: &url::Url) -> Self {
        self.sign_in_origin = Some(sign_in.origin());
        self
    }

    /// Start password resets through `resets`, whose links the account UI
    /// opens.
    pub fn with_password_resets(
        mut self,
        resets: Arc<sid_authn::password_reset::PasswordResetService>,
    ) -> Self {
        self.password_resets = Some(resets);
        self
    }

    /// Name this authority's IdP session cookie `cookie`, the one its issuer
    /// derives (`BrowserCookie::for_issuer`).
    pub fn with_browser_cookie(
        mut self,
        cookie: sid_authn::browser_session::BrowserCookie,
    ) -> Self {
        self.sign_ins.set_cookie(cookie);
        self
    }

    /// This authority's IdP session cookie.
    pub fn browser_cookie(&self) -> &sid_authn::browser_session::BrowserCookie {
        self.sign_ins.cookie()
    }

    /// The security policy sign-ins follow.
    fn security_policy(&self) -> &SecurityPolicy {
        self.sign_ins.policy()
    }

    /// Apply `mode` to self-registration whatever mode is stored: the
    /// deployment pins it (`SID_ENROLLMENT_MODE`).
    pub fn with_enrollment_pin(mut self, mode: Option<sid_core::models::EnrollmentMode>) -> Self {
        self.registration.set_pinned(mode);
        self
    }

    /// Who completes a sign-in ceremony sent with `metadata`: a native
    /// client, or this authority's sign-in page.
    #[allow(clippy::result_large_err)]
    fn ceremony_client(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<CeremonyClient, Status> {
        sid_infra::authn::ceremony::ceremony_client(metadata, self.sign_in_origin.as_ref())
    }

    /// Accept `code` for `secret` once: a wrong code and a code already
    /// accepted on any path answer alike (RFC 6238 §5.2).
    async fn accept_totp(
        &self,
        profile_id: ProfileId,
        secret: &[u8],
        code: &str,
    ) -> Result<(), Status> {
        let step = sid_authn::totp_step(secret, code).ok_or_else(authentication_failed)?;
        let first = self
            .totp_replay
            .first_use(profile_id, step)
            .await
            .map_err(|e| dependency_unavailable("TOTP replay record", e))?;
        if first {
            Ok(())
        } else {
            Err(authentication_failed())
        }
    }

    /// The client address of `request`; a call whose address did not resolve
    /// is refused before anything counts it.
    fn client_ip<T>(&self, request: &Request<T>) -> Result<Option<std::net::IpAddr>, Status> {
        #[cfg(feature = "http")]
        return sid_infra::http::client_ip(request);
        #[cfg(not(feature = "http"))]
        Ok(request.remote_addr().map(|addr| addr.ip()))
    }

    /// Override the security policy (useful for testing conditional access
    /// wiring); its login requirements apply unless the host states its own.
    pub fn with_security_policy(mut self, policy: SecurityPolicy) -> Self {
        if !self.host_login_policy {
            self.oauth
                .set_login_policy(Arc::new(sid_authn::login_policy::FixedLoginPolicy::of(
                    &policy,
                )));
        }
        self.sign_ins.set_policy(policy);
        self
    }

    /// Read the login requirements from `source`, the host's policy, instead
    /// of this installation's fixed ones: every sign-in and authorization
    /// asks it, and commits only under the fence it states.
    pub fn with_login_policy(
        mut self,
        source: Arc<dyn sid_authn::login_policy::LoginPolicySource>,
    ) -> Self {
        self.oauth.set_login_policy(source);
        self.host_login_policy = true;
        self
    }

    /// The login requirements of an authentication for `client_id` (none:
    /// the organization's). A source that cannot state them refuses rather
    /// than leaving the fixed baseline in their place.
    async fn login_requirements(
        &self,
        client_id: Option<&str>,
    ) -> Result<sid_authn::login_policy::LoginRequirements, Status> {
        self.oauth
            .login_requirements(client_id)
            .await
            .map_err(oauth_refusal)
    }

    /// The magic-link service, or FEATURE_NOT_CONFIGURED when the instance has
    /// not enabled magic links. The answer does not depend on the address asked
    /// about.
    #[allow(clippy::result_large_err)]
    fn require_magic_links(&self) -> Result<&MagicLinkService, Status> {
        self.magic_link
            .as_deref()
            .ok_or_else(|| not_configured("magic_links"))
    }

    /// Evaluate login security: anomaly detection, then the organization's
    /// login requirements, on the level and `amr` methods the session being
    /// created records.
    ///
    /// Called AFTER credential verification, BEFORE session creation.
    /// Returns the policy fence the session commits under, or the refusal.
    async fn evaluate_login_security(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        auth_method: &str,
        (assurance, amr): (sid_core::models::session::AuthLevel, &[String]),
        extras: AttemptContext<'_>,
    ) -> Result<Option<sid_core::models::ActorFence>, Status> {
        self.evaluate_sign_in(
            profile_id,
            client_ip,
            sid_authn::sign_in_security::AttemptAuthentication::Local {
                method: auth_method,
                assurance,
                amr,
            },
            extras,
            None,
        )
        .await
    }

    /// The organization's login requirements alone, on a session of
    /// `profile_id` at `assurance` with `amr`: the policy fence it commits
    /// under, or the step-up the requirements ask for.
    async fn admit_by_requirements(
        &self,
        profile_id: ProfileId,
        assurance: sid_core::models::session::AuthLevel,
        amr: &[String],
    ) -> Result<Option<sid_core::models::ActorFence>, Status> {
        use sid_authn::login_policy::LoginDecision;
        let requirements = self.login_requirements(None).await?;
        let now = Utc::now();
        let probe = sid_authn::login_policy::local_authentication(profile_id, assurance, amr, now);
        match requirements.decide(&probe, now) {
            LoginDecision::Allow { .. } => Ok(requirements.fence),
            LoginDecision::StepUp(unmet) => Err(step_up_required(&unmet).into()),
        }
    }

    /// The same rules for a sign-in verified as `authentication`, under the
    /// login requirements of `client_id` (none: the organization's). Returns
    /// the policy fence the session commits under.
    async fn evaluate_sign_in(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        authentication: sid_authn::sign_in_security::AttemptAuthentication<'_>,
        extras: AttemptContext<'_>,
        client_id: Option<&str>,
    ) -> Result<Option<sid_core::models::ActorFence>, Status> {
        self.client_sign_in_rules(
            profile_id,
            client_ip,
            (authentication, extras),
            client_id,
            Judging::Record,
        )
        .await
    }

    /// The same rules as [`Self::evaluate_sign_in`] for a repeat of a sign-in
    /// already admitted and recorded from `admitted_from`: judged on its own
    /// request, recorded as no further sign-in.
    async fn check_sign_in(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        attempt: (
            sid_authn::sign_in_security::AttemptAuthentication<'_>,
            AttemptContext<'_>,
        ),
        client_id: Option<&str>,
        admitted_from: Option<std::net::IpAddr>,
    ) -> Result<(), Status> {
        self.client_sign_in_rules(
            profile_id,
            client_ip,
            attempt,
            client_id,
            Judging::Repeat { admitted_from },
        )
        .await
        .map(|_| ())
    }

    /// The sign-in rules under `client_id`'s requirements, judged as
    /// `judging` says.
    async fn client_sign_in_rules(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        attempt: (
            sid_authn::sign_in_security::AttemptAuthentication<'_>,
            AttemptContext<'_>,
        ),
        client_id: Option<&str>,
        judging: Judging,
    ) -> Result<Option<sid_core::models::ActorFence>, Status> {
        let requirements = self.login_requirements(client_id).await?;
        match judging {
            Judging::Record => {
                self.sign_ins
                    .evaluate(profile_id, client_ip, attempt, &requirements)
                    .await
            }
            Judging::Repeat { admitted_from } => {
                self.sign_ins
                    .check(profile_id, client_ip, attempt, &requirements, admitted_from)
                    .await
            }
        }
        .map_err(sign_in_refusal)?;
        Ok(requirements.fence)
    }

    /// The same rules for a local sign-in that proved its first factor at
    /// `assurance` with `amr`, under the organization's requirements: admitted,
    /// or, when it owes the requirements or an anomaly rule's step-up and a
    /// second factor the account has enrolled answers that, awaiting the factor.
    async fn evaluate_first_factor(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        auth_method: &str,
        (assurance, amr): (sid_core::models::session::AuthLevel, &[String]),
        extras: AttemptContext<'_>,
    ) -> Result<FirstFactor, Status> {
        let requirements = self.login_requirements(None).await?;
        self.sign_ins
            .first_factor(
                profile_id,
                client_ip,
                (auth_method, assurance, amr),
                extras,
                &requirements,
            )
            .await
            .map_err(sign_in_refusal)
    }

    /// Record an authentication on the active session `id`: `authenticate`
    /// changes it and the result is stored with a compare-and-swap on the
    /// session's authentication, so an ended session is never recreated and a
    /// concurrent authentication is not undone. Returns the stored session.
    /// An ended or expired session is Unauthenticated, a provisional one
    /// FailedPrecondition, one authenticated again in between Aborted.
    async fn authenticate_session(
        &self,
        id: SessionId,
        ctx: MutationContext,
        authenticate: impl FnOnce(&mut sid_core::models::session::ActiveSession<'_>),
    ) -> Result<Session, Status> {
        let mut session = self
            .storage
            .get_session(id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(session_ended)?;
        let expected = session.authentication();
        if session.is_provisional {
            return Err(session_provisional(id));
        }
        let mut active = session.as_active().ok_or_else(session_ended)?;
        authenticate(&mut active);
        let recorded = self
            .storage
            .record_session_authentication(id, &expected, &session.authentication(), ctx)
            .await
            .map_err(storage_failure)?;
        if recorded {
            return Ok(session);
        }
        match self
            .storage
            .get_session(id)
            .await
            .map_err(storage_failure)?
        {
            Some(now) if !now.is_expired() => Err(changed_concurrently()),
            _ => Err(session_ended()),
        }
    }

    /// Spend one recovery code of the profile's active set; returns how many
    /// remain. The code is removed with a compare-and-swap on the stored set,
    /// so concurrent requests spend a code once and never lose each other's
    /// removals; every stored hash is compared, in constant time.
    async fn consume_recovery_code(
        &self,
        profile_id: ProfileId,
        code: &str,
    ) -> Result<usize, Status> {
        use subtle::ConstantTimeEq;
        let input_hash = sid_authn::hash_code(&sid_authn::normalize_code(code));
        // A lost race re-reads the set; a bound keeps a stuck writer from spinning.
        for _ in 0..8 {
            let credentials = self
                .storage
                .get_credentials_by_profile(profile_id, Some(CredentialType::Recovery))
                .await
                .map_err(storage_failure)?;
            let set = credentials
                .into_iter()
                .find(|c| c.status.is_active())
                .ok_or_else(|| mfa_not_enrolled("recovery code set"))?;
            let mut hashes: Vec<String> = serde_json::from_slice(set.data.expose())
                .map_err(|e| internal("read recovery code set", e))?;
            let mut matched = None;
            for (i, stored) in hashes.iter().enumerate() {
                if bool::from(input_hash.as_bytes().ct_eq(stored.as_bytes())) {
                    matched = Some(i);
                }
            }
            let Some(index) = matched else {
                return Err(authentication_failed());
            };
            hashes.remove(index);
            let remaining =
                serde_json::to_vec(&hashes).map_err(|e| internal("write recovery code set", e))?;
            // A spent code is security-relevant (it may mean the account is
            // compromised); the spend owes the event, a lost race owes nothing.
            let used = Event::new(&self.issuer, event_types::MFA_RECOVERY_CODE_USED)
                .with_subject(format!("profile/{}", profile_id))
                .with_data(serde_json::json!({
                    "remaining": hashes.len(),
                    "needs_regeneration": hashes.len() <= 3,
                }));
            let ctx = MutationContext::from(AuditEntry::user(
                profile_id.to_string(),
                "credential.recovery_code_used",
                set.id.0.to_string(),
            ))
            .with_work(used.relay());
            if self
                .storage
                .replace_credential_data(set.id, set.data.expose(), &remaining, ctx)
                .await
                .map_err(storage_failure)?
            {
                return Ok(hashes.len());
            }
        }
        // Each lost race means another spend committed; after the bound the
        // caller retries rather than being told the code is wrong.
        Err(changed_concurrently())
    }

    /// Refuse a sign-in attempt while `identity` is locked out. Checked before
    /// any password work and for known and unknown identities alike, so a
    /// lockout neither lets guessing continue nor confirms a guess.
    async fn refuse_if_locked(&self, identity: &str) -> Result<(), Status> {
        self.sign_ins
            .refuse_if_locked(identity)
            .await
            .map_err(sign_in_refusal)
    }

    /// Count a failed login attempt (brute force and stuffing limits); one
    /// that cannot be counted refuses the request.
    async fn record_failed_login(
        &self,
        identity: &str,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(), Status> {
        self.sign_ins
            .record_failed_login(identity, client_ip)
            .await
            .map_err(sign_in_refusal)
    }

    /// Count a failed attempt against its source address only.
    async fn record_failed_from(&self, client_ip: Option<std::net::IpAddr>) -> Result<(), Status> {
        self.sign_ins
            .record_failed_from(client_ip)
            .await
            .map_err(sign_in_refusal)
    }

    /// Count an attempt from `client_ip` against the stuffing limit.
    async fn record_ip_attempt(&self, client_ip: Option<std::net::IpAddr>) -> Result<(), Status> {
        self.sign_ins
            .record_ip_attempt(client_ip)
            .await
            .map_err(sign_in_refusal)
    }

    /// The installation's public origin, which every URI a sender proof
    /// names starts with.
    pub(crate) fn public_origin(&self) -> &str {
        &self.public_origin
    }

    /// The application key `proof` binds to the ceremony whose echoed
    /// reference is `reference`, none without a proof.
    async fn native_ceremony_key(
        &self,
        proof: Option<&NativeProof>,
        reference: &[u8],
    ) -> Result<Option<String>, Status> {
        match proof {
            Some(proof) => Ok(Some(
                proof.ceremony_key(self.oauth.dpop(), reference).await?,
            )),
            None => Ok(None),
        }
    }

    /// The issuer a request's path names, when it serves clients of
    /// `client_org` ([`sid::oauth::OAuth::issuer_serving`]).
    async fn issuer_serving(
        &self,
        handle: &str,
        client_org: Option<sid_core::models::OrgId>,
    ) -> Result<Option<OidcIssuer>, Status> {
        self.oauth
            .issuer_serving(handle, client_org)
            .await
            .map_err(oauth_refusal)
    }

    /// The resource a new grant of `requester` under `issuer` is for
    /// ([`sid::oauth::OAuth::select_target`]).
    async fn select_target<'r>(
        &self,
        issuer: &OidcIssuer,
        requester: impl Into<sid_authn::target::Requester<'r>>,
        resource: &[String],
    ) -> Result<sid_authn::target::Target, Status> {
        self.oauth
            .select_target(issuer, requester, resource)
            .await
            .map_err(oauth_refusal)
    }

    /// Resolve a profile by principal (email, phone, or username).
    ///
    /// Uses principal-type-aware lookup, falling back to username lookup.
    /// Like `resolve_profile`, but returns `None` for nonexistent users instead
    /// of an error. Storage errors still propagate.
    async fn resolve_profile_optional(
        &self,
        identifier: &str,
    ) -> Result<Option<sid_core::models::Profile>, Status> {
        self.sign_ins
            .resolve_profile(identifier)
            .await
            .map_err(sign_in_refusal)
    }

    /// The mailbox login mail for the email key `key` goes to on `profile`,
    /// the account it routes to: the address in the spelling that profile
    /// bound it with (its binding's contact, which registration, import and
    /// directory provisioning each record with the binding), never another
    /// spelling of the key. `None` when that binding records no such
    /// contact: a lost spelling is not inferred from the key.
    async fn login_mail_destination(
        &self,
        profile: ProfileId,
        key: &str,
    ) -> Result<Option<String>, Status> {
        let principals = self
            .storage
            .get_principals_by_profile(profile)
            .await
            .map_err(storage_failure)?;
        let Some(contact) = principals
            .iter()
            .find(|p| p.principal_type == PrincipalType::Email && p.value == key)
            .and_then(|p| p.source_email_id)
        else {
            return Ok(None);
        };
        Ok(self
            .storage
            .get_profile_email(contact)
            .await
            .map_err(storage_failure)?
            .filter(|email| email.profile_id == profile)
            .map(|email| email.email))
    }

    /// Decide what a registration started for `principal` may commit. The
    /// server decides new registration versus existing account; a client
    /// cannot claim an identifier that already belongs to someone. A held
    /// identifier's start is answered like a new one but can never be
    /// committed to.
    async fn begin_registration(
        &self,
        principal: &str,
        claim_token: Option<&str>,
        invite_code: Option<&str>,
    ) -> Result<PendingRegistration, Status> {
        let enabled = self.feature_flags.is_registration_enabled().await;
        self.registration
            .begin(principal, claim_token, invite_code, enabled)
            .await
            .map_err(registration_refusal)
    }

    /// Commit a pending registration with its first credential, atomically. A taken
    /// identifier answers `ALREADY_EXISTS` and nothing is written: the holder is not
    /// contacted, and the registrant must use another identifier and claim this one
    /// from their own account. `history` is the first password's accepted
    /// history; `completion` the durable result of the operation that installs
    /// it.
    async fn commit_registration(
        &self,
        pending: PendingRegistration,
        credential: Credential,
        history: Option<HistoryCommit>,
        completion: Option<OperationCompletion>,
    ) -> Result<(ProfileId, CredentialId), Status> {
        let enabled = self.feature_flags.is_registration_enabled().await;
        self.registration
            .commit(pending, credential, history, completion, enabled)
            .await
            .map_err(registration_refusal)
    }

    /// A password credential the caller owns; anything else reads as not found, so a
    /// foreign credential id reveals nothing.
    #[allow(clippy::result_large_err)]
    fn require_own_password(credential: &Credential, caller: ProfileId) -> Result<(), Status> {
        if credential.profile_id != caller
            || credential.credential_type != CredentialType::Opaque
            || !credential.status.is_active()
        {
            return Err(credential_not_found(credential.id));
        }
        Ok(())
    }

    /// The refusal of a held identifier's registration finish
    /// ([`sid::registration::Registration::refuse_held`]).
    async fn refuse_held(&self, pending: &PendingRegistration) -> Status {
        let enabled = self.feature_flags.is_registration_enabled().await;
        registration_refusal(self.registration.refuse_held(pending, enabled).await)
    }

    /// Refuse unless the caller's own interactive session may bind a new
    /// `credential_type` credential to `profile_id` now. Checked at the start
    /// and again at the finish of every ceremony that binds one, against the
    /// stored session and the account's current credentials.
    async fn require_enrollment_authority(
        &self,
        caller: &sid_authn::caller::Caller,
        profile_id: ProfileId,
        credential_type: CredentialType,
    ) -> Result<(), Status> {
        if caller.profile_id != profile_id {
            return Err(ApiError::new(
                ErrorReason::InsufficientPermissions,
                "a credential is bound only to the caller's own profile",
            )
            .into());
        }
        sid_authn::credential_enrollment::authorize(
            self.storage.as_ref(),
            caller,
            credential_type,
            self.security_policy().auth.passkey_satisfies_mfa,
        )
        .await
        .or_status()
    }

    /// Who binds a second factor in `request`: a sign-in's pending context
    /// when it presents one, otherwise the caller's session.
    async fn enroller<T>(&self, request: &Request<T>) -> Result<Enroller, Status> {
        if let Ok(FactorCaller::Pending(pending, _)) = self.factor_caller(request).await {
            return Ok(Enroller::SignIn(Box::new(pending)));
        }
        Ok(Enroller::Session(self.caller_claims(request).await?.caller))
    }

    /// Refuse unless `enroller` may bind a new TOTP authenticator now.
    async fn require_totp_enrollment_authority(&self, enroller: &Enroller) -> Result<(), Status> {
        match enroller {
            Enroller::Session(caller) => {
                self.require_enrollment_authority(caller, caller.profile_id, CredentialType::Totp)
                    .await
            }
            Enroller::SignIn(pending) => {
                // A password replaced since the first factor binds nothing.
                self.first_factor_fence(pending).await?;
                sid_authn::credential_enrollment::authorize_sign_in(
                    self.storage.as_ref(),
                    pending,
                    self.security_policy().auth.passkey_satisfies_mfa,
                )
                .await
                .or_status()
            }
        }
    }

    /// The credential `pending`'s first factor proved, while it still holds:
    /// it commits with what the context completes, as in a sign-in that needs
    /// no second factor. One replaced or revoked since completes nothing, and
    /// a reset after waits for the session and ends it.
    async fn first_factor_fence(
        &self,
        pending: &Session,
    ) -> Result<Option<sid_core::models::CredentialFence>, Status> {
        self.sign_ins
            .first_factor_fence(pending)
            .await
            .map_err(sign_in_refusal)
    }

    /// Refuse unless the caller may change its own password now; answer
    /// whether the change must prove the current password (see
    /// [`sid_authn::credential_enrollment::password_change_authority`]).
    async fn password_change_authority(
        &self,
        caller: &sid_authn::caller::Caller,
    ) -> Result<bool, Status> {
        sid_authn::credential_enrollment::password_change_authority(
            self.storage.as_ref(),
            caller,
            self.security_policy().auth.passkey_satisfies_mfa,
            self.security_policy().password.change_current_password,
        )
        .await
        .or_status()
    }

    /// The OPAQUE password file of `credential`, opened, with its curve, and
    /// the credential's data as the store holds it afterwards.
    async fn stored_password(
        &self,
        credential: &Credential,
    ) -> Result<(StoredCredential, sid_core::models::CredentialData), Status> {
        self.sign_ins
            .stored_password(credential)
            .await
            .map_err(sign_in_refusal)
    }

    /// The profile's passkeys that may still sign in (revoked ones never do).
    async fn active_passkeys(&self, profile_id: ProfileId) -> Result<Vec<Credential>, Status> {
        Ok(self
            .storage
            .get_credentials_by_profile(profile_id, Some(CredentialType::WebAuthn))
            .await
            .map_err(storage_failure)?
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect())
    }

    /// Record a successful assertion on the passkey that made it (see
    /// [`sid_authn::webauthn::record_passkey_use`]): a lost race or a revoked
    /// passkey fails the sign-in. Returns the RFC 8176 method of the key and
    /// the fence that proved this sign-in's first factor.
    async fn record_passkey_use(
        &self,
        passkeys: &[Credential],
        verified: &VerifiedAssertion,
    ) -> Result<(&'static str, sid_core::models::CredentialFence), Status> {
        sid_authn::webauthn::record_passkey_use(self.storage.as_ref(), passkeys, verified)
            .await
            .map_err(storage_failure)?
            .map(|fence| (verified.key_amr, fence))
            .ok_or_else(authentication_failed)
    }

    /// The result of a passkey assertion finish: a refused assertion counts
    /// as a failed sign-in of `profile_id`; any other failure is internal.
    async fn passkey_outcome(
        &self,
        finished: sid_core::Result<VerifiedAssertion>,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<VerifiedAssertion, Status> {
        match finished {
            Ok(verified) => Ok(verified),
            Err(sid_core::Error::AuthenticationFailed(why)) => {
                warn!("WebAuthn authentication failed: {why}");
                self.record_failed_login(&profile_id.to_string(), client_ip)
                    .await?;
                Err(authentication_failed())
            }
            Err(other) => Err(internal("finish passkey sign-in", other)),
        }
    }

    /// The active account `identifier` signs in to, or the same refusal as a
    /// wrong password whatever keeps it from resolving.
    async fn resolve_profile(&self, identifier: &str) -> Result<sid_core::models::Profile, Status> {
        self.resolve_profile_optional(identifier)
            .await?
            .ok_or_else(authentication_failed)
    }

    /// The caller's verified access token and the caller it stands for
    /// (signature, issuer, audience, expiry, revocation, sender constraint).
    #[allow(clippy::result_large_err)]
    async fn caller_claims<T>(
        &self,
        request: &Request<T>,
    ) -> Result<sid_authn::caller::Verified, Status> {
        sid_infra::authn::caller::verify_request(
            request,
            self.jwt.verifier(),
            &self.revocation_cache,
        )
        .await
    }

    /// The profile's active TOTP credential and its seed. A seed stored under
    /// an older key version is written back re-sealed under the current one.
    async fn active_totp_seed(
        &self,
        profile_id: ProfileId,
    ) -> Result<Option<(Credential, zeroize::Zeroizing<Vec<u8>>)>, Status> {
        let credential = self
            .storage
            .get_credentials_by_profile(profile_id, Some(CredentialType::Totp))
            .await
            .map_err(storage_failure)?
            .into_iter()
            .find(|c| c.status.is_active());
        let Some(mut credential) = credential else {
            return Ok(None);
        };
        let opened = sid_authn::sealed_secret::open(
            self.key_manager.as_ref(),
            &sid_authn::sealed_secret::totp_context(profile_id),
            credential.data.expose(),
        )
        .await
        .map_err(|e| internal("open TOTP seed", e))?;
        if let Some(resealed) = opened.resealed {
            // Not applied when another reader resealed it first or it was
            // revoked meanwhile; the use that follows is conditional on the
            // credential still being active.
            let applied = self
                .storage
                .reseal_credential_data(
                    credential.id,
                    credential.data.expose(),
                    &resealed,
                    AuditEntry::system("credential.secret_resealed", credential.id.0.to_string())
                        .into(),
                )
                .await
                .map_err(storage_failure)?;
            if applied {
                credential.data = CredentialData::new(resealed);
            }
        }
        Ok(Some((credential, opened.secret)))
    }

    /// The OPAQUE envelope `data` sealed for `profile_id`, as it is stored.
    async fn seal_envelope(&self, profile_id: ProfileId, data: &[u8]) -> Result<Vec<u8>, Status> {
        sid_authn::sealed_secret::seal(
            self.key_manager.as_ref(),
            &sid_authn::sealed_secret::opaque_context(profile_id),
            data,
        )
        .await
        .map_err(|e| internal("seal OPAQUE envelope", e))
    }

    /// The authenticated caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<sid_authn::caller::Caller, Status> {
        sid_infra::authn::caller::authenticate(request, self.jwt.verifier(), &self.revocation_cache)
            .await
    }

    /// Create session and issue tokens (shared logic for login flows).
    ///
    /// Sets `assurance_level` and `amr` from how the sign-in authenticated.
    /// The session records the client's address and device: the sign-in
    /// history the new-device rule compares later sign-ins with.
    /// Its credential goes to `client` as [`Self::sign_in`] delivers it.
    #[allow(clippy::too_many_arguments)]
    async fn create_session_and_issue_tokens(
        &self,
        profile: &sid_core::models::Profile,
        method: LoginMethod,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<std::net::IpAddr>,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<&sid_core::models::CredentialFence>,
        policy: Option<sid_core::models::ActorFence>,
    ) -> Result<SignedIn, Status> {
        self.sign_ins
            .sign_in_by(
                profile, method, device_id, client_ip, client, native_key, proved_by, policy,
            )
            .await
            .map_err(sign_in_refusal)
    }

    /// A full session of `profile_id` from `ip_address`, for the
    /// installation's absolute lifetime when it sets one, with the sign-in
    /// scopes; its authentication is the caller's to set.
    fn new_session(&self, profile_id: ProfileId, ip_address: Option<std::net::IpAddr>) -> Session {
        self.sign_ins.new_session(profile_id, ip_address)
    }

    /// Who verifies a second factor in `request`: a sign-in's pending
    /// context, named by its token or, from the browser sign-in page, by its
    /// cookie with the CSRF token it was given; or an installation session
    /// stepping up, by its token.
    async fn factor_caller<T>(&self, request: &Request<T>) -> Result<FactorCaller, Status> {
        let metadata = request.metadata();
        if metadata.get("authorization").is_none() {
            // Only the exact sign-in page completes a pending sign-in with its
            // cookie; a native client presents its token.
            if self.ceremony_client(metadata)? != CeremonyClient::Browser {
                return Err(session_ended());
            }
            let pending = self
                .browser_session(metadata)
                .await?
                .filter(|s| s.awaits_second_factor() && !s.is_expired())
                .ok_or_else(session_ended)?;
            let sent = metadata
                .get_all("x-csrf-token")
                .iter()
                .filter_map(|value| value.to_str().ok());
            let csrf = pending.browser_csrf.as_ref().ok_or_else(session_ended)?;
            if !sid_authn::browser_session::BrowserCsrf::matches(sent, csrf) {
                return Err(ApiError::new(
                    ErrorReason::CsrfTokenInvalid,
                    "the sign-in's CSRF token is missing or wrong",
                )
                .into());
            }
            return Ok(FactorCaller::Pending(pending, CeremonyClient::Browser));
        }
        // The pending context's token is accepted here and nowhere else.
        let (claims, profile_id, pending) = match sid_infra::authn::caller::verify_factor_request(
            request,
            self.jwt.verifier(),
            &self.revocation_cache,
        )
        .await?
        {
            sid_authn::caller::FactorToken::Pending(claims) => {
                let caller = sid_authn::caller::Caller::from_claims(&claims).or_status()?;
                (claims, caller.profile_id, true)
            }
            sid_authn::caller::FactorToken::Session(verified) => {
                verified.require_installation().or_status()?;
                (verified.claims, verified.caller.profile_id, false)
            }
        };
        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(storage_failure)?
            .filter(|session| session.profile_id == profile_id)
            .filter(|session| session.awaits_second_factor() == pending)
            .ok_or_else(session_ended)?;
        Ok(if pending {
            FactorCaller::Pending(session, CeremonyClient::Native)
        } else {
            FactorCaller::StepUp(session)
        })
    }

    /// Complete `pending` with the verified second factor `method` (RFC 8176):
    /// the current login requirements are met by the completed
    /// authentication, the pending context ends exactly once and the account
    /// gets its session with a new credential, delivered to `client` (with
    /// the refresh generation bound to `native_key` when it proved one).
    async fn complete_pending_sign_in(
        &self,
        pending: Session,
        method: &str,
        client: CeremonyClient,
        native_key: Option<&str>,
    ) -> Result<SignedIn, Status> {
        use sid_core::models::session::AuthLevel;
        let profile = self
            .storage
            .get_profile(pending.profile_id)
            .await
            .map_err(storage_failure)?
            .filter(|p| p.status == sid_core::models::ProfileStatus::Active)
            .ok_or_else(authentication_failed)?;
        let now = Utc::now();
        let requirements = self.login_requirements(None).await?;
        if !requirements.met_with(&pending, AuthLevel::Standard, method, now) {
            let mut completed = pending.clone();
            completed.assurance_level = completed.assurance_level.max(AuthLevel::Standard);
            completed.amr.push(method.to_string());
            return Err(step_up_required(&requirements.unmet(&completed, now)).into());
        }

        let proved_by = self.first_factor_fence(&pending).await?;

        let mut session = self.new_session(profile.id, pending.ip_address);
        session.device_id = pending.device_id;
        session.user_agent = pending.user_agent.clone();
        session.assurance_level = pending.assurance_level.max(AuthLevel::Standard);
        session.amr = pending.amr.clone();
        if !session.amr.iter().any(|m| m == method) {
            session.amr.push(method.to_string());
        }
        // The authentication began with the first factor.
        session.authenticated_at = pending.authenticated_at;
        // The pending context ends in the session's own commit: of concurrent
        // completions one signs in, and one ended meanwhile completes nothing.
        let signed_in = self
            .sign_ins
            .complete_pending(
                &profile,
                (
                    pending.id,
                    &sid_core::models::SessionEnd::new(
                        sid_core::models::RevocationReason::SignInCompleted,
                        pending.profile_id.to_string(),
                    ),
                ),
                session,
                client,
                native_key,
                proved_by
                    .as_ref()
                    .map(sid_core::models::SignInProof::Credential),
                requirements.fence,
            )
            .await
            .map_err(sign_in_refusal)?;
        // Recorded from the address the rules judged at the first factor.
        self.sign_ins
            .record_completed(profile.id, pending.ip_address)
            .await;
        Ok(signed_in)
    }

    /// Complete a local first-factor sign-in as `admission` decided: the
    /// session, or its pending context with the second factors that complete
    /// it and, for a browser, the CSRF token the completion sends. A session
    /// of a native client that proved the application key `native_key` gets
    /// its refresh generation; a pending context gets none.
    #[allow(clippy::too_many_arguments)]
    async fn complete_first_factor(
        &self,
        profile: &sid_core::models::Profile,
        method: LoginMethod,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<std::net::IpAddr>,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<&sid_core::models::CredentialFence>,
        admission: FirstFactor,
    ) -> Result<FirstFactorSignedIn, Status> {
        self.sign_ins
            .complete_first_factor(
                profile, method, device_id, client_ip, client, native_key, proved_by, admission,
            )
            .await
            .map_err(sign_in_refusal)
    }

    /// Provisional session for a weak-possession login (email OTP, magic link):
    /// 15 minutes, provisional scopes only. Mailbox possession alone never grants
    /// a full session to an existing account.
    async fn create_provisional_session_and_issue_tokens(
        &self,
        profile: &sid_core::models::Profile,
        amr: &str,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<std::net::IpAddr>,
        client: CeremonyClient,
        policy: Option<sid_core::models::ActorFence>,
    ) -> Result<SignedIn, Status> {
        let mut session = sid_core::models::Session::new_provisional(profile.id, client_ip);
        session.device_id = device_id;
        session.amr = vec![amr.to_string()];
        // Mailbox possession proves no stored credential, and a provisional
        // session is not renewable.
        self.sign_in(profile, session, client, None, None, policy, None)
            .await
    }

    /// Store `session` and deliver its credential to `client`: the browser
    /// sign-in page gets the IdP session cookie, a fresh secret whose hash
    /// the session stores, and no access token; a native client gets the
    /// session's access token. `proved_by` is what the sign-in proved and
    /// `policy` the login policy it was admitted under; both must still hold
    /// when the session commits. A native client whose ceremony proved the
    /// application key `native_key` also gets its refresh generation.
    #[allow(clippy::too_many_arguments)]
    async fn sign_in(
        &self,
        profile: &sid_core::models::Profile,
        session: sid_core::models::Session,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<sid_core::models::SignInProof<'_>>,
        policy: Option<sid_core::models::ActorFence>,
        retained: Option<sid::sign_in::RetainedSignIn<'_>>,
    ) -> Result<SignedIn, Status> {
        self.sign_ins
            .sign_in(
                profile, session, client, native_key, proved_by, policy, retained,
            )
            .await
            .map_err(sign_in_refusal)
    }

    /// Who completes the upstream sign-in `request`: its client (a browser
    /// off the sign-in page completes nothing), address and device.
    #[allow(clippy::result_large_err)]
    pub(crate) fn upstream_ceremony<T>(
        &self,
        request: &Request<T>,
    ) -> Result<UpstreamCeremony, Status> {
        Ok(UpstreamCeremony {
            client: self.ceremony_client(request.metadata())?,
            client_ip: self.client_ip(request)?,
            user_agent: extract_user_agent(request.metadata()),
            captcha_pass: extract_captcha_pass(request.metadata()),
        })
    }

    /// Sign `profile` in after an upstream identity provider verified the
    /// user, as every other sign-in completes: only an active Profile, after
    /// the sign-in security rules for this client, with a session of this
    /// authority's lifetime and limit. The provider, not SID, verified the
    /// user: the session names no `amr` method (RFC 8176 §1) and has basic
    /// assurance.
    pub(crate) async fn complete_upstream_sign_in(
        &self,
        profile: &sid_core::models::Profile,
        ceremony: &UpstreamCeremony,
    ) -> Result<SignedIn, Status> {
        if !profile.status.can_authenticate() {
            return Err(authentication_failed());
        }
        let policy = self
            .evaluate_login_security(
                profile.id,
                ceremony.client_ip,
                "upstream",
                (sid_core::models::session::AuthLevel::Basic, &[]),
                AttemptContext {
                    captcha_pass: ceremony.captcha_pass.as_deref(),
                    user_agent: ceremony.user_agent.as_deref(),
                },
            )
            .await?;
        let lifetime = match self.security_policy().session.max_lifetime_hours {
            0 => Duration::hours(24),
            hours => Duration::hours(i64::from(hours)),
        };
        let mut session =
            sid_core::models::Session::new(profile.id, ceremony.client_ip, Utc::now() + lifetime);
        session.device_id = ceremony.user_agent.as_deref().map(compute_device_id);
        session.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
        self.sign_in(profile, session, ceremony.client, None, None, policy, None)
            .await
    }

    /// Sign `profile` in on the accepted evidence of an explicitly trusted
    /// issuer: a host admitted a federated entry (its exact issuer, client
    /// and subject), resolved its Profile through `assignment` (the current
    /// assignment of that issuer's subject), and `authentication` is what the
    /// evidence attests (see `AcceptedEvidence::authentication`). The session
    /// commits only while `assignment` still holds, and a repeat is delivered
    /// only while it does: a retired association admits nothing. It completes as
    /// every sign-in does: only an active Profile, after the sign-in rules
    /// and this authority's policy weigh that authentication, with a session
    /// of this authority's lifetime and limit recording it. `request` is the
    /// browser's return the host checked by its state: its client address
    /// and device are the sign-in's, and the browser gets the IdP session
    /// cookie. `client_id` is the application the sign-in continues to: its
    /// login requirements are the ones weighed.
    ///
    /// With `completion`, the host's keyed operation (a federated entry's
    /// return), the session commits with that operation's completion and
    /// its delivery sealed for a lost response: a repeat of the operation
    /// gets the same live session again, after the current checks, never a
    /// second one (the recoverable federation callback completion contract).
    pub async fn complete_admitted_sign_in<T>(
        &self,
        request: &Request<T>,
        profile: &sid_core::models::Profile,
        assignment: sid_core::models::PrincipalAssignmentFence,
        authentication: &sid_core::models::session::SessionAuthentication,
        client_id: &str,
        completion: Option<AdmittedCompletion<'_>>,
    ) -> Result<SignedIn, Status> {
        if !profile.status.can_authenticate() || assignment.profile != profile.id {
            return Err(authentication_failed());
        }
        // An operation past its end admits nothing, neither a repeat nor a
        // new sign-in: its retained delivery is gone with it.
        if completion
            .as_ref()
            .is_some_and(|c| c.deadline <= Utc::now())
        {
            return Err(authentication_failed());
        }
        // The rules this request meets now (address, lockout, anomalies and
        // requirements), a repeat of a completed operation included: a
        // retained credential is never delivered where the sign-in itself
        // would be refused.
        let client_ip = self.client_ip(request)?;
        let user_agent = extract_user_agent(request.metadata());
        let user_agent = user_agent.as_deref();
        let captcha_pass = extract_captcha_pass(request.metadata());
        let attempt =
            || sid_authn::sign_in_security::AttemptAuthentication::Accepted(authentication);
        let extras = || AttemptContext {
            captcha_pass: captcha_pass.as_deref(),
            user_agent,
        };
        // A repeat of an operation already committed is judged by the rules
        // of its own request but records no further sign-in; the admission
        // it repeats answers a CAPTCHA from the address it was made from.
        if let Some(completion) = &completion
            && let Some((delivery, session)) = self.admitted_session(completion, assignment).await?
        {
            self.check_sign_in(
                profile.id,
                client_ip,
                (attempt(), extras()),
                Some(client_id),
                session.ip_address,
            )
            .await?;
            return self
                .deliver_admitted(delivery, &session, client_id, assignment)
                .await;
        }
        let proved_by = Some(sid_core::models::SignInProof::Assignment(assignment));
        let policy = self
            .evaluate_sign_in(profile.id, client_ip, attempt(), extras(), Some(client_id))
            .await?;
        let lifetime = match self.security_policy().session.max_lifetime_hours {
            0 => Duration::hours(24),
            hours => Duration::hours(i64::from(hours)),
        };
        let mut session =
            sid_core::models::Session::new(profile.id, client_ip, Utc::now() + lifetime);
        session.device_id = user_agent.map(compute_device_id);
        session.assurance_level = authentication.assurance_level;
        session.elevation = authentication.elevation;
        session.authenticated_at = authentication.authenticated_at;
        session.amr = authentication.amr.clone();
        session.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
        let Some(completion) = completion else {
            return self
                .sign_in(
                    profile,
                    session,
                    CeremonyClient::Browser,
                    None,
                    proved_by,
                    policy,
                    None,
                )
                .await;
        };
        // The delivery lives no longer than the operation, nor than the
        // session it delivers.
        let retained = sid::sign_in::RetainedSignIn {
            keys: self.key_manager.as_ref(),
            completion_key: completion.key()?,
            context: self.admitted_context(&completion),
            deadline: completion.deadline.min(session.expires_at),
            inputs: sid::sign_in::admitted_inputs(assignment),
        };
        match self
            .sign_in(
                profile,
                session,
                CeremonyClient::Browser,
                None,
                proved_by,
                policy,
                Some(retained),
            )
            .await
        {
            // A concurrent repeat committed first: its session is this one.
            // Anything else keeps its refusal.
            Err(refused) => match self
                .redeliver_admitted(&completion, client_id, assignment)
                .await
            {
                Ok(Some(signed_in)) => Ok(signed_in),
                Ok(None) | Err(_) => Err(refused),
            },
            Ok(signed_in) => Ok(signed_in),
        }
    }

    /// The sealing context of an admitted sign-in's delivery: its operation
    /// at this issuer.
    fn admitted_context(&self, completion: &AdmittedCompletion<'_>) -> String {
        format!("admitted-sign-in:{}:{}", self.issuer, completion.operation)
    }

    /// The sign-in `completion` already committed for `assignment`'s Profile,
    /// delivered again: before the operation's deadline, while its session
    /// lives, its Profile can sign in, `assignment` still holds and its
    /// authentication meets `client_id`'s current requirements. None when
    /// the operation has not committed; a refusal when it has but may not be
    /// delivered again.
    async fn redeliver_admitted(
        &self,
        completion: &AdmittedCompletion<'_>,
        client_id: &str,
        assignment: sid_core::models::PrincipalAssignmentFence,
    ) -> Result<Option<SignedIn>, Status> {
        match self.admitted_session(completion, assignment).await? {
            Some((delivery, session)) => self
                .deliver_admitted(delivery, &session, client_id, assignment)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    /// The live session `completion` committed under `assignment` and its
    /// retained delivery; None when the operation has not committed; a
    /// refusal when it has but under another assignment, or may not be
    /// delivered again (see [`Self::redeliver_admitted`]).
    async fn admitted_session(
        &self,
        completion: &AdmittedCompletion<'_>,
        assignment: sid_core::models::PrincipalAssignmentFence,
    ) -> Result<
        Option<(
            sid_authn::sign_in_delivery::RetainedDelivery,
            sid_core::models::Session,
        )>,
        Status,
    > {
        let Some(record) = self
            .storage
            .get_operation_result(sid::sign_in::ADMITTED_NAMESPACE, &completion.key()?)
            .await
            .map_err(storage_failure)?
        else {
            return Ok(None);
        };
        if !record.matches(
            sid::sign_in::ADMITTED_METHOD,
            &sid::sign_in::admitted_inputs(assignment),
            // The sign-in ceremony's own record, under no period.
            None,
        ) {
            return Err(authentication_failed());
        }
        let delivery = sid_authn::sign_in_delivery::RetainedDelivery::open(
            self.key_manager.as_ref(),
            &self.admitted_context(completion),
            &record.completion.result,
        )
        .await
        .map_err(|e| internal("open the retained sign-in delivery", e))?;
        let now = Utc::now();
        if delivery.deadline <= now {
            return Err(authentication_failed());
        }
        // The commit is the whole sign-in: what it owes (its evictions'
        // revocations) committed with it as owed work, so the same session
        // is delivered again from the moment it committed.
        let session = self
            .storage
            .get_session(delivery.session_id)
            .await
            .map_err(storage_failure)?
            .filter(|session| !session.is_expired() && session.profile_id == assignment.profile)
            .ok_or_else(authentication_failed)?;
        self.storage
            .get_profile(session.profile_id)
            .await
            .map_err(storage_failure)?
            .filter(|profile| profile.status.can_authenticate())
            .ok_or_else(authentication_failed)?;
        Ok(Some((delivery, session)))
    }

    /// `session`'s retained `delivery`, while `assignment` still assigns the
    /// session's Profile and its authentication meets `client_id`'s current
    /// requirements: a retired or moved association delivers nothing again.
    async fn deliver_admitted(
        &self,
        delivery: sid_authn::sign_in_delivery::RetainedDelivery,
        session: &sid_core::models::Session,
        client_id: &str,
        assignment: sid_core::models::PrincipalAssignmentFence,
    ) -> Result<SignedIn, Status> {
        let current = self
            .storage
            .get_principal(assignment.principal)
            .await
            .map_err(storage_failure)?
            .is_some_and(|p| {
                p.assigned_profile_id == Some(session.profile_id)
                    && p.assignment_revision == assignment.revision
            });
        if !current || assignment.profile != session.profile_id {
            return Err(authentication_failed());
        }
        // The requirements the sign-in itself was weighed under, read now;
        // the client's own are applied where the sign-in continues.
        let requirements = self.login_requirements(Some(client_id)).await?;
        if let sid_authn::login_policy::LoginDecision::StepUp(unmet) =
            requirements.decide(session, Utc::now())
        {
            return Err(step_up_required(&unmet).into());
        }
        delivery
            .signed_in(self.browser_cookie(), session)
            .ok_or_else(authentication_failed)
    }

    /// Refuse to create an account for an upstream sign-in this authority
    /// does not admit, as it refuses a self-registration: the registration
    /// switch, then the effective enrollment policy, the provider's verified
    /// email as the address a domain policy checks. An upstream sign-in
    /// carries no invite.
    pub(crate) async fn admit_upstream_account(
        &self,
        claims: &sid_core::models::MappedClaims,
    ) -> Result<(), Status> {
        if !self.feature_flags.is_registration_enabled().await {
            return Err(not_configured("registration"));
        }
        let policy = sid::enrollment::effective(self.storage.as_ref(), self.registration.pinned())
            .await
            .map_err(storage_failure)?;
        let email = claims
            .has_verified_email()
            .then_some(claims.email.as_deref())
            .flatten();
        match sid_core::enrollment::evaluate_enrollment(&policy, email, None) {
            sid_core::enrollment::EnrollmentDecision::Allow => Ok(()),
            sid_core::enrollment::EnrollmentDecision::Deny(reason) => {
                Err(registration_restricted(enrollment_requirement(&reason)))
            }
        }
    }

    /// SERVICE_MAINTENANCE while the installation is in maintenance mode.
    pub(crate) async fn check_maintenance(&self) -> Result<(), Status> {
        if self.feature_flags.is_maintenance_mode().await {
            Err(maintenance())
        } else {
            Ok(())
        }
    }

    /// The ZKPP server, or DEPENDENCY_UNAVAILABLE while its verification keys
    /// are still being generated.
    #[allow(clippy::result_large_err)]
    fn require_zkpp(&self) -> Result<Arc<ZkppOpaqueServer>, Status> {
        let guard = self.opaque_zkpp.load();
        match guard.as_ref() {
            Some(server) => Ok(Arc::clone(server)),
            None => Err(dependency_unavailable(
                "password proof verification keys",
                "key generation in progress",
            )),
        }
    }

    /// The password credential `credential_id` of `caller`, or `NOT_FOUND`
    /// (a foreign or wrong credential id reveals nothing).
    async fn own_password(
        &self,
        credential_id: Option<&sid_ids_proto::CredentialId>,
        caller: ProfileId,
    ) -> Result<Credential, Status> {
        let cred_id = CredentialId(wire_id(credential_id, "credential_id")?.into_uuid());
        let credential = self
            .storage
            .get_credential(cred_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| credential_not_found(cred_id))?;
        Self::require_own_password(&credential, caller)?;
        Ok(credential)
    }

    /// The password history evaluator interface, served as its own gRPC
    /// service, when the evaluator runs in this process; `None` when it is
    /// its own service. Nobody prepares at it over the network: this
    /// process's credential service prepares in process. An evaluator that
    /// takes Prepare from a remote credential service is a separate
    /// composition of
    /// [`PasswordHistoryEvaluatorImpl`](PasswordHistoryEvaluatorImpl)
    /// on an internal listener, with its own database and keys; this server
    /// never serves one.
    pub fn history_evaluator(&self) -> Option<PasswordHistoryEvaluatorImpl> {
        self.history_evaluation.clone().map(|evaluation| {
            PasswordHistoryEvaluatorImpl::new(evaluation, Arc::new(ClientListener))
        })
    }

    /// `history` with this installation's age retention: an accepted
    /// password's commit also drops the owner's entries older than the policy
    /// keeps, under the same revision fence.
    fn with_history_age(
        &self,
        history: Option<sid_core::models::HistoryCommit>,
    ) -> Option<sid_core::models::HistoryCommit> {
        history.map(|mut commit| {
            commit.max_age_days = self.security_policy().password.history_max_age_days;
            commit
        })
    }

    /// Where this service's evaluator is told what was settled here: the
    /// in-process evaluator directly, a separate one by relayed events.
    fn evaluator_delivery(&self) -> sid_authn::password_operation::EvaluatorDelivery {
        use sid_authn::password_operation::EvaluatorDelivery;
        match self.history_evaluation.clone() {
            Some(evaluation) => EvaluatorDelivery::InProcess(evaluation),
            None => EvaluatorDelivery::Relay {
                source: self.issuer.clone(),
            },
        }
    }

    /// The credential authority whose cleanup settlements this service
    /// consumes: its own, when its evaluator runs separately; `None` when the
    /// evaluator runs in process and settles directly.
    pub fn cleanup_settlement_authority(&self) -> Option<String> {
        self.history_evaluation
            .is_none()
            .then(|| self.issuer.clone())
    }

    /// The handler that ends this service's first enrollments at their
    /// expiry: the evaluator reclaims an aborted one's key.
    pub fn enrollment_handler(&self) -> Arc<dyn sid_authn::work_runner::WorkHandler> {
        Arc::new(sid_authn::password_operation::EnrollmentHandler::new(
            self.storage.clone(),
            self.evaluator_delivery(),
        ))
    }

    /// The handler that has the evaluator destroy a deleted owner's keys.
    pub fn owner_purge_handler(&self) -> Arc<dyn sid_authn::work_runner::WorkHandler> {
        Arc::new(sid_authn::password_operation::OwnerPurgeHandler::new(
            self.storage.clone(),
            self.evaluator_delivery(),
        ))
    }

    /// The history evaluator, when it runs in this process: the engine's
    /// enrollment compaction drops its fences too.
    pub fn history_evaluation(
        &self,
    ) -> Option<Arc<sid_authn::password_operation::HistoryEvaluation>> {
        self.history_evaluation.clone()
    }

    /// The result bytes a finish records for its retries: the response, encoded.
    fn finish_result<T: prost::Message>(response: &T) -> Vec<u8> {
        response.encode_to_vec()
    }

    /// The response a recorded finish result decodes to.
    #[allow(clippy::result_large_err)]
    fn recorded_response<T: prost::Message + Default>(result: &[u8]) -> Result<T, Status> {
        T::decode(result).map_err(|e| internal("decode recorded password operation result", e))
    }

    /// The reset session `id` while it is verified and unexpired.
    async fn verified_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
    ) -> Result<sid_core::models::PasswordResetSession, Status> {
        // An unknown reset session and an expired one answer alike: either
        // way the reset starts again.
        let session = self
            .storage
            .get_reset_session(id)
            .await
            .map_err(storage_failure)?
            .filter(|s| !s.is_expired())
            .ok_or_else(|| ceremony_expired("password reset"))?;
        if session.status != sid_core::models::ResetSessionStatus::Verified {
            return Err(
                ApiError::new(ErrorReason::InvalidState, "the reset is not verified yet")
                    .with_precondition("RESET_SESSION_STATE", id.0.to_string(), "unverified")
                    .into(),
            );
        }
        Ok(session)
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    // ── OPAQUE Login ──

    #[tracing::instrument(skip_all, fields(rpc = "opaque_login_start"))]
    #[instrument(skip_all, fields(method = "opaque_login_start"))]
    async fn opaque_login_start(
        &self,
        request: Request<OpaqueLoginStartRequest>,
    ) -> Result<Response<OpaqueLoginStartResponse>, Status> {
        self.check_maintenance().await?;
        let client_ip = self.client_ip(&request)?;
        let req = request.into_inner();
        let started = self
            .sign_ins
            .password_start(&req.principal, &req.credential_request, client_ip)
            .await
            .map_err(sign_in_refusal)?;
        Ok(Response::new(OpaqueLoginStartResponse {
            credential_response: started.credential_response,
            login_id: Some(started.login_id.into()),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "opaque_login_finish"))]
    #[instrument(skip_all, fields(method = "opaque_login_finish"))]
    async fn opaque_login_finish(
        &self,
        request: Request<OpaqueLoginFinishRequest>,
    ) -> Result<Response<OpaqueLoginFinishResponse>, Status> {
        self.check_maintenance().await?;
        // Refused before the attempt is consumed.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let native = NativeProof::of(
            &request,
            client,
            self.public_origin(),
            "/sid.v1.authn.AuthService/OpaqueLoginFinish",
        )?;
        let req = request.into_inner();
        let login = sid_infra::authn::password_sign_in::login_id(req.login_id.as_ref())?;
        // The key is bound to this ceremony, checked before it is consumed.
        let native_key = self
            .native_ceremony_key(native.as_ref(), login.as_bytes())
            .await?;

        let verified = self
            .sign_ins
            .password_finish(&login, &req.credential_finalization, client_ip)
            .await
            .map_err(sign_in_refusal)?;
        let profile = verified.account;
        // Evaluate login security (anomaly detection + policy enforcement).
        let method = LoginMethod::Password;
        let admission = self
            .evaluate_first_factor(
                profile.id,
                client_ip,
                "opaque",
                (
                    method.auth_level(self.security_policy().auth.passkey_satisfies_mfa),
                    &method.amr(),
                ),
                AttemptContext {
                    captcha_pass: captcha_pass.as_deref(),
                    user_agent: user_agent.as_deref(),
                },
            )
            .await?;

        let FirstFactorSignedIn {
            signed_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        } = self
            .complete_first_factor(
                &profile,
                method,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                client,
                native_key.as_deref(),
                Some(&verified.proved_by),
                admission,
            )
            .await?;

        info!("OPAQUE login for profile {}", profile.id);

        signed_in.respond(|session_id, expires_in| OpaqueLoginFinishResponse {
            session_id: Some(session_id.into()),
            expires_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        })
    }

    /// Renew a native session with one credential of its current generation
    /// and a fresh proof by its application key, or deliver again the
    /// generation a lost response of the same exchange carried.
    #[tracing::instrument(skip_all, fields(rpc = "refresh_native_session"))]
    async fn refresh_native_session(
        &self,
        request: Request<RefreshNativeSessionRequest>,
    ) -> Result<Response<RefreshNativeSessionResponse>, Status> {
        self.check_maintenance().await?;
        // A browser renews by its cookie: it is refused here.
        let client = self.ceremony_client(request.metadata())?;
        let proof = NativeProof::of(
            &request,
            client,
            self.public_origin(),
            "/sid.v1.authn.AuthService/RefreshNativeSession",
        )?
        .ok_or_else(|| missing_field(PROOF_METADATA))?;
        let credential = super::native_session::single_value(request.metadata(), REFRESH_METADATA)?
            .ok_or_else(|| missing_field(REFRESH_METADATA))?;
        let req = request.into_inner();
        let exchange = sid_core::models::NativeExchange::from_bytes(&req.exchange)
            .ok_or_else(|| invalid_field("exchange", "must be 16 bytes"))?;
        let policy = NativePolicy::from_session_policy(&self.security_policy().session)
            .map_err(|e| internal("read the native session policy", e))?;

        let refreshed = sid_authn::native_session::refresh(
            self.storage.as_ref(),
            self.key_manager.as_ref(),
            self.oauth.dpop(),
            &self.revocation_cache,
            sid_authn::native_session::RefreshRequest {
                proof: proof.proof(),
                method: &proof.target().method,
                url: &proof.target().uri,
                credential: &credential,
                exchange,
            },
            policy,
        )
        .await
        .map_err(super::native_session::refusal)?;
        // An account that can no longer authenticate gets no access token,
        // however its session renewed.
        let profile = self
            .storage
            .get_profile(refreshed.session.profile_id)
            .await
            .map_err(storage_failure)?
            .filter(|p| p.status.can_authenticate())
            .ok_or_else(session_ended)?;
        self.sign_ins
            .native_access(&profile, &refreshed.session, Some(refreshed.set))
            .await
            .map_err(sign_in_refusal)?
            .respond(|session_id, expires_in| RefreshNativeSessionResponse {
                session_id: Some(session_id.into()),
                expires_in,
            })
    }

    // ── OPAQUE-ZKPP ──

    /// Start a registration: the operation is prepared for the new account
    /// (or as a decoy for a held identifier) and its OPAQUE request answered
    /// under the new password's own OPRF key. The proof arrives at finish.
    #[tracing::instrument(skip_all, fields(rpc = "opaque_zkpp_registration_start"))]
    #[instrument(skip_all, fields(method = "opaque_zkpp_registration_start"))]
    async fn opaque_zkpp_registration_start(
        &self,
        request: Request<OpaqueZkppRegistrationStartRequest>,
    ) -> Result<Response<OpaqueZkppRegistrationStartResponse>, Status> {
        self.check_maintenance().await?;
        let zkpp = self.require_zkpp()?;

        let req = request.into_inner();
        let (_, charged) = parse_principal(&req.principal)?;
        let pending = self
            .begin_registration(
                &req.principal,
                req.claim_token.as_deref(),
                req.invite_code.as_deref(),
            )
            .await?;
        let owner = match &pending {
            PendingRegistration::NewAccount { profile_id, .. } => OperationOwner::New(*profile_id),
            PendingRegistration::ExistingAccount { .. } => {
                OperationOwner::Decoy(ProfileId::generate())
            }
        };
        let prepared = self
            .password_ops
            .prepare(
                &zkpp,
                OperationPurpose::Registration { pending },
                owner,
                format!("registration:{charged}"),
                Some(req.registration_request),
            )
            .await
            .or_status()?;

        Ok(Response::new(OpaqueZkppRegistrationStartResponse {
            registration_response: prepared.registration_response.unwrap_or_default(),
            history: Some(prepared.context),
        }))
    }

    /// Finish a registration: verify the proof and the history over the
    /// final record, then commit the account, its first credential with the
    /// proof's evidence and its first history entry together. A held
    /// identifier's decoy operation is verified like any other and refused
    /// here, so the answer tells nothing that a real refusal would not.
    #[tracing::instrument(skip_all, fields(rpc = "opaque_zkpp_registration_finish"))]
    #[instrument(skip_all, fields(method = "opaque_zkpp_registration_finish"))]
    async fn opaque_zkpp_registration_finish(
        &self,
        request: Request<OpaqueZkppRegistrationFinishRequest>,
    ) -> Result<Response<OpaqueZkppRegistrationFinishResponse>, Status> {
        self.check_maintenance().await?;
        let zkpp = self.require_zkpp()?;

        let req = request.into_inner();
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        let done = match self
            .password_ops
            .finish(
                zkpp,
                &id,
                "registration",
                &req.registration_record,
                req.proof,
                |op| match op.purpose {
                    OperationPurpose::Registration { .. } => Ok(()),
                    _ => Err(operation_not_pending()),
                },
            )
            .await
            .or_status()?
        {
            Finish::Completed(result) => {
                return Ok(Response::new(Self::recorded_response(&result)?));
            }
            Finish::Ready(done) => *done,
        };
        let OperationPurpose::Registration { pending } = &done.operation.purpose else {
            return Err(operation_not_pending());
        };
        let pending = pending.clone();
        let profile_id = match &pending {
            PendingRegistration::NewAccount { profile_id, .. } => *profile_id,
            held @ PendingRegistration::ExistingAccount { .. } => {
                return Err(self.refuse_held(held).await);
            }
        };
        let credential = done.credential(profile_id, done.password_file.clone());
        let response = OpaqueZkppRegistrationFinishResponse {
            credential_id: credential_wire(credential.id)?,
        };
        let completion = done.completion(Self::finish_result(&response));
        self.commit_registration(
            pending,
            credential,
            self.with_history_age(done.history),
            Some(completion),
        )
        .await?;

        Ok(Response::new(response))
    }

    // ── Password Change (ZKPP) ──

    /// Prepare a change of the caller's own password: the operation with the
    /// owner's history domains, which the client evaluates and proves over.
    #[tracing::instrument(skip_all, fields(rpc = "password_change_challenge"))]
    #[instrument(skip_all, fields(method = "password_change_challenge"))]
    async fn password_change_challenge(
        &self,
        request: Request<PasswordChangeChallengeRequest>,
    ) -> Result<Response<PasswordChangeChallengeResponse>, Status> {
        self.check_maintenance().await?;

        // Auth first, feature check second
        let verified = self.caller_claims(&request).await?;
        let caller = verified.caller.profile_id;

        let zkpp = self.require_zkpp()?;
        let required = self.password_change_authority(&verified.caller).await?;

        let req = request.into_inner();
        let credential = self
            .own_password(req.credential_id.as_ref(), caller)
            .await?;
        // The challenge fixes the new password's request: the current
        // password is confirmed for it, and execute starts no other.
        if req.registration_request.is_empty() {
            return Err(missing_field("registration_request"));
        }
        let proves = !req.credential_request.is_empty();
        if required && !proves {
            return Err(
                sid_authn::credential_enrollment::EnrollmentRefusal::CurrentPasswordRequired
                    .into_status(),
            );
        }
        let guesses = current_password_guesses(caller);
        if proves {
            // As at sign-in: during a lockout the current password is not tried.
            self.refuse_if_locked(&caller.to_string()).await?;
            self.refuse_if_locked(&guesses).await?;
        }
        // The current password's sign-in starts first, under the operation it
        // confirms: a malformed one is refused before any history is
        // prepared for it, and charges nothing.
        let id = sid_ids::PasswordOperationId::generate();
        let started = if proves {
            let (stored, _) = self.stored_password(&credential).await?;
            Some(
                self.opaque_router
                    .login_start(
                        &stored,
                        &req.credential_request,
                        &credential.opaque_credential_identifier(),
                        &change_context(&id, &req.registration_request),
                    )
                    .map_err(|e| {
                        warn!("current-password sign-in start failed: {e}");
                        invalid_field("credential_request", "not an OPAQUE credential request")
                    })?,
            )
        } else {
            None
        };
        let prepared = self
            .password_ops
            .prepare_as(
                id,
                &zkpp,
                OperationPurpose::Change {
                    profile_id: caller,
                    credential_id: credential.id,
                    password: credential.opaque_credential_identifier(),
                },
                OperationOwner::Existing(caller),
                format!("profile:{caller}"),
                // Fixed now; its response is withheld until execute confirms.
                Some(req.registration_request.clone()),
            )
            .await
            .or_status()?;

        let credential_response = if let Some((response, state)) = started {
            // A wrong guess fails on the client at KE2 and need never reach
            // execute, so each KE2 is counted just before it is issued,
            // against the change's own budget: a stolen session cannot guess
            // the password through changes, and the account's sign-in budget
            // is untouched. A challenge refused earlier taught nothing.
            if !self
                .sign_ins
                .anomaly()
                .count_attempt(&guesses)
                .await
                .map_err(anomaly_unavailable)?
            {
                return Err(too_many_attempts(
                    self.sign_ins.anomaly().lockout_duration(),
                ));
            }
            self.password_ops
                .begin_current_password(&id, state, |op| own_change(op, caller, &credential))
                .await
                .or_status()?;
            response
        } else {
            Vec::new()
        };

        Ok(Response::new(PasswordChangeChallengeResponse {
            history: Some(prepared.context),
            credential_response,
        }))
    }

    /// The OPAQUE start of the new password, under the operation's own OPRF
    /// key: the request the proof is bound to.
    #[tracing::instrument(skip_all, fields(rpc = "password_change_execute"))]
    #[instrument(skip_all, fields(method = "password_change_execute"))]
    async fn password_change_execute(
        &self,
        request: Request<PasswordChangeExecuteRequest>,
    ) -> Result<Response<PasswordChangeExecuteResponse>, Status> {
        self.check_maintenance().await?;

        // Auth first, feature check second
        let verified = self.caller_claims(&request).await?;
        let client_ip = self.client_ip(&request)?;

        let zkpp = self.require_zkpp()?;
        let caller = verified.caller.profile_id;
        let required = self.password_change_authority(&verified.caller).await?;

        let req = request.into_inner();
        let credential = self
            .own_password(req.credential_id.as_ref(), caller)
            .await?;
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        if !req.credential_finalization.is_empty() {
            // As at sign-in: during a lockout a right and a wrong password
            // get the same answer.
            self.refuse_if_locked(&caller.to_string()).await?;
        }
        let check = self
            .password_ops
            .prove_current_password(
                &id,
                &req.credential_finalization,
                |op| own_change(op, caller, &credential),
                |state, finalization, context| {
                    self.opaque_router
                        .login_finish(state, finalization, context)
                        .inspect_err(|e| warn!("current-password sign-in failed: {e}"))
                        .is_ok()
                },
            )
            .await
            .or_status()?;
        match check {
            CurrentPasswordCheck::Failed => {
                // The guess was charged to the change's own budget when its
                // KE2 was issued; the account's sign-in budget stays apart.
                self.record_failed_from(client_ip).await?;
                return Err(authentication_failed());
            }
            CurrentPasswordCheck::NotBegun if required => {
                return Err(
                    sid_authn::credential_enrollment::EnrollmentRefusal::CurrentPasswordRequired
                        .into_status(),
                );
            }
            CurrentPasswordCheck::NotBegun => {}
            CurrentPasswordCheck::Proven => {
                // The budget limits guesses, not the owner: the right
                // password clears it, while abandoned and wrong guesses stay
                // charged until one is proven.
                self.sign_ins
                    .anomaly()
                    .clear_lockout(&current_password_guesses(caller))
                    .await
                    .map_err(anomaly_unavailable)?;
            }
        }
        let registration_response = self
            .password_ops
            .fixed_opaque_start(&zkpp, &id, |op| own_change(op, caller, &credential))
            .await
            .or_status()?;

        Ok(Response::new(PasswordChangeExecuteResponse {
            registration_response,
        }))
    }

    /// Finish the change: verify the proof and the history over the final
    /// record, then replace the password, its evidence and the owner's
    /// history in one write over the password that was read.
    #[tracing::instrument(skip_all, fields(rpc = "password_change_finish"))]
    #[instrument(skip_all, fields(method = "password_change_finish"))]
    async fn password_change_finish(
        &self,
        request: Request<PasswordChangeFinishRequest>,
    ) -> Result<Response<()>, Status> {
        self.check_maintenance().await?;

        // Auth first, feature check second
        let verified = self.caller_claims(&request).await?;
        let caller = verified.caller.profile_id;

        let zkpp = self.require_zkpp()?;
        // Rechecked at the commit: time may have run out since the challenge.
        let required = self.password_change_authority(&verified.caller).await?;

        let req = request.into_inner();
        let credential = self
            .own_password(req.credential_id.as_ref(), caller)
            .await?;
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        let done = match self
            .password_ops
            .finish(
                zkpp,
                &id,
                "change",
                &req.registration_record,
                req.proof,
                |op| {
                    own_change(op, caller, &credential)?;
                    if required && !op.current_password_proven() {
                        return Err(sid_authn::credential_enrollment::EnrollmentRefusal::CurrentPasswordRequired.into_status());
                    }
                    Ok(())
                },
            )
            .await
            .or_status()?
        {
            Finish::Completed(_) => return Ok(Response::new(())),
            Finish::Ready(done) => *done,
        };

        // The new password, the evidence its proof gave it, its OPRF key and
        // the history entry are one write: none is ever the old password's.
        let current = credential.data.expose().to_vec();
        let sealed = self.seal_envelope(caller, &done.password_file).await?;
        let mut new = done.credential(caller, sealed);
        new.id = credential.id;
        new.label = credential.label.clone();
        new.created_at = credential.created_at;
        let ctx = MutationContext::from(AuditEntry::user(
            caller.to_string(),
            "credential.password_change",
            credential.id.0.to_string(),
        ))
        .with_operation(done.completion(Self::finish_result(&())));

        // Applies only over the password just read, and only while it is
        // active: a revocation or another change in between is not undone.
        let history = self.with_history_age(done.history);
        let changed = self
            .storage
            .change_password(credential.id, &current, &new, history.as_ref(), ctx)
            .await
            .map_err(|e| {
                sid_authn::password_operation::commit_refusal(e, storage_failure).into_status()
            })?;
        if !changed {
            return Err(changed_concurrently());
        }

        info!("Password changed for credential {}", credential.id.0);

        Ok(Response::new(()))
    }

    /// How long, by this server's clock, the caller's session may still
    /// change its password without the current password.
    #[instrument(skip_all, fields(method = "get_password_change_requirement"))]
    async fn get_password_change_requirement(
        &self,
        request: Request<()>,
    ) -> Result<Response<prost_types::Duration>, Status> {
        self.check_maintenance().await?;
        let verified = self.caller_claims(&request).await?;
        let left = sid_authn::credential_enrollment::password_change_requirement(
            self.storage.as_ref(),
            &verified.caller,
            self.security_policy().password.change_current_password,
        )
        .await
        .or_status()?;
        // Never negative: the requirement clamps at zero.
        let left = left
            .to_std()
            .map_err(|e| internal("password change requirement", e))?;
        let left = prost_types::Duration::try_from(left)
            .map_err(|e| internal("password change requirement", e))?;
        Ok(Response::new(left))
    }

    // ── Deferred ZK Proof ──

    #[tracing::instrument(skip_all, fields(rpc = "submit_deferred_zk_proof"))]
    #[instrument(skip_all, fields(method = "submit_deferred_zk_proof"))]
    /// A stored credential never changes to policy-verified: a proof proves
    /// the registration it is bound to, so verified status comes only with a
    /// new password registration carrying its proof.
    async fn submit_deferred_zk_proof(
        &self,
        _request: Request<SubmitDeferredZkProofRequest>,
    ) -> Result<Response<SubmitDeferredZkProofResponse>, Status> {
        Err(ApiError::new(
            ErrorReason::InvalidState,
            "a policy proof is accepted only with a new password registration",
        )
        .with_precondition(
            "POLICY_PROOF",
            "credential",
            "proved only together with a new password registration",
        )
        .into())
    }

    // ── WebAuthn ──

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_registration_start"))]
    #[instrument(skip_all, fields(method = "web_authn_registration_start"))]
    async fn web_authn_registration_start(
        &self,
        request: Request<WebAuthnRegistrationStartRequest>,
    ) -> Result<Response<WebAuthnRegistrationStartResponse>, Status> {
        self.check_maintenance().await?;

        // Profile from the verified token, never a client-sent profile_id
        let caller = self.caller_claims(&request).await?.caller;
        let profile_id = caller.profile_id;
        self.require_enrollment_authority(&caller, profile_id, CredentialType::WebAuthn)
            .await?;

        let _req = request.into_inner();

        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProfileNotFound,
                    "Profile",
                    profile_id.to_string(),
                )
            })?;

        // The profile's passkeys are excluded, so one authenticator does not
        // register twice; a storage failure fails the start.
        let existing = self.active_passkeys(profile.id).await?;

        // The profile's account handle at this RP: created by its first
        // authorized enrollment and kept for every later passkey.
        let user_handle = self
            .storage
            .ensure_webauthn_user_handle(
                profile.id,
                self.webauthn.rp_id(),
                WebAuthnUserHandle(rand::random()),
                AuditEntry::user(
                    profile.id.to_string(),
                    "webauthn.user_handle",
                    profile.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        let result = self
            .webauthn
            .registration_start(
                user_handle,
                profile.username.as_deref().unwrap_or(""),
                &existing,
            )
            .await
            .map_err(|e| internal("start passkey registration", e))?;

        // Only the profile that started the ceremony may finish it.
        self.webauthn_state
            .insert(&result.state_key, &profile.id)
            .await
            .or_status()?;

        Ok(Response::new(WebAuthnRegistrationStartResponse {
            challenge: result.state_key.into_bytes(),
            options: result.options,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_registration_finish"))]
    #[instrument(skip_all, fields(method = "web_authn_registration_finish"))]
    async fn web_authn_registration_finish(
        &self,
        request: Request<WebAuthnRegistrationFinishRequest>,
    ) -> Result<Response<WebAuthnRegistrationFinishResponse>, Status> {
        self.check_maintenance().await?;

        // Profile from the verified token, never a client-sent profile_id
        let caller = self.caller_claims(&request).await?.caller;
        let profile_id = caller.profile_id;

        let req = request.into_inner();

        let credential = RegistrationResponse::parse(&req.credential)
            .map_err(|_| invalid_field("credential", "not a WebAuthn registration response"))?;

        // The ceremony is the one the response answers; it must be the
        // caller's own (another profile's pending ceremony reads as expired).
        let expired = || ceremony_expired("passkey registration");
        let state_key = credential.state_key().map_err(|_| expired())?;
        let started_by = self
            .webauthn_state
            .take(&state_key)
            .await
            .or_status()?
            .ok_or_else(expired)?;
        if started_by != profile_id {
            return Err(expired());
        }
        // The account may have changed since the start.
        self.require_enrollment_authority(&caller, profile_id, CredentialType::WebAuthn)
            .await?;

        let passkey = self
            .webauthn
            .registration_finish(&credential)
            .await
            .map_err(|e| match e {
                sid_core::Error::AuthenticationFailed(_) => {
                    warn!("WebAuthn registration finish failed: {}", e);
                    invalid_field("credential", "the passkey registration does not verify")
                }
                other => internal("finish passkey registration", other),
            })?;
        let data = passkey.data;

        let label = req.label.unwrap_or_else(|| "Passkey".to_string());
        let cred = Credential::new(profile_id, CredentialType::WebAuthn, data, Some(label));

        self.storage
            .create_credential(
                &cred,
                AuditEntry::user(
                    profile_id.to_string(),
                    "credential.save",
                    cred.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Registered passkey {} for profile {}",
            cred.id.0, profile_id
        );

        Ok(Response::new(WebAuthnRegistrationFinishResponse {
            credential_id: credential_wire(cred.id)?,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_authentication_start"))]
    #[instrument(skip_all, fields(method = "web_authn_authentication_start"))]
    async fn web_authn_authentication_start(
        &self,
        request: Request<WebAuthnAuthenticationStartRequest>,
    ) -> Result<Response<WebAuthnAuthenticationStartResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        let result = if let Some(identifier) = &req.principal {
            // Identifier-based: fetch passkeys for this user
            let profile = self.resolve_profile(identifier).await?;

            let passkeys = self.active_passkeys(profile.id).await?;

            // An account without passkeys is answered like an unknown one.
            if passkeys.is_empty() {
                return Err(authentication_failed());
            }

            let r = self
                .webauthn
                .authentication_start(AssertionPurpose::SignIn, &passkeys)
                .await
                .map_err(|e| internal("start passkey sign-in", e))?;

            // The ceremony signs in this profile only.
            self.webauthn_state
                .insert(&r.state_key, &profile.id)
                .await
                .or_status()?;
            r
        } else {
            // Conditional UI: the profile comes from the authenticator's user
            // handle at finish; the ceremony state itself is single-use.
            self.webauthn
                .discoverable_authentication_start()
                .await
                .map_err(|e| internal("start discoverable passkey sign-in", e))?
        };

        Ok(Response::new(WebAuthnAuthenticationStartResponse {
            challenge: result.state_key.into_bytes(),
            options: result.options,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_authentication_finish"))]
    #[instrument(skip_all, fields(method = "web_authn_authentication_finish"))]
    async fn web_authn_authentication_finish(
        &self,
        request: Request<WebAuthnAuthenticationFinishRequest>,
    ) -> Result<Response<WebAuthnAuthenticationFinishResponse>, Status> {
        self.check_maintenance().await?;
        // Refused before the ceremony is consumed.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let native = NativeProof::of(
            &request,
            client,
            self.public_origin(),
            "/sid.v1.authn.AuthService/WebAuthnAuthenticationFinish",
        )?;
        let req = request.into_inner();

        let not_an_assertion = || invalid_field("credential", "not a WebAuthn assertion");
        let expired = || ceremony_expired("passkey sign-in");

        let user_verified;
        let key_amr;
        let proved_by;
        // The key is bound to the ceremony the assertion answers (its
        // start's `challenge`, taken from the assertion's own challenge),
        // checked before that ceremony is consumed.
        let native_key;
        let profile = if let Some(identifier) = &req.principal {
            // ── Identifier-based flow ──
            let credential =
                AssertionResponse::parse(&req.credential).map_err(|_| not_an_assertion())?;
            let state_key = credential.state_key().map_err(|_| expired())?;
            native_key = self
                .native_ceremony_key(native.as_ref(), state_key.as_bytes())
                .await?;
            let p = self.resolve_profile(identifier).await?;

            // The ceremony the assertion answers, started for this profile.
            let started_for = self
                .webauthn_state
                .take(&state_key)
                .await
                .or_status()?
                .ok_or_else(expired)?;
            if started_for != p.id {
                return Err(expired());
            }

            let passkeys = self.active_passkeys(p.id).await?;
            let finished = self
                .webauthn
                .authentication_finish(AssertionPurpose::SignIn, &credential, &passkeys)
                .await;
            let verified = self.passkey_outcome(finished, p.id, client_ip).await?;
            user_verified = verified.user_verified;
            (key_amr, proved_by) = self.record_passkey_use(&passkeys, &verified).await?;

            p
        } else {
            // ── Conditional UI / Discoverable flow ──
            // The ceremony state is found from the assertion and consumed by
            // the finish below (single use).
            let credential = DiscoverableAssertionResponse::parse(&req.credential)
                .map_err(|_| not_an_assertion())?;
            let state_key = credential.state_key().map_err(|_| expired())?;
            native_key = self
                .native_ceremony_key(native.as_ref(), state_key.as_bytes())
                .await?;

            // The returned handle names an account only through the stored
            // association at this RP; an unknown one authenticates nobody
            // and creates nothing.
            let user_handle = credential.user_handle();
            let profile_id = self
                .storage
                .get_profile_by_webauthn_user_handle(self.webauthn.rp_id(), user_handle)
                .await
                .map_err(storage_failure)?
                .ok_or_else(authentication_failed)?;
            let p = self
                .storage
                .get_profile(profile_id)
                .await
                .map_err(storage_failure)?
                // Generic error: don't reveal profile existence
                .ok_or_else(authentication_failed)?;

            let passkeys = self.active_passkeys(p.id).await?;
            let finished = self
                .webauthn
                .discoverable_authentication_finish(&credential, user_handle, &passkeys)
                .await;
            let verified = self.passkey_outcome(finished, p.id, client_ip).await?;
            user_verified = verified.user_verified;
            (key_amr, proved_by) = self.record_passkey_use(&passkeys, &verified).await?;

            p
        };

        // Evaluate login security (anomaly detection + policy enforcement).
        let method = LoginMethod::Passkey {
            user_verified,
            key_amr,
        };
        let admission = self
            .evaluate_first_factor(
                profile.id,
                client_ip,
                "webauthn",
                (
                    method.auth_level(self.security_policy().auth.passkey_satisfies_mfa),
                    &method.amr(),
                ),
                AttemptContext {
                    captcha_pass: captcha_pass.as_deref(),
                    user_agent: user_agent.as_deref(),
                },
            )
            .await?;

        let FirstFactorSignedIn {
            signed_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        } = self
            .complete_first_factor(
                &profile,
                method,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                client,
                native_key.as_deref(),
                // The asserting passkey, as it holds after this use, fences
                // the session's commit (or the pending context's completion).
                Some(&proved_by),
                admission,
            )
            .await?;

        info!("WebAuthn login for profile {}", profile.id);

        signed_in.respond(
            |session_id, expires_in| WebAuthnAuthenticationFinishResponse {
                session_id: Some(session_id.into()),
                expires_in,
                second_factors,
                enrollable_factors,
                browser_csrf,
            },
        )
    }

    // ── OAuth2 ──

    #[instrument(skip_all, fields(method = "get_sign_in_context"))]
    async fn get_sign_in_context(
        &self,
        request: Request<GetSignInContextRequest>,
    ) -> Result<Response<SignInContext>, Status> {
        let addressed = request
            .extensions()
            .get::<sid_authn::issuer::AddressedIssuer>()
            .cloned();
        let context = self
            .sign_in_context(&request.get_ref().authorization_request, addressed.as_ref())
            .await?;
        Ok(Response::new(context))
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_authorize"))]
    #[instrument(skip_all, fields(method = "o_auth2_authorize"))]
    async fn o_auth2_authorize(
        &self,
        request: Request<OAuth2AuthorizeRequest>,
    ) -> Result<Response<OAuth2AuthorizeResponse>, Status> {
        self.check_maintenance().await?;
        let (client, issuer) = self
            .authorize_client(request.get_ref(), request.extensions().get())
            .await?;

        // The bearer token names the session; the code carries that session's
        // authentication, so it must still authorize and be fresh enough for
        // the request. A caller of this RPC is its own interface, so the
        // interaction `prompt` asks for is its to have shown.
        // Only the IdP session's own token: an application's session never
        // authorizes codes for other clients.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation().or_status()?;
        let prompt = sid_authn::oauth2::prompt::Prompt::parse(request.get_ref().prompt.as_deref())
            .map_err(authorize_refusal)?;
        let now = Utc::now();
        let session_id = SessionId::parse(&verified.claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
        // An ended session, and one authenticated too long ago for the
        // request's max_age or prompt, answer alike: sign in again.
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(storage_failure)?
            .filter(|session| session.profile_id == verified.caller.profile_id)
            .filter(|session| self.authorizes(session, now))
            .filter(|session| {
                prompt
                    .authenticated_after(request.get_ref().max_age, now)
                    .is_none_or(|after| session.authenticated_at >= after)
            })
            .ok_or_else(session_ended)?;

        let answer = self
            .authorize_with(&client, &issuer, &session, request.into_inner())
            .await?;
        Ok(Response::new(answer))
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_token"))]
    #[instrument(skip_all, fields(method = "o_auth2_token"))]
    async fn o_auth2_token(
        &self,
        request: Request<OAuth2TokenRequest>,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        self.check_maintenance().await?;
        let client_ip = self.client_ip(&request)?;
        // The request a DPoP proof must name: as received, over REST or gRPC.
        let proof_target = sid_infra::authn::resource::request_target(
            &request,
            &self.public_origin,
            OAUTH2_TOKEN_RPC,
        );
        let (metadata, _, mut req) = request.into_parts();
        // RFC 9449 §4.1, §4.3: the proof travels in exactly one `DPoP` HTTP
        // header (gRPC metadata `dpop`), never in the request body.
        let mut proofs = metadata.get_all("dpop").iter();
        req.dpop_proof = match (proofs.next(), proofs.next()) {
            (None, _) => None,
            (Some(value), None) => Some(
                value
                    .to_str()
                    .map_err(|_| dpop_refusal("header is not ASCII"))?
                    .to_owned(),
            ),
            (Some(_), Some(_)) => return Err(dpop_refusal("more than one DPoP header")),
        };

        self.oauth
            .token(&req, authorization(&metadata), client_ip, &proof_target)
            .await
            .map(Response::new)
            .map_err(oauth_refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_introspect"))]
    #[instrument(skip_all, fields(method = "o_auth2_introspect"))]
    async fn o_auth2_introspect(
        &self,
        request: Request<OAuth2IntrospectRequest>,
    ) -> Result<Response<OAuth2IntrospectResponse>, Status> {
        let client_ip = self.client_ip(&request)?;
        let (metadata, _, req) = request.into_parts();
        self.oauth
            .introspect(&req, authorization(&metadata), client_ip)
            .await
            .map(Response::new)
            .map_err(oauth_refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_revoke"))]
    #[instrument(skip_all, fields(method = "o_auth2_revoke"))]
    async fn o_auth2_revoke(
        &self,
        request: Request<OAuth2RevokeRequest>,
    ) -> Result<Response<OAuth2RevokeResponse>, Status> {
        let (metadata, _, req) = request.into_parts();
        self.oauth
            .revoke(&req, authorization(&metadata))
            .await
            .map(|()| Response::new(OAuth2RevokeResponse {}))
            .map_err(oauth_refusal)
    }

    // ── Magic Link (passwordless) ──

    #[tracing::instrument(skip_all, fields(rpc = "request_magic_link"))]
    #[instrument(skip_all, fields(method = "request_magic_link"))]
    async fn request_magic_link(
        &self,
        request: Request<RequestMagicLinkRequest>,
    ) -> Result<Response<RequestMagicLinkResponse>, Status> {
        self.check_maintenance().await?;
        let magic_link = self.require_magic_links()?;
        let req = request.into_inner();

        // Anti-enumeration: an unknown address, an account that may not use
        // magic links (anything but a Corporate Profile) and an account past
        // its request limit get the same answer; only a real request sends a
        // link.
        let unsent = || {
            Ok(Response::new(RequestMagicLinkResponse {
                magic_link_id: Some(sid_ids::MagicLinkId::generate().into()),
                expires_in: sid_core::models::MAGIC_LINK_EXPIRY_SECS as i32,
            }))
        };
        // Links go to an email address, to the account its sign-in assignment
        // routes to, under the normalized address (one request limit for
        // every spelling of it).
        let (principal_type, address) = parse_principal(&req.principal)?;
        if principal_type != PrincipalType::Email {
            return unsent();
        }
        let profile = self.resolve_profile_optional(&address).await?;
        let Some(profile) = profile.filter(|p| p.profile_type == ProfileType::Corporate) else {
            return unsent();
        };
        // The link goes to the mailbox the account bound the address with,
        // never the key or the caller's spelling of it.
        let Some(destination) = self.login_mail_destination(profile.id, &address).await? else {
            info!("magic link requested for an account with no login mailbox: no link sent");
            return unsent();
        };

        // The session and the work emailing its link commit together; the
        // token leaves this service only inside that email, never logged or
        // put into an event.
        let (result, _token) = match magic_link.request_magic_link(&address, &destination).await {
            Ok(sent) => sent,
            Err(sid_authn::magic_link::MagicLinkError::RateLimited { .. }) => {
                info!("Magic link request past the per-address limit: no link sent");
                return unsent();
            }
            // A full email queue refuses only real accounts' requests; it
            // answers as an unknown address does, so a backlog never tells the
            // caller which addresses have accounts.
            Err(sid_authn::magic_link::MagicLinkError::DeliveryBacklog(why)) => {
                warn!(%why, "magic link email queue full: no link sent");
                return unsent();
            }
            Err(
                e @ (sid_authn::magic_link::MagicLinkError::Internal(_)
                | sid_authn::magic_link::MagicLinkError::Sealed(_)),
            ) => {
                return Err(internal("request magic link", e));
            }
        };

        info!(session_id = %result.session_id, "Magic link requested");

        let magic_link_id = sid_ids::MagicLinkId::from_uuid(result.session_id)
            .map_err(|e| internal("magic link id", e))?;
        Ok(Response::new(RequestMagicLinkResponse {
            magic_link_id: Some(magic_link_id.into()),
            expires_in: result.expires_in_seconds as i32,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "verify_magic_link"))]
    #[instrument(skip_all, fields(method = "verify_magic_link"))]
    async fn verify_magic_link(
        &self,
        request: Request<VerifyMagicLinkRequest>,
    ) -> Result<Response<VerifyMagicLinkResponse>, Status> {
        self.check_maintenance().await?;
        let magic_link = self.require_magic_links()?;
        // Refused before the link is consumed.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let req = request.into_inner();

        let session_id = wire_id(req.magic_link_id.as_ref(), "magic_link_id")?.into_uuid();

        let result = magic_link
            .verify_magic_link(session_id, &req.token)
            .await
            .map_err(|e| internal("verify magic link", e))?;

        match result {
            sid_authn::magic_link::MagicLinkVerifyResult::Success { email } => {
                // The account the address's sign-in assignment routes to now,
                // not the one it routed to when the link was mailed; only a
                // Corporate Profile may sign in by link, checked at use.
                let profile = self
                    .resolve_profile_optional(&email)
                    .await?
                    .filter(|p| p.profile_type == ProfileType::Corporate)
                    .ok_or_else(authentication_failed)?;

                // Evaluate login security (anomaly detection + policy enforcement).
                // A mailed link, like a mailed code, is mailbox possession over
                // a second channel: `mca` (RFC 8176 §2).
                let policy = self
                    .evaluate_login_security(
                        profile.id,
                        client_ip,
                        "magic_link",
                        (
                            sid_core::models::session::AuthLevel::Basic,
                            &["mca".to_string()],
                        ),
                        AttemptContext {
                            captcha_pass: captcha_pass.as_deref(),
                            user_agent: user_agent.as_deref(),
                        },
                    )
                    .await?;

                let signed_in = self
                    .create_provisional_session_and_issue_tokens(
                        &profile,
                        "mca",
                        user_agent.as_deref().map(compute_device_id),
                        client_ip,
                        client,
                        policy,
                    )
                    .await?;

                info!("Magic link verified for profile {}", profile.id);

                signed_in.respond(|session_id, expires_in| VerifyMagicLinkResponse {
                    session_id: Some(session_id.into()),
                    // A provisional session lasts minutes.
                    expires_in: expires_in as i32,
                })
            }
            sid_authn::magic_link::MagicLinkVerifyResult::InvalidToken => {
                // Record IP-level failed attempt (no profile_id available for magic link failures).
                self.record_ip_attempt(client_ip).await?;
                Err(authentication_failed())
            }
            sid_authn::magic_link::MagicLinkVerifyResult::Expired => Err(ApiError::new(
                ErrorReason::TokenExpired,
                "the link has expired; request a new one",
            )
            .into()),
            sid_authn::magic_link::MagicLinkVerifyResult::AlreadyConsumed => Err(ApiError::new(
                ErrorReason::TokenInvalid,
                "the link was already used; request a new one",
            )
            .into()),
            sid_authn::magic_link::MagicLinkVerifyResult::SessionNotFound => {
                self.record_ip_attempt(client_ip).await?;
                Err(authentication_failed())
            }
        }
    }

    // ── Session Validation ──

    #[tracing::instrument(skip_all, fields(rpc = "validate_session"))]
    #[instrument(skip_all, fields(method = "validate_session"))]
    async fn validate_session(
        &self,
        request: Request<ValidateSessionRequest>,
    ) -> Result<Response<ValidateSessionResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();
        let session_id = wire_id(req.session_id.as_ref(), "session_id")?;

        match self.storage.get_session(session_id).await {
            // Someone else's session answers exactly like an unknown one.
            Ok(Some(session)) if caller.require_self_or_admin(session.profile_id).is_ok() => {
                let now = chrono::Utc::now();
                let valid = session.expires_at > now;

                // The owner and the expiry are set only for a valid session,
                // as the response contract says.
                Ok(Response::new(ValidateSessionResponse {
                    valid,
                    profile_id: valid.then(|| session.profile_id.into()),
                    scopes: vec![],
                    expires_at: valid.then(|| super::convert::to_timestamp(session.expires_at)),
                }))
            }
            Ok(_) => Ok(Response::new(ValidateSessionResponse {
                valid: false,
                profile_id: None,
                scopes: vec![],
                expires_at: None,
            })),
            Err(e) => Err(storage_failure(e)),
        }
    }

    // ── Unified Login Flow ──

    #[tracing::instrument(skip_all, fields(rpc = "resolve_principal"))]
    #[instrument(skip_all, fields(method = "resolve_principal"))]
    async fn resolve_principal(
        &self,
        request: Request<ResolvePrincipalRequest>,
    ) -> Result<Response<ResolvePrincipalResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        if req.principal.trim().is_empty() {
            return Err(missing_field("principal"));
        }

        let (principal_type, _) = parse_principal(&req.principal)?;

        // The answer reads no account: it is the same for every identifier of
        // a type, so it cannot tell whether one has an account (WebAuthn
        // Level 3 §14.6.2). Each method's own step decides, refusing an
        // unknown account like a wrong secret. Password and passkey sign-in
        // are always served (passkeys through the discoverable flow); magic
        // links only where enabled, and only to an email address.
        let mut available_methods = vec!["opaque".to_string(), "webauthn".to_string()];
        if principal_type == PrincipalType::Email && self.magic_link.is_some() {
            available_methods.push("magic_link".to_string());
        }

        Ok(Response::new(ResolvePrincipalResponse {
            available_methods,
        }))
    }

    // ── Device Authorization Grant (RFC 8628) ──

    #[tracing::instrument(skip_all, fields(rpc = "start_device_authorization"))]
    #[instrument(skip_all, fields(method = "start_device_authorization"))]
    async fn start_device_authorization(
        &self,
        request: Request<DeviceAuthorizationRequest>,
    ) -> Result<Response<DeviceAuthorizationResponse>, Status> {
        self.check_maintenance().await?;
        let (metadata, _, req) = request.into_parts();
        self.oauth
            .start_device_authorization(&req, authorization(&metadata))
            .await
            .map(Response::new)
            .map_err(oauth_refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "submit_device_user_code"))]
    #[instrument(skip_all, fields(method = "submit_device_user_code"))]
    async fn submit_device_user_code(
        &self,
        request: Request<SubmitDeviceUserCodeRequest>,
    ) -> Result<Response<SubmitDeviceUserCodeResponse>, Status> {
        self.check_maintenance().await?;

        // The user's approval grants another client access: an authorization
        // decision of the IdP session, never of an application's token.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation().or_status()?;
        let profile_id = verified.caller.profile_id;

        let req = request.into_inner();

        // An unknown user code and an expired one answer alike: the user
        // starts again on the device.
        let normalized = device_auth::normalize_user_code(&req.user_code);
        let auth = self
            .storage
            .get_device_auth_by_user_code(&normalized)
            .await
            .map_err(storage_failure)?
            .filter(|auth| !auth.is_expired())
            .ok_or_else(|| invalid_field("user_code", "not a current device code"))?;

        // An approval grants the application access as an authorization does:
        // the approving session is judged against the application's login
        // requirements now, and the decision commits only under their fence.
        // A denial grants nothing and needs no judgement.
        let mut fence = None;
        if req.approve {
            let session_id = SessionId::parse(&verified.claims.sid)
                .map_err(|e| internal("read session id of a verified token", e))?;
            let now = Utc::now();
            let session = self
                .storage
                .get_session(session_id)
                .await
                .map_err(storage_failure)?
                .filter(|session| session.profile_id == profile_id)
                .filter(|session| self.authorizes(session, now))
                .ok_or_else(session_ended)?;
            let client = self
                .storage
                .get_oauth2_client(&auth.client_id)
                .await
                .map_err(storage_failure)?
                .ok_or_else(|| invalid_field("user_code", "not a current device code"))?;
            let requirements = self
                .login_requirements(Some(&auth.client_id))
                .await?
                .with_client(&client, None);
            match requirements.decide(&session, now) {
                sid_authn::login_policy::LoginDecision::Allow { audited } => {
                    if !audited.is_empty() {
                        info!(
                            client = %auth.client_id,
                            unmet = ?audited,
                            "Login requirements unmet, device approval allowed by audit enforcement"
                        );
                    }
                }
                sid_authn::login_policy::LoginDecision::StepUp(unmet) => {
                    return Err(step_up_required(&unmet).into());
                }
            }
            fence = requirements.fence;
        }

        let decision = if req.approve {
            sid_core::models::DeviceAuthDecision::Authorize(profile_id)
        } else {
            sid_core::models::DeviceAuthDecision::Deny
        };
        let audit = sid_core::models::AuditEntry::user(
            profile_id.to_string(),
            "device_authorization.submit",
            format!(
                "user_code={}, approve={}, client_id={}",
                normalized, req.approve, auth.client_id
            ),
        );
        // Only a pending request takes a decision, once: a concurrent approval
        // and denial cannot both apply, and a resolved one is not changed.
        let mut ctx: sid_core::models::MutationContext = audit.into();
        if let Some(fence) = fence {
            ctx = ctx.fenced_by(fence);
        }
        let decided = match self
            .storage
            .decide_device_auth(auth.id, decision, ctx)
            .await
        {
            Ok(decided) => decided,
            Err(sid_core::Error::Fenced(_)) => return Err(authorize::policy_changed()),
            Err(e) => return Err(storage_failure(e)),
        };
        if !decided {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "the device authorization is already decided",
            )
            .with_precondition("DEVICE_AUTHORIZATION_STATE", "user_code", "decided")
            .into());
        }

        info!(
            "Device user code submitted: code={}, approve={}, profile={:?}",
            normalized, req.approve, profile_id
        );

        Ok(Response::new(SubmitDeviceUserCodeResponse {
            client_id: auth.client_id,
            scope: auth.scope,
            completed: true,
        }))
    }

    // ── Legacy Password Migration ──

    #[tracing::instrument(skip_all, fields(rpc = "legacy_migrate_start"))]
    #[instrument(skip_all, fields(method = "legacy_migrate_start"))]
    async fn legacy_migrate_start(
        &self,
        request: Request<LegacyMigrateStartRequest>,
    ) -> Result<Response<LegacyMigrateStartResponse>, Status> {
        self.check_maintenance().await?;
        let client_ip = self.client_ip(&request)?;
        let req = request.into_inner();
        let password = SecretBox::new(Box::new(req.password));

        // A password guess like any sign-in: refused during a lockout, and a
        // wrong one counted. An unknown principal and an account without a
        // legacy hash are answered like a wrong password, after about the
        // same work, so the answer tells nothing about the account.
        let profile = self.resolve_profile_optional(&req.principal).await?;
        let identity = profile
            .as_ref()
            .map_or_else(|| req.principal.clone(), |p| p.id.to_string());
        self.refuse_if_locked(&identity).await?;

        let legacy_cred = match &profile {
            Some(profile) => self
                .storage
                .get_credentials_by_profile(profile.id, Some(CredentialType::LegacyHash))
                .await
                .map_err(storage_failure)?
                .into_iter()
                .next(),
            None => None,
        };
        let verified = match (&profile, &legacy_cred) {
            (Some(profile), Some(legacy_cred)) => {
                // The legacy hash is stored as UTF-8 text.
                let hash_str = std::str::from_utf8(legacy_cred.data.expose()).map_err(|e| {
                    internal(
                        "read legacy hash",
                        format!("credential {}: {e}", legacy_cred.id.0),
                    )
                })?;
                BuiltinLegacyVerifier::verify(password.expose_secret().as_bytes(), hash_str)
                    .map_err(|e| internal("verify legacy hash", e))?
                    .then_some((profile, legacy_cred))
            }
            _ => {
                BuiltinLegacyVerifier::verify_decoy(password.expose_secret().as_bytes());
                None
            }
        };
        let Some((profile, legacy_cred)) = verified else {
            self.record_failed_login(&identity, client_ip).await?;
            return Err(authentication_failed());
        };

        // Password verified — proceed with OPAQUE registration start under
        // the new password's own OPRF credential identifier.
        let credential_identifier: [u8; 16] = rand::random();
        let (response_bytes, _state) = self
            .opaque_router
            .registration_start(&req.opaque_registration_request, &credential_identifier)
            .map_err(|e| {
                warn!("OPAQUE registration start failed during migration: {}", e);
                invalid_field(
                    "opaque_registration_request",
                    "not a valid OPAQUE registration request",
                )
            })?;

        // Store migration state
        let upgrade = sid_ids::ImportedPasswordUpgradeId::generate();
        self.migration_state
            .insert(
                &upgrade.to_string(),
                &MigrationState {
                    profile_id: profile.id,
                    credential_identifier,
                },
            )
            .await
            .or_status()?;

        info!(
            "Legacy migration started for profile {} (algorithm: {})",
            profile.id,
            legacy_cred.legacy_algorithm.as_deref().unwrap_or("unknown")
        );

        Ok(Response::new(LegacyMigrateStartResponse {
            upgrade_id: Some(upgrade.into()),
            opaque_registration_response: response_bytes,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "legacy_migrate_finish"))]
    #[instrument(skip_all, fields(method = "legacy_migrate_finish"))]
    async fn legacy_migrate_finish(
        &self,
        request: Request<LegacyMigrateFinishRequest>,
    ) -> Result<Response<LegacyMigrateFinishResponse>, Status> {
        self.check_maintenance().await?;
        // Refused before the migration is consumed.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let req = request.into_inner();

        // Retrieve migration state
        let upgrade = wire_id(req.upgrade_id.as_ref(), "upgrade_id")?;
        let migration = self
            .migration_state
            .take(&upgrade.to_string())
            .await
            .or_status()?
            .ok_or_else(|| ceremony_expired("password migration"))?;

        // Complete OPAQUE registration
        let stored = self
            .opaque_router
            .registration_finish(&req.opaque_registration_record)
            .map_err(|e| {
                warn!("OPAQUE registration finish failed during migration: {}", e);
                invalid_field(
                    "opaque_registration_record",
                    "not a valid OPAQUE registration record",
                )
            })?;

        // Create new OPAQUE credential
        let mut new_credential = Credential::new(
            migration.profile_id,
            CredentialType::Opaque,
            self.seal_envelope(migration.profile_id, &stored.data)
                .await?,
            None,
        );
        new_credential.opaque_curve = Some(stored.curve as u8);
        new_credential.opaque_credential_identifier = Some(migration.credential_identifier);

        // The OPAQUE credential replaces the legacy hash in one transaction.
        self.storage
            .replace_credential(
                &new_credential,
                AuditEntry::user(
                    migration.profile_id.to_string(),
                    "credential.migrated",
                    new_credential.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        // A profile deleted meanwhile signs nobody in.
        let mut profile = self
            .storage
            .get_profile(migration.profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(authentication_failed)?;

        // Mark migration as completed
        if profile.migration_pending {
            profile.migration_pending = false;
            profile.migration_completed_at = Some(chrono::Utc::now());
            // A profile changed meanwhile keeps the flag; the next sign-in
            // clears it. The migrated credential is already stored.
            match self
                .storage
                .update_profile(
                    &profile,
                    AuditEntry::user(
                        migration.profile_id.to_string(),
                        "profile.migration_completed",
                        migration.profile_id.to_string(),
                    )
                    .into(),
                )
                .await
            {
                Ok(true) => profile.revision += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(profile_id = %profile.id, error = %e, "Failed to clear migration flag")
                }
            }
        }

        // Evaluate login security (anomaly detection + policy enforcement).
        let method = LoginMethod::Password;
        let admission = self
            .evaluate_first_factor(
                profile.id,
                client_ip,
                "opaque",
                (
                    method.auth_level(self.security_policy().auth.passkey_satisfies_mfa),
                    &method.amr(),
                ),
                AttemptContext {
                    captcha_pass: captcha_pass.as_deref(),
                    user_agent: user_agent.as_deref(),
                },
            )
            .await?;

        let FirstFactorSignedIn {
            signed_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        } = self
            .complete_first_factor(
                &profile,
                method,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                client,
                None,
                Some(&sid_core::models::CredentialFence {
                    id: new_credential.id,
                    data: new_credential.data.clone(),
                }),
                admission,
            )
            .await?;

        info!(
            "Legacy migration completed for profile {}",
            migration.profile_id
        );

        signed_in.respond(|session_id, expires_in| LegacyMigrateFinishResponse {
            session_id: Some(session_id.into()),
            expires_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        })
    }

    #[instrument(skip_all, fields(method = "get_zkpp_policy"))]
    async fn get_zkpp_policy(
        &self,
        _request: Request<GetZkppPolicyRequest>,
    ) -> Result<Response<GetZkppPolicyResponse>, Status> {
        self.check_maintenance().await?;

        let zkpp = self.require_zkpp()?;
        let config = zkpp.config();
        let policy = sid_pake_core::types::CE_DEFAULT_POLICY;

        Ok(Response::new(GetZkppPolicyResponse {
            policy_version: config.policy_version,
            min_length: policy.min_length,
            min_uppercase: policy.min_upper,
            min_lowercase: policy.min_lower,
            min_digit: policy.min_digit,
            min_symbol: policy.min_symbol,
        }))
    }

    // ── MFA: TOTP ──

    async fn start_totp_enrollment(
        &self,
        request: Request<StartTotpEnrollmentRequest>,
    ) -> Result<Response<TotpEnrollmentChallenge>, Status> {
        self.check_maintenance().await?;
        let enroller = self.enroller(&request).await?;
        let profile_id = enroller.profile_id();
        self.require_totp_enrollment_authority(&enroller).await?;

        // Check if user already has an active TOTP credential.
        let existing = self
            .storage
            .get_credentials_by_profile(profile_id, Some(CredentialType::Totp))
            .await
            .map_err(storage_failure)?;
        if existing.iter().any(|c| c.status.is_active()) {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "a TOTP authenticator is already enrolled",
            )
            .with_precondition("MFA_ENROLLMENT", "TOTP", "already enrolled")
            .into());
        }

        // Generate TOTP secret and build enrollment challenge.
        let secret = sid_authn::generate_secret();
        // Resolve account name for the otpauth URI (email or username).
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProfileNotFound,
                    "Profile",
                    profile_id.to_string(),
                )
            })?;
        let primary_email = self
            .storage
            .get_primary_profile_email(profile.id)
            .await
            .map_err(storage_failure)?;
        let account_name_owned = primary_email
            .as_ref()
            .map(|e| e.email.clone())
            .or_else(|| profile.username.clone())
            .unwrap_or_else(|| profile.id.to_string());
        // The caller's own pending enrollment (5 min TTL): both steps are
        // authenticated as this profile, and a new start replaces the old.
        let enrollment_key = format!("totp:{}", profile_id);
        self.totp_enrollment
            .insert(&enrollment_key, &(profile_id, secret.clone()))
            .await
            .or_status()?;

        // The secret and the parameters the codes are checked with; the
        // client presents them (Base32, otpauth URI, QR).
        Ok(Response::new(TotpEnrollmentChallenge {
            issuer: "StructuredID".to_string(),
            account_name: account_name_owned,
            shared_secret: secret,
            algorithm: TotpAlgorithm::Sha1.into(),
            digits: sid_authn::TOTP_DIGITS,
            period_seconds: u32::try_from(sid_authn::TOTP_PERIOD)
                .expect("the TOTP period is a few seconds"),
        }))
    }

    async fn finish_totp_enrollment(
        &self,
        request: Request<FinishTotpEnrollmentRequest>,
    ) -> Result<Response<FinishTotpEnrollmentResponse>, Status> {
        self.check_maintenance().await?;
        let enroller = self.enroller(&request).await?;
        let profile_id = enroller.profile_id();

        let req = request.into_inner();
        require_totp_code_format(&req.code)?;

        // The caller's own pending enrollment (keyed by profile id); another
        // profile's never matches, and reads as expired.
        let enrollment_key = format!("totp:{}", profile_id);
        let secret = self
            .totp_enrollment
            .take(&enrollment_key)
            .await
            .or_status()?
            .filter(|(enrolled_pid, _)| *enrolled_pid == profile_id)
            .map(|(_, secret)| secret)
            .ok_or_else(|| ceremony_expired("TOTP enrollment"))?;
        // The account may have changed since the start.
        self.require_totp_enrollment_authority(&enroller).await?;

        // Verify the TOTP code to confirm the user set up their authenticator
        // correctly; the code is spent, like any accepted one.
        self.accept_totp(profile_id, &secret, &req.code).await?;

        // Store the seed only sealed under the key manager, bound to this profile.
        let sealed = sid_authn::sealed_secret::seal(
            self.key_manager.as_ref(),
            &sid_authn::sealed_secret::totp_context(profile_id),
            &secret,
        )
        .await
        .map_err(|e| internal("seal TOTP seed", e))?;
        let credential = Credential::new(
            profile_id,
            CredentialType::Totp,
            CredentialData::new(sealed),
            Some("TOTP Authenticator".to_string()),
        );
        let credential_id = credential.id;

        // Whether this is the first MFA factor: it then gets recovery codes.
        let existing_mfa = self
            .storage
            .get_credentials_by_profile(profile_id, None)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .filter(|c| {
                matches!(
                    c.credential_type,
                    CredentialType::Totp | CredentialType::WebAuthn
                ) && c.status.is_active()
                    && c.id != credential_id
            })
            .count();

        let enrolled = Event::new(&self.issuer, event_types::MFA_ENROLLED)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({
                "method": "totp",
                "credential_id": credential_id.0.to_string(),
                "first_mfa": existing_mfa == 0,
            }));
        // The first MFA factor comes with recovery codes, stored with it: a
        // factor without its codes could not be enrolled again to get them.
        let (recovery_codes, recovery_set) = if existing_mfa == 0 {
            let (plaintext, hashes) = sid_authn::generate_recovery_codes();
            let recovery_data =
                serde_json::to_vec(&hashes).map_err(|e| internal("encode recovery codes", e))?;
            let set = Credential::new(
                profile_id,
                CredentialType::Recovery,
                CredentialData::new(recovery_data),
                Some("Recovery Codes".to_string()),
            );
            (plaintext, Some(set))
        } else {
            (vec![], None)
        };
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "credential.totp_enrolled",
            credential_id.0.to_string(),
        ))
        .with_work(enrolled.relay());
        self.storage
            .enroll_credential(&credential, recovery_set.as_ref(), ctx)
            .await
            .map_err(storage_failure)?;

        info!("TOTP enrolled for profile {}", profile_id);

        Ok(Response::new(FinishTotpEnrollmentResponse {
            credential_id: credential_wire(credential_id)?,
            recovery_codes,
        }))
    }

    async fn verify_totp(
        &self,
        request: Request<VerifyTotpRequest>,
    ) -> Result<Response<MfaVerifyResponse>, Status> {
        self.check_maintenance().await?;
        // Step-up elevates the IdP session and answers with its new token: an
        // application's token never turns into one. A sign-in's pending
        // context is completed into its session instead.
        let caller = self.factor_caller(&request).await?;
        let profile_id = match &caller {
            FactorCaller::Pending(session, _) | FactorCaller::StepUp(session) => session.profile_id,
        };
        let client_ip = self.client_ip(&request)?;
        // A native completion asking for a renewable session binds its key
        // to the pending context it presents; a step-up renews nothing.
        let native = match &caller {
            FactorCaller::Pending(_, client) => NativeProof::of(
                &request,
                *client,
                self.public_origin(),
                "/sid.v1.authn.AuthService/VerifyTotp",
            )?,
            FactorCaller::StepUp(_) => {
                if request.metadata().get(PROOF_METADATA).is_some() {
                    return Err(super::native_session::field_refused(
                        PROOF_METADATA,
                        "a step-up renews no session",
                    ));
                }
                None
            }
        };
        let native_key = match &native {
            Some(_) => {
                let pending = sid_infra::authn::caller::bearer_token(&request)?.to_owned();
                self.native_ceremony_key(native.as_ref(), pending.as_bytes())
                    .await?
            }
            None => None,
        };

        let req = request.into_inner();
        require_totp_code_format(&req.code)?;

        // A code guess spends the account's sign-in budget, shared by every
        // context and replica: once it is spent, no code is checked.
        let identity = profile_id.to_string();
        self.refuse_if_locked(&identity).await?;

        // The active TOTP credential only; a revoked one never verifies.
        let (totp_cred, secret) = self
            .active_totp_seed(profile_id)
            .await?
            .ok_or_else(|| mfa_not_enrolled("TOTP authenticator"))?;
        if let Err(refused) = self.accept_totp(profile_id, &secret, &req.code).await {
            self.record_failed_login(&identity, client_ip).await?;
            return Err(refused);
        }

        // The use is recorded only on a credential still active: one revoked
        // since it was read neither verifies nor comes back.
        let used = self
            .storage
            .mark_credential_used(
                totp_cred.id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "credential.mfa_verified",
                    totp_cred.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !used {
            return Err(authentication_failed());
        }

        let session_id = match caller {
            FactorCaller::Pending(pending, client) => {
                let signed_in = self
                    .complete_pending_sign_in(pending, "otp", client, native_key.as_deref())
                    .await?;
                info!("TOTP completed the sign-in of profile {}", profile_id);
                return signed_in.respond(|session_id, expires_in| MfaVerifyResponse {
                    verified: true,
                    session_id: Some(session_id.into()),
                    expires_in: Some(expires_in),
                    redirect_to: None,
                    remaining_codes: None,
                });
            }
            FactorCaller::StepUp(session) => session.id,
        };

        // Elevate the session; a token must not claim an elevation that was not stored.
        let session = self
            .authenticate_session(
                session_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "session.step_up",
                    session_id.to_string(),
                )
                .into(),
                |active| {
                    active.elevate(sid_core::models::session::AuthLevel::Standard);
                    active.add_amr("otp");
                },
            )
            .await?;

        // Issue new token with elevated claims.
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(session_ended)?;

        let sub = profile_id.to_string();
        let roles = sid_authn::account_roles::account_roles(self.storage.as_ref(), &profile)
            .await
            .map_err(storage_failure)?;
        let access_token = self
            .jwt
            .issue_access_token(
                &sub,
                Some(&sub),
                &roles,
                &session,
                &session.scopes,
                None,
                None,
            )
            .map_err(|e| internal("issue access token", e))?;

        info!("TOTP step-up verified for profile {}", profile_id);

        // The caller presented the session's token, so the elevated one goes
        // back the same way, whoever it is (a native client or a BFF).
        SignedIn {
            session_id,
            expires_in: self.jwt.access_token_ttl_secs(),
            delivery: Delivery::bearer(access_token.into()),
        }
        .respond(|session_id, expires_in| MfaVerifyResponse {
            verified: true,
            session_id: Some(session_id.into()),
            expires_in: Some(expires_in),
            redirect_to: None,
            remaining_codes: None,
        })
    }

    // ── MFA: SMS ──

    async fn verify_sms_mfa(
        &self,
        _request: Request<VerifySmsMfaRequest>,
    ) -> Result<Response<MfaVerifyResponse>, Status> {
        Err(not_in_this_build("sms_mfa"))
    }

    async fn resend_sms_mfa(
        &self,
        _request: Request<ResendSmsMfaRequest>,
    ) -> Result<Response<ResendSmsMfaResponse>, Status> {
        Err(not_in_this_build("sms_mfa"))
    }

    // ── MFA: Recovery codes ──

    async fn generate_recovery_codes(
        &self,
        request: Request<GenerateRecoveryCodesRequest>,
    ) -> Result<Response<GenerateRecoveryCodesResponse>, Status> {
        self.check_maintenance().await?;
        let caller = self.caller_claims(&request).await?.caller;
        let profile_id = caller.profile_id;
        // New codes step up to Standard, so issuing them is an enrollment.
        self.require_enrollment_authority(&caller, profile_id, CredentialType::Recovery)
            .await?;
        let context = context(&request)?;
        let command = sid_authn::operation::KeyedCommand::by_profile::<
            sid_proto::keyed::authn::auth_service::GenerateRecoveryCodes,
        >(profile_id, context, request.get_ref());
        // SID keeps only the codes' hashes: a retry of a completed generation
        // names the set it issued and issues no other, so the codes already
        // delivered stay valid until a new command replaces them.
        if let Some(recorded) = command.completed(&*self.storage).await.or_status()? {
            return Err(recovery_codes_issued(&recorded));
        }

        // Generate new recovery codes.
        let (plaintext, hashes) = sid_authn::generate_recovery_codes();
        let recovery_data =
            serde_json::to_vec(&hashes).map_err(|e| internal("encode recovery codes", e))?;

        // The new set takes the old one's place in one transaction: old codes
        // never keep working beside the new ones, and a failure leaves the
        // old set usable rather than none.
        let credential = Credential::new(
            profile_id,
            CredentialType::Recovery,
            CredentialData::new(recovery_data),
            Some("Recovery Codes".to_string()),
        );
        let generated = Event::new(&self.issuer, event_types::MFA_ENROLLED)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({
                "method": "recovery",
                "credential_id": credential.id.0.to_string(),
                "regenerated": true,
            }));
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "credential.recovery_codes_generated",
            credential.id.0.to_string(),
        ))
        .with_work(generated.relay())
        .with_operation(command.completion(credential.id.0.as_bytes().to_vec()));
        match self.storage.replace_credential(&credential, ctx).await {
            Ok(_) => {}
            // Another attempt of this command committed first: its set is
            // the issued one.
            Err(sid_core::Error::OperationCompleted(_)) => {
                return Err(recovery_codes_issued(
                    &command
                        .committed_elsewhere(&*self.storage)
                        .await
                        .or_status()?,
                ));
            }
            Err(e) => return Err(storage_failure(e)),
        }

        info!(
            "Recovery codes generated for profile {} ({} codes)",
            profile_id,
            plaintext.len()
        );

        Ok(Response::new(GenerateRecoveryCodesResponse {
            codes: plaintext,
        }))
    }

    async fn verify_recovery_code(
        &self,
        request: Request<VerifyRecoveryCodeRequest>,
    ) -> Result<Response<MfaVerifyResponse>, Status> {
        self.check_maintenance().await?;
        // A second factor authenticates the IdP session, never an
        // application's session.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation().or_status()?;
        let claims = verified.claims;
        let profile_id = verified.caller.profile_id;

        let req = request.into_inner();
        if req.code.is_empty() {
            return Err(missing_field("code"));
        }

        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
        let remaining = i32::try_from(self.consume_recovery_code(profile_id, &req.code).await?)
            .map_err(|e| internal("count remaining recovery codes", e))?;

        // Record the method on the session (recovery codes grant Basic, fallback only).
        self.authenticate_session(
            session_id,
            AuditEntry::user(
                profile_id.to_string(),
                "session.recovery_code_used",
                session_id.to_string(),
            )
            .into(),
            |active| active.add_amr("mca"), // multi-code authenticator
        )
        .await?;

        info!(
            "Recovery code used for profile {} ({} remaining)",
            profile_id, remaining
        );

        Ok(Response::new(MfaVerifyResponse {
            verified: true,
            session_id: Some(session_id.into()),
            // Recovery doesn't elevate: no new token is delivered.
            expires_in: None,
            redirect_to: None,
            remaining_codes: Some(remaining),
        }))
    }

    // ── OTP ──

    #[instrument(skip_all, fields(method = "request_otp"))]
    async fn request_otp(
        &self,
        request: Request<RequestOtpRequest>,
    ) -> Result<Response<RequestOtpResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        let handle = parse_handle(&req.principal)?;
        let Some(email) = handle.email.as_ref() else {
            return Err(invalid_field(
                "principal",
                "a code is sent to an email address",
            ));
        };
        let normalized = &handle.normalized;
        // The caller sees the address as they typed it; the key only limits
        // requests across every spelling.
        let masked =
            sid_plugin::otp::mask_target(&email.delivery, sid_plugin::otp::OtpChannel::Email);

        // Every address gets a real pending code, whether or not it routes to
        // an account, and resend and verify answer alike, so no answer tells
        // whether the account exists. Only an account's code is emailed, to
        // the mailbox its assignment was bound with, fixed now: neither the
        // resolution key nor a caller's equivalent spelling (another mailbox
        // where the key folds dots or tags) ever receives it. The code leaves
        // this service only inside that email; it is never logged or put
        // into an event.
        let destination = match self.resolve_profile_optional(normalized).await? {
            Some(account) => self.login_mail_destination(account.id, normalized).await?,
            None => None,
        };
        if destination.is_none() {
            tracing::debug!("email code requested for an address with no login mailbox: no mail");
        }
        let destination = match destination.as_deref() {
            Some(mailbox) => sid_authn::otp::CodeDestination::Email(mailbox),
            None => sid_authn::otp::CodeDestination::None,
        };
        let (result, _code) = self
            .otp
            .request_otp(normalized, destination)
            .await
            .map_err(otp_refusal)?;

        info!(session_id = %result.session_id, "OTP code requested");

        let otp_session_id = sid_ids::OtpSessionId::from_uuid(result.session_id)
            .map_err(|e| internal("email code session id", e))?;
        Ok(Response::new(RequestOtpResponse {
            otp_session_id: Some(otp_session_id.into()),
            masked_target: masked,
            expires_in_seconds: result.expires_in_seconds,
            code_length: result.code_length,
        }))
    }

    #[instrument(skip_all, fields(method = "verify_otp"))]
    async fn verify_otp(
        &self,
        request: Request<VerifyOtpRequest>,
    ) -> Result<Response<VerifyOtpResponse>, Status> {
        self.check_maintenance().await?;
        // Refused before the code is spent.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let req = request.into_inner();

        let session_id = wire_id(req.otp_session_id.as_ref(), "otp_session_id")?.into_uuid();

        let result = self
            .otp
            .verify_otp(&session_id, &req.code)
            .await
            .map_err(|e| internal("verify email code", e))?;

        match result {
            sid_authn::otp::OtpVerifyResult::Success { target } => {
                // The account the address routes to; an address that routes
                // nowhere answers like a wrong code.
                let Some(profile) = self.resolve_profile_optional(&target).await? else {
                    return Ok(Response::new(VerifyOtpResponse::default()));
                };

                // Evaluate login security (anomaly detection + policy enforcement).
                // An emailed code confirms the address over a second channel:
                // `mca` (RFC 8176 §2), not `otp`, which names a code generator.
                let policy = self
                    .evaluate_login_security(
                        profile.id,
                        client_ip,
                        "otp",
                        (
                            sid_core::models::session::AuthLevel::Basic,
                            &["mca".to_string()],
                        ),
                        AttemptContext {
                            captcha_pass: captcha_pass.as_deref(),
                            user_agent: user_agent.as_deref(),
                        },
                    )
                    .await?;

                let signed_in = self
                    .create_provisional_session_and_issue_tokens(
                        &profile,
                        "mca",
                        user_agent.as_deref().map(compute_device_id),
                        client_ip,
                        client,
                        policy,
                    )
                    .await?;

                info!("OTP verified for profile {}", profile.id);

                signed_in.respond(|session_id, expires_in| VerifyOtpResponse {
                    verified: true,
                    redirect_to: None,
                    session_id: Some(session_id.into()),
                    expires_in: Some(expires_in),
                })
            }
            sid_authn::otp::OtpVerifyResult::InvalidCode { remaining_attempts } => {
                self.record_ip_attempt(client_ip).await?;
                warn!(
                    session_id = %session_id,
                    remaining_attempts = remaining_attempts,
                    "OTP verification failed: invalid code"
                );
                Ok(Response::new(VerifyOtpResponse::default()))
            }
            sid_authn::otp::OtpVerifyResult::Expired => Err(ApiError::new(
                ErrorReason::TokenExpired,
                "the code has expired; request a new one",
            )
            .into()),
            sid_authn::otp::OtpVerifyResult::MaxAttempts => {
                self.record_ip_attempt(client_ip).await?;
                Err(ApiError::new(
                    ErrorReason::QuotaExceeded,
                    "too many wrong codes; request a new one",
                )
                .with_quota_violation("email_code_attempts", "attempts per code")
                .into())
            }
            sid_authn::otp::OtpVerifyResult::SessionNotFound => {
                self.record_ip_attempt(client_ip).await?;
                Err(ceremony_expired("email code"))
            }
        }
    }

    #[instrument(skip_all, fields(method = "resend_otp"))]
    async fn resend_otp(
        &self,
        request: Request<ResendOtpRequest>,
    ) -> Result<Response<ResendOtpResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        let session_id = wire_id(req.otp_session_id.as_ref(), "otp_session_id")?.into_uuid();

        // A new code in the same session, the one the client verifies
        // against, sent to the mailbox bound at the request.
        let (result, _code) = self
            .otp
            .resend_otp(&session_id)
            .await
            .map_err(otp_refusal)?
            .ok_or_else(|| ceremony_expired("email code"))?;

        info!(session_id = %result.session_id, "OTP code resent");

        Ok(Response::new(ResendOtpResponse {
            expires_in: result.expires_in_seconds as i32,
        }))
    }

    // ── Email/Phone verification ──

    async fn resend_email_verification(
        &self,
        _request: Request<ResendEmailVerificationRequest>,
    ) -> Result<Response<ResendEmailVerificationResponse>, Status> {
        Err(not_in_this_build("email_verification"))
    }

    async fn verify_phone(
        &self,
        _request: Request<VerifyPhoneRequest>,
    ) -> Result<Response<VerifyPhoneResponse>, Status> {
        Err(not_in_this_build("phone_verification"))
    }

    async fn resend_phone_verification(
        &self,
        _request: Request<ResendPhoneVerificationRequest>,
    ) -> Result<Response<ResendPhoneVerificationResponse>, Status> {
        Err(not_in_this_build("phone_verification"))
    }

    // ── IdP linking ──

    async fn confirm_idp_link(
        &self,
        _request: Request<ConfirmIdpLinkRequest>,
    ) -> Result<Response<ConfirmIdpLinkResponse>, Status> {
        Err(not_in_this_build("idp_linking"))
    }

    // ── Organization selection ──

    async fn list_user_organizations(
        &self,
        _request: Request<ListUserOrganizationsRequest>,
    ) -> Result<Response<ListUserOrganizationsResponse>, Status> {
        Err(not_in_this_build("organization_selection"))
    }

    async fn select_organization(
        &self,
        _request: Request<SelectOrganizationRequest>,
    ) -> Result<Response<SelectOrganizationResponse>, Status> {
        Err(not_in_this_build("organization_selection"))
    }

    // ── Terms of service ──

    async fn get_terms(
        &self,
        _request: Request<GetTermsRequest>,
    ) -> Result<Response<GetTermsResponse>, Status> {
        Err(not_in_this_build("terms_acceptance"))
    }

    async fn accept_terms(
        &self,
        _request: Request<AcceptTermsRequest>,
    ) -> Result<Response<AcceptTermsResponse>, Status> {
        Err(not_in_this_build("terms_acceptance"))
    }

    // ── CIBA ──

    async fn approve_ciba(
        &self,
        _request: Request<ApproveCibaRequest>,
    ) -> Result<Response<CibaConsentResponse>, Status> {
        Err(not_in_this_build("ciba"))
    }

    async fn deny_ciba(
        &self,
        _request: Request<DenyCibaRequest>,
    ) -> Result<Response<CibaConsentResponse>, Status> {
        Err(not_in_this_build("ciba"))
    }

    // ── Captcha ──

    async fn verify_captcha(
        &self,
        request: Request<VerifyCaptchaRequest>,
    ) -> Result<Response<VerifyCaptchaResponse>, Status> {
        let remote_ip = self.client_ip(&request)?;
        let req = request.into_inner();

        // The provider's own error text stays in the log.
        let rejected = || invalid_field("token", "the CAPTCHA solution was not accepted");
        let result = self
            .sign_ins
            .captcha_provider()
            .verify(&req.challenge_id, &req.token, remote_ip.as_ref())
            .await
            .map_err(|e| match e {
                sid_authn::captcha::CaptchaError::Expired => ceremony_expired("CAPTCHA"),
                sid_authn::captcha::CaptchaError::ProviderError(e) => {
                    dependency_unavailable("CAPTCHA provider", e)
                }
                sid_authn::captcha::CaptchaError::NotConfigured => {
                    internal("verify CAPTCHA", "provider not configured")
                }
                e => {
                    warn!(error = %e, "CAPTCHA solution rejected");
                    rejected()
                }
            })?;

        if !result.success {
            return Err(rejected());
        }

        // The solution counts once, and only for a challenge a sign-in was
        // asked; the pass answers that sign-in's retry.
        let bypass_token = self
            .sign_ins
            .captcha_gate()
            .solved(&req.challenge_id)
            .await
            .map_err(anomaly_unavailable)?
            .ok_or_else(|| ceremony_expired("CAPTCHA"))?;

        Ok(Response::new(VerifyCaptchaResponse {
            verified: true,
            redirect_to: None,
            bypass_token,
        }))
    }

    // ── Dynamic prompts ──

    async fn get_dynamic_prompt(
        &self,
        _request: Request<GetDynamicPromptRequest>,
    ) -> Result<Response<DynamicPrompt>, Status> {
        Err(not_in_this_build("dynamic_prompts"))
    }

    async fn submit_dynamic_prompt(
        &self,
        _request: Request<SubmitDynamicPromptRequest>,
    ) -> Result<Response<SubmitDynamicPromptResponse>, Status> {
        Err(not_in_this_build("dynamic_prompts"))
    }

    // ── Generic step-up (D006: Pattern D — 2-phase) ──

    async fn request_step_up(
        &self,
        request: Request<RequestStepUpRequest>,
    ) -> Result<Response<StepUpChallenge>, Status> {
        self.check_maintenance().await?;
        // Step-up elevates the IdP session, never an application's session.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation().or_status()?;
        verified.caller.require_interactive().or_status()?;
        let claims = verified.claims;
        let req_inner = request.into_inner();

        let method = StepUpMethod::try_from(req_inner.method).unwrap_or(StepUpMethod::Unspecified);

        // ── Session decay + method filtering ──
        // Step-up always works on the caller's own session, the token's.
        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(session_ended)?;

        let decay = session.decay_level();

        // Low decay (12h+) → full re-auth required, no step-up possible.
        // The token itself still works for other calls, so this is a state of
        // the session, not a failed authentication.
        if decay > sid_core::models::session::SessionDecayLevel::Medium {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "the session is too old for a step-up: full re-authentication required",
            )
            .with_precondition("SESSION_DECAY", "low", "sign in again")
            .into());
        }

        // Determine which methods are available at current decay level.
        // Only credentials that may still authenticate offer a method.
        let enrolled_creds: Vec<Credential> = self
            .storage
            .get_credentials_by_profile(session.profile_id, None)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect();

        let has_totp = enrolled_creds
            .iter()
            .any(|c| c.credential_type == CredentialType::Totp);
        let has_webauthn = enrolled_creds
            .iter()
            .any(|c| c.credential_type == CredentialType::WebAuthn);
        let has_recovery = enrolled_creds
            .iter()
            .any(|c| c.credential_type == CredentialType::Recovery);

        // Medium decay (4-12h) → phishing-resistant only (WebAuthn).
        // Full/High (0-4h) → all enrolled methods.
        let phishing_resistant_only = decay >= sid_core::models::session::SessionDecayLevel::Medium;

        let mut allowed = Vec::new();
        if has_webauthn {
            allowed.push(StepUpMethod::Webauthn as i32);
        }
        if !phishing_resistant_only {
            if has_totp {
                allowed.push(StepUpMethod::Totp as i32);
            }
            if has_recovery {
                allowed.push(StepUpMethod::RecoveryCode as i32);
            }
        }

        let decay_str = match decay {
            sid_core::models::session::SessionDecayLevel::Full => "full",
            sid_core::models::session::SessionDecayLevel::High => "high",
            sid_core::models::session::SessionDecayLevel::Medium => "medium",
            sid_core::models::session::SessionDecayLevel::Low => "low",
        };

        match method {
            StepUpMethod::Unspecified => {
                // Query mode: return available methods without starting a challenge.
                // If no methods are available, step-up is impossible — fail now rather
                // than returning an empty allowed_methods list (empty success = nonsense).
                if allowed.is_empty() {
                    return Err(mfa_not_enrolled("second factor usable for a step-up"));
                }
                Ok(Response::new(StepUpChallenge {
                    method: StepUpMethod::Unspecified as i32,
                    challenge_id: None,
                    challenge: None,
                    allowed_methods: allowed,
                    decay_level: decay_str.to_string(),
                }))
            }
            StepUpMethod::Totp | StepUpMethod::RecoveryCode => {
                // Validate method is allowed at current decay level.
                if !allowed.contains(&(method as i32)) {
                    return Err(step_up_method_unavailable(method, decay_str));
                }
                // 1-phase methods: no challenge needed, client calls CompleteStepUp directly.
                Ok(Response::new(StepUpChallenge {
                    method: req_inner.method,
                    challenge_id: None,
                    challenge: None,
                    allowed_methods: allowed,
                    decay_level: decay_str.to_string(),
                }))
            }
            StepUpMethod::Webauthn => {
                // 2-phase: generate WebAuthn authentication challenge.
                let passkeys: Vec<&Credential> = enrolled_creds
                    .iter()
                    .filter(|c| c.credential_type == CredentialType::WebAuthn)
                    .collect();

                if passkeys.is_empty() {
                    return Err(mfa_not_enrolled("passkey"));
                }

                let result = self
                    .webauthn
                    .authentication_start(AssertionPurpose::StepUp, passkeys)
                    .await
                    .map_err(|e| internal("start passkey step-up", e))?;
                let options_json = result.options;

                // Store state_key keyed by session and challenge: only a completion
                // on the same session can consume it.
                let challenge_id = sid_ids::StepUpChallengeId::generate();
                self.step_up_state
                    .insert(
                        &step_up_challenge_key(&claims.sid, &challenge_id.to_string()),
                        &result.state_key,
                    )
                    .await
                    .or_status()?;

                Ok(Response::new(StepUpChallenge {
                    method: req_inner.method,
                    challenge_id: Some(challenge_id.into()),
                    challenge: Some(step_up_challenge::Challenge::WebauthnOptions(options_json)),
                    allowed_methods: allowed,
                    decay_level: decay_str.to_string(),
                }))
            }
        }
    }

    async fn complete_step_up(
        &self,
        request: Request<CompleteStepUpRequest>,
    ) -> Result<Response<CompleteStepUpResponse>, Status> {
        self.check_maintenance().await?;
        // Step-up elevates the IdP session, never an application's session.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation().or_status()?;
        let claims = verified.claims;
        let profile_id = verified.caller.profile_id;
        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;

        let req = request.into_inner();
        let method = StepUpMethod::try_from(req.method).unwrap_or(StepUpMethod::Unspecified);

        // Dispatch proof verification by method.
        let (amr_methods, target_level) = match method {
            StepUpMethod::Totp => {
                let Some(complete_step_up_request::Proof::TotpCode(code)) = req.proof else {
                    return Err(missing_field("totp_code"));
                };
                require_totp_code_format(&code)?;

                let (_, secret) = self
                    .active_totp_seed(profile_id)
                    .await?
                    .ok_or_else(|| mfa_not_enrolled("TOTP authenticator"))?;
                self.accept_totp(profile_id, &secret, &code).await?;

                (vec!["otp"], sid_core::models::session::AuthLevel::Standard)
            }

            StepUpMethod::RecoveryCode => {
                let Some(complete_step_up_request::Proof::RecoveryCode(code)) = req.proof else {
                    return Err(missing_field("recovery_code"));
                };

                // The code is spent before it counts: a code that cannot be
                // removed would stay reusable, so a failed write fails the step-up.
                self.consume_recovery_code(profile_id, &code).await?;

                (vec!["mca"], sid_core::models::session::AuthLevel::Standard)
            }

            StepUpMethod::Webauthn => {
                let Some(complete_step_up_request::Proof::WebauthnAssertion(assertion_bytes)) =
                    req.proof
                else {
                    return Err(missing_field("webauthn_assertion"));
                };

                let credential = AssertionResponse::parse(&assertion_bytes)
                    .map_err(|_| invalid_field("webauthn_assertion", "not a WebAuthn assertion"))?;

                // The step-up this session requested, and the assertion must
                // answer that step-up's own challenge.
                let expired = || ceremony_expired("passkey step-up");
                let challenge_id = wire_id(req.challenge_id.as_ref(), "challenge_id")?;
                let state_key = self
                    .step_up_state
                    .take(&step_up_challenge_key(
                        &claims.sid,
                        &challenge_id.to_string(),
                    ))
                    .await
                    .or_status()?
                    .ok_or_else(expired)?;
                if credential.state_key().ok() != Some(state_key) {
                    return Err(expired());
                }

                let passkeys = self.active_passkeys(profile_id).await?;
                let verified = self
                    .webauthn
                    .authentication_finish(AssertionPurpose::StepUp, &credential, &passkeys)
                    .await
                    .map_err(|e| match e {
                        sid_core::Error::AuthenticationFailed(why) => {
                            warn!("WebAuthn step-up verification failed: {why}");
                            authentication_failed()
                        }
                        other => internal("finish passkey step-up", other),
                    })?;
                let (key_amr, _) = self.record_passkey_use(&passkeys, &verified).await?;

                // Determine target level based on user_verified.
                // user_verified=true → Elevated (phishing-resistant, 2 NIST factors).
                // user_verified=false → Standard (possession only).
                let target = if verified.user_verified {
                    sid_core::models::session::AuthLevel::Elevated
                } else {
                    sid_core::models::session::AuthLevel::Standard
                };

                (
                    sid_authn::webauthn::passkey_amr(key_amr, verified.user_verified),
                    target,
                )
            }

            StepUpMethod::Unspecified => return Err(missing_field("method")),
        };

        // ── Shared elevation logic ──

        // The elevated token is issued only for an elevation that is stored.
        let session = self
            .authenticate_session(
                session_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "session.step_up",
                    session_id.to_string(),
                )
                .into(),
                |active| {
                    active.elevate(target_level);
                    for method in &amr_methods {
                        active.add_amr(method);
                    }
                    // The step-up is an authentication now: it is what a
                    // later sensitive operation counts as fresh.
                    active.refresh_authentication();
                },
            )
            .await?;

        // Issue rotated access token with elevated assurance.
        let acr = session.assurance_at(Utc::now()).acr_value().to_string();
        let amr = session.amr.clone();
        let new_token = self
            .jwt
            .reissue_elevated_token(&claims, &session)
            .map_err(|e| internal("reissue stepped-up token", e))?;
        // The rotated token replaces the one this call came with; that one
        // stops for its remaining lifetime.
        // Both are Unix-second timestamps of this era: the difference cannot
        // overflow; a negative one is a token already expired.
        let remaining = u64::try_from(claims.exp - Utc::now().timestamp()).unwrap_or(0);
        self.revocation_cache
            .revoke_jti(
                claims.jti.clone(),
                std::time::Duration::from_secs(remaining),
            )
            .await
            .map_err(|e| dependency_unavailable("token revocation", e))?;

        info!(
            profile = %profile_id,
            methods = ?amr_methods,
            acr = %acr,
            "Step-up completed via generic RPC"
        );

        Ok(Response::new(CompleteStepUpResponse {
            new_session_token: new_token,
            acr,
            amr,
        }))
    }

    // ── MFA credential management ──

    async fn delete_mfa_credential(
        &self,
        request: Request<DeleteMfaCredentialRequest>,
    ) -> Result<Response<DeleteMfaCredentialResponse>, Status> {
        self.check_maintenance().await?;
        let verified = self.caller_claims(&request).await?;
        let claims = verified.claims;

        // Require elevated session (step-up auth completed).
        if !claims.acr.contains("elevated") && !claims.acr.contains("critical") {
            return Err(step_up_required(&sid_authn::login_policy::Unmet {
                acr: Some(sid_core::models::session::AuthLevel::Elevated),
                ..Default::default()
            })
            .into());
        }

        let profile_id = verified.caller.profile_id;

        let context = context(&request)?;
        let req = request.into_inner();
        let credential_id = sid_core::models::CredentialId(
            wire_id(req.credential_id.as_ref(), "credential_id")?.into_uuid(),
        );

        // A retry of a completed deletion answers as it did, not as a
        // credential no longer there, and owes no second event.
        let command = sid_authn::operation::KeyedCommand::by_profile::<
            sid_proto::keyed::authn::auth_service::DeleteMfaCredential,
        >(profile_id, context, &req);
        let response = run(&command, &*self.storage, || async {
            // Load credential and verify ownership + type.
            let credentials = self
                .storage
                .get_credentials_by_profile(profile_id, None)
                .await?;
            let credential = credentials
                .iter()
                .find(|c| c.id == credential_id)
                .ok_or_else(|| credential_not_found(credential_id))?;

            // Only allow deleting MFA credentials (TOTP, WebAuthn, Recovery).
            let cred_type = match credential.credential_type {
                CredentialType::Totp => "totp",
                CredentialType::WebAuthn => "webauthn",
                CredentialType::Recovery => "recovery",
                _ => {
                    return Err(invalid_field(
                        "credential_id",
                        "not a second factor (TOTP, passkey or recovery codes)",
                    )
                    .into());
                }
            };

            let response = DeleteMfaCredentialResponse {
                deleted: true,
                credential_type: cred_type.to_string(),
            };
            let disabled = Event::new("sid-auth", event_types::MFA_DISABLED)
                .with_subject(format!("profile/{}", profile_id))
                .with_data(serde_json::json!({
                    "credential_type": cred_type,
                    "credential_id": credential_id.0.to_string(),
                }));
            let ctx = MutationContext::from(AuditEntry::user(
                profile_id.to_string(),
                "credential.mfa_deleted",
                credential_id.0.to_string(),
            ))
            .with_work(disabled.relay())
            .with_operation(command.completion(prost::Message::encode_to_vec(&response)));
            // Revoked, not deleted; a passkey that is the last way to sign
            // in stays. The event commits only with a revocation that
            // happened.
            let outcome = self.storage.revoke_credential(credential_id, ctx).await?;
            crate::grpc::identity_service::refuse_last_primary(outcome, credential_id)?;

            info!(
                profile = %profile_id,
                credential = %credential_id.0,
                r#type = cred_type,
                "MFA credential deleted (self-service)"
            );
            Ok(response)
        })
        .await?;

        Ok(Response::new(response))
    }

    // ── Account deletion ──

    async fn confirm_account_deletion(
        &self,
        _request: Request<ConfirmAccountDeletionRequest>,
    ) -> Result<Response<ConfirmAccountDeletionResponse>, Status> {
        Err(not_in_this_build("account_deletion_confirmation"))
    }

    // ── Password Reset Flow (credential replacement) ──

    // Password reset = magic link → new OPAQUE → done.

    #[tracing::instrument(skip_all, fields(rpc = "request_password_reset"))]
    async fn request_password_reset(
        &self,
        request: Request<RequestPasswordResetRequest>,
    ) -> Result<Response<RequestPasswordResetResponse>, Status> {
        // Refused alike for every address, before any lookup: without the
        // page a link opens, or a provider to mail it, a reset could never
        // reach anyone.
        let resets = self
            .password_resets
            .as_deref()
            .ok_or_else(|| not_configured("password_reset"))?;
        if self
            .storage
            .get_email_provider_config()
            .await
            .map_err(storage_failure)?
            .is_none()
        {
            return Err(not_configured("email_provider"));
        }
        let req = request.into_inner();

        // Anti-enumeration: always return success shape
        let anti_enum_response = Response::new(RequestPasswordResetResponse {
            message: "If an account exists, a reset email has been sent.".to_string(),
        });

        // A reset link goes to an email assignment's stored mailbox, so it is
        // requested by an email address, under its normalized key.
        let (principal_type, address) = parse_principal(&req.principal)?;
        if principal_type != PrincipalType::Email {
            return Ok(anti_enum_response);
        }
        // Resolve profile (silently fail for non-existent)
        let profile = self.resolve_profile_optional(&address).await?;
        let profile = match profile {
            Some(p) => p,
            None => return Ok(anti_enum_response),
        };
        // The link goes to the mailbox the account bound the address with,
        // never the key or the caller's spelling of it.
        let Some(destination) = self.login_mail_destination(profile.id, &address).await? else {
            info!("password reset requested for an account with no login mailbox: none started");
            return Ok(anti_enum_response);
        };

        // Rate limit: max 3 active reset sessions per profile. A count that
        // cannot be read starts no reset (the limit would read as zero); the
        // answer keeps the same shape so it tells nothing about the account.
        let active_count = match self.storage.count_active_reset_sessions(profile.id).await {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "reset limit unreadable; no reset started");
                return Ok(anti_enum_response);
            }
        };
        if active_count >= 3 {
            // Still return success (anti-enumeration)
            return Ok(anti_enum_response);
        }

        // The session and the work mailing its link commit together; the
        // token leaves this service only inside that mail. A failure answers
        // like an unknown address: an error only for held addresses would
        // tell which accounts exist.
        match resets.request(profile.id, &address, &destination).await {
            Ok(session) => info!(reset_session = %session, "password reset requested"),
            Err(e) => tracing::error!(error = %e, "reset session not stored; no reset started"),
        }

        Ok(anti_enum_response)
    }

    #[tracing::instrument(skip_all, fields(rpc = "verify_password_reset"))]
    async fn verify_password_reset(
        &self,
        request: Request<VerifyPasswordResetRequest>,
    ) -> Result<Response<VerifyPasswordResetResponse>, Status> {
        let req = request.into_inner();

        let session_id = wire_id(req.reset_session_id.as_ref(), "reset_session_id")?;

        // An unknown reset and an expired one answer alike: the reset starts
        // again from the email.
        let session = self
            .storage
            .get_reset_session(sid_core::models::ResetSessionId(session_id.into_uuid()))
            .await
            .map_err(storage_failure)?
            .filter(|s| !s.is_expired())
            .ok_or_else(|| ceremony_expired("password reset"))?;

        let already_used = || {
            ApiError::new(ErrorReason::InvalidState, "the reset link was already used")
                .with_precondition("RESET_SESSION_STATE", session_id.to_string(), "used")
                .into()
        };
        if session.status != sid_core::models::ResetSessionStatus::Pending {
            return Err(already_used());
        }

        // Verify token (SHA-256, constant-time comparison)
        use subtle::ConstantTimeEq;
        let computed_hash = sid_authn::password_reset::token_hash(&req.token);
        let ct_ok: bool = computed_hash
            .as_bytes()
            .ct_eq(session.token_hash.as_bytes())
            .into();
        if !ct_ok {
            return Err(
                ApiError::new(ErrorReason::TokenInvalid, "the reset link is not valid").into(),
            );
        }

        // Consume the token: of concurrent verifications one succeeds.
        let verified = self
            .storage
            .verify_reset_session(
                session.id,
                AuditEntry::user(
                    session.profile_id.to_string(),
                    "password_reset.verify",
                    session.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !verified {
            return Err(already_used());
        }

        // No recovery sources (no blind vault, no data_key).

        // The replacement password's operation, under the verified reset's
        // authority: the owner's retained history applies, no old password.
        let zkpp = self.require_zkpp()?;
        let prepared = self
            .password_ops
            .prepare(
                &zkpp,
                OperationPurpose::Reset {
                    session: session.id,
                },
                OperationOwner::Existing(session.profile_id),
                format!("profile:{}", session.profile_id),
                None,
            )
            .await
            .or_status()?;

        Ok(Response::new(VerifyPasswordResetResponse {
            expires_in: sid_core::models::RESET_SESSION_TTL_SECS as i32,
            history: Some(prepared.context),
        }))
    }

    /// The OPAQUE start of the replacement password, under the reset
    /// operation's own OPRF key, while its reset session is still verified.
    #[tracing::instrument(skip_all, fields(rpc = "execute_password_reset"))]
    async fn execute_password_reset(
        &self,
        request: Request<ExecutePasswordResetRequest>,
    ) -> Result<Response<ExecutePasswordResetResponse>, Status> {
        let zkpp = self.require_zkpp()?;
        let req = request.into_inner();
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        let mut reset = None;
        let registration_response = self
            .password_ops
            .opaque_start(&zkpp, &id, req.registration_request, |op| {
                match op.purpose {
                    OperationPurpose::Reset { session } => {
                        reset = Some(session);
                        Ok(())
                    }
                    _ => Err(operation_not_pending()),
                }
            })
            .await
            .or_status()?;
        // The operation outlives nothing: a reset that expired or was
        // completed meanwhile does not go on.
        let session = reset.ok_or_else(operation_not_pending)?;
        self.verified_reset_session(session).await?;
        Ok(Response::new(ExecutePasswordResetResponse {
            registration_response,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "complete_password_reset"))]
    async fn complete_password_reset(
        &self,
        request: Request<CompletePasswordResetRequest>,
    ) -> Result<Response<CompletePasswordResetResponse>, Status> {
        // Refused before the reset is consumed.
        let client = self.ceremony_client(request.metadata())?;
        let client_ip = self.client_ip(&request)?;
        let user_agent = extract_user_agent(request.metadata());
        let req = request.into_inner();
        let zkpp = self.require_zkpp()?;

        // 1. The final record and its proof, checked against the reset's own
        //    operation, which names the reset. A retry of a completed reset
        //    gets no session: the password was replaced, the client signs in
        //    with it.
        let id = operation_id(req.operation_id.as_ref()).or_status()?;
        let mut reset = None;
        let done = match self
            .password_ops
            .finish(
                zkpp,
                &id,
                "reset",
                &req.registration_record,
                req.proof,
                |op| match op.purpose {
                    OperationPurpose::Reset { session } => {
                        reset = Some(session);
                        Ok(())
                    }
                    _ => Err(operation_not_pending()),
                },
            )
            .await
            .or_status()?
        {
            Finish::Completed(_) => {
                return Ok(Response::new(CompletePasswordResetResponse::default()));
            }
            Finish::Ready(done) => *done,
        };
        let reset = reset.ok_or_else(operation_not_pending)?;
        let session = self.verified_reset_session(reset).await?;
        let profile_id = session.profile_id;

        // 2. One transaction: the reset completes (only if still verified and
        //    unexpired), the new password replaces the old one with its
        //    evidence and history entry, and every session of the profile
        //    ends, each owing its client's back-channel logout and its
        //    revoked event; the completion owes its own event and records
        //    the operation's result. Of concurrent completions exactly one
        //    gets here.
        let new_cred = done.credential(
            profile_id,
            self.seal_envelope(profile_id, &done.password_file).await?,
        );
        let completed = sid_core::models::event::Event::new(
            format!("profile/{}", profile_id),
            sid_core::models::event::event_types::PASSWORD_RESET_COMPLETED,
        );
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "password_reset.complete",
            session.id.to_string(),
        ))
        .with_work(completed.relay())
        .with_operation(done.completion(Self::finish_result(
            &CompletePasswordResetResponse::default(),
        )));
        let end = sid_core::models::SessionEnd::new(
            RevocationReason::UserRequested,
            profile_id.to_string(),
        );
        let history = self.with_history_age(done.history);
        let ended = self
            .storage
            .complete_password_reset(session.id, &new_cred, history.as_ref(), &end, ctx)
            .await
            .map_err(|e| {
                sid_authn::password_operation::commit_refusal(e, storage_failure).into_status()
            })?
            // Completed, or expired, meanwhile: the reset starts again.
            .ok_or_else(|| ceremony_expired("password reset"))?;

        // 3. The ended sessions' access tokens stop in every process. Their
        //    sessions and refresh tokens are already gone; a failed
        //    propagation leaves only access tokens until they expire.
        for ended in &ended {
            if let Err(e) = self
                .revocation_cache
                .revoke_session(ended.id.to_string())
                .await
            {
                warn!(
                    "Revocation of session {} after password reset not propagated: {}",
                    ended.id, e
                );
            }
        }

        // 4. The reset proved only the mailbox. An account protected by more
        //    than a password is not signed in by it: the new password still
        //    has to pass the account's second factor at sign-in. The absent
        //    session fields say "password replaced, sign in".
        let active: Vec<Credential> = self
            .storage
            .get_credentials_by_profile(profile_id, None)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect();
        let established = sid_authn::credential_enrollment::established_assurance(
            &active,
            self.security_policy().auth.passkey_satisfies_mfa,
        );
        if established > sid_core::models::session::AuthLevel::Basic {
            info!(
                "Password reset completed for profile {}; sign-in left to its second factor",
                profile_id
            );
            return Ok(Response::new(CompletePasswordResetResponse::default()));
        }

        // 5. The reset's sign-in is a sign-in like any other: its session
        //    records the client's device and address, and the organization's
        //    login requirements admit it.
        //    The password is already replaced: a sign-in the requirements do
        //    not admit (or cannot state) leaves the reset successful, with no
        //    session, as an account with a second factor is left.
        let method = LoginMethod::Password;
        let policy = match self
            .admit_by_requirements(
                profile_id,
                method.auth_level(self.security_policy().auth.passkey_satisfies_mfa),
                &method.amr(),
            )
            .await
        {
            Ok(policy) => policy,
            Err(status) => {
                info!(
                    "Password reset completed for profile {}; sign-in not admitted: {}",
                    profile_id,
                    status.message()
                );
                return Ok(Response::new(CompletePasswordResetResponse::default()));
            }
        };
        let signed_in = self
            .create_session_and_issue_tokens(
                &self
                    .storage
                    .get_profile(profile_id)
                    .await
                    .map_err(storage_failure)?
                    // Deleted meanwhile: the password is replaced, no one signs in.
                    .ok_or_else(authentication_failed)?,
                method,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                client,
                None,
                // Another reset committed meanwhile signs this one in no more.
                Some(&sid_core::models::CredentialFence {
                    id: new_cred.id,
                    data: new_cred.data.clone(),
                }),
                policy,
            )
            .await?;

        info!("Password reset completed for profile {}", profile_id);

        let expires_in = i32::try_from(signed_in.expires_in)
            .map_err(|e| internal("session lifetime beyond the response field", e))?;
        signed_in.respond(|session_id, _| CompletePasswordResetResponse {
            session_id: Some(session_id.into()),
            expires_in: Some(expires_in),
        })
    }
}

/// The token endpoint's RPC, as a native gRPC client calls it.
const OAUTH2_TOKEN_RPC: &str = "/sid.v1.authn.AuthService/OAuth2Token";

/// The request's `Authorization` value (HTTP Basic client authentication);
/// a value that is not ASCII is no credential.
fn authorization(metadata: &tonic::metadata::MetadataMap) -> Option<&str> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
}

/// The status an OAuth endpoint refusal answers with: each carries its
/// RFC 6749 (RFC 8628, RFC 9449) error for the HTTP form of the endpoint.
pub(crate) fn oauth_refusal(e: sid::oauth::OAuthError) -> Status {
    use sid::oauth::OAuthError as E;
    match e {
        E::Token { error, message } => token_refusal(error, message),
        // The interval grows by five seconds, which RetryInfo tells the
        // device. It is set only from DEVICE_CODE_POLL_INTERVAL_SECS, which
        // is positive.
        E::SlowDown { interval } => {
            let wait =
                u64::try_from(interval).expect("a device poll interval is never negative") + 5;
            token_error(TokenError::SlowDown, "poll less often")
                .with_retry_after(std::time::Duration::from_secs(wait))
                .into()
        }
        E::ClientRefused => client_refused(),
        E::Target(refusal) => target_refused(refusal),
        E::MissingParameter(field) => missing_parameter(field),
        E::Dpop(detail) => dpop_refusal(detail),
        E::Unavailable { what, cause } => dependency_unavailable(what, cause),
        E::Caller(e) => e.into_status(),
        E::RateLimited { rpm } => {
            ApiError::new(ErrorReason::RateLimitExceeded, "rate limit exceeded")
                .with_quota_violation(
                    "machine_user_token_requests",
                    format!("{rpm} token requests per minute"),
                )
                .with_retry_after(std::time::Duration::from_secs(60))
                .into()
        }
        E::PolicyChanged => authorize::policy_changed(),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

/// The status for a refused authorization request. An unregistered redirect
/// URI is marked with `field = redirect_uri` (the front channel must not
/// redirect there); every other refusal carries the RFC 6749 §4.1.2.1 `error`
/// code in `oauthError`, to be sent to the verified redirect URI.
fn authorize_refusal(error: sid_authn::oauth2::AuthorizeError) -> Status {
    let refusal = ApiError::new(ErrorReason::InvalidFieldValue, error.to_string());
    match error {
        sid_authn::oauth2::AuthorizeError::UnregisteredRedirectUri => refusal
            .with_metadata("field", "redirect_uri")
            .with_field_violation("redirect_uri", error.to_string()),
        _ => refusal.with_metadata("oauthError", error.oauth_error()),
    }
    .into()
}

#[cfg(test)]
mod tests;
