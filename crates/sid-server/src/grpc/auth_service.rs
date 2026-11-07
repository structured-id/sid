// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AuthService implementation.
//!
//! Wraps the same OPAQUE, WebAuthn, OAuth2, and JWT services used by
//! the REST handlers.

use crate::feature_flags::FeatureFlagService;
use chrono::{Duration, Utc};
use sid::sign_in::{AttemptContext, FirstFactor, FirstFactorSignedIn, LoginMethod};
use sid_authn::anomaly::AnomalyDetector;
use sid_authn::geoip::GeoIpChain;
use sid_authn::ip_intelligence::IpIntelligenceAggregator;
use sid_authn::jwt::JwtService;
use sid_authn::magic_link::MagicLinkService;
use sid_authn::oauth2::{OAuth2Server, TokenError};
use sid_authn::opaque::OpaqueRouter;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::otp::OtpService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::sign_in_delivery::{CeremonyClient, SignedIn};
use sid_authn::webauthn::WebAuthnServer;
use sid_core::models::OidcIssuer;
use sid_core::models::principal::PrincipalType;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{CredentialId, ProfileId, SessionId};
use sid_infra::authn::ceremony::Respond;
use sid_infra::authn::operation::context;
use sid_infra::authn::password_operation::{ClientListener, PasswordHistoryEvaluatorImpl};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};
use sid_infra::oauth_http::{
    client_refused, dpop_refusal, missing_parameter, target_refused, token_error, token_refusal,
};
use sid_plugin::cache::CacheBackend;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument, warn};

use super::native_session::NativeProof;
use sid_authn::native_session::{NativePolicy, PROOF_METADATA, REFRESH_METADATA};
use sid_infra::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, maintenance,
    missing_field, not_configured, not_found, not_in_this_build, storage_failure,
};

mod authorize;
mod end_session;
mod refusal;
mod sign_in_security;
use authorize::authorization_refusal;
pub(crate) use authorize::{BrowserAuthorization, PendingAuthorization, REQUEST_URI_PREFIX};
pub(crate) use end_session::{EndSession, LogoutRequest};
use refusal::{
    anomaly_unavailable, authentication_failed, ceremony_expired, enrollment_requirement,
    mfa_not_enrolled, registration_restricted, session_ended, session_provisional,
    step_up_required,
};
use sid::second_factor::{Enroller, FactorCaller};
use sid_authn::sign_in_security::device_id as compute_device_id;
use sign_in_security::sign_in_refusal;

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

/// The answer to a refused or failed device authorization decision.
fn device_approval_refusal(e: sid::oauth::device_approval::DeviceApprovalError) -> Status {
    use sid::oauth::device_approval::DeviceApprovalError as E;
    match e {
        E::NotCurrent => invalid_field("user_code", "not a current device code"),
        E::SessionEnded => session_ended(),
        E::StepUp(unmet) => step_up_required(&unmet).into(),
        E::AlreadyDecided => ApiError::new(
            ErrorReason::InvalidState,
            "the device authorization is already decided",
        )
        .with_precondition("DEVICE_AUTHORIZATION_STATE", "user_code", "decided")
        .into(),
        E::Caller(e) => e.into_status(),
        E::OAuth(e) => oauth_refusal(e),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

/// The answer to a refused or failed mailbox sign-in step.
fn email_sign_in_refusal(e: sid::email_sign_in::EmailSignInError) -> Status {
    use sid::email_sign_in::EmailSignInError as E;
    match e {
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::Code(e) => otp_refusal(e),
        E::CodeSessionExpired => ceremony_expired("email code"),
        E::CodeExpired => ApiError::new(
            ErrorReason::TokenExpired,
            "the code has expired; request a new one",
        )
        .into(),
        E::TooManyCodes => ApiError::new(
            ErrorReason::QuotaExceeded,
            "too many wrong codes; request a new one",
        )
        .with_quota_violation("email_code_attempts", "attempts per code")
        .into(),
        E::LinkExpired => ApiError::new(
            ErrorReason::TokenExpired,
            "the link has expired; request a new one",
        )
        .into(),
        E::LinkUsed => ApiError::new(
            ErrorReason::TokenInvalid,
            "the link was already used; request a new one",
        )
        .into(),
        E::AuthenticationFailed => authentication_failed(),
        E::SignIn(e) => sign_in_refusal(e),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

/// The answer to a refused or failed second-factor step.
fn second_factor_refusal(e: sid::second_factor::SecondFactorError) -> Status {
    use sid::second_factor::SecondFactorError as E;
    match e {
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::MissingField(field) => missing_field(field),
        E::AlreadyEnrolled => ApiError::new(
            ErrorReason::InvalidState,
            "a TOTP authenticator is already enrolled",
        )
        .with_precondition("MFA_ENROLLMENT", "TOTP", "already enrolled")
        .into(),
        E::NotEnrolled(what) => mfa_not_enrolled(what),
        E::ProfileNotFound(id) => {
            not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
        }
        E::Expired(ceremony) => ceremony_expired(ceremony),
        E::AuthenticationFailed => authentication_failed(),
        E::SessionEnded => session_ended(),
        E::SessionProvisional(id) => session_provisional(id),
        E::ChangedConcurrently => changed_concurrently(),
        E::SessionTooOld => ApiError::new(
            ErrorReason::InvalidState,
            "the session is too old for a step-up: full re-authentication required",
        )
        .with_precondition("SESSION_DECAY", "low", "sign in again")
        .into(),
        E::MethodUnavailable(method, decay) => step_up_method_unavailable(method, decay),
        E::StepUpRequired(unmet) => step_up_required(&unmet).into(),
        E::RecoveryCodesIssued(recorded) => recovery_codes_issued(&recorded),
        E::CredentialNotFound(id) => credential_not_found(id),
        E::Identity(e) => super::identity_service::refusal(e),
        E::Caller(e) => e.into_status(),
        E::Enrollment(e) => e.into_status(),
        E::Operation(e) => e.into_status(),
        E::SignIn(e) => sign_in_refusal(e),
        E::Unavailable { what, cause } => dependency_unavailable(what, cause),
        E::Store(e) => storage_failure(e),
        E::Internal | E::ContextRequired => ApiError::internal().into(),
    }
}

/// A request's operation context for an operation that requires it only
/// after its other checks: the context, or the refusal of its absence.
fn deferred_context<T>(
    request: &Request<T>,
) -> (Option<sid_core::models::OperationContext>, Option<Status>) {
    match context(request) {
        Ok(context) => (Some(context), None),
        Err(refused) => (None, Some(refused)),
    }
}

/// The answer of a second-factor operation that deferred its context: the
/// context's own refusal where the operation required it.
#[allow(clippy::result_large_err)]
fn deferred_second_factor<T>(
    result: Result<T, sid::second_factor::SecondFactorError>,
    refused: Option<Status>,
) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(|e| match (e, refused) {
        (sid::second_factor::SecondFactorError::ContextRequired, Some(refused)) => refused,
        (e, _) => second_factor_refusal(e),
    })
}

/// The answer to a refused or failed passkey ceremony.
fn passkey_refusal(e: sid::passkey::PasskeyError) -> Status {
    use sid::passkey::PasskeyError as E;
    match e {
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::ProfileNotFound(id) => {
            not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
        }
        E::Expired(ceremony) => ceremony_expired(ceremony),
        E::AuthenticationFailed => authentication_failed(),
        E::Enrollment(e) => e.into_status(),
        E::SignIn(e) => sign_in_refusal(e),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

/// The answer to a refused or failed password replacement.
fn password_refusal(e: sid::password::PasswordError) -> Status {
    use sid::password::PasswordError as E;
    match e {
        E::InvalidField { field, reason } => invalid_field(field, reason),
        E::MissingField(field) => missing_field(field),
        E::CredentialNotFound(id) => credential_not_found(id),
        E::ChangedConcurrently => changed_concurrently(),
        E::AuthenticationFailed => authentication_failed(),
        E::NotConfigured(feature) => not_configured(feature),
        E::ResetExpired => ceremony_expired("password reset"),
        E::ResetUsed(session) => {
            ApiError::new(ErrorReason::InvalidState, "the reset link was already used")
                .with_precondition("RESET_SESSION_STATE", session, "used")
                .into()
        }
        E::ResetUnverified(session) => {
            ApiError::new(ErrorReason::InvalidState, "the reset is not verified yet")
                .with_precondition("RESET_SESSION_STATE", session, "unverified")
                .into()
        }
        E::ResetTokenInvalid => {
            ApiError::new(ErrorReason::TokenInvalid, "the reset link is not valid").into()
        }
        E::UpgradeExpired => ceremony_expired("password migration"),
        E::Enrollment(e) => e.into_status(),
        E::Operation(e) => e.into_status(),
        E::SignIn(e) => sign_in_refusal(e),
        E::Store(e) => storage_failure(e),
        E::Internal => ApiError::internal().into(),
    }
}

pub struct AuthServiceImpl {
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) jwt: Arc<JwtService>,
    pub(crate) opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    pub(crate) revocation_cache: Arc<RevocationCache>,
    pub(crate) feature_flags: FeatureFlagService,
    /// Password registrations, changes and resets between their steps, and
    /// the history evaluator and checker they use.
    pub(crate) password_ops: Arc<sid::password_operation::PasswordOperations>,
    /// The history evaluator, when it runs in this process.
    history_evaluation: Option<Arc<sid_authn::password_operation::HistoryEvaluation>>,
    /// Passkey binding and sign-in ceremonies.
    passkeys: sid::passkey::Passkeys,
    /// Second factors: TOTP and recovery codes, step-ups and their pending
    /// ceremonies.
    second_factors: sid::second_factor::SecondFactors,
    /// Upgrades of imported password hashes between their steps.
    imported_passwords: sid::password::ImportedPasswordUpgrades,
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
    /// Origin of the browser sign-in page: a ceremony it runs sets the IdP
    /// session cookie. None sets no cookie.
    sign_in_origin: Option<url::Origin>,
    /// The enrollment mode the deployment pins over the stored one.
    /// Self-registration: its admission, held identifiers and the commit of
    /// a new account.
    registration: sid::registration::Registration,
    /// Browser authorization requests kept while the user signs in, by
    /// reference, shared by every replica.
    authorizations: sid::oauth::authorization::Authorizations,
    /// The end-session endpoint, with the logout confirmations it offered.
    end_sessions: sid::oauth::end_session::EndSessions,
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
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
        let captcha_gate =
            sid_authn::captcha::CaptchaGate::new(ceremonies.clone(), key_manager.clone());
        let (password_ops, history_evaluation) =
            sid::password_operation::PasswordOperations::with_authority(
                storage.clone(),
                ceremonies.clone(),
                key_manager.clone(),
                installation_org,
                password_history,
            );
        let password_ops = Arc::new(password_ops);
        let oauth = sid::oauth::OAuth::new(sid::oauth::OAuthParts {
            storage: storage.clone(),
            oauth2,
            jwt: jwt.clone(),
            issuers,
            installation_org,
            authz,
            revocation: revocation_cache.clone(),
            cascade,
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
        let passkeys =
            sid::passkey::Passkeys::new(webauthn.clone(), ceremonies.clone(), key_manager.clone());
        let second_factors = sid::second_factor::SecondFactors::new(
            webauthn,
            issuer.clone(),
            ceremonies.clone(),
            key_manager.clone(),
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
            opaque: opaque_router,
            keys: key_manager.clone(),
        });
        Self {
            storage,
            jwt,
            opaque_zkpp,
            revocation_cache,
            feature_flags,
            password_ops,
            history_evaluation,
            passkeys,
            second_factors,
            imported_passwords: sid::password::ImportedPasswordUpgrades::new(
                ceremonies.clone(),
                key_manager.clone(),
            ),
            authorizations: sid::oauth::authorization::Authorizations::new(
                ceremonies.clone(),
                key_manager.clone(),
            ),
            end_sessions: sid::oauth::end_session::EndSessions::new(
                ceremonies.clone(),
                key_manager.clone(),
            ),
            magic_link,
            otp,
            password_resets: None,
            oauth,
            host_login_policy: false,
            public_origin: url::Url::parse(&issuer)
                .expect("the installation URL is validated at start-up")
                .origin()
                .ascii_serialization(),
            issuer,
            sign_ins,
            key_manager,
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

    /// Sign-ins by mailbox over this service's sign-ins.
    fn email_sign_in(&self) -> sid::email_sign_in::EmailSignIn<'_> {
        sid::email_sign_in::EmailSignIn::new(&self.sign_ins, self.oauth.login_policy())
    }

    /// Password replacement over this service's sign-ins and operations.
    fn passwords(&self) -> sid::password::Passwords<'_> {
        sid::password::Passwords::new(&self.sign_ins, &self.password_ops)
    }

    /// Resets of forgotten passwords, where this service mails their links.
    fn password_resets(&self) -> sid::password::PasswordResets<'_> {
        sid::password::PasswordResets::new(
            &self.sign_ins,
            &self.password_ops,
            self.oauth.login_policy(),
            self.password_resets.as_deref(),
        )
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

    /// Who binds a second factor in `request`: a sign-in's pending context
    /// when it presents one, otherwise the caller's session.
    async fn enroller<T>(&self, request: &Request<T>) -> Result<Enroller, Status> {
        if let Ok(FactorCaller::Pending(pending, _)) = self.factor_caller(request).await {
            return Ok(Enroller::SignIn(Box::new(pending)));
        }
        Ok(Enroller::Session(self.caller_claims(request).await?.caller))
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

    /// The authenticated caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<sid_authn::caller::Caller, Status> {
        sid_infra::authn::caller::authenticate(request, self.jwt.verifier(), &self.revocation_cache)
            .await
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
        let enabled = self.feature_flags.is_registration_enabled().await;
        self.registration
            .start(
                &self.password_ops,
                &zkpp,
                &req.principal,
                req.claim_token.as_deref(),
                req.invite_code.as_deref(),
                req.registration_request,
                enabled,
            )
            .await
            .map(Response::new)
            .map_err(registration_refusal)
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

        let enabled = self.feature_flags.is_registration_enabled().await;
        self.registration
            .finish(
                &self.password_ops,
                zkpp,
                request.into_inner(),
                self.security_policy().password.history_max_age_days,
                enabled,
            )
            .await
            .map(Response::new)
            .map_err(registration_refusal)
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
        let zkpp = self.require_zkpp()?;
        self.passwords()
            .change_challenge(&zkpp, &verified.caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        self.passwords()
            .change_execute(&zkpp, &verified.caller, client_ip, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        let zkpp = self.require_zkpp()?;
        self.passwords()
            .change_finish(zkpp, &verified.caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        self.passwords()
            .change_requirement(&verified.caller)
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        self.passkeys
            .registration_start(&self.sign_ins, &caller)
            .await
            .map(Response::new)
            .map_err(passkey_refusal)
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
        self.passkeys
            .registration_finish(&self.sign_ins, &caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(passkey_refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_authentication_start"))]
    #[instrument(skip_all, fields(method = "web_authn_authentication_start"))]
    async fn web_authn_authentication_start(
        &self,
        request: Request<WebAuthnAuthenticationStartRequest>,
    ) -> Result<Response<WebAuthnAuthenticationStartResponse>, Status> {
        self.check_maintenance().await?;
        self.passkeys
            .authentication_start(&self.sign_ins, request.into_inner())
            .await
            .map(Response::new)
            .map_err(passkey_refusal)
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
        let assertion = sid::passkey::Assertion::parse(req.principal, &req.credential)
            .map_err(passkey_refusal)?;
        // The key is bound to the ceremony the assertion answers, checked
        // before that ceremony is consumed.
        let ceremony = assertion.ceremony().map_err(passkey_refusal)?;
        let native_key = self
            .native_ceremony_key(native.as_ref(), ceremony.as_bytes())
            .await?;
        let FirstFactorSignedIn {
            signed_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        } = self
            .passkeys
            .authentication_finish(
                &self.sign_ins,
                self.oauth.login_policy(),
                assertion,
                client,
                client_ip,
                AttemptContext {
                    captcha_pass: captcha_pass.as_deref(),
                    user_agent: user_agent.as_deref(),
                },
                native_key.as_deref(),
            )
            .await
            .map_err(passkey_refusal)?;
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
        // authentication.
        let verified = self.caller_claims(&request).await?;
        self.oauth
            .authorize_session(
                &self.sign_ins,
                &verified,
                &client,
                &issuer,
                request.into_inner(),
            )
            .await
            .map(Response::new)
            .map_err(authorization_refusal)
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
        self.email_sign_in()
            .request_link(magic_link, &request.into_inner().principal)
            .await
            .map(Response::new)
            .map_err(email_sign_in_refusal)
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
        let attempt = sid::email_sign_in::Attempt {
            client,
            client_ip,
            context: AttemptContext {
                captcha_pass: captcha_pass.as_deref(),
                user_agent: user_agent.as_deref(),
            },
        };
        self.email_sign_in()
            .verify_link(magic_link, attempt, request.into_inner())
            .await
            .map_err(email_sign_in_refusal)?
            .respond(|session_id, expires_in| VerifyMagicLinkResponse {
                session_id: Some(session_id.into()),
                // A provisional session lasts minutes.
                expires_in: expires_in as i32,
            })
    }

    // ── Session Validation ──

    #[tracing::instrument(skip_all, fields(rpc = "validate_session"))]
    #[instrument(skip_all, fields(method = "validate_session"))]
    async fn validate_session(
        &self,
        request: Request<ValidateSessionRequest>,
    ) -> Result<Response<ValidateSessionResponse>, Status> {
        let caller = self.caller(&request).await?;
        let session_id = wire_id(request.get_ref().session_id.as_ref(), "session_id")?;
        self.sign_ins
            .validate_session(&caller, session_id)
            .await
            .map(Response::new)
            .map_err(sign_in_refusal)
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
        self.sign_ins
            .sign_in_methods(&req.principal, self.magic_link.is_some())
            .map(Response::new)
            .map_err(sign_in_refusal)
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

        let verified = self.caller_claims(&request).await?;
        self.oauth
            .submit_device_user_code(&self.sign_ins, &verified, request.into_inner())
            .await
            .map(Response::new)
            .map_err(device_approval_refusal)
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
        self.imported_passwords
            .start(&self.sign_ins, client_ip, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        let FirstFactorSignedIn {
            signed_in,
            second_factors,
            enrollable_factors,
            browser_csrf,
        } = self
            .imported_passwords
            .finish(
                &self.sign_ins,
                self.oauth.login_policy(),
                client,
                client_ip,
                AttemptContext {
                    captcha_pass: captcha_pass.as_deref(),
                    user_agent: user_agent.as_deref(),
                },
                request.into_inner(),
            )
            .await
            .map_err(password_refusal)?;
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
        self.second_factors
            .totp_enrollment_start(&self.sign_ins, &enroller)
            .await
            .map(Response::new)
            .map_err(second_factor_refusal)
    }

    async fn finish_totp_enrollment(
        &self,
        request: Request<FinishTotpEnrollmentRequest>,
    ) -> Result<Response<FinishTotpEnrollmentResponse>, Status> {
        self.check_maintenance().await?;
        let enroller = self.enroller(&request).await?;
        self.second_factors
            .totp_enrollment_finish(&self.sign_ins, &enroller, &request.into_inner().code)
            .await
            .map(Response::new)
            .map_err(second_factor_refusal)
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

        // A completed sign-in and a step-up both answer with the session's
        // new credential.
        self.second_factors
            .verify_totp(
                &self.sign_ins,
                self.oauth.login_policy(),
                caller,
                client_ip,
                native_key.as_deref(),
                &request.into_inner().code,
            )
            .await
            .map_err(second_factor_refusal)?
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
        let (context, refused) = deferred_context(&request);
        deferred_second_factor(
            self.second_factors
                .generate_recovery_codes(&self.sign_ins, &caller, context, request.get_ref())
                .await,
            refused,
        )
    }

    async fn verify_recovery_code(
        &self,
        request: Request<VerifyRecoveryCodeRequest>,
    ) -> Result<Response<MfaVerifyResponse>, Status> {
        self.check_maintenance().await?;
        let verified = self.caller_claims(&request).await?;
        self.second_factors
            .verify_recovery_code(&self.sign_ins, &verified, &request.into_inner().code)
            .await
            .map(Response::new)
            .map_err(second_factor_refusal)
    }

    // ── OTP ──

    #[instrument(skip_all, fields(method = "request_otp"))]
    async fn request_otp(
        &self,
        request: Request<RequestOtpRequest>,
    ) -> Result<Response<RequestOtpResponse>, Status> {
        self.check_maintenance().await?;
        self.email_sign_in()
            .request_code(&self.otp, &request.into_inner().principal)
            .await
            .map(Response::new)
            .map_err(email_sign_in_refusal)
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
        let attempt = sid::email_sign_in::Attempt {
            client,
            client_ip,
            context: AttemptContext {
                captcha_pass: captcha_pass.as_deref(),
                user_agent: user_agent.as_deref(),
            },
        };
        // A wrong code, and an address that routes nowhere, answer alike.
        let Some(signed_in) = self
            .email_sign_in()
            .verify_code(&self.otp, attempt, request.into_inner())
            .await
            .map_err(email_sign_in_refusal)?
        else {
            return Ok(Response::new(VerifyOtpResponse::default()));
        };
        signed_in.respond(|session_id, expires_in| VerifyOtpResponse {
            verified: true,
            redirect_to: None,
            session_id: Some(session_id.into()),
            expires_in: Some(expires_in),
        })
    }

    #[instrument(skip_all, fields(method = "resend_otp"))]
    async fn resend_otp(
        &self,
        request: Request<ResendOtpRequest>,
    ) -> Result<Response<ResendOtpResponse>, Status> {
        self.check_maintenance().await?;
        self.email_sign_in()
            .resend_code(&self.otp, request.into_inner().otp_session_id.as_ref())
            .await
            .map(Response::new)
            .map_err(email_sign_in_refusal)
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
        let verified = self.caller_claims(&request).await?;
        self.second_factors
            .step_up_request(&self.sign_ins, &verified, request.into_inner().method)
            .await
            .map(Response::new)
            .map_err(second_factor_refusal)
    }

    async fn complete_step_up(
        &self,
        request: Request<CompleteStepUpRequest>,
    ) -> Result<Response<CompleteStepUpResponse>, Status> {
        self.check_maintenance().await?;
        let verified = self.caller_claims(&request).await?;
        self.second_factors
            .step_up_complete(&self.sign_ins, &verified, request.into_inner())
            .await
            .map(Response::new)
            .map_err(second_factor_refusal)
    }

    // ── MFA credential management ──

    async fn delete_mfa_credential(
        &self,
        request: Request<DeleteMfaCredentialRequest>,
    ) -> Result<Response<DeleteMfaCredentialResponse>, Status> {
        self.check_maintenance().await?;
        let verified = self.caller_claims(&request).await?;
        let (context, refused) = deferred_context(&request);
        deferred_second_factor(
            self.second_factors
                .delete(&self.sign_ins, &verified, context, request.into_inner())
                .await,
            refused,
        )
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
        self.password_resets()
            .request(&request.into_inner().principal)
            .await
            .map(Response::new)
            .map_err(password_refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "verify_password_reset"))]
    async fn verify_password_reset(
        &self,
        request: Request<VerifyPasswordResetRequest>,
    ) -> Result<Response<VerifyPasswordResetResponse>, Status> {
        // Before the link's token is consumed: a reset that cannot prepare
        // its password leaves the link usable.
        let zkpp = self.require_zkpp()?;
        self.password_resets()
            .verify(&zkpp, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
    }

    /// The OPAQUE start of the replacement password, under the reset
    /// operation's own OPRF key, while its reset session is still verified.
    #[tracing::instrument(skip_all, fields(rpc = "execute_password_reset"))]
    async fn execute_password_reset(
        &self,
        request: Request<ExecutePasswordResetRequest>,
    ) -> Result<Response<ExecutePasswordResetResponse>, Status> {
        let zkpp = self.require_zkpp()?;
        self.password_resets()
            .execute(&zkpp, request.into_inner())
            .await
            .map(Response::new)
            .map_err(password_refusal)
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
        let zkpp = self.require_zkpp()?;
        // No session: the password is replaced and the client signs in with
        // it (the absent session fields say so).
        let Some(signed_in) = self
            .password_resets()
            .complete(
                zkpp,
                client,
                client_ip,
                user_agent.as_deref(),
                request.into_inner(),
            )
            .await
            .map_err(password_refusal)?
        else {
            return Ok(Response::new(CompletePasswordResetResponse::default()));
        };
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
