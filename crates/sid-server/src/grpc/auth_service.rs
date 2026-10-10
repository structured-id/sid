// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AuthService implementation.
//!
//! Wraps the same OPAQUE, WebAuthn, OAuth2, and JWT services used by
//! the REST handlers.

use crate::feature_flags::FeatureFlagService;
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretBox};
use sid_authn::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::claim_mapping::resolve_claims;
use sid_authn::client_auth::ClientAuthentication;
use sid_authn::device_auth;
use sid_authn::dpop::DPopValidator;
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
use sid_authn::subject::{SubjectRule, resolve_subject};
use sid_authn::webauthn::{
    AssertionPurpose, AssertionResponse, DiscoverableAssertionResponse, RegistrationResponse,
    VerifiedAssertion, WebAuthnServer,
};
use sid_core::enrollment::{EnrollmentDecision, evaluate_enrollment};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::WebAuthnUserHandle;
use sid_core::models::dpop::DPopBinding;
use sid_core::models::event::{Event, event_types};
use sid_core::models::principal::PrincipalType;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialId, CredentialType,
    DEVICE_CODE_LIFETIME_SECS, DEVICE_CODE_POLL_INTERVAL_SECS, NewRegistration, Profile, ProfileId,
    ProfileType, Session, SessionId,
};
use sid_core::models::{
    HistoryCommit, MutationContext, OidcIssuer, OperationCompletion, ProfileEmail, ProfilePhone,
    RevocationReason,
};
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::{LoginState, StoredCredential};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Code, Request, Response, Status};
use tracing::{info, instrument, warn};

use super::password_operation::{
    CurrentPasswordCheck, Finish, OperationOwner, OperationPurpose, PendingOperation,
    change_context, operation_id,
};
use sid_core::grpc_error::refuse::{
    changed_concurrently, dependency_unavailable, internal, invalid_field, maintenance,
    missing_field, not_configured, not_found, not_in_this_build, storage_failure,
};

mod authorize;
mod end_session;
mod refusal;
pub(crate) use authorize::{BrowserAuthorization, PendingAuthorization};
pub(crate) use end_session::{EndSession, LogoutRequest};
use refusal::{
    anomaly_unavailable, authentication_failed, captcha_required, ceremony_expired,
    mfa_not_enrolled, registration_restricted, session_ended, session_provisional, sign_in_refused,
    step_up_after_anomaly, step_up_to_acr, step_up_to_amr, too_many_attempts,
};

/// Check implied auth level for a given authentication method.
///
/// Returns the auth level that a successful login with this method would grant.
/// Used for pre-session policy enforcement (check policy before creating session).
///
/// When `passkey_satisfies_mfa` is true (CE default, NIST-aligned), a single passkey
/// with user verification satisfies MFA: possession + biometric/PIN = two factors.
/// When false, passkey grants only basic assurance (requires additional MFA for standard).
///
/// `user_verified` must be true for Standard — per NIST, the authenticator must have
/// performed user verification (biometric or PIN). Without UV, passkey = single factor
/// (possession only), so assurance remains Basic even if `passkey_satisfies_mfa` is true.
fn implied_auth_level(
    auth_method: &str,
    passkey_satisfies_mfa: bool,
    user_verified: bool,
) -> sid_core::models::session::AuthLevel {
    match auth_method {
        "webauthn" if passkey_satisfies_mfa && user_verified => {
            sid_core::models::session::AuthLevel::Standard
        }
        _ => sid_core::models::session::AuthLevel::Basic,
    }
}

/// How a full sign-in authenticated.
#[derive(Clone, Copy)]
enum LoginMethod {
    Password,
    /// A passkey assertion: whether the authenticator verified the user, and
    /// the RFC 8176 method of the key that asserted (`hwk` / `swk`).
    Passkey {
        user_verified: bool,
        key_amr: &'static str,
    },
}

impl LoginMethod {
    /// The assurance this sign-in establishes.
    fn auth_level(self, passkey_satisfies_mfa: bool) -> sid_core::models::session::AuthLevel {
        match self {
            Self::Password => implied_auth_level("opaque", passkey_satisfies_mfa, false),
            Self::Passkey { user_verified, .. } => {
                implied_auth_level("webauthn", passkey_satisfies_mfa, user_verified)
            }
        }
    }

    /// The `amr` values (RFC 8176 §2) the session records for this sign-in.
    fn amr(self) -> Vec<String> {
        match self {
            Self::Password => vec!["pwd".to_string()],
            Self::Passkey {
                user_verified,
                key_amr,
            } => passkey_amr(key_amr, user_verified)
                .iter()
                .map(|m| m.to_string())
                .collect(),
        }
    }
}

/// `amr` values of a passkey assertion: the key (`hwk`/`swk`, RFC 8176 §2),
/// proof of possession (`pop`, OpenID EAP ACR Values 1.0), and `mfa` when the
/// authenticator verified the user. WebAuthn reports only that the user was
/// verified, not how, so no biometric or PIN value is claimed.
fn passkey_amr(key_amr: &'static str, user_verified: bool) -> Vec<&'static str> {
    if user_verified {
        vec![key_amr, "pop", "mfa"]
    } else {
        vec![key_amr, "pop"]
    }
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

/// Check if an IP address matches a CIDR entry or exact IP.
///
/// Supports: exact IPs ("10.0.0.1"), IPv4 CIDRs ("10.0.0.0/24"),
/// and IPv6 CIDRs ("::1/128").
fn ip_matches(entry: &str, addr: &std::net::IpAddr) -> bool {
    if let Some((network, prefix)) = entry.split_once('/') {
        let Ok(network_addr): Result<std::net::IpAddr, _> = network.parse() else {
            return false;
        };
        let Ok(prefix_len): Result<u32, _> = prefix.parse() else {
            return false;
        };
        match (network_addr, addr) {
            (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
                if prefix_len > 32 {
                    return false;
                }
                if prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix_len);
                (u32::from(*ip) & mask) == (u32::from(net) & mask)
            }
            (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
                if prefix_len > 128 {
                    return false;
                }
                if prefix_len == 0 {
                    return true;
                }
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                let mask = u128::MAX << (128 - prefix_len);
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // Mixed v4/v6
        }
    } else {
        // Exact IP match.
        entry.parse::<std::net::IpAddr>() == Ok(*addr)
    }
}

/// A token's claims could not be read: the grant fails instead of issuing
/// tokens without them.
fn claims_unavailable(e: sid_core::Error) -> Status {
    internal("token claims", e)
}

/// The address a session records: the client's, or none when the transport
/// reported no peer (an in-process call).
fn session_address(client_ip: Option<std::net::IpAddr>) -> String {
    client_ip.map(|ip| ip.to_string()).unwrap_or_default()
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

/// Compute a deterministic device_id from User-Agent string.
///
/// SHA-256(UA) → first 16 bytes → UUID v4 (deterministic).
/// Same UA string always produces the same device_id.
fn compute_device_id(user_agent: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(user_agent.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    // Set UUID version 4 bits for format compliance.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
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

/// Server state between OPAQUE login start and finish.
#[derive(serde::Serialize, serde::Deserialize)]
enum PendingLogin {
    /// A login against the profile's password.
    Password {
        state: LoginState,
        profile_id: ProfileId,
        credential_id: CredentialId,
    },
    /// A login that cannot succeed: no profile holds the principal, or its
    /// profile has no password. Stored and consumed like a real state and
    /// refused like a wrong password, so neither the timing of either step nor
    /// the answer tells whether the account exists. `identity` is the key its
    /// failed attempts count against.
    Decoy { identity: String },
}

/// What a pending OPAQUE registration may commit when it finishes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum PendingRegistration {
    /// A new account for an identifier nobody holds. `profile_id` is reserved
    /// at start; `credential_identifier` is the OPRF credential identifier of
    /// its first password, drawn at start and stored with the credential.
    NewAccount {
        profile_id: ProfileId,
        principal_type: PrincipalType,
        value: String,
        /// For an email, the handle as validated at start: the address in the
        /// registrant's spelling (the new contact stores it, while `value` is
        /// the resolution key) and the policy revision of the key.
        email: Option<sid_authn::email::EmailHandle>,
        /// The sealed instance claim the start verified: the account becomes
        /// the first administrator and consumes it when it is committed.
        instance_claim: Option<Vec<u8>>,
        credential_identifier: [u8; 16],
    },
    /// The identifier already belongs to an account. Start still evaluates the
    /// OPRF under a key that exists nowhere, so the answer looks like any other;
    /// finishing commits nothing, so a registration never attaches to an
    /// existing account.
    ExistingAccount { principal_type: PrincipalType },
}

impl PendingRegistration {
    /// The OPRF credential identifier the registration's start evaluates
    /// under: the new password's own for a new account, a throwaway one for a
    /// held identifier.
    fn credential_identifier(&self) -> [u8; 16] {
        match self {
            Self::NewAccount {
                credential_identifier,
                ..
            } => *credential_identifier,
            Self::ExistingAccount { .. } => rand::random(),
        }
    }
}

/// `ALREADY_EXISTS` with the error-model reason for the identifier kind.
fn already_registered(principal_type: PrincipalType) -> tonic::Status {
    let reason = match principal_type {
        PrincipalType::Email => ErrorReason::EmailAlreadyRegistered,
        PrincipalType::Username => ErrorReason::UsernameAlreadyTaken,
        PrincipalType::Phone => ErrorReason::PhoneAlreadyRegistered,
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag => ErrorReason::PrincipalAlreadyHeld,
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

/// The email code session a verify or resend names.
#[allow(clippy::result_large_err)]
fn parse_otp_session(id: Option<&str>) -> Result<uuid::Uuid, Status> {
    let id = id
        .filter(|id| !id.is_empty())
        .ok_or_else(|| missing_field("session_id"))?;
    uuid::Uuid::parse_str(id)
        .map_err(|_| invalid_field("session_id", "not an email code session identifier"))
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
        sid_authn::otp::OtpError::Internal(msg) => internal("request email code", msg),
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

/// CREDENTIAL_NOT_FOUND for `id`: also the answer for a credential the caller
/// does not own, so a foreign id reveals nothing.
fn credential_not_found(id: CredentialId) -> Status {
    not_found(
        ErrorReason::CredentialNotFound,
        "Credential",
        id.0.to_string(),
    )
}

/// The signup identifier for a parsed `value` of `principal_type`; an email
/// carries its validated handle (address and key revision) beside the key.
#[allow(clippy::result_large_err)]
pub(crate) fn signup_identifier<'a>(
    principal_type: PrincipalType,
    value: &'a str,
    email: Option<&'a sid_authn::email::EmailHandle>,
) -> Result<sid_core::models::SignupIdentifier<'a>, tonic::Status> {
    use sid_core::models::SignupIdentifier;
    match principal_type {
        PrincipalType::Email => {
            let email = email.ok_or_else(|| internal("sign up", "an email without its address"))?;
            Ok(SignupIdentifier::Email {
                key: value,
                address: &email.delivery,
                revision: email.revision,
            })
        }
        PrincipalType::Phone => Ok(SignupIdentifier::Phone(value)),
        PrincipalType::Username => Ok(SignupIdentifier::Username(value)),
        PrincipalType::FaceEmbedding | PrincipalType::NfcTag => Err(invalid_field(
            "identifier",
            "a new account starts from an email, phone or username",
        )),
    }
}

/// Build the records a self-registration commits: the profile, its single signup
/// principal, the contact row it came from, the first credential and, when the
/// site tracks it, the self-signup source.
fn new_self_registration(
    profile_id: ProfileId,
    principal_type: PrincipalType,
    value: &str,
    email: Option<&sid_authn::email::EmailHandle>,
    credential: Credential,
) -> Result<NewRegistration, tonic::Status> {
    let identifier = signup_identifier(principal_type, value, email)?;
    let username = matches!(principal_type, PrincipalType::Username).then_some(value);
    let mut profile = Profile::new(username);
    profile.id = profile_id;
    let registration = NewRegistration::new(profile, identifier, Some(credential))
        .map_err(|e| invalid_field("identifier", e.to_string()))?;
    Ok(
        if sid_core::models::security_policy::SecurityPolicy::ce_default()
            .enrollment
            .track_source
        {
            registration.with_source(sid_core::models::RegistrationSource::self_signup(None))
        } else {
            registration
        },
    )
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
        _ => Err(super::password_operation::operation_not_pending()),
    }
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
    /// OPAQUE login state between start and finish.
    login_state: ChallengeStore<PendingLogin>,
    /// Ephemeral OPAQUE registration state: key → what the registration may commit.
    registration_state: ChallengeStore<PendingRegistration>,
    /// Password registrations, changes and resets between their steps, and
    /// the history evaluator and checker they use.
    pub(crate) password_ops: Arc<super::password_operation::PasswordOperations>,
    /// The history evaluator, when it runs in this process.
    history_evaluation: Option<Arc<super::password_operation::HistoryEvaluation>>,
    /// Who may prepare at that evaluator over the network: nobody, unless
    /// it serves a remote credential service.
    evaluator_admission: super::password_operation::PrepareAdmission,
    /// The shared cache, for components rebuilt after construction.
    cache: Arc<dyn CacheBackend>,
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
    pub(crate) otp: OtpService,
    /// DPoP proof validator (RFC 9449).
    pub(crate) dpop_validator: DPopValidator,
    /// The OIDC issuers whose endpoints the OAuth requests arrive at, and
    /// their signers.
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    /// The installation's organization: machine users, which belong to the
    /// installation rather than to an application, are served by its issuer.
    installation_org: sid_core::models::OrgId,
    /// Issuer URL (e.g., "https://sid.example.com").
    issuer: String,
    /// Its origin (scheme and authority): the prefix of every URI a sender
    /// proof names, never taken from a request.
    public_origin: String,
    /// RFC 7523: assertion JTI replay prevention cache.
    assertion_jti_cache: Arc<sid_authn::client_assertion::AssertionJtiCache>,
    /// Per-client rate limiter for machine user requests.
    rate_limiter: Arc<crate::rate_limit::RateLimiter>,
    /// Distributed rate limit stats for admin dashboard.
    rate_limit_stats: Arc<crate::rate_limit::RateLimitStats>,
    /// CE anomaly detection engine (brute force, country, Tor, etc.).
    anomaly_detector: Arc<AnomalyDetector>,
    /// IP intelligence aggregator (Tor exit, datacenter, blocklist detection).
    ip_intelligence: Arc<IpIntelligenceAggregator>,
    /// GeoIP resolution chain (country, lat/lon for anomaly rules).
    geoip: Arc<GeoIpChain>,
    /// CE hardcoded security policy (not configurable via UI in CE).
    security_policy: SecurityPolicy,
    /// CAPTCHA provider for RequireCaptcha anomaly reaction.
    captcha_provider: Arc<dyn sid_authn::captcha::CaptchaProvider>,
    /// Which sign-in each CAPTCHA was asked of, and the single-use passes earned.
    captcha_gate: sid_authn::captcha::CaptchaGate,
    /// Field encryption for credential secrets the server reads back (TOTP seeds).
    key_manager: Arc<dyn sid_keys::KeyManager>,
    /// TOTP codes already accepted, shared by every replica.
    totp_replay: sid_authn::TotpReplayGuard,
    /// Ends a profile's sessions everywhere (tokens, RPs) on a password reset.
    cascade: Arc<RevocationCascadeService>,
    /// Proxies whose forwarding headers name the client; none by default.
    trusted_proxies: sid_authn::client_address::TrustedProxies,
    /// The shared authorization evaluator: decides who may inspect the
    /// tokens of a protected resource.
    authz: Arc<dyn sid_plugin::AuthzEngine>,
    /// Origin of the browser sign-in page: a ceremony it runs sets the IdP
    /// session cookie. None sets no cookie.
    sign_in_origin: Option<url::Origin>,
    /// Browser authorization requests kept while the user signs in, by
    /// reference, shared by every replica.
    continuations: ChallengeStore<authorize::PendingAuthorization>,
    /// One-time values of the logout confirmation form, each naming the IdP
    /// session it ends and where the browser returns, shared by every replica.
    logout_confirmations: ChallengeStore<end_session::LogoutConfirmation>,
}

/// A session a sign-in ceremony created: its id, its access token and the
/// token's lifetime, and the `Set-Cookie` value for a ceremony run on the
/// browser sign-in page.
struct SignedIn {
    session_id: String,
    access_token: String,
    expires_in: i64,
    cookie: Option<String>,
}

impl SignedIn {
    /// The ceremony's answer `message` builds from the session id, access
    /// token and its lifetime, carrying the cookie when there is one.
    fn respond<T>(
        self,
        message: impl FnOnce(String, String, i64) -> T,
    ) -> Result<Response<T>, Status> {
        let mut response =
            Response::new(message(self.session_id, self.access_token, self.expires_in));
        if let Some(cookie) = self.cookie {
            response.metadata_mut().insert(
                "set-cookie",
                cookie
                    .parse()
                    .map_err(|e| internal("encode session cookie", e))?,
            );
        }
        Ok(response)
    }
}

/// Extra parameters for login security evaluation (avoids too_many_arguments).
#[derive(Default)]
struct LoginSecurityExtras<'a> {
    /// Pass earned by solving the CAPTCHA this sign-in was asked for.
    captcha_pass: Option<&'a str>,
    user_agent: Option<&'a str>,
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
        otp: OtpService,
        issuers: Arc<sid_authn::issuer::IssuerRegistry>,
        installation_org: sid_core::models::OrgId,
        issuer: String,
        captcha_provider: Arc<dyn sid_authn::captcha::CaptchaProvider>,
        cache_backend: Arc<dyn CacheBackend>,
        ip_intelligence: Arc<IpIntelligenceAggregator>,
        geoip: Arc<GeoIpChain>,
        key_manager: Arc<dyn sid_keys::KeyManager>,
        cascade: Arc<RevocationCascadeService>,
        authz: Arc<dyn sid_plugin::AuthzEngine>,
    ) -> Self {
        let ttl = std::time::Duration::from_secs(300); // 5 minutes
        let captcha_gate =
            sid_authn::captcha::CaptchaGate::new(cache_backend.clone(), key_manager.clone());
        // A standalone installation co-locates the history evaluator.
        let (password_ops, history_evaluation) =
            super::password_operation::PasswordOperations::with_authority(
                storage.clone(),
                cache_backend.clone(),
                key_manager.clone(),
                installation_org,
                super::password_operation::PasswordHistoryAuthority::InProcess {
                    history_keys: key_manager.clone(),
                    epoch_cutoff: None,
                    serve: None,
                },
            );
        let password_ops = Arc::new(password_ops);
        Self {
            storage,
            oauth2,
            webauthn,
            jwt,
            opaque_router,
            opaque_zkpp,
            revocation_cache,
            feature_flags,
            login_state: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "opaque-login",
                ttl,
            ),
            registration_state: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "opaque-registration",
                ttl,
            ),
            password_ops,
            history_evaluation,
            evaluator_admission: super::password_operation::PrepareAdmission::InProcess,
            cache: cache_backend.clone(),
            webauthn_state: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "webauthn-binding",
                ttl,
            ),
            step_up_state: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "webauthn-step-up",
                ttl,
            ),
            migration_state: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "legacy-migration",
                ttl,
            ),
            totp_enrollment: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "totp-enrollment",
                ttl,
            ),
            continuations: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "authorize-continuation",
                authorize::CONTINUATION_TTL,
            ),
            logout_confirmations: ChallengeStore::new(
                cache_backend.clone(),
                key_manager.clone(),
                "logout-confirmation",
                end_session::CONFIRMATION_TTL,
            ),
            magic_link,
            otp,
            dpop_validator: DPopValidator::new(cache_backend.clone()),
            issuers,
            installation_org,
            public_origin: url::Url::parse(&issuer)
                .expect("the installation URL is validated at start-up")
                .origin()
                .ascii_serialization(),
            issuer,
            assertion_jti_cache: Arc::new(sid_authn::client_assertion::AssertionJtiCache::new(
                cache_backend.clone(),
            )),
            rate_limiter: Arc::new(crate::rate_limit::RateLimiter::new(cache_backend.clone())),
            rate_limit_stats: Arc::new(crate::rate_limit::RateLimitStats::new(
                cache_backend.clone(),
            )),
            totp_replay: sid_authn::TotpReplayGuard::new(cache_backend.clone()),
            anomaly_detector: Arc::new(AnomalyDetector::ce_default(cache_backend)),
            ip_intelligence,
            geoip,
            security_policy: SecurityPolicy::ce_default(),
            captcha_provider,
            captcha_gate,
            key_manager,
            cascade,
            trusted_proxies: sid_authn::client_address::TrustedProxies::none(),
            authz,
            sign_in_origin: None,
        }
    }

    /// Set the IdP session cookie on ceremonies the sign-in page at
    /// `sign_in` runs.
    pub fn with_sign_in_page(mut self, sign_in: &url::Url) -> Self {
        self.sign_in_origin = Some(sign_in.origin());
        self
    }

    /// Whether `metadata` is a request of the sign-in page: exactly one
    /// `Origin`, equal to that page's. The check is the login-CSRF defence of
    /// the cookie a ceremony sets; another caller gets no cookie.
    fn is_sign_in_page_request(&self, metadata: &tonic::metadata::MetadataMap) -> bool {
        let Some(allowed) = &self.sign_in_origin else {
            return false;
        };
        let mut origins = metadata.get_all("origin").iter();
        match (origins.next(), origins.next()) {
            (Some(origin), None) => origin
                .to_str()
                .is_ok_and(|origin| sid_authn::browser_session::origin_is(origin, allowed)),
            _ => false,
        }
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

    /// The `sub` a token `issuer` gives `client` carries for `profile_id`,
    /// under the rule of that hop.
    async fn subject_for(
        &self,
        issuer: &sid_core::models::OidcIssuer,
        profile_id: ProfileId,
        client: &sid_core::models::OAuth2Client,
    ) -> Result<String, Status> {
        let rule = SubjectRule::for_hop(issuer, client).map_err(|e| {
            tracing::error!(error = %e, client = %client.client_id, "no subject rule for this hop");
            Status::from(ApiError::internal())
        })?;
        resolve_subject(self.storage.as_ref(), profile_id, client, rule)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, client = %client.client_id, "subject not resolved");
                Status::from(ApiError::internal())
            })
    }

    /// Believe the forwarding headers of these proxies.
    pub fn with_trusted_proxies(
        mut self,
        proxies: sid_authn::client_address::TrustedProxies,
    ) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    /// Where this service's password history evaluator runs.
    pub fn with_password_history(
        mut self,
        authority: super::password_operation::PasswordHistoryAuthority,
    ) -> Self {
        let (ops, evaluation) = super::password_operation::PasswordOperations::with_authority(
            self.storage.clone(),
            self.cache.clone(),
            self.key_manager.clone(),
            self.installation_org,
            authority,
        );
        self.password_ops = Arc::new(ops);
        self.history_evaluation = evaluation;
        self
    }

    /// Who may prepare at this server's history evaluator over the network.
    pub fn with_evaluator_admission(
        mut self,
        admission: super::password_operation::PrepareAdmission,
    ) -> Self {
        self.evaluator_admission = admission;
        self
    }

    /// The client address of `request`: the transport peer, or what a
    /// trusted proxy in front of it reports.
    fn client_ip<T>(&self, request: &Request<T>) -> Option<std::net::IpAddr> {
        let header = |name| {
            request
                .metadata()
                .get(name)
                .and_then(|v: &tonic::metadata::MetadataValue<_>| v.to_str().ok())
        };
        self.trusted_proxies.client_ip(
            request.remote_addr().map(|addr| addr.ip()),
            header("x-forwarded-for"),
            header("x-real-ip"),
        )
    }

    /// Override the security policy (useful for testing conditional access wiring).
    pub fn with_security_policy(mut self, policy: SecurityPolicy) -> Self {
        self.security_policy = policy;
        self
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

    /// A profile's primary email and phone for token claims.
    async fn primary_contacts(
        &self,
        profile_id: ProfileId,
    ) -> Result<(Option<ProfileEmail>, Option<ProfilePhone>), Status> {
        let email = self
            .storage
            .get_primary_profile_email(profile_id)
            .await
            .map_err(claims_unavailable)?;
        let phone = self
            .storage
            .get_primary_profile_phone(profile_id)
            .await
            .map_err(claims_unavailable)?;
        Ok((email, phone))
    }

    /// Evaluate login security: anomaly detection + conditional access policy.
    ///
    /// Called AFTER credential verification, BEFORE session creation.
    /// Pipeline: anomaly rules (first match wins) → policy enforcement.
    ///
    /// Returns `Ok(())` if login is allowed, or an appropriate gRPC error.
    async fn evaluate_login_security(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        auth_method: &str,
        user_verified: bool,
        extras: LoginSecurityExtras<'_>,
    ) -> Result<(), Status> {
        let user_agent = extras.user_agent;
        let identity = profile_id.to_string();

        // ── GeoIP resolution ──
        let geo_location = if let Some(ip) = client_ip {
            self.geoip.resolve(ip).await
        } else {
            None
        };
        let country = geo_location.as_ref().map(|g| g.country.clone());

        // ── Stage 1: Anomaly detection ──
        // Every rule runs on every sign-in; a solved CAPTCHA answers only a
        // CAPTCHA requirement, never a lockout or a block.
        // Evaluate CE hardcoded rules in priority order (first match wins).
        // ── IP Intelligence enrichment ──
        // A provider that cannot answer refuses the sign-in: an unknown IP
        // would pass the blocklist it could not check.
        let ip_classification = if let Some(ip) = client_ip {
            self.ip_intelligence
                .classify(ip)
                .await
                .map_err(anomaly_unavailable)?
        } else {
            Default::default()
        };

        // Rules read the sign-in history below; one that cannot be read
        // refuses the sign-in like unreadable attempt state, since an empty
        // history would switch the travel and location checks off.
        // ── Previous sign-in: the baseline of the history rules ──
        let previous = self
            .storage
            .get_most_recent_session_ip(profile_id)
            .await
            .map_err(anomaly_unavailable)?;
        let prev_login_at = previous.as_ref().map(|(_, at)| *at);

        // ── new_ip detection ──
        let new_ip = if let Some(ip) = client_ip {
            let ip_window = std::time::Duration::from_secs(90 * 24 * 3600); // 90 days
            let seen = self
                .storage
                .has_recent_session_from_ip(profile_id, &ip.to_string(), ip_window)
                .await
                .map_err(anomaly_unavailable)?;
            !seen
        } else {
            false
        };

        // ── Impossible travel: previous session location ──
        // Only resolved with a current location to compare against.
        let (prev_latitude, prev_longitude, prev_country) = match (&geo_location, &previous) {
            (Some(_), Some((prev_ip, _))) => {
                // Re-resolve previous IP via GeoIP (cache hit in most cases).
                match prev_ip.parse::<std::net::IpAddr>() {
                    Ok(prev_ip_addr) => match self.geoip.resolve(prev_ip_addr).await {
                        Some(prev_geo) => (
                            Some(prev_geo.latitude),
                            Some(prev_geo.longitude),
                            Some(prev_geo.country),
                        ),
                        None => (None, None, None),
                    },
                    Err(_) => (None, None, None),
                }
            }
            _ => (None, None, None),
        };

        // ── Designated locations: suppress impossible travel between known locations ──
        let designated_countries = self
            .storage
            .get_designated_countries(profile_id)
            .await
            .map_err(anomaly_unavailable)?;

        // ── Device fingerprint: UA hash → device_id ──
        let new_device = if let Some(ua) = user_agent {
            let device_id = compute_device_id(ua);
            let device_window = std::time::Duration::from_secs(90 * 24 * 3600); // 90 days
            let seen = self
                .storage
                .has_recent_session_from_device(profile_id, device_id, device_window)
                .await
                .map_err(anomaly_unavailable)?;
            !seen
        } else {
            false
        };

        let ctx = LoginContext {
            identity: identity.clone(),
            ip: client_ip,
            country,
            failed: false, // This is post-credential-success evaluation
            new_device,
            new_ip,
            is_tor_exit: ip_classification.is_tor_exit(),
            is_datacenter_ip: ip_classification.is_datacenter(),
            is_blocklisted: ip_classification.is_blocklisted(),
            latitude: geo_location.as_ref().map(|g| g.latitude),
            longitude: geo_location.as_ref().map(|g| g.longitude),
            prev_latitude,
            prev_longitude,
            prev_login_at,
            prev_country,
            designated_countries,
        };

        // Rules that cannot read the shared attempt state refuse the
        // sign-in rather than skip the lockout.
        let rule_match = self
            .anomaly_detector
            .evaluate(&ctx)
            .await
            .map_err(anomaly_unavailable)?;

        match rule_match.reaction {
            RuleReaction::Allow => {
                // No anomaly detected — continue to policy evaluation.
                // Publish location_switch event for observability.
                if rule_match.rule == "location_switch" {
                    info!(
                        profile_id = %identity,
                        rule = "location_switch",
                        reason = %rule_match.reason,
                        "Impossible travel suppressed: both locations are designated"
                    );
                    self.publish_security_event(
                        &identity,
                        "location_switch",
                        "allow",
                        &rule_match.reason,
                        client_ip,
                    )
                    .await;
                }
            }
            RuleReaction::HardNo => {
                // Absolute deny — no override, no escalation.
                warn!(
                    profile_id = %identity,
                    rule = rule_match.rule,
                    reason = %rule_match.reason,
                    "Anomaly: HardNo — login denied"
                );
                self.publish_security_event(
                    &identity,
                    rule_match.rule,
                    rule_match.reaction.as_str(),
                    &rule_match.reason,
                    client_ip,
                )
                .await;
                return Err(sign_in_refused());
            }
            RuleReaction::Block => {
                warn!(
                    profile_id = %identity,
                    rule = rule_match.rule,
                    reason = %rule_match.reason,
                    "Anomaly: Block — login denied"
                );
                self.publish_security_event(
                    &identity,
                    rule_match.rule,
                    rule_match.reaction.as_str(),
                    &rule_match.reason,
                    client_ip,
                )
                .await;
                return Err(too_many_attempts(self.anomaly_detector.lockout_duration()));
            }
            RuleReaction::RequireCaptcha => {
                let subject = sid_authn::captcha::CaptchaSubject {
                    profile_id,
                    client_ip,
                };
                if let Some(pass) = extras.captcha_pass
                    && self
                        .captcha_gate
                        .redeem(pass, &subject)
                        .await
                        .map_err(anomaly_unavailable)?
                {
                    info!(
                        profile_id = %identity,
                        rule = rule_match.rule,
                        "Anomaly: RequireCaptcha answered by a solved challenge"
                    );
                } else {
                    warn!(
                        profile_id = %identity,
                        rule = rule_match.rule,
                        reason = %rule_match.reason,
                        "Anomaly: RequireCaptcha — issuing CAPTCHA challenge"
                    );
                    self.publish_security_event(
                        &identity,
                        rule_match.rule,
                        rule_match.reaction.as_str(),
                        &rule_match.reason,
                        client_ip,
                    )
                    .await;
                    // The challenge is recorded for this sign-in, so solving it
                    // earns a pass only for this profile from this client.
                    let challenge = self.captcha_provider.create_challenge();
                    self.captcha_gate
                        .asked(&challenge.challenge_id, &subject)
                        .await
                        .map_err(anomaly_unavailable)?;
                    return Err(captcha_required(&challenge)?.into());
                }
            }
            RuleReaction::StepUp => {
                warn!(
                    profile_id = %identity,
                    rule = rule_match.rule,
                    reason = %rule_match.reason,
                    "Anomaly: StepUp required — MFA verification needed"
                );
                self.publish_security_event(
                    &identity,
                    rule_match.rule,
                    rule_match.reaction.as_str(),
                    &rule_match.reason,
                    client_ip,
                )
                .await;
                return Err(step_up_after_anomaly(rule_match.rule).into());
            }
        }

        // ── Stage 2: Conditional access policy enforcement ──
        // Use ConditionalAccessEngine to evaluate the implied auth level against
        // the CE security policy. Creates a temporary session-like check object
        // since the real session doesn't exist yet.
        let implied = implied_auth_level(
            auth_method,
            self.security_policy.auth.passkey_satisfies_mfa,
            user_verified,
        );
        let mut probe_session = sid_core::models::Session::new(
            profile_id,
            "probe".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        probe_session.assurance_level = implied;

        let decision = sid_authz::conditional_access::ConditionalAccessEngine::check(
            &self.security_policy,
            None, // per-app client override checked at authorize time
            None,
            &probe_session,
        );

        match decision.action {
            sid_core::models::enforcement::EnforcementAction::Allow => {
                // Policy satisfied — continue.
            }
            sid_core::models::enforcement::EnforcementAction::StepUp => {
                info!(
                    profile_id = %identity,
                    auth_method,
                    violations = ?decision.violations,
                    "Policy enforcement: step-up required"
                );
                return Err(step_up_to_acr(self.security_policy.auth.min_acr.acr_value()).into());
            }
            sid_core::models::enforcement::EnforcementAction::Block => {
                warn!(
                    profile_id = %identity,
                    auth_method,
                    violations = ?decision.violations,
                    "Policy enforcement: access denied"
                );
                return Err(sign_in_refused());
            }
            sid_core::models::enforcement::EnforcementAction::Grace => {
                // No grace periods are configured, so this does not occur;
                // if it does, treat as allow.
            }
        }

        // Session limit is enforced atomically in create_session_atomic().
        // No separate check here — the atomic method uses pg_advisory_xact_lock
        // to prevent TOCTOU race conditions.

        // Record successful login for IP reputation (self-learned provider).
        // Both records are evidence for later sign-ins, not limits on this
        // one: a failed write is reported and the sign-in proceeds.
        if let Some(ip) = client_ip
            && let Err(e) = self
                .storage
                .record_ip_reputation_event(&ip.to_string(), true)
                .await
        {
            warn!(error = %e, "failed to record IP reputation event");
        }

        // Record login location for designated location tracking.
        // After 3 logins from the same country, it becomes "designated"
        // and impossible travel between designated locations is suppressed.
        if let Some(geo) = &geo_location
            && let Err(e) = self
                .storage
                .record_login_location(
                    profile_id,
                    &geo.country,
                    geo.latitude,
                    geo.longitude,
                    3, // designated threshold
                )
                .await
        {
            warn!(error = %e, "failed to record login location");
        }

        Ok(())
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
        let locked = self
            .anomaly_detector
            .lockout_active(identity)
            .await
            .map_err(anomaly_unavailable)?;
        if locked {
            return Err(too_many_attempts(self.anomaly_detector.lockout_duration()));
        }
        Ok(())
    }

    /// Answer a login start that cannot succeed exactly like a real one: a
    /// decoy OPAQUE response and a stored state that finish refuses like a
    /// wrong password (RFC 9807 §10.9).
    async fn decoy_login_start(
        &self,
        principal: &str,
        credential_request: &[u8],
        identity: String,
    ) -> Result<OpaqueLoginStartResponse, Status> {
        let fake_id = Self::fake_credential_id(principal);
        let credential_response = self
            .opaque_router
            .fake_login_start(credential_request, &fake_id)
            .map_err(|e| {
                // A malformed request fails here as it would on a real
                // account: the same answer either way.
                warn!("OPAQUE fake login start failed: {}", e);
                authentication_failed()
            })?;
        let state_key = uuid::Uuid::now_v7().to_string();
        self.login_state
            .insert(&state_key, &PendingLogin::Decoy { identity })
            .await?;
        Ok(OpaqueLoginStartResponse {
            credential_response,
            server_login_state: state_key,
        })
    }

    /// Count a failed login attempt (brute force and stuffing limits). An
    /// attempt that cannot be counted refuses the request: an uncounted
    /// guess would never reach the lockout.
    async fn record_failed_login(
        &self,
        identity: &str,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(), Status> {
        self.anomaly_detector
            .record_failed_attempt(identity)
            .await
            .map_err(anomaly_unavailable)?;
        self.record_ip_attempt(client_ip).await?;
        if let Some(ip) = client_ip
            && let Err(e) = self
                .storage
                .record_ip_reputation_event(&ip.to_string(), false)
                .await
        {
            // Reputation is advisory evidence for later scoring, not a limit.
            warn!(error = %e, "failed to record IP reputation event");
        }
        Ok(())
    }

    /// Count an attempt from `client_ip` against the stuffing limit.
    async fn record_ip_attempt(&self, client_ip: Option<std::net::IpAddr>) -> Result<(), Status> {
        match client_ip {
            Some(ip) => self
                .anomaly_detector
                .record_ip_attempt(ip)
                .await
                .map_err(anomaly_unavailable),
            None => Ok(()),
        }
    }

    /// Publish a security event for anomaly rule matches.
    async fn publish_security_event(
        &self,
        profile_id: &str,
        rule: &str,
        reaction: &str,
        reason: &str,
        client_ip: Option<std::net::IpAddr>,
    ) {
        let event_type = match rule {
            "brute_force" | "brute_force_lockout" => event_types::SECURITY_BRUTE_FORCE,
            "country_restriction" => event_types::SECURITY_COUNTRY_BLOCKED,
            "tor_exit" => event_types::SECURITY_TOR_BLOCKED,
            "datacenter_ip" => event_types::SECURITY_DATACENTER_IP,
            "location_switch" => event_types::SECURITY_LOCATION_SWITCH,
            _ => event_types::SECURITY_SUSPICIOUS_LOGIN,
        };
        let event = Event::new(&self.issuer, event_type)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({
                "rule": rule,
                "reaction": reaction,
                "reason": reason,
                "ip": client_ip.map(|ip| ip.to_string()),
            }));
        // No state change carries a refused attempt, so its event is relayed
        // as work of its own; a full backlog drops it with a warning, the
        // anomaly record below still keeps the attempt.
        if let Err(e) = sid_authn::event_relay::relay_observed(&*self.storage, &event).await {
            warn!("Failed to relay security event: {}", e);
        }

        // Persist anomaly event for admin dashboard queries.
        let risk_score = match rule {
            "brute_force" | "brute_force_lockout" => 95,
            "credential_stuffing" => 90,
            "country_restriction" => 50,
            "tor_exit" => 80,
            "datacenter_ip" => 60,
            "new_device_ip" => 30,
            _ => 50,
        };
        let record = sid_core::models::AnomalyEventRecord::new(
            rule,
            profile_id,
            client_ip.map_or(String::new(), |ip| ip.to_string()),
            reason,
            risk_score,
            reaction,
        );
        if let Err(e) = self.storage.save_anomaly_event(&record).await {
            warn!("Failed to persist anomaly event: {}", e);
        }
    }

    /// The installation's public origin, which every URI a sender proof
    /// names starts with.
    pub(crate) fn public_origin(&self) -> &str {
        &self.public_origin
    }

    /// Validate DPoP proof from an OAuth2 token request, if present, against
    /// `target`, the request as it was received (RFC 9449 §4.3).
    /// Returns `Some(DPopBinding)` if proof is valid, `None` if no proof provided.
    async fn validate_dpop_proof(
        &self,
        dpop_proof: &Option<String>,
        target: &sid_authn::resource::RequestTarget,
    ) -> Result<Option<DPopBinding>, Status> {
        let proof_jwt = match dpop_proof.as_deref() {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(None),
        };

        let validated = self
            .dpop_validator
            .validate(proof_jwt, &target.method, &target.uri)
            .await
            .map_err(|e| match e {
                // An unreachable replay record cannot rule out a replay; the
                // client retries the same request.
                sid_authn::dpop::DPopError::ReplayCacheUnavailable => {
                    dependency_unavailable("DPoP replay record", "replay cache unreachable")
                }
                other => {
                    warn!("DPoP proof validation failed: {}", other);
                    dpop_refusal(other)
                }
            })?;

        Ok(Some(validated))
    }

    /// The issuer a request's path names, when it serves clients of
    /// `client_org`. An unknown handle and a client of another issuer both
    /// yield `None`: to the caller the client is unknown at this endpoint, and
    /// no other issuer stands in.
    async fn issuer_serving(
        &self,
        handle: &str,
        client_org: Option<sid_core::models::OrgId>,
    ) -> Result<Option<OidcIssuer>, Status> {
        let issuer = self.issuers.by_handle(handle).await.map_err(|e| {
            warn!(error = %e, "reading the request's OIDC issuer");
            Status::from(ApiError::internal())
        })?;
        Ok(issuer.filter(|issuer| issuer.serves(client_org)))
    }

    /// The client a request to the endpoint of issuer `issuer_handle`
    /// authenticates as (RFC 6749 §2.3), with that issuer.
    async fn authenticated_client(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
    ) -> Result<(sid_core::models::OAuth2Client, OidcIssuer), Status> {
        let client = self
            .storage
            .get_oauth2_client(auth.client_id())
            .await
            .map_err(storage_failure)?
            .ok_or_else(client_refused)?;
        let issuer = self.client_issuer(issuer_handle, &client).await?;
        self.check_client_authentication(&client, &issuer, auth)
            .await?;
        Ok((client, issuer))
    }

    /// The issuer `issuer_handle` names, when it serves the active `client`.
    /// A client this issuer does not serve is refused exactly like one that
    /// does not exist (RFC 6749 §5.2 `invalid_client`).
    async fn client_issuer(
        &self,
        issuer_handle: &str,
        client: &sid_core::models::OAuth2Client,
    ) -> Result<OidcIssuer, Status> {
        let issuer = self
            .issuer_serving(issuer_handle, client.org_id)
            .await?
            .ok_or_else(client_refused)?;
        if !client.active {
            return Err(client_refused());
        }
        Ok(issuer)
    }

    /// Check the credential a request to `issuer` presents for `client`. A
    /// public client presents none; a confidential one proves itself by the
    /// method it registered (OIDC Dynamic Client Registration 1.0 §2
    /// `token_endpoint_auth_method`), so a secret registered for Basic is not
    /// accepted from the request body, and a `private_key_jwt` client signs an
    /// assertion for this issuer's token endpoint with a registered key
    /// (RFC 7523 §3).
    async fn check_client_authentication(
        &self,
        client: &sid_core::models::OAuth2Client,
        issuer: &OidcIssuer,
        auth: &ClientAuthentication,
    ) -> Result<(), Status> {
        if client.is_public() {
            return match auth {
                ClientAuthentication::None { .. } => Ok(()),
                _ => Err(client_refused()),
            };
        }
        if auth.method() != client.token_endpoint_auth_method {
            return Err(client_refused());
        }
        if let ClientAuthentication::Assertion { assertion, .. } = auth {
            let keys = client.jwks.as_ref().ok_or_else(client_refused)?;
            return match sid_authn::client_assertion::validate_client_assertion_with_keys(
                assertion,
                &client.client_id,
                &token_endpoint(issuer),
                keys,
                &self.assertion_jti_cache,
            )
            .await
            {
                Ok(_) => Ok(()),
                Err(sid_core::Error::Internal(e)) => {
                    // An unreachable replay record cannot rule out a replay.
                    Err(dependency_unavailable("client assertion replay record", e))
                }
                Err(e) => {
                    warn!(client_id = %client.client_id, error = %e, "client assertion refused");
                    Err(client_refused())
                }
            };
        }
        let secret = auth.secret().ok_or_else(client_refused)?;
        self.oauth2
            .authenticate_client(secret, client)
            .map_err(|_| client_refused())
    }

    /// The machine user a token request authenticates as, the `kid` of the
    /// credential it used and the issuer its request reached: machine users
    /// belong to the installation, so only the installation organization's
    /// issuer serves them; any other endpoint knows no such client.
    async fn authenticate_machine_user(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
    ) -> Result<(sid_core::models::MachineUser, String, OidcIssuer), Status> {
        use sid_core::models::{CredentialStatus, MachineCredentialType};

        let issuer = self
            .issuer_serving(issuer_handle, Some(self.installation_org))
            .await?
            .ok_or_else(client_refused)?;
        let mu = self
            .storage
            .get_machine_user_by_client_id(auth.client_id())
            .await
            .map_err(storage_failure)?
            .ok_or_else(client_refused)?;
        if !mu.can_authenticate() {
            warn!(client_id = %mu.client_id, "inactive machine user tried to authenticate");
            return Err(client_refused());
        }

        let credentials = self
            .storage
            .list_machine_credentials_by_user(mu.id)
            .await
            .map_err(storage_failure)?;
        let usable = |c: &&sid_core::models::MachineUserCredential, kind: MachineCredentialType| {
            c.credential_type == kind
                && matches!(
                    c.status,
                    CredentialStatus::Active | CredentialStatus::GracePeriod
                )
                && !c.is_expired()
        };

        let used = match auth {
            ClientAuthentication::Basic { secret, .. }
            | ClientAuthentication::Post { secret, .. } => credentials
                .iter()
                .filter(|c| usable(c, MachineCredentialType::ClientSecret))
                .find(|c| {
                    sid_authn::bearer_secret::matches(secret.expose_secret(), &c.credential_data)
                })
                .map(|c| c.kid.clone()),
            ClientAuthentication::Assertion { assertion, .. } => {
                // The assertion's audience is the token endpoint of the issuer
                // the request reached, so one made for another issuer is
                // refused (RFC 7523 §3).
                let audience = token_endpoint(&issuer);
                let mut valid = None;
                for cred in credentials
                    .iter()
                    .filter(|c| usable(c, MachineCredentialType::PrivateKeyJwt))
                {
                    let Some(alg) = cred.algorithm.as_deref() else {
                        continue;
                    };
                    match sid_authn::client_assertion::validate_client_assertion(
                        assertion,
                        &mu.client_id,
                        &audience,
                        &cred.credential_data,
                        alg,
                        &self.assertion_jti_cache,
                    )
                    .await
                    {
                        Ok(_) => {
                            valid = Some(cred.kid.clone());
                            break;
                        }
                        Err(e) => {
                            warn!(client_id = %mu.client_id, error = %e, "client assertion refused");
                        }
                    }
                }
                valid
            }
            ClientAuthentication::None { .. } => None,
        };
        let Some(kid) = used else {
            return Err(client_refused());
        };
        Ok((mu, kid, issuer))
    }

    /// An access token for a client acting for itself (`client_credentials`):
    /// `sub` is the client's own principal and `sid` the credential it used
    /// (see [`ClientActor`]), `aud` the `target` resource, signed by `issuer`,
    /// bound to the request's DPoP key when it sent a proof.
    async fn client_token(
        &self,
        issuer: &OidcIssuer,
        actor: ClientActor<'_>,
        target: &sid_authn::target::Target,
        scopes: Vec<String>,
        req: &OAuth2TokenRequest,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let dpop_binding = self
            .validate_dpop_proof(&req.dpop_proof, proof_target)
            .await?;
        let signer = self.issuer_signer(issuer).await?;
        let client_id = actor.client_id;
        let access_token = self
            .jwt
            .client_access_token_signed_by(
                signer.as_ref(),
                &sid_authn::jwt::ClientGrant {
                    resource: target.audience().as_str(),
                    client_id,
                    subject: actor.subject,
                    credential: actor.credential,
                    scopes: &scopes,
                    dpop: dpop_binding.as_ref(),
                    max_lifetime: actor.max_lifetime,
                },
            )
            .map_err(|e| {
                warn!("Token issuance failed: {}", e);
                Status::from(ApiError::internal())
            })?;
        let token_type = if dpop_binding.is_some() {
            "DPoP"
        } else {
            "Bearer"
        };
        info!("Issued client_credentials token for {}", client_id);
        // RFC 6749 §5.1: the lifetime the token actually has.
        let lifetime = self.jwt.access_token_ttl_secs();
        let expires_in = actor
            .max_lifetime
            .map_or(lifetime, |cap| cap.num_seconds().min(lifetime));
        Ok(Response::new(OAuth2TokenResponse {
            access_token,
            token_type: token_type.to_string(),
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            issued_token_type: None,
        }))
    }
}

/// A client acting for itself, as its token names it.
#[derive(Clone, Copy)]
struct ClientActor<'a> {
    client_id: &'a str,
    /// Its own principal: a machine user's ID, else the OAuth client's id.
    subject: &'a str,
    /// The credential it authenticated with, checked again by the resource.
    credential: &'a str,
    /// Its own token lifetime cap.
    max_lifetime: Option<Duration>,
}

impl AuthServiceImpl {
    /// The authenticated inspector at `issuer_handle`, as its authorization
    /// subject, with the issuer: a confidential OAuth client, or else a
    /// machine user, resolved as the token endpoint resolves a client id. A
    /// machine user's credentials resolve to that machine user under its
    /// restrictions, never to an OAuth client.
    async fn inspector(
        &self,
        issuer_handle: &str,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(String, OidcIssuer), Status> {
        let client = self
            .storage
            .get_oauth2_client(auth.client_id())
            .await
            .map_err(storage_failure)?;
        if let Some(client) = client {
            // A public client has no credential to authenticate with.
            if client.is_public() {
                return Err(client_refused());
            }
            let issuer = self.client_issuer(issuer_handle, &client).await?;
            self.check_client_authentication(&client, &issuer, auth)
                .await?;
            return Ok((format!("oauth_client:{}", client.client_id), issuer));
        }
        let (machine, _, issuer) = self.authenticate_machine_user(issuer_handle, auth).await?;
        self.enforce_machine_restrictions(&machine, client_ip)
            .await?;
        Ok((format!("machine:{}", machine.id), issuer))
    }

    /// The resource a new grant of `requester` under `issuer` is for: the one
    /// the request's `resource` values name, or the requester's default
    /// (RFC 8707 §2). Any refusal is `invalid_target`.
    async fn select_target<'r>(
        &self,
        issuer: &OidcIssuer,
        requester: impl Into<sid_authn::target::Requester<'r>>,
        resource: &[String],
    ) -> Result<sid_authn::target::Target, Status> {
        let requested = sid_authn::target::requested_indicator(resource).map_err(target_refused)?;
        sid_authn::target::select_target(
            self.storage.as_ref(),
            issuer.id,
            requester,
            requested.as_ref(),
        )
        .await
        .map_err(storage_failure)?
        .map_err(target_refused)
    }

    /// The resource an existing grant bound to `bound` is redeemed for: the
    /// request may only repeat it, and it must still accept tokens for
    /// `client` (RFC 8707 §2.2).
    async fn resume_target<'r>(
        &self,
        issuer: &OidcIssuer,
        client: impl Into<sid_authn::target::Requester<'r>>,
        bound: sid_core::models::ResourceId,
        resource: &[String],
    ) -> Result<sid_authn::target::Target, Status> {
        let requested = sid_authn::target::requested_indicator(resource).map_err(target_refused)?;
        sid_authn::target::resume_target(
            self.storage.as_ref(),
            issuer.id,
            client,
            bound,
            requested.as_ref(),
        )
        .await
        .map_err(storage_failure)?
        .map_err(target_refused)
    }

    /// The signer of `issuer`; a key that cannot be opened fails the request.
    async fn issuer_signer(
        &self,
        issuer: &OidcIssuer,
    ) -> Result<Arc<sid_authn::issuer::IssuerSigner>, Status> {
        self.issuers.signer(issuer).await.map_err(|e| {
            warn!(error = %e, issuer = %issuer.canonical_url, "issuer signing key unavailable");
            Status::from(ApiError::internal())
        })
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
        match self.resolve_profile(identifier).await {
            Ok(p) => Ok(Some(p)),
            Err(s) if s.code() == tonic::Code::Unauthenticated => Ok(None),
            Err(s) => Err(s),
        }
    }

    /// Deterministic fake credential ID for anti-enumeration.
    /// Same identifier always produces the same fake ID.
    fn fake_credential_id(identifier: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"sid-fake-credential-id:");
        hasher.update(identifier.as_bytes());
        hasher.finalize().to_vec()
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
    ) -> Result<PendingRegistration, Status> {
        let handle = parse_handle(principal)?;
        let principal_type = handle.principal_type.to_principal_type();
        let (value, email) = (handle.normalized, handle.email);
        match self.resolve_profile(principal).await {
            Ok(_) => Ok(PendingRegistration::ExistingAccount { principal_type }),
            Err(status) if status.code() == Code::Unauthenticated => {
                let held = self
                    .storage
                    .get_principal_by_value(principal_type, &value)
                    .await
                    .map_err(storage_failure)?;
                if held.is_some() {
                    // Held but not resolvable (contested, closed): never registered over.
                    return Ok(PendingRegistration::ExistingAccount { principal_type });
                }
                let instance_claim = self
                    .check_self_registration(principal_type, &value, claim_token)
                    .await?;
                Ok(PendingRegistration::NewAccount {
                    profile_id: ProfileId::generate(),
                    principal_type,
                    value,
                    email,
                    instance_claim,
                    credential_identifier: rand::random(),
                })
            }
            Err(status) => Err(status),
        }
    }

    /// Commit a pending registration with its first credential, atomically. A taken
    /// identifier answers `ALREADY_EXISTS` and nothing is written: the holder is not
    /// contacted, and the registrant must use another identifier and claim this one
    /// from their own account. `finish_principal`, when the finish names one, must
    /// be the identifier the start reserved. `history` is the first password's
    /// accepted history; `completion` the durable result of the operation that
    /// installs it.
    async fn commit_registration(
        &self,
        pending: PendingRegistration,
        finish_principal: Option<&str>,
        build_credential: impl FnOnce(ProfileId) -> Credential,
        history: Option<HistoryCommit>,
        completion: Option<OperationCompletion>,
    ) -> Result<(ProfileId, CredentialId), Status> {
        let (profile_id, principal_type, value, email, instance_claim) = match pending {
            PendingRegistration::NewAccount {
                profile_id,
                principal_type,
                value,
                email,
                instance_claim,
                ..
            } => (profile_id, principal_type, value, email, instance_claim),
            PendingRegistration::ExistingAccount { principal_type } => {
                return Err(already_registered(principal_type));
            }
        };
        if let Some(finish_principal) = finish_principal {
            let (finish_type, finish_value) = parse_principal(finish_principal)?;
            if finish_type != principal_type || finish_value != value {
                return Err(invalid_field(
                    "principal",
                    "not the identifier the registration started for",
                ));
            }
        }

        let mut credential = build_credential(profile_id);
        if credential.credential_type == CredentialType::Opaque {
            credential.data = CredentialData::new(
                self.seal_envelope(profile_id, credential.data.expose())
                    .await?,
            );
        }
        let credential_id = credential.id;
        let mut registration = new_self_registration(
            profile_id,
            principal_type,
            &value,
            email.as_ref(),
            credential,
        )?;
        if let Some(history) = history {
            registration = registration
                .with_history(history)
                .map_err(|e| internal("attach password history", e))?;
        }
        let action = match instance_claim {
            Some(claim) => {
                registration = registration.claiming_instance(claim);
                "profile.admin_claimed"
            }
            None => "profile.self_register",
        };
        let created = Event::new(&self.issuer, event_types::USER_CREATED)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({ "profile_id": profile_id.to_string() }));
        let mut ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            action,
            profile_id.to_string(),
        ))
        .with_work(created.relay());
        if let Some(completion) = completion {
            ctx = ctx.with_operation(completion);
        }
        match self.storage.register_profile(&registration, ctx).await {
            Ok(()) => {}
            // Another registration took the identifier between start and finish.
            Err(sid_core::Error::Conflict(_)) => return Err(already_registered(principal_type)),
            // The claim was taken between start and finish.
            Err(sid_core::Error::InvalidState(_)) => {
                return Err(registration_restricted("instance_claim"));
            }
            Err(e) => return Err(storage_failure(e)),
        }

        info!("Self-registration committed for profile {}", profile_id);
        Ok((profile_id, credential_id))
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

    /// Gate a new self-registration. While the installation has no
    /// administrator, the only registration accepted is one presenting the
    /// instance claim token, whatever the mode (enrollment-policy.md, First
    /// Administrator); it returns the sealed claim to consume with the account.
    /// Otherwise the registration switch and the enrollment policy decide.
    /// Self-registration carries no invite, so invite-only and admin-only modes refuse it.
    async fn check_self_registration(
        &self,
        principal_type: PrincipalType,
        value: &str,
        claim_token: Option<&str>,
    ) -> Result<Option<Vec<u8>>, Status> {
        use sid_authn::admin_claim::{self, ClaimError};
        use sid_core::enrollment::EnrollmentDenialReason;
        if admin_claim::is_open(self.storage.as_ref())
            .await
            .map_err(|e| internal("check instance claim", e))?
        {
            let Some(token) = claim_token.filter(|t| !t.is_empty()) else {
                return Err(registration_restricted("instance_claim"));
            };
            let token = secrecy::SecretString::from(token.to_owned());
            match admin_claim::verify(self.storage.as_ref(), self.key_manager.as_ref(), &token)
                .await
            {
                Ok(Some(sealed)) => return Ok(Some(sealed)),
                // Claimed meanwhile: an ordinary registration from here on.
                Ok(None) => {}
                Err(ClaimError::Mismatch) => return Err(registration_restricted("instance_claim")),
                Err(e) => return Err(internal("verify instance claim", e)),
            }
        }
        if !self.feature_flags.is_registration_enabled().await {
            return Err(not_configured("registration"));
        }
        let email = matches!(principal_type, PrincipalType::Email).then_some(value);
        if let EnrollmentDecision::Deny(reason) =
            evaluate_enrollment(&self.security_policy.enrollment, email, None)
        {
            return Err(registration_restricted(match reason {
                EnrollmentDenialReason::AdminOnly => "admin_only",
                EnrollmentDenialReason::InviteRequired => "invite",
                EnrollmentDenialReason::EmailRequired => "email",
                EnrollmentDenialReason::DomainNotAllowed { .. } => "email_domain",
            }));
        }
        Ok(None)
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
            self.security_policy.auth.passkey_satisfies_mfa,
        )
        .await
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
            self.security_policy.auth.passkey_satisfies_mfa,
            self.security_policy.password.change_current_password,
        )
        .await
    }

    /// The OPAQUE password file of `credential`, opened, with its curve.
    async fn stored_password(&self, credential: &Credential) -> Result<StoredCredential, Status> {
        let curve = super::convert::opaque_curve(credential, self.opaque_router.primary_curve())?;
        Ok(StoredCredential {
            curve,
            data: self.open_envelope(credential).await?.to_vec(),
        })
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

    /// Record a successful assertion on the passkey that made it: its new
    /// signature counter and backup state, and when it was used. The counter
    /// is what later assertions are checked against, so a copy of the key is
    /// noticed; the write is a compare-and-swap on the credential, so of two
    /// assertions racing on one key only one is recorded and the other
    /// sign-in fails, as it does when the credential was revoked meanwhile.
    /// Returns the RFC 8176 method of the key that asserted.
    async fn record_passkey_use(
        &self,
        passkeys: &[Credential],
        verified: &VerifiedAssertion,
    ) -> Result<&'static str, Status> {
        let credential = passkeys
            .iter()
            .find(|c| c.id == verified.credential)
            .ok_or_else(authentication_failed)?;
        let audit = || {
            MutationContext::from(AuditEntry::user(
                credential.profile_id.to_string(),
                "credential.passkey_used",
                credential.id.0.to_string(),
            ))
        };
        let recorded = match &verified.updated_data {
            Some(updated) => {
                self.storage
                    .replace_credential_data(
                        credential.id,
                        credential.data.expose(),
                        updated,
                        audit(),
                    )
                    .await
            }
            None => {
                self.storage
                    .mark_credential_used(credential.id, audit())
                    .await
            }
        }
        .map_err(storage_failure)?;
        if recorded {
            Ok(verified.key_amr)
        } else {
            Err(authentication_failed())
        }
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

    async fn resolve_profile(&self, identifier: &str) -> Result<sid_core::models::Profile, Status> {
        let handle = parse_handle(identifier)?;
        let principal_type = handle.principal_type.to_principal_type();

        // The explicit assignment is the only route: other claims and the age
        // of the proof neither select nor block a subject, and an email key
        // of another policy revision (one whose address is not established
        // under the current rules) routes nobody. Every refusal reads the
        // same, so the answer does not reveal the state of the address.
        match self
            .storage
            .get_principal_by_value(principal_type, &handle.normalized)
            .await
        {
            Ok(Some(principal)) => {
                let Some(profile_id) = principal.assigned_profile_id else {
                    return Err(authentication_failed());
                };
                let bindings = self
                    .storage
                    .get_principal_bindings(principal.id)
                    .await
                    .map_err(storage_failure)?;
                let has_claim = bindings.iter().any(|b| b.profile_id == profile_id);
                if !sid_core::models::check_principal_eligibility(
                    &principal,
                    profile_id,
                    has_claim,
                    handle.key_revision(),
                )
                .is_eligible()
                {
                    return Err(authentication_failed());
                }
                match self
                    .storage
                    .get_profile(profile_id)
                    .await
                    .map_err(storage_failure)?
                {
                    Some(profile) if profile.status == sid_core::models::ProfileStatus::Active => {
                        Ok(profile)
                    }
                    _ => Err(authentication_failed()),
                }
            }
            // Sign-in resolves principals only; a profile's stored user name or
            // email is not a second route to it.
            Ok(None) => Err(authentication_failed()),
            Err(e) => Err(storage_failure(e)),
        }
    }

    /// The caller's verified access token and the caller it stands for
    /// (signature, issuer, audience, expiry, revocation, sender constraint).
    #[allow(clippy::result_large_err)]
    async fn caller_claims<T>(
        &self,
        request: &Request<T>,
    ) -> Result<sid_authn::caller::Verified, Status> {
        sid_authn::caller::verify_request(request, self.jwt.verifier(), &self.revocation_cache)
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

    /// The envelope `credential` holds, stored back under the current key
    /// version when it was sealed under an older one.
    async fn open_envelope(
        &self,
        credential: &Credential,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Status> {
        let opened = sid_authn::sealed_secret::open(
            self.key_manager.as_ref(),
            &sid_authn::sealed_secret::opaque_context(credential.profile_id),
            credential.data.expose(),
        )
        .await
        .map_err(|e| internal("open OPAQUE envelope", e))?;
        if let Some(resealed) = opened.resealed {
            // Not applied when another reader resealed it first or the
            // password changed meanwhile.
            self.storage
                .reseal_credential_data(
                    credential.id,
                    credential.data.expose(),
                    &resealed,
                    AuditEntry::system("credential.secret_resealed", credential.id.0.to_string())
                        .into(),
                )
                .await
                .map_err(storage_failure)?;
        }
        Ok(opened.secret)
    }

    /// The authenticated caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<sid_authn::caller::Caller, Status> {
        sid_authn::caller::authenticate(request, self.jwt.verifier(), &self.revocation_cache).await
    }

    /// Create session and issue tokens (shared logic for login flows).
    ///
    /// Sets `assurance_level` and `amr` from how the sign-in authenticated.
    /// The session records the client's address and device: the sign-in
    /// history the new-device rule compares later sign-ins with.
    /// A ceremony `metadata` shows the sign-in page ran also gets the IdP
    /// session cookie: a fresh secret whose hash the session stores.
    async fn create_session_and_issue_tokens(
        &self,
        profile: &sid_core::models::Profile,
        method: LoginMethod,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<std::net::IpAddr>,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<SignedIn, Status> {
        // The installation's absolute lifetime, when it sets one.
        let lifetime = match self.security_policy.session.max_lifetime_hours {
            0 => Duration::hours(24),
            hours => Duration::hours(i64::from(hours)),
        };
        let mut session = sid_core::models::Session::new(
            profile.id,
            session_address(client_ip),
            Utc::now() + lifetime,
        );
        let browser = self
            .is_sign_in_page_request(metadata)
            .then(sid_authn::browser_session::BrowserSecret::generate);
        session.browser_secret_hash = browser.as_ref().map(|secret| secret.hash());
        session.device_id = device_id;
        session.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
        session.assurance_level =
            method.auth_level(self.security_policy.auth.passkey_satisfies_mfa);
        session.amr = method.amr();
        let expires_at = session.expires_at;
        let (session_id, access_token, expires_in) = self
            .persist_session_and_issue_token(profile, session)
            .await?;
        Ok(SignedIn {
            session_id,
            access_token,
            expires_in,
            cookie: browser
                .map(|secret| secret.set_cookie((expires_at - Utc::now()).num_seconds())),
        })
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
    ) -> Result<(String, String, i64), Status> {
        let mut session =
            sid_core::models::Session::new_provisional(profile.id, session_address(client_ip));
        session.device_id = device_id;
        session.amr = vec![amr.to_string()];
        self.persist_session_and_issue_token(profile, session).await
    }

    /// Store `session` under the concurrent-session limit, announce it and issue
    /// its access token. Returns (session id, token, seconds until the token expires).
    async fn persist_session_and_issue_token(
        &self,
        profile: &sid_core::models::Profile,
        session: sid_core::models::Session,
    ) -> Result<(String, String, i64), Status> {
        // The storage counts, evicts and inserts in one serialized step, and
        // owes each evicted session's client a logout; the same commit owes
        // the session.created event.
        let max_sessions = self.security_policy.session.max_concurrent_sessions;
        let _audit_start = std::time::Instant::now();
        let created = Event::new(&self.issuer, event_types::SESSION_CREATED)
            .with_subject(format!("session/{}", session.id))
            .with_data(serde_json::json!({
                "profile_id": profile.id.to_string(),
                "session_id": session.id.to_string(),
            }));
        let ctx = MutationContext::from(AuditEntry::user(
            profile.id.to_string(),
            "session.create",
            session.id.to_string(),
        ))
        .with_work(created.relay());
        let evicted = self
            .storage
            .create_session_atomic(&session, max_sessions, ctx)
            .await
            .map_err(storage_failure)?;
        if !evicted.is_empty() {
            info!(
                profile_id = %profile.id,
                evicted_count = evicted.len(),
                "Session limit enforced: evicted oldest sessions"
            );
        }
        // An evicted session's access tokens stop at once in every process;
        // when that cannot be propagated the sign-in fails rather than leave
        // them live elsewhere.
        for ended in &evicted {
            self.revocation_cache
                .revoke_session(ended.to_string())
                .await
                .map_err(|e| dependency_unavailable("session revocation", e))?;
        }
        #[cfg(feature = "telemetry")]
        {
            use opentelemetry::{KeyValue, global};
            global::meter("sid")
                .f64_histogram("sid_audit_write_seconds")
                .build()
                .record(
                    _audit_start.elapsed().as_secs_f64(),
                    &[KeyValue::new("chain_scope", "session")],
                );
        }

        let sub = profile.id.to_string();
        let access_token = self
            .jwt
            .issue_access_token(
                &sub,
                Some(&sub),
                profile,
                &session,
                &session.scopes,
                None,
                None,
            )
            .map_err(|e| internal("issue access token", e))?;

        // The token expires with the session when the session is shorter.
        let expires_in = self
            .jwt
            .access_token_ttl_secs()
            .min((session.expires_at - Utc::now()).num_seconds());

        Ok((session.id.to_string(), access_token, expires_in))
    }

    /// SERVICE_MAINTENANCE while the installation is in maintenance mode.
    async fn check_maintenance(&self) -> Result<(), Status> {
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
        credential_id: &str,
        caller: ProfileId,
    ) -> Result<Credential, Status> {
        let cred_id = uuid::Uuid::parse_str(credential_id)
            .map(CredentialId)
            .map_err(|_| invalid_field("credential_id", "not a credential identifier"))?;
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
    /// its own service.
    pub fn history_evaluator(
        &self,
    ) -> Option<super::password_operation::PasswordHistoryEvaluatorImpl> {
        self.history_evaluation.clone().map(|evaluation| {
            super::password_operation::PasswordHistoryEvaluatorImpl::new(
                evaluation,
                self.evaluator_admission.clone(),
            )
        })
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
        id: &str,
    ) -> Result<sid_core::models::PasswordResetSession, Status> {
        let session_id = uuid::Uuid::parse_str(id)
            .map_err(|_| invalid_field("reset_session_id", "not a reset session identifier"))?;
        // An unknown reset session and an expired one answer alike: either
        // way the reset starts again.
        let session = self
            .storage
            .get_reset_session(sid_core::models::ResetSessionId(session_id))
            .await
            .map_err(storage_failure)?
            .filter(|s| !s.is_expired())
            .ok_or_else(|| ceremony_expired("password reset"))?;
        if session.status != sid_core::models::ResetSessionStatus::Verified {
            return Err(
                ApiError::new(ErrorReason::InvalidState, "the reset is not verified yet")
                    .with_precondition("RESET_SESSION_STATE", id, "unverified")
                    .into(),
            );
        }
        Ok(session)
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    // ── OPAQUE Registration ──

    #[tracing::instrument(skip_all, fields(rpc = "opaque_registration_start"))]
    #[instrument(skip_all, fields(method = "opaque_registration_start"))]
    async fn opaque_registration_start(
        &self,
        request: Request<OpaqueRegistrationStartRequest>,
    ) -> Result<Response<OpaqueRegistrationStartResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();
        let pending = self
            .begin_registration(&req.principal, req.claim_token.as_deref())
            .await?;

        let (response_bytes, _state) = self
            .opaque_router
            .registration_start(&req.registration_request, &pending.credential_identifier())
            .map_err(|e| {
                warn!("OPAQUE registration start failed: {}", e);
                invalid_field(
                    "registration_request",
                    "not a valid OPAQUE registration request",
                )
            })?;

        let state_key = uuid::Uuid::now_v7().to_string();
        self.registration_state.insert(&state_key, &pending).await?;

        Ok(Response::new(OpaqueRegistrationStartResponse {
            registration_response: response_bytes,
            server_setup: state_key,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "opaque_registration_finish"))]
    #[instrument(skip_all, fields(method = "opaque_registration_finish"))]
    async fn opaque_registration_finish(
        &self,
        request: Request<OpaqueRegistrationFinishRequest>,
    ) -> Result<Response<OpaqueRegistrationFinishResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        let pending = self
            .registration_state
            .take(&req.server_setup)
            .await?
            .ok_or_else(|| ceremony_expired("registration"))?;

        let stored = self
            .opaque_router
            .registration_finish(&req.registration_record)
            .map_err(|e| {
                warn!("OPAQUE registration finish failed: {}", e);
                invalid_field(
                    "registration_record",
                    "not a valid OPAQUE registration record",
                )
            })?;

        let curve = stored.curve as u8;
        let identifier = pending.credential_identifier();
        let (profile_id, credential_id) = self
            .commit_registration(
                pending,
                Some(&req.principal),
                |profile_id| {
                    let mut credential =
                        Credential::new(profile_id, CredentialType::Opaque, stored.data, None);
                    credential.opaque_curve = Some(curve);
                    credential.opaque_credential_identifier = Some(identifier);
                    credential
                },
                None,
                None,
            )
            .await?;

        Ok(Response::new(OpaqueRegistrationFinishResponse {
            profile_id: profile_id.to_string(),
            credential_id: credential_id.0.to_string(),
        }))
    }

    // ── OPAQUE Login ──

    #[tracing::instrument(skip_all, fields(rpc = "opaque_login_start"))]
    #[instrument(skip_all, fields(method = "opaque_login_start"))]
    async fn opaque_login_start(
        &self,
        request: Request<OpaqueLoginStartRequest>,
    ) -> Result<Response<OpaqueLoginStartResponse>, Status> {
        self.check_maintenance().await?;
        let req = request.into_inner();

        // Anti-enumeration: a start that cannot succeed is answered like a
        // real one (decoy), never refused early. Failed attempts count against
        // the profile when one holds the principal, else against the principal.
        let profile = self.resolve_profile_optional(&req.principal).await?;
        let identity = profile
            .as_ref()
            .map_or_else(|| req.principal.clone(), |p| p.id.to_string());
        self.refuse_if_locked(&identity).await?;

        let Some(profile) = profile else {
            return Ok(Response::new(
                self.decoy_login_start(&req.principal, &req.credential_request, identity)
                    .await?,
            ));
        };

        // Get OPAQUE credential
        let credentials = self
            .storage
            .get_credentials_by_profile(profile.id, Some(CredentialType::Opaque))
            .await
            .map_err(storage_failure)?;

        // Storage keeps at most one active OPAQUE credential per profile; revoked
        // rows stay for history and never authenticate.
        let opaque_cred = match credentials.iter().find(|c| c.status.is_active()) {
            Some(cred) => cred,
            None => {
                // No OPAQUE credential — check for legacy hash (migration case)
                let legacy = self
                    .storage
                    .get_credentials_by_profile(profile.id, Some(CredentialType::LegacyHash))
                    .await
                    .map_err(storage_failure)?;

                if !legacy.is_empty() {
                    return Err(ApiError::new(
                        ErrorReason::LegacyMigrationRequired,
                        "the password must be migrated before signing in",
                    )
                    .with_precondition(
                        "legacy_migration",
                        "credential",
                        "complete the password migration flow",
                    )
                    .into());
                }
                // A profile without a password (passkey-only, provisioned)
                // is answered like an unknown principal.
                return Ok(Response::new(
                    self.decoy_login_start(&req.principal, &req.credential_request, identity)
                        .await?,
                ));
            }
        };

        let credential_id = opaque_cred.opaque_credential_identifier();
        let stored_cred = self.stored_password(opaque_cred).await?;
        let (credential_response, login_state) = self
            .opaque_router
            // An ordinary sign-in has the empty context.
            .login_start(&stored_cred, &req.credential_request, &credential_id, &[])
            .map_err(|e| {
                warn!("OPAQUE login start failed for {}: {}", req.principal, e);
                authentication_failed()
            })?;

        // Store login state server-side, return key to client
        let state_key = uuid::Uuid::now_v7().to_string();
        self.login_state
            .insert(
                &state_key,
                &PendingLogin::Password {
                    state: login_state,
                    profile_id: profile.id,
                    credential_id: opaque_cred.id,
                },
            )
            .await?;

        Ok(Response::new(OpaqueLoginStartResponse {
            credential_response,
            server_login_state: state_key,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "opaque_login_finish"))]
    #[instrument(skip_all, fields(method = "opaque_login_finish"))]
    async fn opaque_login_finish(
        &self,
        request: Request<OpaqueLoginFinishRequest>,
    ) -> Result<Response<OpaqueLoginFinishResponse>, Status> {
        self.check_maintenance().await?;
        let client_ip = self.client_ip(&request);
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let (metadata, _, req) = request.into_parts();

        // Retrieve login state
        let pending = self
            .login_state
            .take(&req.server_login_state)
            .await?
            .ok_or_else(|| ceremony_expired("sign-in"))?;
        let (login_state, profile_id, credential_id) = match pending {
            PendingLogin::Password {
                state,
                profile_id,
                credential_id,
            } => (state, profile_id, credential_id),
            PendingLogin::Decoy { identity } => {
                // A lockout reached while this attempt was in flight answers
                // the same here as for a real account.
                self.refuse_if_locked(&identity).await?;
                self.record_failed_login(&identity, client_ip).await?;
                return Err(authentication_failed());
            }
        };
        // Checked before the password: during a lockout a right and a wrong
        // password get the same answer.
        self.refuse_if_locked(&profile_id.to_string()).await?;

        // Verify OPAQUE login
        let _session_key =
            match self
                .opaque_router
                .login_finish(&login_state, &req.credential_finalization, &[])
            {
                Ok(key) => key,
                Err(e) => {
                    warn!("OPAQUE login finish failed: {}", e);
                    self.record_failed_login(&profile_id.to_string(), client_ip)
                        .await?;
                    return Err(authentication_failed());
                }
            };

        // A profile deleted while the sign-in was in flight signs nobody in.
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(authentication_failed)?;

        // The password this login used must still be active: one revoked while
        // the login was in flight neither signs in nor comes back to active.
        let still_active = self
            .storage
            .mark_credential_used(
                credential_id,
                AuditEntry::user(
                    profile.id.to_string(),
                    "credential.used",
                    credential_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !still_active {
            return Err(authentication_failed());
        }
        // Evaluate login security (anomaly detection + policy enforcement).
        self.evaluate_login_security(
            profile.id,
            client_ip,
            "opaque",
            false,
            LoginSecurityExtras {
                captcha_pass: captcha_pass.as_deref(),
                user_agent: user_agent.as_deref(),
            },
        )
        .await?;

        let signed_in = self
            .create_session_and_issue_tokens(
                &profile,
                LoginMethod::Password,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                &metadata,
            )
            .await?;

        info!("OPAQUE login for profile {}", profile.id);

        signed_in.respond(
            |session_id, access_token, expires_in| OpaqueLoginFinishResponse {
                session_id,
                access_token,
                expires_in,
            },
        )
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
            .begin_registration(&req.principal, req.claim_token.as_deref())
            .await?;
        let owner = match &pending {
            PendingRegistration::NewAccount { profile_id, .. } => OperationOwner::New(*profile_id),
            PendingRegistration::ExistingAccount { .. } => OperationOwner::Decoy,
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
            .await?;

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
        let id = operation_id(req.operation_id.as_ref())?;
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
                    _ => Err(super::password_operation::operation_not_pending()),
                },
            )
            .await?
        {
            Finish::Completed(result) => {
                return Ok(Response::new(Self::recorded_response(&result)?));
            }
            Finish::Ready(done) => *done,
        };
        let OperationPurpose::Registration { pending } = &done.operation.purpose else {
            return Err(super::password_operation::operation_not_pending());
        };
        let pending = pending.clone();
        let profile_id = match &pending {
            PendingRegistration::NewAccount { profile_id, .. } => *profile_id,
            PendingRegistration::ExistingAccount { principal_type } => {
                return Err(already_registered(*principal_type));
            }
        };
        let credential = done.credential(profile_id, done.password_file.clone());
        let response = OpaqueZkppRegistrationFinishResponse {
            profile_id: profile_id.to_string(),
            credential_id: credential.id.0.to_string(),
        };
        let completion = done.completion(Self::finish_result(&response));
        self.commit_registration(
            pending,
            None,
            |_| credential,
            done.history,
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
        let credential = self.own_password(&req.credential_id, caller).await?;
        // The challenge fixes the new password's request: the current
        // password is confirmed for it, and execute starts no other.
        if req.registration_request.is_empty() {
            return Err(missing_field("registration_request"));
        }
        let proves = !req.credential_request.is_empty();
        if required && !proves {
            return Err(sid_authn::credential_enrollment::current_password_required());
        }
        if proves {
            // As at sign-in: during a lockout the current password is not tried.
            self.refuse_if_locked(&caller.to_string()).await?;
            // A wrong guess fails on the client at KE2 and need never reach
            // execute, so each KE2 issued is counted now, against the
            // change's own budget: a stolen session cannot guess the password
            // through changes, and the account's sign-in budget is untouched.
            let guesses = current_password_guesses(caller);
            self.refuse_if_locked(&guesses).await?;
            self.anomaly_detector
                .record_failed_attempt(&guesses)
                .await
                .map_err(anomaly_unavailable)?;
        }
        let prepared = self
            .password_ops
            .prepare(
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
            .await?;

        let credential_response = if proves {
            let id = operation_id(prepared.context.operation_id.as_ref())?;
            let stored = self.stored_password(&credential).await?;
            let (response, state) = self
                .opaque_router
                .login_start(
                    &stored,
                    &req.credential_request,
                    &credential.opaque_credential_identifier(),
                    &change_context(&id, &req.registration_request),
                )
                .map_err(|e| {
                    warn!("current-password sign-in start failed: {e}");
                    invalid_field("credential_request", "not an OPAQUE credential request")
                })?;
            self.password_ops
                .begin_current_password(&id, state, |op| own_change(op, caller, &credential))
                .await?;
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
        let client_ip = self.client_ip(&request);

        let zkpp = self.require_zkpp()?;
        let caller = verified.caller.profile_id;
        let required = self.password_change_authority(&verified.caller).await?;

        let req = request.into_inner();
        let credential = self.own_password(&req.credential_id, caller).await?;
        let id = operation_id(req.operation_id.as_ref())?;
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
            .await?;
        match check {
            CurrentPasswordCheck::Failed => {
                self.record_failed_login(&caller.to_string(), client_ip)
                    .await?;
                return Err(authentication_failed());
            }
            CurrentPasswordCheck::NotBegun if required => {
                return Err(sid_authn::credential_enrollment::current_password_required());
            }
            CurrentPasswordCheck::NotBegun | CurrentPasswordCheck::Proven => {}
        }
        let registration_response = self
            .password_ops
            .fixed_opaque_start(&zkpp, &id, |op| own_change(op, caller, &credential))
            .await?;

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
        let credential = self.own_password(&req.credential_id, caller).await?;
        let id = operation_id(req.operation_id.as_ref())?;
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
                        return Err(sid_authn::credential_enrollment::current_password_required());
                    }
                    Ok(())
                },
            )
            .await?
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
        let changed = self
            .storage
            .change_password(credential.id, &current, &new, done.history.as_ref(), ctx)
            .await
            .map_err(storage_failure)?;
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
            self.security_policy.password.change_current_password,
        )
        .await?;
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
            .await?;

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
            .await?
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
            credential_id: cred.id.0.to_string(),
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
                .await?;
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
            challenge: result.state_key.clone().into_bytes(),
            options: result.options,
            state_key: result.state_key,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "web_authn_authentication_finish"))]
    #[instrument(skip_all, fields(method = "web_authn_authentication_finish"))]
    async fn web_authn_authentication_finish(
        &self,
        request: Request<WebAuthnAuthenticationFinishRequest>,
    ) -> Result<Response<WebAuthnAuthenticationFinishResponse>, Status> {
        self.check_maintenance().await?;
        let client_ip = self.client_ip(&request);
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let (metadata, _, req) = request.into_parts();

        let not_an_assertion = || invalid_field("credential", "not a WebAuthn assertion");

        let user_verified;
        let key_amr;
        let profile = if let Some(identifier) = &req.principal {
            // ── Identifier-based flow ──
            let credential =
                AssertionResponse::parse(&req.credential).map_err(|_| not_an_assertion())?;
            let p = self.resolve_profile(identifier).await?;

            // The ceremony the assertion answers, started for this profile.
            let expired = || ceremony_expired("passkey sign-in");
            let state_key = credential.state_key().map_err(|_| expired())?;
            let started_for = self
                .webauthn_state
                .take(&state_key)
                .await?
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
            key_amr = self.record_passkey_use(&passkeys, &verified).await?;

            p
        } else {
            // ── Conditional UI / Discoverable flow ──
            // The ceremony state is found from the assertion and consumed by
            // the finish below (single use); `req.state_key` is not needed.
            let credential = DiscoverableAssertionResponse::parse(&req.credential)
                .map_err(|_| not_an_assertion())?;

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
            key_amr = self.record_passkey_use(&passkeys, &verified).await?;

            p
        };

        // Evaluate login security (anomaly detection + policy enforcement).
        self.evaluate_login_security(
            profile.id,
            client_ip,
            "webauthn",
            user_verified,
            LoginSecurityExtras {
                captcha_pass: captcha_pass.as_deref(),
                user_agent: user_agent.as_deref(),
            },
        )
        .await?;

        let signed_in = self
            .create_session_and_issue_tokens(
                &profile,
                LoginMethod::Passkey {
                    user_verified,
                    key_amr,
                },
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                &metadata,
            )
            .await?;

        info!("WebAuthn login for profile {}", profile.id);

        signed_in.respond(|session_id, access_token, expires_in| {
            WebAuthnAuthenticationFinishResponse {
                session_id,
                access_token,
                expires_in,
            }
        })
    }

    // ── OAuth2 ──

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_authorize"))]
    #[instrument(skip_all, fields(method = "o_auth2_authorize"))]
    async fn o_auth2_authorize(
        &self,
        request: Request<OAuth2AuthorizeRequest>,
    ) -> Result<Response<OAuth2AuthorizeResponse>, Status> {
        self.check_maintenance().await?;
        let (client, issuer) = self.authorize_client(request.get_ref()).await?;

        // The bearer token names the session; the code carries that session's
        // authentication, so it must still authorize and be fresh enough for
        // the request. A caller of this RPC is its own interface, so the
        // interaction `prompt` asks for is its to have shown.
        // Only the IdP session's own token: an application's session never
        // authorizes codes for other clients.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation()?;
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
        let client_ip = self.client_ip(&request);
        // The request a DPoP proof must name: as received, over REST or gRPC.
        let proof_target =
            sid_authn::resource::request_target(&request, &self.public_origin, OAUTH2_TOKEN_RPC);
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

        let client = || {
            client_authentication(
                &metadata,
                req.client_id.as_deref(),
                req.client_secret.as_deref(),
                req.client_assertion.as_deref(),
                req.client_assertion_type.as_deref(),
            )
        };
        match req.grant_type.as_str() {
            "authorization_code" => {
                self.handle_authorization_code_grant(&req, &client()?, &proof_target)
                    .await
            }
            "refresh_token" => {
                self.handle_refresh_token_grant(&req, &client()?, &proof_target)
                    .await
            }
            "client_credentials" => {
                self.handle_client_credentials_grant(&req, &client()?, client_ip, &proof_target)
                    .await
            }
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                self.handle_token_exchange_grant(&req, &client()?, client_ip)
                    .await
            }
            DEVICE_CODE_GRANT => self.handle_device_code_grant(&req, &client()?).await,
            _ => Err(token_refusal(
                TokenError::UnsupportedGrantType,
                "unsupported grant_type",
            )),
        }
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_introspect"))]
    #[instrument(skip_all, fields(method = "o_auth2_introspect"))]
    async fn o_auth2_introspect(
        &self,
        request: Request<OAuth2IntrospectRequest>,
    ) -> Result<Response<OAuth2IntrospectResponse>, Status> {
        let client_ip = self.client_ip(&request);
        let (metadata, _, req) = request.into_parts();

        // RFC 7662 §2.1, §4: only an authenticated service identity of this
        // issuer may introspect, so tokens cannot be probed.
        let auth = client_authentication(
            &metadata,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (inspector, issuer) = self.inspector(&req.issuer_handle, &auth, client_ip).await?;

        let inactive = || Response::new(OAuth2IntrospectResponse::default());
        let verifier = self
            .issuers
            .verifier(&issuer)
            .await
            .map_err(|e| internal("read issuer keys for introspection", e))?;
        // Only this issuer's access tokens are active here (RFC 7662 §2.2).
        let Ok(claims) = verifier.validate_access_token(&req.token) else {
            return Ok(inactive());
        };
        // The token's target is the registered resource its one audience
        // names; the inspector must hold the inspection permission on it.
        let target = match claims.aud.as_slice() {
            [audience] => match sid_core::models::ResourceIndicator::parse(audience) {
                Ok(indicator) => self
                    .storage
                    .protected_resource_by_indicator(issuer.id, &indicator)
                    .await
                    .map_err(storage_failure)?,
                Err(_) => None,
            },
            _ => None,
        };
        let Some(target) = target else {
            return Ok(inactive());
        };
        let decision = self
            .authz
            .check(&sid_plugin::authz::AuthzCheckRequest {
                subject: inspector,
                action: sid_core::models::TOKEN_INTROSPECT.to_string(),
                resource: format!("oauth_resource:{}", target.id),
                context: Default::default(),
            })
            .await
            // Never disclose claims without a decision.
            .map_err(|e| dependency_unavailable("inspection permission", e))?;
        if !decision.is_allowed() {
            return Ok(inactive());
        }
        if sid_authn::caller::check_revocation(&self.revocation_cache, &claims).await? {
            return Ok(inactive());
        }
        // A valid signature says what was true at issuance; the token is
        // active only while the actor it stands for can act now. An
        // unreadable state is an error, never a guess (RFC 7662 §2.2).
        if sid_authn::token_state::current_state(self.storage.as_ref(), &claims)
            .await
            .map_err(|e| dependency_unavailable("token state", e))?
            == sid_authn::token_state::TokenState::Inactive
        {
            return Ok(inactive());
        }
        Ok(Response::new(OAuth2IntrospectResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: claims.client_id,
            username: None,
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "o_auth2_revoke"))]
    #[instrument(skip_all, fields(method = "o_auth2_revoke"))]
    async fn o_auth2_revoke(
        &self,
        request: Request<OAuth2RevokeRequest>,
    ) -> Result<Response<OAuth2RevokeResponse>, Status> {
        let (metadata, _, req) = request.into_parts();

        // RFC 7009 §2.1: the client authenticates as at the token endpoint (a
        // public one only names itself), and only a token issued to it is
        // revoked; another client's token is refused.
        let auth = client_authentication(
            &metadata,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, &auth).await?;
        let not_its_own = || {
            token_refusal(
                TokenError::UnauthorizedClient,
                "the token was issued to another client",
            )
        };
        let verifier = self
            .issuers
            .verifier(&issuer)
            .await
            .map_err(|e| internal("read issuer keys for revocation", e))?;

        // Only this issuer's tokens are revoked here; a token of another
        // issuer is left alone and the answer is still success (RFC 7009 §2.2).
        if let Ok(claims) = verifier.validate_access_token(&req.token) {
            if claims.client_id.as_deref() != Some(client.client_id.as_str()) {
                return Err(not_its_own());
            }
            let now = chrono::Utc::now().timestamp();
            let remaining = claims.exp - now;
            if remaining > 0 {
                self.revocation_cache
                    .revoke_jti(
                        claims.jti.clone(),
                        std::time::Duration::from_secs(remaining as u64),
                    )
                    .await
                    .map_err(|e| dependency_unavailable("token revocation", e))?;
            }
            return Ok(Response::new(OAuth2RevokeResponse {}));
        }

        // Revoke as a refresh token, found by its value: the whole grant ends
        // with it, the token it replaced still inside its rotation grace
        // window included (RFC 7009 §2.1). An unknown value is not an error
        // (§2.2), a storage fault is. The authenticated client is this
        // issuer's, so a refresh token of its own is too.
        let token_hash = OAuth2Server::hash_token(&req.token);
        let stored = self
            .storage
            .get_refresh_token_by_hash(&token_hash)
            .await
            .map_err(storage_failure)?;
        if let Some(refresh) = stored {
            if refresh.client_id != client.client_id {
                return Err(not_its_own());
            }
            self.storage
                .revoke_refresh_tokens_by_family(
                    refresh.family_id,
                    AuditEntry::system("token.revoke", refresh.id.to_string()).into(),
                )
                .await
                .map_err(storage_failure)?;
        }

        // RFC 7009: always return 200 OK
        Ok(Response::new(OAuth2RevokeResponse {}))
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
                session_id: uuid::Uuid::now_v7().to_string(),
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
        if !profile.is_some_and(|p| p.profile_type == ProfileType::Corporate) {
            return unsent();
        }

        // The token leaves this service only inside the email delivery; it is
        // never logged or put into an event.
        let (result, _token) = match magic_link.request_magic_link(&address).await {
            Ok(sent) => sent,
            Err(sid_authn::magic_link::MagicLinkError::RateLimited { .. }) => {
                info!("Magic link request past the per-address limit: no link sent");
                return unsent();
            }
            Err(sid_authn::magic_link::MagicLinkError::Internal(msg)) => {
                return Err(internal("request magic link", msg));
            }
        };

        info!(session_id = %result.session_id, "Magic link requested");

        Ok(Response::new(RequestMagicLinkResponse {
            session_id: result.session_id.to_string(),
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
        let client_ip = self.client_ip(&request);
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let req = request.into_inner();

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| invalid_field("session_id", "not a magic link session identifier"))?;

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
                self.evaluate_login_security(
                    profile.id,
                    client_ip,
                    "magic_link",
                    false,
                    LoginSecurityExtras {
                        captcha_pass: captcha_pass.as_deref(),
                        user_agent: user_agent.as_deref(),
                    },
                )
                .await?;

                // A mailed link, like a mailed code, is mailbox possession over
                // a second channel: `mca` (RFC 8176 §2).
                let (session_id, access_token, expires_in) = self
                    .create_provisional_session_and_issue_tokens(
                        &profile,
                        "mca",
                        user_agent.as_deref().map(compute_device_id),
                        client_ip,
                    )
                    .await?;

                info!("Magic link verified for profile {}", profile.id);

                Ok(Response::new(VerifyMagicLinkResponse {
                    session_id,
                    access_token,
                    expires_in: expires_in as i32,
                }))
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
        let session_id = SessionId::parse(&req.session_id)
            .map_err(|_| invalid_field("session_id", "not a session identifier"))?;

        match self.storage.get_session(session_id).await {
            // Someone else's session answers exactly like an unknown one.
            Ok(Some(session)) if caller.require_self_or_admin(session.profile_id).is_ok() => {
                let now = chrono::Utc::now();
                let valid = session.expires_at > now;

                Ok(Response::new(ValidateSessionResponse {
                    valid,
                    profile_id: Some(session.profile_id.to_string()),
                    scopes: vec![],
                    expires_at: Some(super::convert::to_timestamp(session.expires_at)),
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
        // The client authenticates as at the token endpoint (RFC 8628 §3.1).
        let auth = client_authentication(
            &metadata,
            req.client_id.as_deref(),
            req.client_secret.as_deref(),
            req.client_assertion.as_deref(),
            req.client_assertion_type.as_deref(),
        )?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, &auth).await?;
        // Only a client registered for the device grant starts it (RFC 7591
        // §2 `grant_types`).
        if !client.is_grant_type_allowed(DEVICE_CODE_GRANT) {
            return Err(token_refusal(
                TokenError::UnauthorizedClient,
                "the client may not use the device authorization grant",
            ));
        }
        // The transaction is bound to the resource its tokens will be for.
        let target = self.select_target(&issuer, &client, &req.resource).await?;

        // Only scopes the client may have are recorded, as for an
        // authorization request; the token response says what was granted
        // (RFC 6749 §3.3).
        let scope = req.scope.as_deref().map(|requested| {
            let requested: Vec<String> = requested.split_whitespace().map(String::from).collect();
            client.filter_scopes(&requested).join(" ")
        });

        // The user sees "WDJB-MJHT"; it is stored as looked up, normalized. A
        // taken code (one in 20^8) is drawn again.
        const CODE_ATTEMPTS: usize = 3;
        let mut issued = None;
        for _ in 0..CODE_ATTEMPTS {
            let user_code = device_auth::generate_user_code();
            let (raw_device_code, device_code_hash) = device_auth::generate_device_code();
            let auth_code = sid_core::models::DeviceAuthorizationCode::new(
                client.client_id.clone(),
                device_code_hash,
                device_auth::normalize_user_code(&user_code),
                scope.clone(),
                target.resource_id(),
                client.project_id,
            );
            let audit = sid_core::models::AuditEntry::system(
                "device_authorization.start",
                format!("client_id={}", client.client_id),
            );
            match self
                .storage
                .create_device_auth_code(&auth_code, audit.into())
                .await
            {
                Ok(()) => {
                    issued = Some((user_code, raw_device_code));
                    break;
                }
                Err(sid_core::Error::Conflict(_)) => continue,
                Err(e) => return Err(storage_failure(e)),
            }
        }
        let (user_code, raw_device_code) = issued.ok_or_else(|| {
            storage_failure(format!(
                "no free device user code after {CODE_ATTEMPTS} attempts"
            ))
        })?;

        // Build verification URIs
        let verification_uri = format!("{}/device", self.issuer);
        let verification_uri_complete =
            device_auth::build_verification_uri_complete(&verification_uri, &user_code);

        info!(
            "Device authorization started for client={}",
            client.client_id
        );

        Ok(Response::new(DeviceAuthorizationResponse {
            device_code: raw_device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: DEVICE_CODE_LIFETIME_SECS as i32,
            interval: DEVICE_CODE_POLL_INTERVAL_SECS,
        }))
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
        verified.require_installation()?;
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
        let decided = self
            .storage
            .decide_device_auth(auth.id, decision, audit.into())
            .await
            .map_err(storage_failure)?;
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
        let client_ip = self.client_ip(&request);
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
        let state_key = uuid::Uuid::now_v7().to_string();
        self.migration_state
            .insert(
                &state_key,
                &MigrationState {
                    profile_id: profile.id,
                    credential_identifier,
                },
            )
            .await?;

        info!(
            "Legacy migration started for profile {} (algorithm: {})",
            profile.id,
            legacy_cred.legacy_algorithm.as_deref().unwrap_or("unknown")
        );

        Ok(Response::new(LegacyMigrateStartResponse {
            migration_token: state_key,
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
        let client_ip = self.client_ip(&request);
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let (metadata, _, req) = request.into_parts();

        // Retrieve migration state
        let migration = self
            .migration_state
            .take(&req.migration_token)
            .await?
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
        self.evaluate_login_security(
            profile.id,
            client_ip,
            "opaque",
            false,
            LoginSecurityExtras {
                captcha_pass: captcha_pass.as_deref(),
                user_agent: user_agent.as_deref(),
            },
        )
        .await?;

        let signed_in = self
            .create_session_and_issue_tokens(
                &profile,
                LoginMethod::Password,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                &metadata,
            )
            .await?;

        info!(
            "Legacy migration completed for profile {}",
            migration.profile_id
        );

        signed_in.respond(
            |session_id, access_token, expires_in| LegacyMigrateFinishResponse {
                session_id,
                access_token,
                expires_in,
            },
        )
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
        let caller = self.caller_claims(&request).await?.caller;
        let profile_id = caller.profile_id;
        self.require_enrollment_authority(&caller, profile_id, CredentialType::Totp)
            .await?;

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
        let account_name = account_name_owned.as_str();

        let qr_uri = sid_authn::build_otpauth_uri("StructuredID", account_name, &secret);
        let secret_b32 = sid_authn::base32_encode(&secret);

        // The caller's own pending enrollment (5 min TTL): both steps are
        // authenticated as this profile, and a new start replaces the old.
        let enrollment_key = format!("totp:{}", profile_id);
        self.totp_enrollment
            .insert(&enrollment_key, &(profile_id, secret))
            .await?;

        Ok(Response::new(TotpEnrollmentChallenge {
            secret: secret_b32,
            qr_uri,
            issuer: "StructuredID".to_string(),
            account_name: account_name.to_string(),
        }))
    }

    async fn finish_totp_enrollment(
        &self,
        request: Request<FinishTotpEnrollmentRequest>,
    ) -> Result<Response<FinishTotpEnrollmentResponse>, Status> {
        self.check_maintenance().await?;
        let caller = self.caller_claims(&request).await?.caller;
        let profile_id = caller.profile_id;

        let req = request.into_inner();
        require_totp_code_format(&req.code)?;

        // The caller's own pending enrollment (keyed by profile id); another
        // profile's never matches, and reads as expired.
        let enrollment_key = format!("totp:{}", profile_id);
        let secret = self
            .totp_enrollment
            .take(&enrollment_key)
            .await?
            .filter(|(enrolled_pid, _)| *enrolled_pid == profile_id)
            .map(|(_, secret)| secret)
            .ok_or_else(|| ceremony_expired("TOTP enrollment"))?;
        // The account may have changed since the start.
        self.require_enrollment_authority(&caller, profile_id, CredentialType::Totp)
            .await?;

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
            credential_id: credential_id.0.to_string(),
            recovery_codes,
        }))
    }

    async fn verify_totp(
        &self,
        request: Request<VerifyTotpRequest>,
    ) -> Result<Response<MfaVerifyResponse>, Status> {
        self.check_maintenance().await?;
        // Step-up elevates the IdP session and answers with its new token: an
        // application's token never turns into one.
        let verified = self.caller_claims(&request).await?;
        verified.require_installation()?;
        let claims = verified.claims;
        let profile_id = verified.caller.profile_id;

        let req = request.into_inner();
        require_totp_code_format(&req.code)?;

        // The active TOTP credential only; a revoked one never verifies.
        let (totp_cred, secret) = self
            .active_totp_seed(profile_id)
            .await?
            .ok_or_else(|| mfa_not_enrolled("TOTP authenticator"))?;
        self.accept_totp(profile_id, &secret, &req.code).await?;

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

        // Elevate the session; a token must not claim an elevation that was not stored.
        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
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
        let access_token = self
            .jwt
            .issue_access_token(
                &sub,
                Some(&sub),
                &profile,
                &session,
                &session.scopes,
                None,
                None,
            )
            .map_err(|e| internal("issue access token", e))?;

        info!("TOTP step-up verified for profile {}", profile_id);

        Ok(Response::new(MfaVerifyResponse {
            verified: true,
            session_id: Some(session_id.to_string()),
            access_token: Some(access_token),
            expires_in: Some(self.jwt.access_token_ttl_secs()),
            redirect_to: None,
            remaining_codes: None,
        }))
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
        .with_work(generated.relay());
        self.storage
            .replace_credential(&credential, ctx)
            .await
            .map_err(storage_failure)?;

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
        verified.require_installation()?;
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
            session_id: Some(session_id.to_string()),
            access_token: None, // Recovery doesn't elevate — no new token needed.
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
        // an account: the same work, and resend and verify answer alike, so no
        // step tells whether the account exists. The code leaves this service
        // only inside the delivery to the target; it is never logged or put
        // into an event.
        let (result, _code) = self
            .otp
            .request_otp(normalized)
            .await
            .map_err(otp_refusal)?;

        info!(session_id = %result.session_id, "OTP code requested");

        Ok(Response::new(RequestOtpResponse {
            otp_session_id: result.session_id.to_string(),
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
        let client_ip = self.client_ip(&request);
        let user_agent = extract_user_agent(request.metadata());
        let captcha_pass = extract_captcha_pass(request.metadata());
        let req = request.into_inner();

        let session_id = parse_otp_session(req.session_id.as_deref())?;

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
                self.evaluate_login_security(
                    profile.id,
                    client_ip,
                    "otp",
                    false,
                    LoginSecurityExtras {
                        captcha_pass: captcha_pass.as_deref(),
                        user_agent: user_agent.as_deref(),
                    },
                )
                .await?;

                // An emailed code confirms the address over a second channel:
                // `mca` (RFC 8176 §2), not `otp`, which names a code generator.
                let (session_id, access_token, expires_in) = self
                    .create_provisional_session_and_issue_tokens(
                        &profile,
                        "mca",
                        user_agent.as_deref().map(compute_device_id),
                        client_ip,
                    )
                    .await?;

                info!("OTP verified for profile {}", profile.id);

                Ok(Response::new(VerifyOtpResponse {
                    verified: true,
                    redirect_to: None,
                    session_id: Some(session_id),
                    access_token: Some(access_token),
                    expires_in: Some(expires_in),
                }))
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

        let session_id = parse_otp_session(req.session_id.as_deref())?;

        let target = self
            .otp
            .get_session_target(&session_id)
            .await
            .map_err(|e| internal("read email code session", e))?
            .ok_or_else(|| ceremony_expired("email code"))?;

        let (result, _code) = self.otp.request_otp(&target).await.map_err(otp_refusal)?;

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
        let remote_ip = self.client_ip(&request);
        let req = request.into_inner();

        // The provider's own error text stays in the log.
        let rejected = || invalid_field("token", "the CAPTCHA solution was not accepted");
        let result = self
            .captcha_provider
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
            .captcha_gate
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
        verified.require_installation()?;
        verified.caller.require_interactive()?;
        let claims = verified.claims;
        let req_inner = request.into_inner();

        let method = StepUpMethod::try_from(req_inner.method).unwrap_or(StepUpMethod::Unspecified);

        // ── Session decay + method filtering ──
        // Step-up always works on the caller's own session; a session id in the
        // request may only name that same session.
        let session_id = SessionId::parse(&claims.sid)
            .map_err(|e| internal("read session id of a verified token", e))?;
        if !req_inner.session_id.is_empty() && req_inner.session_id != claims.sid {
            return Err(ApiError::new(
                ErrorReason::InsufficientPermissions,
                "a step-up applies only to the caller's own session",
            )
            .into());
        }
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
                    challenge_id: String::new(),
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
                    challenge_id: String::new(),
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
                let challenge_id = uuid::Uuid::now_v7().to_string();
                self.step_up_state
                    .insert(
                        &step_up_challenge_key(&claims.sid, &challenge_id),
                        &result.state_key,
                    )
                    .await?;

                Ok(Response::new(StepUpChallenge {
                    method: req_inner.method,
                    challenge_id,
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
        verified.require_installation()?;
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
                let state_key = self
                    .step_up_state
                    .take(&step_up_challenge_key(&claims.sid, &req.challenge_id))
                    .await?
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
                let key_amr = self.record_passkey_use(&passkeys, &verified).await?;

                // Determine target level based on user_verified.
                // user_verified=true → Elevated (phishing-resistant, 2 NIST factors).
                // user_verified=false → Standard (possession only).
                let target = if verified.user_verified {
                    sid_core::models::session::AuthLevel::Elevated
                } else {
                    sid_core::models::session::AuthLevel::Standard
                };

                (passkey_amr(key_amr, verified.user_verified), target)
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
            return Err(
                step_up_to_acr(sid_core::models::session::AuthLevel::Elevated.acr_value()).into(),
            );
        }

        let profile_id = verified.caller.profile_id;

        let req = request.into_inner();
        let credential_id = sid_core::models::CredentialId(
            uuid::Uuid::parse_str(&req.credential_id)
                .map_err(|_| invalid_field("credential_id", "not a credential identifier"))?,
        );

        // Load credential and verify ownership + type.
        let credentials = self
            .storage
            .get_credentials_by_profile(profile_id, None)
            .await
            .map_err(storage_failure)?;

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
                ));
            }
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
        .with_work(disabled.relay());
        // Revoked, not deleted; a passkey that is the last way to sign in
        // stays. The event commits only with a revocation that happened.
        let outcome = self
            .storage
            .revoke_credential(credential_id, ctx)
            .await
            .map_err(storage_failure)?;
        crate::grpc::identity_service::refuse_last_primary(outcome, credential_id)?;

        info!(
            profile = %profile_id,
            credential = %credential_id.0,
            r#type = cred_type,
            "MFA credential deleted (self-service)"
        );

        Ok(Response::new(DeleteMfaCredentialResponse {
            deleted: true,
            credential_type: cred_type.to_string(),
        }))
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
        let req = request.into_inner();

        // Anti-enumeration: always return success shape
        let anti_enum_response = Response::new(RequestPasswordResetResponse {
            message: "If an account exists, a reset email has been sent.".to_string(),
        });

        // Resolve profile (silently fail for non-existent)
        let profile = self.resolve_profile_optional(&req.principal).await?;
        let profile = match profile {
            Some(p) => p,
            None => return Ok(anti_enum_response),
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

        // Generate reset token (256-bit, hex-encoded)
        use sha2::{Digest, Sha256};
        let mut token_bytes = [0u8; 32];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut token_bytes)
            .map_err(|_| Status::internal("operating system random source unavailable"))?;
        let token = token_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // Hash token with SHA-256
        let hash_bytes = Sha256::digest(token.as_bytes());
        let token_hash = hash_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // Create reset session
        let session = sid_core::models::PasswordResetSession::new(
            profile.id,
            req.principal.clone(),
            token_hash,
        );

        // The event names only the reset session: the event stream is read beyond
        // the notification service, so it never carries the token, a link or an
        // address. It is owed by the commit that stores the reset session.
        let requested = sid_core::models::event::Event::new(
            format!("profile/{}", profile.id),
            "sid.auth.password_reset_requested.v1",
        )
        .with_data(serde_json::json!({
            "reset_session_id": session.id.to_string(),
        }));
        let ctx = MutationContext::from(AuditEntry::user(
            profile.id.to_string(),
            "password_reset.request",
            session.id.to_string(),
        ))
        .with_work(requested.relay());
        // A failure answers like an unknown address: an error only for held
        // addresses would tell which accounts exist.
        if let Err(e) = self.storage.create_reset_session(&session, ctx).await {
            tracing::error!(error = %e, "reset session not stored; no reset started");
            return Ok(anti_enum_response);
        }

        info!("Password reset requested for profile {}", profile.id);

        Ok(anti_enum_response)
    }

    #[tracing::instrument(skip_all, fields(rpc = "verify_password_reset"))]
    async fn verify_password_reset(
        &self,
        request: Request<VerifyPasswordResetRequest>,
    ) -> Result<Response<VerifyPasswordResetResponse>, Status> {
        let req = request.into_inner();

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| invalid_field("session_id", "not a reset session identifier"))?;

        // An unknown reset and an expired one answer alike: the reset starts
        // again from the email.
        let session = self
            .storage
            .get_reset_session(sid_core::models::ResetSessionId(session_id))
            .await
            .map_err(storage_failure)?
            .filter(|s| !s.is_expired())
            .ok_or_else(|| ceremony_expired("password reset"))?;

        let already_used = || {
            ApiError::new(ErrorReason::InvalidState, "the reset link was already used")
                .with_precondition("RESET_SESSION_STATE", req.session_id.clone(), "used")
                .into()
        };
        if session.status != sid_core::models::ResetSessionStatus::Pending {
            return Err(already_used());
        }

        // Verify token (SHA-256, constant-time comparison)
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let hash_bytes = Sha256::digest(req.token.as_bytes());
        let computed_hash: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
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
            .await?;

        Ok(Response::new(VerifyPasswordResetResponse {
            reset_session_id: session.id.to_string(),
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
        let id = operation_id(req.operation_id.as_ref())?;
        let mut reset = None;
        let registration_response = self
            .password_ops
            .opaque_start(&zkpp, &id, req.registration_request, |op| {
                match op.purpose {
                    OperationPurpose::Reset { session } => {
                        reset = Some(session);
                        Ok(())
                    }
                    _ => Err(super::password_operation::operation_not_pending()),
                }
            })
            .await?;
        // The operation outlives nothing: a reset that expired or was
        // completed meanwhile does not go on.
        let session = reset.ok_or_else(super::password_operation::operation_not_pending)?;
        self.verified_reset_session(&session.to_string()).await?;
        Ok(Response::new(ExecutePasswordResetResponse {
            registration_response,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "complete_password_reset"))]
    async fn complete_password_reset(
        &self,
        request: Request<CompletePasswordResetRequest>,
    ) -> Result<Response<CompletePasswordResetResponse>, Status> {
        let client_ip = self.client_ip(&request);
        let (metadata, _, req) = request.into_parts();
        let user_agent = extract_user_agent(&metadata);
        let zkpp = self.require_zkpp()?;

        let session = self.verified_reset_session(&req.reset_session_id).await?;
        let profile_id = session.profile_id;

        // 1. The final record and its proof, checked against the reset's own
        //    operation. A retry of a completed reset gets no session: the
        //    password was replaced, the client signs in with it.
        let id = operation_id(req.operation_id.as_ref())?;
        let done = match self
            .password_ops
            .finish(
                zkpp,
                &id,
                "reset",
                &req.registration_record,
                req.proof,
                |op| match op.purpose {
                    OperationPurpose::Reset { session: s } if s == session.id => Ok(()),
                    _ => Err(super::password_operation::operation_not_pending()),
                },
            )
            .await?
        {
            Finish::Completed(_) => {
                return Ok(Response::new(CompletePasswordResetResponse::default()));
            }
            Finish::Ready(done) => *done,
        };

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
            "sid.auth.password_reset_completed.v1",
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
        let ended = self
            .storage
            .complete_password_reset(session.id, &new_cred, done.history.as_ref(), &end, ctx)
            .await
            .map_err(storage_failure)?
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
        //    has to pass the account's second factor at sign-in. The empty
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
            self.security_policy.auth.passkey_satisfies_mfa,
        );
        if established > sid_core::models::session::AuthLevel::Basic {
            info!(
                "Password reset completed for profile {}; sign-in left to its second factor",
                profile_id
            );
            return Ok(Response::new(CompletePasswordResetResponse {
                session_id: String::new(),
                access_token: String::new(),
                expires_in: 0,
            }));
        }

        // 5. The reset's sign-in is a sign-in like any other: its session
        //    records the client's device and address.
        let signed_in = self
            .create_session_and_issue_tokens(
                &self
                    .storage
                    .get_profile(profile_id)
                    .await
                    .map_err(storage_failure)?
                    // Deleted meanwhile: the password is replaced, no one signs in.
                    .ok_or_else(authentication_failed)?,
                LoginMethod::Password,
                user_agent.as_deref().map(compute_device_id),
                client_ip,
                &metadata,
            )
            .await?;

        info!("Password reset completed for profile {}", profile_id);

        signed_in.respond(
            |session_id, access_token, expires_in| CompletePasswordResetResponse {
                session_id,
                access_token,
                expires_in: expires_in as i32,
            },
        )
    }
}

// ── OAuth2 grant type handlers ──

impl AuthServiceImpl {
    /// Revoke the session (and its refresh tokens and live access tokens)
    /// that the first redemption of a reused authorization code created.
    /// End a session whose credential was replayed (a reused authorization
    /// code or refresh token): its access tokens, refresh tokens and the
    /// session itself. `action` names the replay in the audit trail.
    async fn revoke_compromised_session(
        &self,
        session_id: Option<SessionId>,
        action: &str,
    ) -> Result<(), Status> {
        let Some(session_id) = session_id else {
            return Ok(());
        };
        warn!(%session_id, action, "credential replayed; revoking its session");
        self.cascade
            .revoke_session(
                session_id,
                RevocationReason::AnomalyDetected,
                "system",
                action,
            )
            .await
            .map(drop)
            .map_err(|e| internal("revoke a compromised session", e))
    }

    async fn handle_authorization_code_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let raw_code = req
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| missing_parameter("code"))?;
        let redirect_uri = req
            .redirect_uri
            .as_deref()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| missing_parameter("redirect_uri"))?;

        let (client, issuer) = self.authenticated_client(&req.issuer_handle, auth).await?;

        // Look up authorization code
        let code_hash = OAuth2Server::hash_token(raw_code);
        let auth_code = self
            .storage
            .get_auth_code_by_hash(&code_hash)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                token_refusal(TokenError::InvalidGrant, "authorization code not found")
            })?;

        // RFC 6749 §4.1.2: a code used more than once is refused, and the
        // tokens issued from its first use are revoked.
        if auth_code.used {
            self.revoke_compromised_session(auth_code.session_id, "auth_code.reuse")
                .await?;
            return Err(token_refusal(
                TokenError::InvalidGrant,
                "authorization code already used",
            ));
        }

        // Validate and exchange code (consume-self — auth_code is consumed).
        // Every refusal here (expired, other client or redirect URI, PKCE) is
        // `invalid_grant` (RFC 6749 §5.2, RFC 7636 §4.6).
        let exchanged = self
            .oauth2
            .validate_code_exchange(
                &client,
                auth_code,
                req.code_verifier.as_deref(),
                redirect_uri,
            )
            .map_err(|e| token_refusal(TokenError::InvalidGrant, e.to_string()))?;
        // The tokens are for the resource the code was issued for, and only
        // while the client still has access to it; the code is not consumed
        // by a refusal here.
        let target = self
            .resume_target(&issuer, &client, exchanged.resource(), &req.resource)
            .await?;

        // Look up profile
        let profile = self
            .storage
            .get_profile(exchanged.profile_id())
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                token_refusal(
                    TokenError::InvalidGrant,
                    "the code's account no longer exists",
                )
            })?;

        // The application's session reports the authentication of the session
        // that authorized the code (`auth_time`, `amr`, `acr`) and ends with it.
        let mut session = sid_core::models::Session::new(
            profile.id,
            "grpc".to_string(),
            Utc::now() + Duration::hours(24),
        )
        .with_grant_authentication(exchanged.authentication());
        session.client_id = Some(client.client_id.clone());
        session.scopes = exchanged.scopes().to_vec();

        // Validate DPoP proof if present
        let dpop_binding = self
            .validate_dpop_proof(&req.dpop_proof, proof_target)
            .await?;

        // Fetch primary contacts for OIDC claims; a failed read fails the
        // grant rather than issue tokens missing the claims.
        let (primary_email, primary_phone) = self.primary_contacts(profile.id).await?;

        // Resolve custom claims from client claim mappings (AUTH-017)
        let custom_claims = if !client.claim_mappings.is_empty() {
            let metadata = self
                .storage
                .list_profile_metadata(profile.id)
                .await
                .map_err(claims_unavailable)?;
            let scopes: Vec<String> = exchanged.scopes().to_vec();
            let resolved = resolve_claims(
                &client.claim_mappings,
                &profile,
                &metadata,
                &scopes,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            );
            if resolved.is_empty() {
                None
            } else {
                Some(resolved)
            }
        } else {
            None
        };

        // Issue tokens
        let sub = self.subject_for(&issuer, profile.id, &client).await?;
        let signer = self.issuer_signer(&issuer).await?;
        let (response, refresh_model) = self
            .oauth2
            .issue_tokens(
                &signer,
                &sub,
                &profile,
                &session,
                &client,
                &target,
                exchanged.scopes(),
                exchanged.nonce(),
                dpop_binding.as_ref(),
                custom_claims.as_ref(),
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )
            .map_err(|e| internal("issue tokens", e))?;

        // The code, the session and the refresh token are committed together:
        // of concurrent exchanges exactly one gets tokens.
        let redemption = self
            .storage
            .redeem_auth_code(
                &code_hash,
                &session,
                &refresh_model,
                AuditEntry::user(
                    profile.id.to_string(),
                    "auth_code.exchange",
                    session.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if let sid_core::models::AuthCodeRedemption::AlreadyRedeemed { session_id } = redemption {
            self.revoke_compromised_session(session_id, "auth_code.reuse")
                .await?;
            return Err(token_refusal(
                TokenError::InvalidGrant,
                "authorization code already used",
            ));
        }

        info!(
            "Issued tokens for profile {} via authorization_code",
            profile.id
        );

        Ok(Response::new(OAuth2TokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
            refresh_token: response.refresh_token,
            id_token: response.id_token,
            scope: response.scope,
            issued_token_type: None,
        }))
    }

    async fn handle_refresh_token_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let raw_token = req
            .refresh_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| missing_parameter("refresh_token"))?;

        let (client, issuer) = self.authenticated_client(&req.issuer_handle, auth).await?;

        // Look up refresh token
        let token_hash = OAuth2Server::hash_token(raw_token);
        let old_token = self
            .storage
            .get_refresh_token_by_hash(&token_hash)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| token_refusal(TokenError::InvalidGrant, "refresh token not found"))?;

        // Validate the presented token (active, or inside its grace window).
        let validated = match self.oauth2.validate_refresh(old_token, &client) {
            Ok(v) => v,
            Err(sid_authn::oauth2::RefreshRefusal::Reused {
                session_id,
                family_id,
            }) => {
                // A rotated token came back after its grace window: whoever
                // holds the family is not the client alone. The family and its
                // session end; a failure to revoke fails the request.
                warn!(%family_id, "refresh token reused; revoking family and session");
                self.storage
                    .revoke_refresh_tokens_by_family(
                        family_id,
                        AuditEntry::system("token.reuse", family_id.to_string()).into(),
                    )
                    .await
                    .map_err(storage_failure)?;
                self.revoke_compromised_session(Some(session_id), "token.reuse")
                    .await?;
                return Err(token_refusal(
                    TokenError::InvalidGrant,
                    "refresh token reused, all tokens revoked",
                ));
            }
            // Every refresh refusal is `invalid_grant` (RFC 6749 §5.2).
            Err(refusal) => {
                return Err(token_refusal(TokenError::InvalidGrant, refusal.to_string()));
            }
        };
        // Refresh keeps the resource of its grant and never acquires another;
        // access revoked since ends further issuance.
        let target = self
            .resume_target(&issuer, &client, validated.resource(), &req.resource)
            .await?;

        // Look up profile and session
        let profile = self
            .storage
            .get_profile(validated.profile_id())
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                token_refusal(
                    TokenError::InvalidGrant,
                    "the token's account no longer exists",
                )
            })?;

        let _session = self
            .storage
            .get_session(validated.session_id())
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| token_refusal(TokenError::InvalidGrant, "session ended"))?;

        // Validate DPoP proof if present
        let dpop_binding = self
            .validate_dpop_proof(&req.dpop_proof, proof_target)
            .await?;
        // A key-bound refresh token is used only with a proof for its key
        // (RFC 9449 §5).
        if let Some(bound) = validated.dpop_jkt()
            && dpop_binding.as_ref().map(|b| b.jkt.as_str()) != Some(bound)
        {
            return Err(dpop_refusal("refresh token is bound to another key"));
        }

        // Fetch primary contacts for OIDC claims; a failed read fails the
        // refresh rather than issue tokens missing the claims.
        let (primary_email, primary_phone) = self.primary_contacts(profile.id).await?;

        // Resolve custom claims from client claim mappings (AUTH-017)
        let custom_claims = if !client.claim_mappings.is_empty() {
            let metadata = self
                .storage
                .list_profile_metadata(profile.id)
                .await
                .map_err(claims_unavailable)?;
            let scopes: Vec<String> = validated.scopes().to_vec();
            let resolved = resolve_claims(
                &client.claim_mappings,
                &profile,
                &metadata,
                &scopes,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            );
            if resolved.is_empty() {
                None
            } else {
                Some(resolved)
            }
        } else {
            None
        };

        // Issue new tokens (rotation)
        let sub = self.subject_for(&issuer, profile.id, &client).await?;
        let signer = self.issuer_signer(&issuer).await?;
        let (response, mut new_refresh) = self
            .oauth2
            .issue_tokens(
                &signer,
                &sub,
                &profile,
                &_session,
                &client,
                &target,
                validated.scopes(),
                None,
                dpop_binding.as_ref(),
                custom_claims.as_ref(),
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )
            .map_err(|e| internal("issue tokens", e))?;

        // Inherit family_id from old token (rotation chain continuity)
        new_refresh.family_id = validated.family_id();
        new_refresh.replaced_by = None;
        new_refresh.grace_expires_at = None;

        // Replace the old token with the new one in one write. The old token
        // was revoked meanwhile (sign-out, reuse) → nothing is issued; a
        // storage failure fails the request rather than hand out a refresh
        // token that does not exist.
        let rotated = self
            .storage
            .rotate_refresh_token(
                validated.id(),
                &new_refresh,
                chrono::Utc::now()
                    + chrono::Duration::seconds(
                        sid_core::models::refresh_token::DEFAULT_GRACE_WINDOW_SECS,
                    ),
                AuditEntry::user(
                    profile.id.to_string(),
                    "token.rotate",
                    new_refresh.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !rotated {
            return Err(token_refusal(
                TokenError::InvalidGrant,
                "refresh token revoked",
            ));
        }

        info!("Rotated refresh token for profile {}", profile.id);

        Ok(Response::new(OAuth2TokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
            refresh_token: response.refresh_token,
            id_token: response.id_token,
            scope: response.scope,
            issued_token_type: None,
        }))
    }

    /// The device_code grant (RFC 8628 §3.4): a device's poll, answered with
    /// tokens once, after the user approved, or with the state of the request
    /// as an RFC 8628 §3.5 error.
    async fn handle_device_code_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let raw_code = req
            .device_code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| missing_parameter("device_code"))?;
        let (client, issuer) = self.authenticated_client(&req.issuer_handle, auth).await?;
        if !client.is_grant_type_allowed(DEVICE_CODE_GRANT) {
            return Err(token_refusal(
                TokenError::UnauthorizedClient,
                "the client may not use the device authorization grant",
            ));
        }

        let code_hash = device_auth::hash_device_code(raw_code);
        let unknown = || token_refusal(TokenError::InvalidGrant, "unknown device code");
        let code = self
            .storage
            .get_device_auth_by_device_code_hash(&code_hash)
            .await
            .map_err(storage_failure)?
            .ok_or_else(unknown)?;
        // A code issued to another client is unknown to this one (RFC 6749
        // §5.2 `invalid_grant`), and takes no effect here.
        if code.client_id != client.client_id {
            return Err(unknown());
        }

        // A device code grants once, like an authorization code (RFC 6749
        // §4.1.2): a code already exchanged gets nothing, whatever its pace,
        // and the session its first exchange opened is ended.
        if code.status == sid_core::models::DeviceAuthStatus::Redeemed {
            self.revoke_compromised_session(code.redeemed_session_id, "device_code.reuse")
                .await?;
            return Err(token_refusal(
                TokenError::InvalidGrant,
                "device code already used",
            ));
        }

        // slow_down (RFC 8628 §3.5): the check and the recorded poll are one
        // step, so concurrent polls cannot both pass.
        let pace = self
            .storage
            .record_device_poll(
                code.id,
                AuditEntry::system("device_auth.poll", code.id.0.to_string()).into(),
            )
            .await
            .map_err(storage_failure)?;
        if pace == sid_core::models::DevicePoll::SlowDown {
            return Err(slow_down(code.interval));
        }

        match device_auth::validate_poll(&code) {
            Ok(()) => {}
            Err(device_auth::DeviceAuthError::AuthorizationPending) => {
                return Err(token_refusal(
                    TokenError::AuthorizationPending,
                    "the user has not decided yet",
                ));
            }
            Err(device_auth::DeviceAuthError::SlowDown) => {
                return Err(slow_down(code.interval));
            }
            Err(device_auth::DeviceAuthError::ExpiredToken) => {
                return Err(token_refusal(
                    TokenError::ExpiredToken,
                    "the device code expired",
                ));
            }
            Err(device_auth::DeviceAuthError::AccessDenied) => {
                return Err(token_refusal(
                    TokenError::AccessDenied,
                    "the user denied the request",
                ));
            }
            Err(e) => {
                warn!(error = %e, "device poll in an unexpected state");
                return Err(ApiError::internal().into());
            }
        }
        // The tokens are for the resource the device transaction is bound to.
        let target = self
            .resume_target(&issuer, &client, code.resource, &req.resource)
            .await?;

        let profile_id = code
            .authorized_by
            .ok_or_else(|| storage_failure("an approved device code has no approver"))?;
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                token_refusal(
                    TokenError::InvalidGrant,
                    "the approving account no longer exists",
                )
            })?;

        let mut session = sid_core::models::Session::new(
            profile.id,
            "device".to_string(),
            Utc::now() + Duration::hours(24),
        );
        session.client_id = Some(client.client_id.clone());
        session.scopes = code
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        let sub = self.subject_for(&issuer, profile.id, &client).await?;
        let (primary_email, primary_phone) = self.primary_contacts(profile.id).await?;
        let signer = self.issuer_signer(&issuer).await?;
        let (response, refresh_model) = self
            .oauth2
            .issue_tokens(
                &signer,
                &sub,
                &profile,
                &session,
                &client,
                &target,
                &session.scopes,
                None,
                None,
                None,
                primary_email.as_ref(),
                primary_phone.as_ref(),
            )
            .map_err(|e| internal("issue tokens", e))?;

        // The code, the session and the refresh token are committed together:
        // of concurrent polls exactly one gets tokens.
        let redemption = self
            .storage
            .redeem_device_code(
                &code_hash,
                &session,
                &refresh_model,
                AuditEntry::user(
                    profile.id.to_string(),
                    "device_code.exchange",
                    session.id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        match redemption {
            sid_core::models::DeviceCodeRedemption::Redeemed => {}
            sid_core::models::DeviceCodeRedemption::AlreadyRedeemed { session_id } => {
                self.revoke_compromised_session(session_id, "device_code.reuse")
                    .await?;
                return Err(token_refusal(
                    TokenError::InvalidGrant,
                    "device code already used",
                ));
            }
            // Expired or decided otherwise between the read and the exchange.
            sid_core::models::DeviceCodeRedemption::NotAuthorized => {
                return Err(token_refusal(
                    TokenError::InvalidGrant,
                    "device code is not authorized",
                ));
            }
        }

        info!(
            "Device authorization completed for client={}, profile={}",
            client.client_id, profile.id
        );
        Ok(Response::new(OAuth2TokenResponse {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
            refresh_token: response.refresh_token,
            id_token: response.id_token,
            scope: response.scope,
            issued_token_type: None,
        }))
    }

    /// A client acting for itself (RFC 6749 §4.4): a registered confidential
    /// client, or else a machine user of the installation.
    async fn handle_client_credentials_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
        proof_target: &sid_authn::resource::RequestTarget,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        let client = self
            .storage
            .get_oauth2_client(auth.client_id())
            .await
            .map_err(storage_failure)?;

        let Some(client) = client else {
            if let Some(response) = self.connector_client_credentials(req, auth).await? {
                return Ok(response);
            }
            let (mu, kid, issuer) = self
                .authenticate_machine_user(&req.issuer_handle, auth)
                .await?;
            self.enforce_machine_restrictions(&mu, client_ip).await?;
            let target = self.select_target(&issuer, &mu, &req.resource).await?;
            // Without a requested scope, everything the target grants that
            // the machine user may have (RFC 6749 §3.3).
            let wanted = match req.scope.as_deref() {
                Some(_) => machine_scopes(&mu, req.scope.as_deref()),
                None => target
                    .scopes()
                    .into_iter()
                    .filter(|s| mu.scopes.is_empty() || mu.scopes.contains(s))
                    .collect(),
            };
            let scopes = target.granted_scopes(&wanted);
            let subject = mu.id.to_string();
            let actor = ClientActor {
                client_id: &mu.client_id,
                subject: &subject,
                credential: &kid,
                max_lifetime: mu
                    .max_token_lifetime
                    .map(|seconds| Duration::seconds(i64::from(seconds))),
            };
            return self
                .client_token(&issuer, actor, &target, scopes, req, proof_target)
                .await;
        };

        let issuer = self.client_issuer(&req.issuer_handle, &client).await?;
        self.check_client_authentication(&client, &issuer, auth)
            .await?;
        // RFC 6749 §4.4: only a confidential client may use this grant.
        if client.is_public() || !client.is_grant_type_allowed("client_credentials") {
            return Err(token_refusal(
                TokenError::UnauthorizedClient,
                "the client may not use the client_credentials grant",
            ));
        }
        let target = self.select_target(&issuer, &client, &req.resource).await?;
        // The requested scopes the client may have, or all of them when none
        // are requested (RFC 6749 §3.3), limited to what the target grants.
        let requested = match req.scope.as_deref() {
            Some(scope) => {
                let asked: Vec<String> = scope.split_whitespace().map(String::from).collect();
                client.filter_scopes(&asked)
            }
            None => client.allowed_scopes.clone(),
        };
        let scopes = target.granted_scopes(&requested);
        // An OAuth client has one registered credential; its client_id names
        // both the principal and that authentication.
        let actor = ClientActor {
            client_id: &client.client_id,
            subject: &client.client_id,
            credential: &client.client_id,
            max_lifetime: None,
        };
        self.client_token(&issuer, actor, &target, scopes, req, proof_target)
            .await
    }

    /// `client_credentials` for a provisioning connector: `None` when the
    /// client_id names no connector. A connector authenticates with a client
    /// secret of its own (client_secret_basic or client_secret_post) and gets
    /// a token for its SCIM directory resource only, with the provisioning
    /// scopes it asked for that its grants allow now. The token's `sub` is the
    /// connector, `client_id` its client_id and `sid` the credential it used,
    /// so the resource checks all three again on every request.
    async fn connector_client_credentials(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
    ) -> Result<Option<Response<OAuth2TokenResponse>>, Status> {
        let as_client_error = |e: Status| {
            if e.code() == Code::Unauthenticated {
                client_refused()
            } else {
                e
            }
        };
        let caller = match auth {
            ClientAuthentication::Basic { secret, .. }
            | ClientAuthentication::Post { secret, .. } => {
                sid_authn::connector_auth::authenticate_connector_client(
                    self.storage.as_ref(),
                    self.installation_org,
                    auth.client_id(),
                    secret.expose_secret(),
                )
                .await
                .map_err(as_client_error)?
            }
            // A connector has no key credential and is never a public client.
            _ => {
                return if self
                    .storage
                    .get_provisioning_connector_by_client_id(auth.client_id())
                    .await
                    .map_err(storage_failure)?
                    .is_some()
                {
                    Err(client_refused())
                } else {
                    Ok(None)
                };
            }
        };
        let Some(caller) = caller else {
            return Ok(None);
        };
        let issuer = self
            .issuer_serving(&req.issuer_handle, Some(self.installation_org))
            .await?
            .ok_or_else(client_refused)?;
        // The SCIM resource takes no DPoP proof, so a sender-constrained
        // token would be unusable there (RFC 9449 §7.1).
        if req.dpop_proof.as_deref().is_some_and(|p| !p.is_empty()) {
            return Err(token_refusal(
                TokenError::InvalidRequest,
                "a provisioning connector's token is a bearer token",
            ));
        }
        let directory = sid_core::models::ResourceIndicator::parse(
            &sid_authn::issuer::scim_endpoint(&issuer.canonical_url),
        )
        .map_err(|e| internal("SCIM resource indicator", e))?;
        let requested =
            sid_authn::target::requested_indicator(&req.resource).map_err(target_refused)?;
        let resource = sid_authn::target::connector_target(
            self.storage.as_ref(),
            issuer.id,
            &directory,
            requested.as_ref(),
        )
        .await
        .map_err(storage_failure)?
        .map_err(target_refused)?;

        // Without a requested scope, every provisioning scope (RFC 6749
        // §3.3); in any case only those its grants allow now.
        let wanted: Vec<String> = match req.scope.as_deref() {
            Some(scope) => scope.split_whitespace().map(String::from).collect(),
            None => resource.scopes.clone(),
        };
        let mut scopes = Vec::new();
        for scope in wanted {
            if !resource.scopes.contains(&scope) || scopes.contains(&scope) {
                continue;
            }
            let decision = self
                .authz
                .check(&sid_plugin::authz::AuthzCheckRequest {
                    subject: format!("provisioning_connector:{}", caller.connector.id),
                    action: scope.clone(),
                    resource: format!("oauth_resource:{}", resource.id),
                    context: Default::default(),
                })
                .await
                .map_err(|e| dependency_unavailable("provisioning authorization", e))?;
            if decision.is_allowed() {
                scopes.push(scope);
            }
        }
        if scopes.is_empty() {
            return Err(token_refusal(
                TokenError::InvalidScope,
                "the connector is granted none of the requested scopes",
            ));
        }

        let signer = self.issuer_signer(&issuer).await?;
        let access_token = self
            .jwt
            .client_access_token_signed_by(
                signer.as_ref(),
                &sid_authn::jwt::ClientGrant {
                    resource: resource.indicator.as_str(),
                    client_id: caller.connector.client_id.as_str(),
                    subject: &caller.connector.id.to_string(),
                    credential: &caller.credential_id.to_string(),
                    scopes: &scopes,
                    dpop: None,
                    max_lifetime: None,
                },
            )
            .map_err(|e| internal("connector token", e))?;
        info!(connector = %caller.connector.id, "Issued client_credentials token for a provisioning connector");
        Ok(Some(Response::new(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.jwt.access_token_ttl_secs(),
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            issued_token_type: None,
        })))
    }

    /// Enforce MachineUser restrictions (IP allowlist + rate limiting).
    ///
    /// Called after authentication, before token issuance.
    async fn enforce_machine_restrictions(
        &self,
        mu: &sid_core::models::MachineUser,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<(), Status> {
        // IP allowlist check: a request from elsewhere is a client this
        // endpoint does not authorize (RFC 6749 §5.2 `unauthorized_client`).
        let not_allowed = || {
            token_refusal(
                TokenError::UnauthorizedClient,
                "the client may not request tokens from this address",
            )
        };
        if !mu.restrictions.ip_allowlist.is_empty() {
            let addr = client_ip.ok_or_else(not_allowed)?;

            let allowed = mu
                .restrictions
                .ip_allowlist
                .iter()
                .any(|entry| ip_matches(entry, &addr));

            if !allowed {
                warn!(
                    "Machine user {} request from {} denied by IP allowlist",
                    mu.client_id, addr
                );
                return Err(not_allowed());
            }
        }

        // Rate limiting.
        if mu.restrictions.rate_limit_rpm > 0
            && !self
                .rate_limiter
                .check_and_record(&mu.client_id, mu.restrictions.rate_limit_rpm)
                .await
                .map_err(|e| dependency_unavailable("machine user rate limit", e))?
        {
            warn!(
                "Machine user {} rate limited ({}rpm)",
                mu.client_id, mu.restrictions.rate_limit_rpm
            );
            let stats = self.rate_limit_stats.clone();
            tokio::spawn(async move {
                stats.record_block(None, "machine_user_token").await;
            });
            return Err(
                ApiError::new(ErrorReason::RateLimitExceeded, "rate limit exceeded")
                    .with_quota_violation(
                        "machine_user_token_requests",
                        format!(
                            "{} token requests per minute",
                            mu.restrictions.rate_limit_rpm
                        ),
                    )
                    .with_retry_after(std::time::Duration::from_secs(60))
                    .into(),
            );
        }

        Ok(())
    }

    /// Handle RFC 8693 Token Exchange (impersonation grant).
    ///
    /// Machine user authenticates via client_credentials (secret or assertion),
    /// provides a `subject_token` identifying the target user, and receives
    /// a short-lived impersonation token with `act` claim.
    async fn handle_token_exchange_grant(
        &self,
        req: &OAuth2TokenRequest,
        auth: &ClientAuthentication,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<Response<OAuth2TokenResponse>, Status> {
        use sid_core::models::machine_user::IMPERSONATION_MAX_LIFETIME_SECONDS;

        let (mu, _, _issuer) = self
            .authenticate_machine_user(&req.issuer_handle, auth)
            .await?;

        // Enforce restrictions (IP allowlist + rate limiting).
        self.enforce_machine_restrictions(&mu, client_ip).await?;

        // Validate subject_token fields. RFC 8693 §2.2.2: an invalid or
        // unacceptable request, subject token included, is `invalid_request`.
        let subject_token = req
            .subject_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| missing_parameter("subject_token"))?;
        let subject_token_type = req
            .subject_token_type
            .as_deref()
            .unwrap_or(ACCESS_TOKEN_TYPE);
        if subject_token_type != ACCESS_TOKEN_TYPE {
            return Err(token_refusal(
                TokenError::InvalidRequest,
                "only subject_token_type=urn:ietf:params:oauth:token-type:access_token is supported",
            ));
        }
        // RFC 8693 §2.1, §2.2.2: only an access token is issued; another
        // requested type is refused, never answered with an access token.
        if req
            .requested_token_type
            .as_deref()
            .is_some_and(|wanted| wanted != ACCESS_TOKEN_TYPE)
        {
            return Err(token_refusal(
                TokenError::InvalidRequest,
                "only requested_token_type=urn:ietf:params:oauth:token-type:access_token is supported",
            ));
        }
        // The exchange issues the installation's own impersonation token. A
        // target named by `resource` or `audience` (RFC 8693 §2.1) is refused
        // rather than ignored, so no token is issued for another audience
        // than the client asked for.
        if sid_authn::target::exchange_indicator(&req.resource, &req.audience)
            .map_err(target_refused)?
            .is_some()
        {
            return Err(target_refused(
                sid_authn::target::TargetRefusal::NotExchangeable,
            ));
        }

        // The subject token is the target user's own sign-in: verified like any
        // bearer token (revocation included). A PAT-derived or impersonation
        // token is refused, so an impersonation cannot be renewed by
        // exchanging its own token.
        let invalid_subject = || token_refusal(TokenError::InvalidRequest, "invalid subject_token");
        let target_claims = sid_authn::caller::verify_token(
            subject_token,
            self.jwt.verifier(),
            &self.revocation_cache,
        )
        .await
        .map_err(|e| {
            if e.code() == Code::Unavailable {
                e
            } else {
                invalid_subject()
            }
        })?;
        let subject = sid_authn::caller::Caller::from_claims(&target_claims)
            .map_err(|_| invalid_subject())?;
        if subject.kind() != sid_authn::caller::TokenKind::Interactive {
            return Err(invalid_subject());
        }
        let profile_id = subject.profile_id;
        let target_profile_id = profile_id.to_string();

        let target_profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(invalid_subject)?;
        // A suspended, closing or closed account cannot be acted for.
        if !target_profile.status.can_authenticate() {
            return Err(invalid_subject());
        }

        // Check that an ImpersonationGrant exists for this machine user → target.
        let grants = self
            .storage
            .list_impersonation_grants(mu.id)
            .await
            .map_err(storage_failure)?;

        let matching_grant = grants.iter().find(|g| match g.target_type {
            sid_core::models::ImpersonationTargetType::User => g.target == target_profile_id,
            sid_core::models::ImpersonationTargetType::Role => {
                target_profile.roles.iter().any(|r| r == &g.target)
            }
        });

        // A subject the client may not act for is unacceptable by policy:
        // `invalid_request` (RFC 8693 §2.2.2).
        let grant = matching_grant.ok_or_else(|| {
            token_refusal(
                TokenError::InvalidRequest,
                "the client may not act for this subject",
            )
        })?;

        let scopes = self.resolve_impersonation_scopes(req, grant, &mu, &target_claims.scope)?;

        // The impersonation is a session of the target: it shows in the
        // target's sessions, and revoking it or the target's access ends the
        // token. It is recorded together with its audit entry, which cannot
        // be skipped.
        let lifetime = chrono::Duration::seconds(i64::from(IMPERSONATION_MAX_LIFETIME_SECONDS));
        let ip = client_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let mut session =
            sid_core::models::Session::new(profile_id, ip.clone(), Utc::now() + lifetime);
        session.client_id = Some(mu.client_id.clone());
        session.scopes = scopes.clone();
        session.amr = vec!["token_exchange".to_string()];
        let audit = AuditEntry::machine(
            mu.id.to_string(),
            "sid.token.impersonation.v1",
            format!("profile:{profile_id}"),
        )
        .with_ip(ip)
        .with_metadata(serde_json::json!({
            "actor": { "type": "machine", "id": mu.id.to_string(), "client_id": mu.client_id },
            "target": { "type": "user", "id": target_profile_id },
            "session_id": session.id.to_string(),
            "scopes": scopes,
        }));
        self.storage
            .create_session(&session, audit.into())
            .await
            .map_err(storage_failure)?;

        // sub = target, act.sub = machine user.
        let access_token = self
            .jwt
            .issue_impersonation_token(&target_profile_id, &session, &mu.client_id, &scopes)
            .map_err(|e| internal("issue impersonation token", e))?;

        Ok(Response::new(OAuth2TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: lifetime.num_seconds(),
            refresh_token: None,
            id_token: None,
            scope: Some(scopes.join(" ")),
            // RFC 8693 §2.2.1: required in a token exchange response.
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
        }))
    }

    /// Resolve scopes for impersonation: requested ∩ mu.scopes ∩
    /// grant.allowed_scopes ∩ `target_scopes` (the target's token scope).
    fn resolve_impersonation_scopes(
        &self,
        req: &OAuth2TokenRequest,
        grant: &sid_core::models::ImpersonationGrant,
        mu: &sid_core::models::MachineUser,
        target_scopes: &str,
    ) -> Result<Vec<String>, Status> {
        // Filter what the machine user may have by grant.allowed_scopes
        // (unless wildcard), then by what the target user's own token holds:
        // impersonation never exceeds the user.
        let final_scopes: Vec<String> = machine_scopes(mu, req.scope.as_deref())
            .into_iter()
            .filter(|s| grant.allows_all_scopes() || grant.allows_scope(s))
            .filter(|s| target_scopes.split_whitespace().any(|t| t == s))
            .collect();

        if final_scopes.is_empty() {
            return Err(token_refusal(
                TokenError::InvalidScope,
                "no scopes available for impersonation after intersection",
            ));
        }

        Ok(final_scopes)
    }
}

/// The token endpoint of `issuer`, as its discovery document advertises it:
/// the `htu` of a DPoP proof sent there (RFC 9449 §4.3) and the audience of a
/// client assertion (RFC 7523 §3).
fn token_endpoint(issuer: &OidcIssuer) -> String {
    sid_authn::issuer::token_endpoint(&issuer.canonical_url)
}

/// A refused DPoP proof, with the `invalid_dpop_proof` error code
/// (RFC 9449 §7.1) for the token endpoint's error response.
fn dpop_refusal(detail: impl std::fmt::Display) -> Status {
    ApiError::new(
        ErrorReason::InvalidFieldValue,
        format!("invalid DPoP proof: {detail}"),
    )
    .with_metadata("field", "DPoP")
    .with_metadata("oauthError", TokenError::InvalidDpopProof.code())
    .into()
}

/// The grant type a device polls the token endpoint with (RFC 8628 §3.4).
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The token endpoint's RPC, as a native gRPC client calls it.
const OAUTH2_TOKEN_RPC: &str = "/sid.v1.authn.AuthService/OAuth2Token";

/// The token type identifier of an access token (RFC 8693 §3).
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The client authentication a request presents: HTTP Basic in its
/// `authorization` metadata, or the given body parameters (RFC 6749 §2.3).
/// An `authorization` value that is not ASCII is no credential.
fn client_authentication(
    metadata: &tonic::metadata::MetadataMap,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
) -> Result<ClientAuthentication, Status> {
    let authorization = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    ClientAuthentication::from_request(
        authorization,
        client_id,
        client_secret,
        client_assertion,
        client_assertion_type,
    )
    .map_err(|error| match error {
        TokenError::InvalidRequest => token_refusal(
            error,
            "the client must name itself and use one authentication method",
        ),
        _ => client_refused(),
    })
}

/// A token endpoint refusal; `ErrorInfo.metadata["oauthError"]` carries the
/// RFC 6749 §5.2 `error` code the endpoint's HTTP form answers with.
fn token_refusal(error: TokenError, message: impl Into<std::borrow::Cow<'static, str>>) -> Status {
    token_error(error, message).into()
}

/// A device polling faster than its `interval` seconds (RFC 8628 §3.5
/// `slow_down`): the interval grows by five seconds, which RetryInfo tells
/// the device.
fn slow_down(interval: i32) -> Status {
    // Set only from DEVICE_CODE_POLL_INTERVAL_SECS, which is positive.
    let wait = u64::try_from(interval).expect("a device poll interval is never negative") + 5;
    token_error(TokenError::SlowDown, "poll less often")
        .with_retry_after(std::time::Duration::from_secs(wait))
        .into()
}

fn token_error(error: TokenError, message: impl Into<std::borrow::Cow<'static, str>>) -> ApiError {
    let reason = match error {
        TokenError::InvalidClient => ErrorReason::AuthenticationFailed,
        TokenError::UnauthorizedClient | TokenError::AccessDenied => {
            ErrorReason::InsufficientPermissions
        }
        TokenError::InvalidScope => ErrorReason::ScopeNotGranted,
        // The user has not yet consented to the device request.
        TokenError::AuthorizationPending => ErrorReason::ConsentRequired,
        TokenError::SlowDown => ErrorReason::RateLimitExceeded,
        TokenError::ExpiredToken => ErrorReason::OperationExpired,
        TokenError::InvalidRequest
        | TokenError::InvalidGrant
        | TokenError::UnsupportedGrantType
        | TokenError::InvalidDpopProof
        | TokenError::InvalidTarget => ErrorReason::InvalidFieldValue,
    };
    ApiError::new(reason, message).with_metadata("oauthError", error.code())
}

/// A request whose target resource is refused (RFC 8707 §2
/// `invalid_target`), naming the `resource` parameter.
fn target_refused(refusal: sid_authn::target::TargetRefusal) -> Status {
    token_error(TokenError::InvalidTarget, refusal.to_string())
        .with_field_violation("resource", refusal.to_string())
        .with_metadata("field", "resource")
        .into()
}

/// A required token request parameter is missing (RFC 6749 §5.2
/// `invalid_request`).
fn missing_parameter(field: &'static str) -> Status {
    ApiError::new(
        ErrorReason::RequiredFieldMissing,
        format!("{field} is required"),
    )
    .with_field_violation(field, "required")
    .with_metadata("field", field)
    .with_metadata("oauthError", TokenError::InvalidRequest.code())
    .into()
}

/// The client failed to authenticate (RFC 6749 §5.2 `invalid_client`); what
/// failed goes to the log, never to the client.
fn client_refused() -> Status {
    token_refusal(TokenError::InvalidClient, "client authentication failed")
}

/// The scopes a machine user's token carries: the requested ones it may
/// have, or all of its own when none are requested. A machine user with no
/// scope list is unrestricted.
fn machine_scopes(mu: &sid_core::models::MachineUser, requested: Option<&str>) -> Vec<String> {
    match requested {
        Some(requested) => requested
            .split_whitespace()
            .filter(|s| mu.scopes.is_empty() || mu.scopes.iter().any(|a| a == s))
            .map(String::from)
            .collect(),
        None => mu.scopes.clone(),
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
