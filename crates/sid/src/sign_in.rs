// SPDX-License-Identifier: AGPL-3.0-only
//! Signing a user in once a ceremony verified them: the rules a verified
//! sign-in passes (anomaly detection over the account's sign-in history and
//! the client address, the login requirements, the attempt counters behind
//! the lockout), and storing its session under the installation's
//! concurrent-session limit with its credential delivered as the ceremony's
//! client takes it. Every ceremony that signs a user in (password, passkey,
//! upstream provider) completes through this one path.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{Duration, Utc};
use sid_authn::anomaly::AnomalyDetector;
use sid_authn::browser_session::{BrowserCookie, BrowserCsrf};
use sid_authn::captcha::{CaptchaGate, CaptchaProvider};
use sid_authn::challenge_store::{ChallengeStore, ChallengeStoreError};
use sid_authn::geoip::GeoIpChain;
use sid_authn::ip_intelligence::IpIntelligenceAggregator;
use sid_authn::jwt::JwtService;
use sid_authn::login_policy::LoginRequirements;
use sid_authn::native_session::{self, NativeError, NativePolicy};
use sid_authn::opaque::OpaqueRouter;
use sid_authn::password_sign_in::{
    OpenedPassword, PasswordSignInError, PasswordSignInHost, PendingSignIn, Started, Verified,
};
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::second_factor::pending::{
    CommitError, CompletedContext, Completion, FirstFactorProofs, PendingError, PendingSignInHost,
};
use sid_authn::second_factor::{FactorError, FactorSpend};
use sid_authn::sign_in_delivery::{BrowserCredential, CeremonyClient, Delivery, SignedIn};
use sid_authn::sign_in_security::{
    Admission, AttemptAuthentication, SignInAttempt, SignInRefusal, SignInSecurityHost,
    implied_auth_level,
};
use sid_core::Error as SidError;
use sid_core::models::event::{Event, event_types};
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    ActorFence, AuditEntry, Credential, CredentialData, CredentialFence, MutationContext,
    OperationCompletion, OperationKey, PrincipalAssignmentFence, Profile, ProfileId, Session,
    SessionEnd, SessionId, SignInProof,
};
use sid_ids::OpaqueLoginId;
use sid_plugin::CredentialStore;
use sid_plugin::SignInHistoryStore;
use sid_plugin::crypto::StoredCredential;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::StepUpMethod;
use sid_proto::sid::v1::authn::NativeCredentialSet;
use tracing::{info, warn};

/// Why a sign-in is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    /// The sign-in rules refused it, or ask for something first.
    #[error("sign-in refused: {0:?}")]
    Rules(SignInRefusal),
    /// The credential it proved or the login policy it was admitted under
    /// changed before the session committed, or the pending context it
    /// completes ended: it completes nothing and is started again.
    #[error("the sign-in's proof or policy changed")]
    Fenced,
    /// The keyed operation it completes already committed its session.
    #[error("the sign-in already completed")]
    AlreadyCompleted,
    /// The native session's refresh generation could not be issued.
    #[error(transparent)]
    Native(#[from] NativeError),
    /// A dependency the sign-in needs cannot answer now; the client retries.
    #[error("{what} unavailable: {cause}")]
    Unavailable { what: &'static str, cause: String },
    /// The password sign-in refused or failed.
    #[error(transparent)]
    Password(#[from] PasswordSignInError),
    /// The identifier is not a valid principal.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    /// The pending second-factor context the call continues has ended.
    #[error("the sign-in has ended")]
    SessionEnded,
    /// The sign-in's kept state is gone; it is started again.
    #[error("the sign-in expired")]
    Expired,
    /// The account no longer signs in; one answer whatever the reason.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The sign-in's kept state could not be read or written.
    #[error(transparent)]
    Ceremony(#[from] ChallengeStoreError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log, not the
    /// refusal.
    #[error("internal error")]
    Internal,
}

impl From<SignInRefusal> for SignInError {
    fn from(r: SignInRefusal) -> Self {
        Self::Rules(r)
    }
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> SignInError {
    tracing::error!(operation, error = %cause, "internal failure");
    SignInError::Internal
}

/// A failed read of the factors a sign-in offers: only the store answers
/// there.
fn factor_failure(e: FactorError) -> SignInError {
    match e {
        FactorError::Store(e) => SignInError::Store(e),
        other => internal("read the account's second factors", other),
    }
}

/// What the rules weigh beside the authentication: the pass earned by
/// solving the CAPTCHA this sign-in was asked for, and the client's
/// User-Agent.
#[derive(Default, Clone, Copy)]
pub struct AttemptContext<'a> {
    pub captcha_pass: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// What the rules decide about a local first-factor sign-in.
pub enum FirstFactor {
    /// Admitted: the session commits under this policy fence.
    Admitted(Option<ActorFence>),
    /// A second factor is owed, one of `factors` the account has enrolled or,
    /// with none ever enrolled, one of `enrollable` it enrolls first: the
    /// sign-in gets its pending context, under this fence.
    AwaitsSecondFactor {
        factors: Vec<StepUpMethod>,
        enrollable: Vec<StepUpMethod>,
        fence: Option<ActorFence>,
    },
}

/// How a full sign-in authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMethod {
    Password,
    /// A passkey assertion: whether the authenticator verified the user, and
    /// the RFC 8176 method of the key that asserted (`hwk` / `swk`).
    Passkey {
        user_verified: bool,
        key_amr: &'static str,
    },
    /// An upstream identity provider verified the user: SID verified no
    /// method itself.
    Upstream,
}

/// How a first factor's sign-in is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Judged {
    /// Its first judgement: an admitted sign-in is recorded as evidence.
    Recorded,
    /// Decided again after its commit was fenced, under what its first
    /// judgement admitted: already recorded, judged by the rules of its own
    /// request without recording it twice.
    Again(Admission),
}

impl LoginMethod {
    /// The assurance this sign-in establishes.
    pub fn auth_level(self, passkey_satisfies_mfa: bool) -> AuthLevel {
        match self {
            Self::Password => implied_auth_level("opaque", passkey_satisfies_mfa, false),
            Self::Passkey { user_verified, .. } => {
                implied_auth_level("webauthn", passkey_satisfies_mfa, user_verified)
            }
            Self::Upstream => AuthLevel::Basic,
        }
    }

    /// The method name the sign-in rules weigh.
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "opaque",
            Self::Passkey { .. } => "webauthn",
            Self::Upstream => "upstream",
        }
    }

    /// The `amr` values (RFC 8176 §2) the session records for this sign-in.
    pub fn amr(self) -> Vec<String> {
        match self {
            Self::Password => vec!["pwd".to_string()],
            Self::Passkey {
                user_verified,
                key_amr,
            } => sid_authn::webauthn::passkey_amr(key_amr, user_verified)
                .iter()
                .map(|m| m.to_string())
                .collect(),
            // RFC 8176 §1: only methods SID itself verified are named.
            Self::Upstream => Vec::new(),
        }
    }
}

/// A completed first-factor sign-in: its credential, and when it is a
/// pending context the second factors that complete it or may be enrolled
/// first (`StepUpMethod` values) with a browser's CSRF token.
pub struct FirstFactorSignedIn {
    pub signed_in: SignedIn,
    pub second_factors: Vec<i32>,
    pub enrollable_factors: Vec<i32>,
    pub browser_csrf: Option<String>,
}

/// The operation a sign-in completes, whose result is its delivery sealed
/// for a lost response: the session commits with that completion, and a
/// repeat of the operation finds it instead of a second session.
pub struct RetainedSignIn<'a> {
    pub keys: &'a dyn sid_keys::KeyManager,
    /// The completions of this kind of sign-in, and the method each names.
    pub namespace: &'static str,
    pub method: &'static str,
    pub completion_key: OperationKey,
    /// The sealing context: this operation of this issuer.
    pub context: String,
    /// The end of the operation; the delivery is never redelivered after.
    pub deadline: chrono::DateTime<Utc>,
    /// The operation's significant inputs: a repeat must present them again.
    pub inputs: Vec<u8>,
}

/// The significant inputs of an admitted sign-in committed under
/// `assignment`: a repeat is the same operation only under the same
/// assignment, so one retired and linked again never receives the earlier
/// session.
pub fn admitted_inputs(assignment: PrincipalAssignmentFence) -> Vec<u8> {
    format!(
        "{}:{}:{}",
        assignment.profile, assignment.principal.0, assignment.revision
    )
    .into_bytes()
}

/// The namespace of admitted sign-ins' completions.
pub const ADMITTED_NAMESPACE: &str = "admitted-sign-in";

/// The method name an admitted sign-in's completion records.
pub const ADMITTED_METHOD: &str = "admitted_sign_in";

/// What signing in uses, handed over by the host.
pub struct SignInParts {
    pub storage: Arc<dyn StorageBackend>,
    pub jwt: Arc<JwtService>,
    pub revocation: Arc<RevocationCache>,
    /// The issuer whose events announce sessions and security reactions.
    pub issuer: String,
    pub anomaly: Arc<AnomalyDetector>,
    pub ip_intelligence: Arc<IpIntelligenceAggregator>,
    pub geoip: Arc<GeoIpChain>,
    /// Which sign-in each CAPTCHA was asked of, and the passes earned.
    pub captcha_gate: CaptchaGate,
    pub captcha_provider: Arc<dyn CaptchaProvider>,
    /// Runs the OPAQUE sign-ins against the stored password files.
    pub opaque: Arc<OpaqueRouter>,
    /// Opens the sealed password files and seals the kept sign-in state.
    pub keys: Arc<dyn sid_keys::KeyManager>,
}

/// How long a started password sign-in may be finished.
const LOGIN_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The pending second-factor context a sign-in completes: it ends in the
/// session's commit, which spends what its factor spends.
struct Completing<'a> {
    id: SessionId,
    end: &'a SessionEnd,
    spend: Option<FactorSpend>,
    /// The CSRF token the sign-in page holds for the context: the session
    /// completing it keeps it, the only one that page has (the completion's
    /// answer carries none).
    csrf: Option<sid_core::models::BrowserCsrfToken>,
}

/// Signing users in for one authority.
pub struct SignIn {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    issuer: String,
    anomaly: Arc<AnomalyDetector>,
    ip_intelligence: Arc<IpIntelligenceAggregator>,
    geoip: Arc<GeoIpChain>,
    captcha_gate: CaptchaGate,
    captcha_provider: Arc<dyn CaptchaProvider>,
    /// The installation's security policy: session lifetime and limit, how
    /// native sessions renew, whether a passkey satisfies MFA.
    policy: SecurityPolicy,
    /// This authority's IdP session cookie, the only one it sets.
    cookie: BrowserCookie,
    opaque: Arc<OpaqueRouter>,
    keys: Arc<dyn sid_keys::KeyManager>,
    /// Password sign-ins between start and finish.
    logins: ChallengeStore<PendingSignIn<ProfileId>>,
    /// The credential each pending second-factor context's first factor
    /// proved, keyed by the context: its completion commits only while that
    /// credential is unchanged.
    first_factor_proofs: FirstFactorProofs,
}

impl SignIn {
    /// Sign-in under the CE default policy with the default cookie.
    pub fn new(parts: SignInParts) -> Self {
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = parts.storage.clone();
        Self {
            logins: ChallengeStore::new(
                ceremonies.clone(),
                parts.keys.clone(),
                "opaque-login",
                LOGIN_TTL,
            ),
            first_factor_proofs: FirstFactorProofs::new(ceremonies, parts.keys.clone(), LOGIN_TTL),
            opaque: parts.opaque,
            keys: parts.keys,
            storage: parts.storage,
            jwt: parts.jwt,
            revocation: parts.revocation,
            issuer: parts.issuer,
            anomaly: parts.anomaly,
            ip_intelligence: parts.ip_intelligence,
            geoip: parts.geoip,
            captcha_gate: parts.captcha_gate,
            captcha_provider: parts.captcha_provider,
            policy: SecurityPolicy::ce_default(),
            cookie: BrowserCookie::default(),
        }
    }

    /// Apply `policy` to every later sign-in.
    pub fn set_policy(&mut self, policy: SecurityPolicy) {
        self.policy = policy;
    }

    /// The security policy sign-ins follow.
    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    /// Name this authority's IdP session cookie `cookie`.
    pub fn set_cookie(&mut self, cookie: BrowserCookie) {
        self.cookie = cookie;
    }

    /// This authority's IdP session cookie.
    pub fn cookie(&self) -> &BrowserCookie {
        &self.cookie
    }

    /// The attempt counters and lockout.
    pub fn anomaly(&self) -> &AnomalyDetector {
        &self.anomaly
    }

    /// The tokens a sign-in's credential is issued with.
    pub(crate) fn jwt(&self) -> &JwtService {
        &self.jwt
    }

    /// The store the sign-ins read and commit to.
    pub(crate) fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
    }

    /// The keys that open and seal the stored password files.
    pub(crate) fn keys(&self) -> &dyn sid_keys::KeyManager {
        self.keys.as_ref()
    }

    /// The OPAQUE server the stored password files are proven against.
    pub(crate) fn opaque(&self) -> &OpaqueRouter {
        &self.opaque
    }

    /// Stops revoked sessions' access tokens in every process.
    pub(crate) fn revocation(&self) -> &RevocationCache {
        &self.revocation
    }

    /// The mailbox login mail for the email key `key` goes to on `profile`,
    /// the account it routes to: the address in the spelling that profile
    /// bound it with (its binding's contact, which registration, import and
    /// directory provisioning each record with the binding), never another
    /// spelling of the key. `None` when that binding records no such
    /// contact: a lost spelling is not inferred from the key.
    pub async fn login_mail_destination(
        &self,
        profile: ProfileId,
        key: &str,
    ) -> Result<Option<String>, SignInError> {
        use sid_core::models::principal::PrincipalType;
        let principals = self.storage.get_principals_by_profile(profile).await?;
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
            .await?
            .filter(|email| email.profile_id == profile)
            .map(|email| email.email))
    }

    /// Which sign-in each CAPTCHA was asked of, and the passes earned.
    pub fn captcha_gate(&self) -> &CaptchaGate {
        &self.captcha_gate
    }

    /// The CAPTCHA provider the rules ask challenges of.
    pub fn captcha_provider(&self) -> &dyn CaptchaProvider {
        self.captcha_provider.as_ref()
    }

    /// Run the rules for `profile_id`'s verified sign-in under
    /// `requirements` and record it, once admitted, as evidence for later
    /// sign-ins; what admitted it.
    pub async fn evaluate(
        &self,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        (authentication, context): (AttemptAuthentication<'_>, AttemptContext<'_>),
        requirements: &LoginRequirements,
    ) -> Result<Admission, SignInError> {
        let requirements = self.for_account(requirements, profile_id).await?;
        let attempt = attempt(client_ip, authentication, context);
        Ok(
            sid_authn::sign_in_security::evaluate(
                &Rules(self),
                &profile_id,
                attempt,
                &requirements,
            )
            .await?,
        )
    }

    /// The same rules again for a sign-in `admitted` admitted whose commit a
    /// policy written meanwhile fenced, under `requirements`, the policy in
    /// force now, recording nothing (see
    /// [`sid_authn::sign_in_security::redecide`]).
    async fn redecide(
        &self,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        (authentication, context): (AttemptAuthentication<'_>, AttemptContext<'_>),
        requirements: &LoginRequirements,
        admitted: Admission,
    ) -> Result<Admission, SignInError> {
        let requirements = self.for_account(requirements, profile_id).await?;
        let attempt = attempt(client_ip, authentication, context);
        Ok(sid_authn::sign_in_security::redecide(
            &Rules(self),
            &profile_id,
            attempt,
            &requirements,
            admitted,
        )
        .await?)
    }

    /// `requirements` for a sign-in of `profile_id`, with the protection its
    /// active credentials establish here, the credential owner.
    pub async fn for_account(
        &self,
        requirements: &LoginRequirements,
        profile_id: ProfileId,
    ) -> Result<LoginRequirements, SignInError> {
        Ok(requirements
            .clone()
            .for_account(self.storage.as_ref(), profile_id)
            .await?)
    }

    /// The same rules for a repeat of a sign-in already admitted and
    /// recorded from `admitted_from`: judged on its own request, recorded as
    /// no further sign-in.
    pub async fn check(
        &self,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        (authentication, context): (AttemptAuthentication<'_>, AttemptContext<'_>),
        requirements: &LoginRequirements,
        admitted_from: Option<IpAddr>,
    ) -> Result<(), SignInError> {
        let requirements = self.for_account(requirements, profile_id).await?;
        let attempt = attempt(client_ip, authentication, context);
        Ok(sid_authn::sign_in_security::check(
            &Rules(self),
            &profile_id,
            attempt,
            &requirements,
            admitted_from,
        )
        .await?)
    }

    /// The same rules for a local sign-in that proved its first factor with
    /// `method` at `assurance` with `amr`, under `requirements`: admitted,
    /// or, when it owes the requirements or an anomaly rule's step-up and a
    /// second factor the account has enrolled (or may enroll first) answers
    /// that, awaiting the factor.
    pub async fn first_factor(
        &self,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        (method, assurance, amr): (&str, AuthLevel, &[String]),
        context: AttemptContext<'_>,
        requirements: &LoginRequirements,
    ) -> Result<FirstFactor, SignInError> {
        self.judge_first_factor(
            profile_id,
            client_ip,
            (method, assurance, amr),
            context,
            requirements,
            Judged::Recorded,
        )
        .await
        .map(|(admission, _)| admission)
    }

    /// [`Self::first_factor`], recording the admitted sign-in as evidence
    /// or, for a sign-in already recorded and decided again, judging it
    /// without recording it twice; with what admitted it (nothing known for
    /// a sign-in that owes its second factor).
    async fn judge_first_factor(
        &self,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        (method, assurance, amr): (&str, AuthLevel, &[String]),
        context: AttemptContext<'_>,
        requirements: &LoginRequirements,
        judged: Judged,
    ) -> Result<(FirstFactor, Admission), SignInError> {
        // The factors are chosen under the same requirements the rules
        // decide on: with the account's protection.
        let requirements = &self.for_account(requirements, profile_id).await?;
        let authentication = AttemptAuthentication::Local {
            method,
            assurance,
            amr,
        };
        let judgement = match judged {
            Judged::Recorded => {
                self.evaluate(
                    profile_id,
                    client_ip,
                    (authentication, context),
                    requirements,
                )
                .await
            }
            Judged::Again(admitted) => {
                self.redecide(
                    profile_id,
                    client_ip,
                    (authentication, context),
                    requirements,
                    admitted,
                )
                .await
            }
        };
        let owed = match judgement {
            Ok(admission) => return Ok((FirstFactor::Admitted(requirements.fence), admission)),
            Err(
                owed @ SignInError::Rules(
                    SignInRefusal::StepUp(_) | SignInRefusal::StepUpAfterAnomaly(_),
                ),
            ) => owed,
            Err(refused) => return Err(refused),
        };
        let now = Utc::now();
        let first = sid_authn::login_policy::local_authentication(profile_id, assurance, amr, now);
        let credentials: &dyn CredentialStore<Owner = ProfileId> = self.storage.as_ref();
        let factors = sid_authn::second_factor::offered_factors(
            credentials,
            profile_id,
            requirements,
            &first,
            now,
        )
        .await
        .map_err(factor_failure)?;
        let enrollable = if factors.is_empty() {
            sid_authn::second_factor::enrollable_factors(
                credentials,
                profile_id,
                requirements,
                &first,
                self.policy.auth.passkey_satisfies_mfa,
                now,
            )
            .await
            .map_err(factor_failure)?
        } else {
            Vec::new()
        };
        if factors.is_empty() && enrollable.is_empty() {
            return Err(owed);
        }
        // The refusal that left the rules carries no admission: a CAPTCHA
        // they took is not counted when the sign-in is decided again.
        Ok((
            FirstFactor::AwaitsSecondFactor {
                factors,
                enrollable,
                fence: requirements.fence,
            },
            Admission::default(),
        ))
    }

    /// Record `profile_id`'s sign-in completed from `client_ip`, the address
    /// the rules judged at its first factor, as evidence for later sign-ins.
    pub async fn record_completed(&self, profile_id: ProfileId, client_ip: Option<IpAddr>) {
        sid_authn::sign_in_security::record_completed_sign_in(&Rules(self), &profile_id, client_ip)
            .await;
    }

    /// Refuse a sign-in attempt while `identity` is locked out. Checked before
    /// any password work and for known and unknown identities alike, so a
    /// lockout neither lets guessing continue nor confirms a guess.
    pub async fn refuse_if_locked(&self, identity: &str) -> Result<(), SignInError> {
        let locked = self
            .anomaly
            .lockout_active(identity)
            .await
            .map_err(unavailable)?;
        if locked {
            return Err(SignInRefusal::TooManyAttempts(self.anomaly.lockout_duration()).into());
        }
        Ok(())
    }

    /// Count a failed sign-in attempt (brute force and stuffing limits). An
    /// attempt that cannot be counted refuses the request: an uncounted
    /// guess would never reach the lockout.
    pub async fn record_failed_login(
        &self,
        identity: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<(), SignInError> {
        self.anomaly
            .record_failed_attempt(identity)
            .await
            .map_err(unavailable)?;
        self.record_failed_from(client_ip).await
    }

    /// Count a failed attempt against its source address only: the stuffing
    /// limit and the address's reputation, not any account's sign-in budget.
    pub async fn record_failed_from(&self, client_ip: Option<IpAddr>) -> Result<(), SignInError> {
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
    pub async fn record_ip_attempt(&self, client_ip: Option<IpAddr>) -> Result<(), SignInError> {
        match client_ip {
            Some(ip) => self
                .anomaly
                .record_ip_attempt(ip)
                .await
                .map_err(unavailable),
            None => Ok(()),
        }
    }

    /// Publish a security event for an anomaly rule's reaction, and keep it
    /// for the dashboard (best effort).
    async fn security_event(
        &self,
        profile_id: &str,
        rule: &str,
        reaction: &str,
        reason: &str,
        client_ip: Option<IpAddr>,
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
            rule, profile_id, client_ip, reason, risk_score, reaction,
        );
        if let Err(e) = self.storage.save_anomaly_event(&record).await {
            warn!("Failed to persist anomaly event: {}", e);
        }
    }

    /// The browser's IdP session, by the secret this authority's session
    /// cookie carries among `cookies` (the `Cookie` header values); `None`
    /// without one, or for a secret no session holds.
    pub async fn browser_session<'c>(
        &self,
        cookies: impl IntoIterator<Item = &'c str>,
    ) -> Result<Option<Session>, SignInError> {
        let Some(secret) = self.cookie.secret(cookies) else {
            return Ok(None);
        };
        Ok(self
            .storage
            .get_session_by_browser_secret(&secret.hash())
            .await?)
    }

    /// The lifetime left of the browser's own live `session`, a sign-in a
    /// completion already delivered by its cookie, answered again without
    /// any effect: only while the account can sign in and the session meets
    /// the requirements `login_policy` states now.
    pub async fn current_sign_in(
        &self,
        login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
        session: &Session,
    ) -> Result<i64, SignInError> {
        if session.is_expired() || session.awaits_second_factor() {
            return Err(SignInError::SessionEnded);
        }
        self.storage
            .get_profile(session.profile_id)
            .await?
            .filter(|profile| profile.status.can_authenticate())
            .ok_or(SignInError::SessionEnded)?;
        let requirements = self
            .for_account(
                &organization_requirements(login_policy).await?,
                session.profile_id,
            )
            .await?;
        if let sid_authn::login_policy::LoginDecision::StepUp(unmet) =
            requirements.decide(session, Utc::now())
        {
            return Err(SignInRefusal::StepUp(unmet).into());
        }
        Ok((session.expires_at - Utc::now()).num_seconds())
    }

    /// Whether the session `session_id` is still valid, as `caller` may ask:
    /// someone else's session answers exactly like an unknown one; the owner
    /// and the expiry are told only for a valid session.
    pub async fn validate_session(
        &self,
        caller: &sid_authn::caller::Caller,
        session_id: SessionId,
    ) -> Result<sid_proto::sid::v1::ValidateSessionResponse, SignInError> {
        let invalid = sid_proto::sid::v1::ValidateSessionResponse {
            valid: false,
            profile_id: None,
            scopes: vec![],
            expires_at: None,
        };
        match self.storage.get_session(session_id).await? {
            Some(session) if caller.require_self_or_admin(session.profile_id).is_ok() => {
                if session.expires_at <= Utc::now() {
                    return Ok(invalid);
                }
                Ok(sid_proto::sid::v1::ValidateSessionResponse {
                    valid: true,
                    profile_id: Some(session.profile_id.into()),
                    scopes: vec![],
                    expires_at: Some(crate::wire::to_timestamp(session.expires_at)),
                })
            }
            _ => Ok(invalid),
        }
    }

    /// The sign-in methods offered for `principal`. The answer reads no
    /// account: it is the same for every identifier of a type, so it cannot
    /// tell whether one has an account (WebAuthn Level 3 §14.6.2); each
    /// method's own step refuses an unknown account like a wrong secret.
    /// Password and passkey sign-in are always served (passkeys through the
    /// discoverable flow); magic links only with `magic_links`, and only to an
    /// email address.
    pub fn sign_in_methods(
        &self,
        principal: &str,
        magic_links: bool,
    ) -> Result<sid_proto::sid::v1::ResolvePrincipalResponse, SignInError> {
        let handle = sid_authn::normalize::normalize_principal(principal)
            .map_err(|e| SignInError::InvalidIdentifier(e.to_string()))?;
        let mut available_methods = vec!["opaque".to_string(), "webauthn".to_string()];
        if magic_links
            && handle.principal_type.to_principal_type()
                == sid_core::models::principal::PrincipalType::Email
        {
            available_methods.push("magic_link".to_string());
        }
        Ok(sid_proto::sid::v1::ResolvePrincipalResponse { available_methods })
    }

    /// Whether `session` may authorize an application at `now`: not
    /// expired, not provisional, and used within the installation's idle
    /// limit.
    pub fn authorizes(&self, session: &Session, now: chrono::DateTime<Utc>) -> bool {
        if session.expires_at <= now || session.is_provisional {
            return false;
        }
        match self.policy.session.idle_timeout_hours {
            0 => true,
            hours => {
                let last = session.last_activity_at.unwrap_or(session.created_at);
                now - last <= Duration::hours(i64::from(hours))
            }
        }
    }

    /// A full session of `profile_id` from `ip_address`, for the
    /// installation's absolute lifetime when it sets one, with the sign-in
    /// scopes; its authentication is the caller's to set.
    pub fn new_session(&self, profile_id: ProfileId, ip_address: Option<IpAddr>) -> Session {
        let mut session =
            Session::new(profile_id, ip_address, Utc::now() + self.session_lifetime());
        session.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
        session
    }

    /// The active account `identifier` (email, phone or username) signs in
    /// to: only through the principal's explicit assignment, and only under
    /// the current email key revision; `None` when none may, whatever the
    /// reason, so the answer does not reveal the state of the address.
    pub async fn resolve_profile(&self, identifier: &str) -> Result<Option<Profile>, SignInError> {
        let handle = sid_authn::normalize::normalize_principal(identifier)
            .map_err(|e| SignInError::InvalidIdentifier(e.to_string()))?;
        Ok(resolve_handle(self.storage.as_ref(), &handle).await?)
    }

    /// The OPAQUE password file of `credential`, opened, with its curve, and
    /// the credential's data as the store holds it afterwards.
    pub async fn stored_password(
        &self,
        credential: &Credential,
    ) -> Result<(StoredCredential, CredentialData), SignInError> {
        use sid_authn::sealed_secret::StoredPasswordError;
        sid_authn::sealed_secret::stored_password(
            self.keys.as_ref(),
            self.storage.as_ref(),
            credential,
        )
        .await
        .map_err(|e| match e {
            StoredPasswordError::Storage(e) => SignInError::Store(e),
            e @ (StoredPasswordError::NoCurve(_) | StoredPasswordError::UnknownCurve { .. }) => {
                internal("read OPAQUE curve", e)
            }
            StoredPasswordError::Sealed(e) => internal("open OPAQUE envelope", e),
        })
    }

    /// Start a password sign-in of `principal` from `client_ip` with the
    /// client's OPAQUE credential request. A principal nobody holds, or one
    /// without a password, is answered alike (RFC 9807 §10.9).
    pub async fn password_start(
        &self,
        principal: &str,
        credential_request: &[u8],
        client_ip: Option<IpAddr>,
    ) -> Result<Started, SignInError> {
        let host = Passwords {
            sign_in: self,
            client_ip,
        };
        sid_authn::password_sign_in::start(&host, principal, credential_request).await
    }

    /// Finish the password sign-in `login` with the client's credential
    /// finalization: the active account whose password it proved, or one
    /// refusal for a wrong password and an unknown account alike, counted
    /// against the lockout.
    pub async fn password_finish(
        &self,
        login: &OpaqueLoginId,
        credential_finalization: &[u8],
        client_ip: Option<IpAddr>,
    ) -> Result<Verified<Profile>, SignInError> {
        let host = Passwords {
            sign_in: self,
            client_ip,
        };
        sid_authn::password_sign_in::finish(&host, login, credential_finalization).await
    }

    /// Complete a local first-factor sign-in of `profile` by `method` as
    /// `admission` decided: the session, or its pending context with the
    /// second factors that complete it and, for a browser, the CSRF token the
    /// completion sends. A session of a native client that proved the
    /// application key `native_key` gets its refresh generation; a pending
    /// context gets none.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_first_factor(
        &self,
        profile: &Profile,
        method: LoginMethod,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<IpAddr>,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<&CredentialFence>,
        admission: FirstFactor,
    ) -> Result<FirstFactorSignedIn, SignInError> {
        match admission {
            FirstFactor::Admitted(policy) => Ok(FirstFactorSignedIn {
                signed_in: self
                    .sign_in_by(
                        profile, method, device_id, client_ip, client, native_key, proved_by,
                        policy,
                    )
                    .await?,
                second_factors: Vec::new(),
                enrollable_factors: Vec::new(),
                browser_csrf: None,
            }),
            FirstFactor::AwaitsSecondFactor {
                factors,
                enrollable,
                fence,
            } => {
                let mut session = Session::new_awaiting_second_factor(
                    profile.id,
                    client_ip,
                    method.auth_level(self.policy.auth.passkey_satisfies_mfa),
                    method.amr(),
                );
                session.device_id = device_id;
                // Kept for as long as the context lives; a completion that
                // finds none completes nothing.
                let kept = self.first_factor_proofs.keep(&session, proved_by).await?;
                if !kept {
                    return Err(SignInError::Expired);
                }
                let (signed_in, browser_csrf) = self
                    .sign_in_pending(
                        profile,
                        session,
                        client,
                        proved_by.map(SignInProof::Credential),
                        fence,
                    )
                    .await?;
                info!(profile = %profile.id, ?factors, ?enrollable, "Sign-in awaits its second factor");
                Ok(FirstFactorSignedIn {
                    signed_in,
                    second_factors: factors.into_iter().map(i32::from).collect(),
                    enrollable_factors: enrollable.into_iter().map(i32::from).collect(),
                    browser_csrf,
                })
            }
        }
    }

    /// Sign `profile` in with a full session authenticated by `method`, at
    /// the level and with the `amr` it establishes, recording the client's
    /// address and device: the history the new-device rule compares later
    /// sign-ins with.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_in_by(
        &self,
        profile: &Profile,
        method: LoginMethod,
        device_id: Option<uuid::Uuid>,
        client_ip: Option<IpAddr>,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
    ) -> Result<SignedIn, SignInError> {
        let mut session = self.new_session(profile.id, client_ip);
        session.device_id = device_id;
        session.assurance_level = method.auth_level(self.policy.auth.passkey_satisfies_mfa);
        session.amr = method.amr();
        self.sign_in(
            profile,
            session,
            client,
            native_key,
            proved_by.map(SignInProof::Credential),
            policy,
            None,
        )
        .await
    }

    /// The credential `pending`'s first factor proved, while it still holds:
    /// it commits with what the context completes, as in a sign-in that needs
    /// no second factor. One replaced or revoked since completes nothing
    /// (`Fenced`), and a context whose proof is gone has ended.
    pub async fn first_factor_fence(
        &self,
        pending: &Session,
    ) -> Result<Option<CredentialFence>, SignInError> {
        Ok(self
            .first_factor_proofs
            .fence(self.storage.as_ref(), pending)
            .await?)
    }

    /// How long a full session lives: the policy's absolute lifetime, a day
    /// when it sets none.
    pub fn session_lifetime(&self) -> Duration {
        match self.policy.session.max_lifetime_hours {
            0 => Duration::hours(24),
            hours => Duration::hours(i64::from(hours)),
        }
    }

    /// Store `session` and deliver its credential to `client`: the browser
    /// sign-in page gets the IdP session cookie, a fresh secret whose hash
    /// the session stores, and no access token; a native client gets the
    /// session's access token. `proved_by` is what the sign-in proved (a
    /// credential, or the principal assignment its evidence resolved), which
    /// must still hold when the session commits, and `policy` the login
    /// policy it was admitted under, which must too.
    /// A browser sign-in completing `retained` commits with that operation's
    /// completion, its sealed delivery. A native client whose ceremony
    /// proved the application key `native_key` (its JWK thumbprint) also
    /// gets the session's first refresh generation, bound to that key.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_in(
        &self,
        profile: &Profile,
        session: Session,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<SignInProof<'_>>,
        policy: Option<ActorFence>,
        retained: Option<RetainedSignIn<'_>>,
    ) -> Result<SignedIn, SignInError> {
        let limit = self.policy.session.max_concurrent_sessions;
        self.deliver(
            profile, session, client, native_key, proved_by, policy, limit, None, retained,
        )
        .await
        .map(|(signed_in, _)| signed_in)
    }

    /// Sign `profile` in as [`Self::sign_in`] does with `session`, the
    /// completion of the pending second-factor context `pending`: the
    /// context ends (owing what its end names) in the session's own commit,
    /// which applies only while the context exists and spends `spend` when
    /// given. Its access tokens stop at once in every process.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_pending(
        &self,
        profile: &Profile,
        (pending, end): (&Session, &SessionEnd),
        session: Session,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<SignInProof<'_>>,
        policy: Option<ActorFence>,
        (spend, retained): (Option<FactorSpend>, Option<RetainedSignIn<'_>>),
    ) -> Result<SignedIn, SignInError> {
        let limit = self.policy.session.max_concurrent_sessions;
        let (signed_in, _) = self
            .deliver(
                profile,
                session,
                client,
                native_key,
                proved_by,
                policy,
                limit,
                Some(Completing {
                    id: pending.id,
                    end,
                    spend,
                    csrf: pending.browser_csrf,
                }),
                retained,
            )
            .await?;
        self.revocation
            .revoke_session(pending.id.to_string())
            .await
            .map_err(|e| SignInError::Unavailable {
                what: "session revocation",
                cause: e.to_string(),
            })?;
        Ok(signed_in)
    }

    /// The requirements `login_policy` states now, with the account's
    /// protection, when `pending` completed by the second factor `method`
    /// would meet them; the step-up they ask otherwise. A factor spent on
    /// the completion is checked here before it is spent.
    pub async fn second_factor_requirements(
        &self,
        login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
        pending: &Session,
        method: &str,
    ) -> Result<LoginRequirements, SignInError> {
        sid_authn::second_factor::pending::second_factor_requirements(
            &self.pending_host(login_policy),
            pending,
            method,
        )
        .await
    }

    /// `pending` as it stands now when it is still a live context of its
    /// account; otherwise the context `client` proves (with `native_key`),
    /// which may only receive again the sign-in its completion committed.
    pub async fn live_pending(
        &self,
        pending: Session,
        client: CeremonyClient,
        native_key: Option<&str>,
    ) -> Result<Result<Session, CompletedContext>, SignInError> {
        Ok(sid_authn::second_factor::pending::live_pending(
            self.storage.as_ref(),
            pending,
            client,
            native_key,
        )
        .await?)
    }

    /// This authority as the host of its pending second-factor contexts,
    /// under the requirements `login_policy` states.
    fn pending_host<'a>(
        &'a self,
        login_policy: &'a dyn sid_authn::login_policy::LoginPolicySource,
    ) -> PendingHost<'a> {
        PendingHost {
            sign_in: self,
            login_policy,
        }
    }

    /// Complete `pending` with the verified second factor `method` (RFC
    /// 8176): the login requirements `login_policy` states now are met by
    /// the completed authentication, the first factor's credential still
    /// holds, the pending context ends exactly once and the account gets its
    /// session with a new credential, delivered to `client` (with the
    /// refresh generation bound to `native_key` when it proved one); the
    /// factor's `spend` commits with that session or not at all.
    pub async fn complete_second_factor(
        &self,
        login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
        pending: Session,
        method: &str,
        client: CeremonyClient,
        native_key: Option<&str>,
        spend: Option<FactorSpend>,
    ) -> Result<SignedIn, SignInError> {
        sid_authn::second_factor::pending::complete_second_factor(
            &self.pending_host(login_policy),
            pending,
            method,
            client,
            native_key,
            spend,
        )
        .await
    }

    /// The sign-in the second factor of `completed` already completed,
    /// delivered again to that context after a lost response: the same
    /// session and credential (and, for a native client, the same first
    /// generation), with no further effect. `None` when no completion of
    /// that context committed, or it is no longer kept. A completion of
    /// another context, an ended or expired session, an account that can no
    /// longer sign in, requirements the session no longer meets, or a native
    /// first generation already rotated deliver nothing.
    pub async fn redeliver_second_factor(
        &self,
        login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
        completed: &CompletedContext,
    ) -> Result<Option<SignedIn>, SignInError> {
        sid_authn::second_factor::pending::redeliver_second_factor(
            &self.pending_host(login_policy),
            completed,
        )
        .await
    }

    /// Whether the native delivery `delivery` retained for `session` may be
    /// handed out again: its first generation still the session's current
    /// one (a client that already renewed with it received it, and retired
    /// credentials are never delivered), and its access token not replaced
    /// and stopped by a later step-up, which would replace the client's
    /// current token with a revoked one.
    async fn native_deliverable(
        &self,
        delivery: &sid_authn::sign_in_delivery::RetainedDelivery,
        session: &Session,
    ) -> Result<bool, SignInError> {
        if let Some(credential) = delivery.refresh_credential() {
            let current = self
                .storage
                .native_generation_by_credential(&sid_authn::oauth2::OAuth2Server::hash_token(
                    credential,
                ))
                .await?
                .is_some_and(|generation| {
                    generation.session_id == session.id
                        && generation.state == sid_core::models::NativeGenerationState::Current
                });
            if !current {
                return Ok(false);
            }
        }
        let Some(token) = delivery.bearer_token() else {
            return Ok(true);
        };
        let Ok(claims) = self
            .jwt()
            .validate_access_token(secrecy::ExposeSecret::expose_secret(token))
        else {
            return Ok(false);
        };
        let revoked = self
            .revocation()
            .is_revoked(&claims.jti, &claims.sid)
            .await
            .map_err(|e| SignInError::Unavailable {
                what: "token revocation",
                cause: e.to_string(),
            })?;
        Ok(!revoked)
    }

    /// Store a sign-in's pending second-factor context and deliver its
    /// credential as [`Self::sign_in`] does, with the CSRF token a browser
    /// completes it with. It takes no place under the session limit: the
    /// session it completes into does. A pending context is never renewable:
    /// it gets no refresh generation, the session completing it does.
    pub async fn sign_in_pending(
        &self,
        profile: &Profile,
        session: Session,
        client: CeremonyClient,
        proved_by: Option<SignInProof<'_>>,
        policy: Option<ActorFence>,
    ) -> Result<(SignedIn, Option<String>), SignInError> {
        self.deliver(
            profile, session, client, None, proved_by, policy, 0, None, None,
        )
        .await
    }

    /// Store `session` under `limit` (completing `pending` when given, with
    /// `retained`'s completion when given) and deliver its credential, with
    /// the browser's encoded CSRF token for a browser and the refresh
    /// generation bound to `native_key` for a native client that proved one.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &self,
        profile: &Profile,
        mut session: Session,
        client: CeremonyClient,
        native_key: Option<&str>,
        proved_by: Option<SignInProof<'_>>,
        policy: Option<ActorFence>,
        limit: u32,
        pending: Option<Completing<'_>>,
        retained: Option<RetainedSignIn<'_>>,
    ) -> Result<(SignedIn, Option<String>), SignInError> {
        // Kept no longer than it can be delivered again.
        let completion = |retained: RetainedSignIn<'_>, sealed: Vec<u8>| {
            OperationCompletion::new(
                retained.namespace,
                retained.completion_key,
                retained.method,
                &retained.inputs,
                sealed,
            )
            .retained_until(retained.deadline)
        };
        match client {
            CeremonyClient::Browser => {
                let credential = BrowserCredential::bind(&mut session);
                if let Some(kept) = pending.as_ref().and_then(|p| p.csrf) {
                    session.browser_csrf = Some(kept);
                }
                let csrf = session.browser_csrf.as_ref().map(BrowserCsrf::encode);
                let retained = match retained {
                    Some(retained) => {
                        let sealed = credential
                            .retain(
                                retained.keys,
                                &retained.context,
                                &session,
                                retained.deadline,
                            )
                            .await
                            .map_err(|e| internal("seal the sign-in delivery", e))?;
                        Some(completion(retained, sealed))
                    }
                    None => None,
                };
                self.persist(
                    profile,
                    &session,
                    proved_by,
                    (policy, limit),
                    pending,
                    retained,
                    None,
                )
                .await?;
                Ok((credential.signed_in(&self.cookie, &session), csrf))
            }
            CeremonyClient::Native => {
                // Checked before anything commits: a policy that cannot shape
                // a generation creates no session.
                let first = native_key
                    .map(|key| {
                        NativePolicy::from_session_policy(&self.policy.session)
                            .map(|policy| native_session::first_generation(&session, key, policy))
                            .map_err(|e| internal("read the native session policy", e))
                    })
                    .transpose()?;
                // The token and the first generation exist before the
                // commit, which stores the generation beside the session and
                // the sealed delivery with them: the session, its generation
                // and the answer to a lost response commit together.
                let (token, expires_in) = self.access_token(profile, &session).await?;
                let token_expires_at = Utc::now() + Duration::seconds(expires_in);
                let (generation, refresh) = match first {
                    Some((generation, set)) => (Some(generation), Some(set)),
                    None => (None, None),
                };
                let retained = match retained {
                    Some(retained) => {
                        let sealed = sid_authn::sign_in_delivery::retain_bearer(
                            retained.keys,
                            &retained.context,
                            &session,
                            sid_authn::sign_in_delivery::BearerCredential {
                                token: &token,
                                token_expires_at,
                                refresh: refresh.as_ref(),
                            },
                            retained.deadline,
                        )
                        .await
                        .map_err(|e| internal("seal the sign-in delivery", e))?;
                        Some(completion(retained, sealed))
                    }
                    None => None,
                };
                self.persist(
                    profile,
                    &session,
                    proved_by,
                    (policy, limit),
                    pending,
                    retained,
                    generation,
                )
                .await?;
                Ok((
                    SignedIn {
                        session_id: session.id,
                        expires_in,
                        delivery: Delivery::Bearer { token, refresh },
                    },
                    None,
                ))
            }
        }
    }

    /// An access token for `session` of `profile` and its lifetime in
    /// seconds: no longer than the session's.
    async fn access_token(
        &self,
        profile: &Profile,
        session: &Session,
    ) -> Result<(secrecy::SecretString, i64), SignInError> {
        let sub = profile.id.to_string();
        let roles = sid_authn::account_roles::account_roles(self.storage.as_ref(), profile)
            .await
            .map_err(|e| internal("read the account's roles", e))?;
        let access_token = self
            .jwt
            .issue_access_token(
                &sub,
                Some(&sub),
                &roles,
                session,
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
        Ok((access_token.into(), expires_in))
    }

    /// A native client's access token for the stored `session` of `profile`,
    /// with `refresh`, the session's refresh generation, beside it when the
    /// client renews the session with one.
    pub async fn native_access(
        &self,
        profile: &Profile,
        session: &Session,
        refresh: Option<NativeCredentialSet>,
    ) -> Result<SignedIn, SignInError> {
        let (token, expires_in) = self.access_token(profile, session).await?;
        Ok(SignedIn {
            session_id: session.id,
            expires_in,
            delivery: Delivery::Bearer { token, refresh },
        })
    }

    /// Store `session` under the concurrent-session `limit` (0: none) and
    /// announce it, while `policy` still holds; with `pending`, as the
    /// completion of that pending context, which ends in the same commit;
    /// with `completion`, committing that keyed operation's completion; with
    /// `generation`, the native session's first generation beside it.
    #[allow(clippy::too_many_arguments)]
    async fn persist(
        &self,
        profile: &Profile,
        session: &Session,
        proved_by: Option<SignInProof<'_>>,
        (policy, limit): (Option<ActorFence>, u32),
        pending: Option<Completing<'_>>,
        completion: Option<OperationCompletion>,
        generation: Option<sid_core::models::NativeGeneration>,
    ) -> Result<(), SignInError> {
        // The storage counts, evicts and inserts in one serialized step, and
        // owes each evicted session's client a logout; the same commit owes
        // the session.created event.
        #[cfg(feature = "telemetry")]
        let audit_start = std::time::Instant::now();
        let created = Event::new(&self.issuer, event_types::SESSION_CREATED)
            .with_subject(format!("session/{}", session.id))
            .with_data(serde_json::json!({
                "profile_id": profile.id.to_string(),
                "session_id": session.id.to_string(),
            }));
        let mut ctx = MutationContext::from(AuditEntry::user(
            profile.id.to_string(),
            "session.create",
            session.id.to_string(),
        ))
        .with_work(created.relay());
        if let Some(fence) = policy {
            ctx = ctx.fenced_by(fence);
        }
        if let Some(completion) = completion {
            ctx = ctx.with_operation(completion);
        }
        if let Some(generation) = generation {
            ctx = ctx.issuing(generation);
        }
        let stored = match pending {
            Some(Completing { id, end, spend, .. }) => {
                if let Some(spend) = spend {
                    ctx = spend.into_context(ctx);
                }
                self.storage
                    .complete_pending_session(id, end, session, limit, proved_by, ctx)
                    .await
            }
            None => {
                self.storage
                    .create_session_atomic(session, limit, proved_by, ctx)
                    .await
            }
        };
        let evicted = match stored {
            Ok(evicted) => evicted,
            Err(SidError::Fenced(_)) => return Err(SignInError::Fenced),
            Err(SidError::OperationCompleted(_)) => return Err(SignInError::AlreadyCompleted),
            Err(e) => return Err(e.into()),
        };
        if !evicted.is_empty() {
            info!(
                profile_id = %profile.id,
                evicted_count = evicted.len(),
                "Session limit enforced: evicted oldest sessions"
            );
        }
        // An evicted session's access tokens stop at once in every process.
        // Its revocation committed as owed work with the eviction: one not
        // published now is published by the work runner, and the committed
        // sign-in stands either way (refusing it would revoke nothing).
        for ended in &evicted {
            if let Err(e) = self.revocation.revoke_session(ended.to_string()).await {
                warn!(session_id = %ended, error = %e, "evicted session revocation left to its owed work");
            }
        }
        #[cfg(feature = "telemetry")]
        {
            use opentelemetry::{KeyValue, global};
            global::meter("sid")
                .f64_histogram("sid_audit_write_seconds")
                .build()
                .record(
                    audit_start.elapsed().as_secs_f64(),
                    &[KeyValue::new("chain_scope", "session")],
                );
        }
        Ok(())
    }
}

/// The active account the normalized principal `handle` signs in to. The
/// explicit assignment is the only route: other claims neither select nor
/// block a subject, an email key of another policy revision routes nobody,
/// and a profile's stored user name or email is not a second route to it.
pub(crate) async fn resolve_handle(
    storage: &dyn StorageBackend,
    handle: &sid_authn::normalize::NormalizedPrincipal,
) -> sid_core::Result<Option<Profile>> {
    let principal_type = handle.principal_type.to_principal_type();
    let Some(profile_id) = storage
        .resolve_sign_in_principal(principal_type, &handle.normalized, handle.key_revision())
        .await?
    else {
        return Ok(None);
    };
    Ok(storage
        .get_profile(profile_id)
        .await?
        .filter(|p| p.status == sid_core::models::ProfileStatus::Active))
}

/// One verified sign-in as the rules see it.
fn attempt<'a>(
    client_ip: Option<IpAddr>,
    authentication: AttemptAuthentication<'a>,
    context: AttemptContext<'a>,
) -> SignInAttempt<'a> {
    SignInAttempt {
        client_ip,
        authentication,
        captcha_pass: context.captcha_pass,
        user_agent: context.user_agent,
    }
}

/// The organization's login requirements as `login_policy` states them; a
/// source that cannot state them refuses rather than leaving a baseline in
/// their place.
pub async fn organization_requirements(
    login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
) -> Result<LoginRequirements, SignInError> {
    requirements_for(login_policy, None).await
}

/// The login requirements of an authentication for `client_id` (none: the
/// organization's) as `login_policy` states them.
pub async fn requirements_for(
    login_policy: &dyn sid_authn::login_policy::LoginPolicySource,
    client_id: Option<&str>,
) -> Result<LoginRequirements, SignInError> {
    login_policy
        .requirements(client_id)
        .await
        .map_err(|e| SignInError::Unavailable {
            what: "login policy",
            cause: e.to_string(),
        })
}

pub(crate) fn unavailable(cause: impl std::fmt::Display) -> SignInError {
    SignInRefusal::Unavailable(cause.to_string()).into()
}

/// The rules' view of a sign-in of a local Profile.
struct Rules<'a>(&'a SignIn);

#[async_trait::async_trait]
impl SignInSecurityHost for Rules<'_> {
    type Owner = ProfileId;
    type Error = SignInRefusal;

    fn history(&self) -> &dyn SignInHistoryStore<Owner = ProfileId> {
        self.0.storage.as_ref()
    }
    fn anomaly(&self) -> &AnomalyDetector {
        &self.0.anomaly
    }
    fn ip_intelligence(&self) -> &IpIntelligenceAggregator {
        &self.0.ip_intelligence
    }
    fn geoip(&self) -> &GeoIpChain {
        &self.0.geoip
    }
    fn captcha_gate(&self) -> &CaptchaGate {
        &self.0.captcha_gate
    }
    fn captcha_provider(&self) -> &dyn CaptchaProvider {
        self.0.captcha_provider.as_ref()
    }

    async fn security_event(
        &self,
        account: &str,
        rule: &str,
        reaction: &str,
        reason: &str,
        client_ip: Option<IpAddr>,
    ) {
        self.0
            .security_event(account, rule, reaction, reason, client_ip)
            .await;
    }

    async fn record_ip_reputation(&self, ip: &str) -> sid_core::Result<()> {
        self.0.storage.record_ip_reputation_event(ip, true).await
    }
}

/// One password sign-in request of a local Profile from `client_ip`.
struct Passwords<'a> {
    sign_in: &'a SignIn,
    client_ip: Option<IpAddr>,
}

#[async_trait::async_trait]
impl PasswordSignInHost for Passwords<'_> {
    type Owner = ProfileId;
    type Account = Profile;
    type Error = SignInError;

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.sign_in.storage.as_ref()
    }

    fn opaque(&self) -> &OpaqueRouter {
        &self.sign_in.opaque
    }

    fn pending(&self) -> &ChallengeStore<PendingSignIn<ProfileId>> {
        &self.sign_in.logins
    }

    async fn resolve(&self, principal: &str) -> Result<Option<ProfileId>, SignInError> {
        Ok(self.sign_in.resolve_profile(principal).await?.map(|p| p.id))
    }

    async fn refuse_if_locked(&self, identity: &str) -> Result<(), SignInError> {
        self.sign_in.refuse_if_locked(identity).await
    }

    /// CE counts the attempt for the lockout; it keeps no per-account
    /// activity, so the account is not needed here.
    async fn record_failure(
        &self,
        identity: &str,
        _owner: Option<&ProfileId>,
    ) -> Result<(), SignInError> {
        self.sign_in
            .record_failed_login(identity, self.client_ip)
            .await
    }

    async fn stored_password(
        &self,
        credential: &Credential<ProfileId>,
    ) -> Result<OpenedPassword, SignInError> {
        let (record, stored) = self.sign_in.stored_password(credential).await?;
        Ok(OpenedPassword { record, stored })
    }

    fn opaque_credential_identifier(&self, credential: &Credential<ProfileId>) -> [u8; 16] {
        credential.opaque_credential_identifier()
    }

    async fn account(&self, owner: &ProfileId) -> Result<Option<Profile>, SignInError> {
        Ok(self.sign_in.storage.get_profile(*owner).await?)
    }
}

impl From<PendingError> for SignInError {
    fn from(e: PendingError) -> Self {
        match e {
            PendingError::SessionEnded => Self::SessionEnded,
            PendingError::Fenced => Self::Fenced,
            PendingError::StepUp(unmet) => SignInRefusal::StepUp(unmet).into(),
            PendingError::AuthenticationFailed => Self::AuthenticationFailed,
            PendingError::State(e) => Self::Ceremony(e),
            PendingError::Store(e) => Self::Store(e),
            e @ (PendingError::Sealed(_) | PendingError::Internal(_)) => {
                internal("a second-factor completion", e)
            }
        }
    }
}

/// A local Profile's pending second-factor context under the requirements
/// `login_policy` states.
struct PendingHost<'a> {
    sign_in: &'a SignIn,
    login_policy: &'a dyn sid_authn::login_policy::LoginPolicySource,
}

#[async_trait::async_trait]
impl PendingSignInHost for PendingHost<'_> {
    type Owner = ProfileId;
    type Error = SignInError;

    fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
        self.sign_in.storage.as_ref()
    }

    fn grants(&self) -> &dyn sid_plugin::GrantStore<Owner = ProfileId> {
        self.sign_in.storage.as_ref()
    }

    fn operations(&self) -> &dyn sid_plugin::OperationResultStore {
        self.sign_in.storage.as_ref()
    }

    fn keys(&self) -> &dyn sid_keys::KeyManager {
        self.sign_in.keys.as_ref()
    }

    fn cookie(&self) -> &BrowserCookie {
        &self.sign_in.cookie
    }

    fn proofs(&self) -> &FirstFactorProofs {
        &self.sign_in.first_factor_proofs
    }

    fn issuer(&self) -> &str {
        &self.sign_in.issuer
    }

    async fn requirements(&self, owner: ProfileId) -> Result<LoginRequirements, SignInError> {
        self.sign_in
            .for_account(&organization_requirements(self.login_policy).await?, owner)
            .await
    }

    async fn can_sign_in(&self, owner: ProfileId) -> Result<bool, SignInError> {
        Ok(self
            .sign_in
            .storage
            .get_profile(owner)
            .await?
            .is_some_and(|profile| profile.status.can_authenticate()))
    }

    fn new_session(&self, owner: ProfileId, ip_address: Option<IpAddr>) -> Session {
        self.sign_in.new_session(owner, ip_address)
    }

    async fn commit(
        &self,
        completion: Completion<'_, ProfileId>,
    ) -> Result<SignedIn, CommitError<SignInError>> {
        let profile = self
            .sign_in
            .storage
            .get_profile(completion.pending.profile_id)
            .await
            .map_err(SignInError::from)?
            .filter(|profile| profile.status.can_authenticate())
            .ok_or(SignInError::AuthenticationFailed)?;
        let retained = completion.retained.map(|retained| RetainedSignIn {
            keys: self.sign_in.keys.as_ref(),
            namespace: retained.namespace,
            method: retained.method,
            completion_key: retained.completion_key,
            context: retained.context,
            deadline: retained.deadline,
            inputs: retained.inputs,
        });
        match self
            .sign_in
            .complete_pending(
                &profile,
                (completion.pending, &completion.end),
                completion.session,
                completion.client,
                completion.native_key,
                completion.proved_by.as_ref().map(SignInProof::Credential),
                completion.policy,
                (completion.spend, retained),
            )
            .await
        {
            Ok(signed_in) => Ok(signed_in),
            Err(SignInError::Fenced) => Err(CommitError::Fenced),
            Err(e) => Err(CommitError::Other(e)),
        }
    }

    async fn bearer_deliverable(
        &self,
        delivery: &sid_authn::sign_in_delivery::RetainedDelivery,
        session: &Session,
    ) -> Result<bool, SignInError> {
        self.sign_in.native_deliverable(delivery, session).await
    }

    async fn record_completed(&self, owner: ProfileId, ip_address: Option<IpAddr>) {
        self.sign_in.record_completed(owner, ip_address).await;
    }
}

pub mod captcha;
pub mod completions;

#[cfg(test)]
mod tests;
