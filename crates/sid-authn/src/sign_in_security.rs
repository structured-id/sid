// SPDX-License-Identifier: AGPL-3.0-only
//! The fixed sign-in rules a verified credential passes before a session is
//! created, for any authenticated account type: anomaly detection over the
//! account's sign-in history and the client address, then the login
//! requirements the host's policy states. The host supplies the history
//! store, where security events go and the address reputation record.

use std::fmt::Display;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use sid_core::models::session::AuthLevel;
use sid_core::models::session::SessionAuthentication;
use sid_plugin::SignInHistoryStore;
use tracing::{info, warn};

use crate::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use crate::captcha::{CaptchaChallenge, CaptchaGate, CaptchaProvider, CaptchaSubject};
use crate::geoip::GeoIpChain;
use crate::ip_intelligence::IpIntelligenceAggregator;
use crate::login_policy::{LoginDecision, LoginRequirements, Unmet};

/// How far back a sign-in from the same address or device counts as seen.
const SEEN_WINDOW: Duration = Duration::from_secs(90 * 24 * 3600);

/// Sign-ins from one country after which it is designated: impossible travel
/// between designated locations is not an anomaly.
const DESIGNATED_THRESHOLD: u32 = 3;

/// The auth level a successful sign-in with `auth_method` grants, checked
/// against the policy before a session exists.
///
/// When `passkey_satisfies_mfa` is true (CE default, NIST SP 800-63B §5.1.8),
/// a passkey with user verification satisfies MFA: possession and a
/// biometric or PIN are two factors. Without user verification a passkey is
/// one factor, so the level stays Basic.
pub fn implied_auth_level(
    auth_method: &str,
    passkey_satisfies_mfa: bool,
    user_verified: bool,
) -> AuthLevel {
    match auth_method {
        "webauthn" if passkey_satisfies_mfa && user_verified => AuthLevel::Standard,
        _ => AuthLevel::Basic,
    }
}

/// How a sign-in's credential was verified, as the rules weigh it.
#[derive(Debug, Clone, Copy)]
pub enum AttemptAuthentication<'a> {
    /// By this authority: the method's name (`opaque`, `webauthn`, ...) and
    /// the level and `amr` methods (RFC 8176) the session it creates records.
    Local {
        method: &'a str,
        assurance: AuthLevel,
        amr: &'a [String],
    },
    /// By an explicitly trusted issuer, as the authentication its accepted
    /// evidence attests: the policy weighs that level, step-up and methods,
    /// never a local method it was not.
    Accepted(&'a SessionAuthentication),
}

impl AttemptAuthentication<'_> {
    /// The name the rules' log and security events give the method.
    fn method(&self) -> &str {
        match self {
            Self::Local { method, .. } => method,
            Self::Accepted(_) => "federated",
        }
    }

    /// Whether this is already the stronger sign-in an anomaly rule asks for:
    /// an authentication established at the multi-factor level, by this
    /// authority or a trusted issuer. The level decides, never a method's name.
    fn answers_step_up(&self) -> bool {
        let level = match self {
            Self::Local { assurance, .. } => *assurance,
            Self::Accepted(evidence) => evidence.assurance_level,
        };
        level >= AuthLevel::Standard
    }
}

/// One verified sign-in as the rules see it.
pub struct SignInAttempt<'a> {
    pub client_ip: Option<IpAddr>,
    /// How the credential was verified.
    pub authentication: AttemptAuthentication<'a>,
    /// Pass earned by solving the CAPTCHA this sign-in was asked for.
    pub captcha_pass: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Why the rules refused a sign-in.
#[derive(Debug)]
pub enum SignInRefusal {
    /// Refused outright: an absolute anomaly rule or the policy.
    Refused,
    /// Too many attempts: retry after the lockout.
    TooManyAttempts(Duration),
    /// The client must solve this challenge, then retry.
    CaptchaRequired(CaptchaChallenge),
    /// An anomaly rule asks for a stronger sign-in.
    StepUpAfterAnomaly(&'static str),
    /// The login requirements are unmet: each unmet one is named.
    StepUp(Unmet),
    /// The state the rules read could not be read: refused rather than
    /// passing with a rule switched off.
    Unavailable(String),
}

/// What a sign-in host supplies to the rules.
#[async_trait]
pub trait SignInSecurityHost: Send + Sync {
    /// The account the history belongs to.
    type Owner: Clone + Display + Send + Sync + 'static;
    type Error: Send + From<SignInRefusal>;

    fn history(&self) -> &dyn SignInHistoryStore<Owner = Self::Owner>;
    fn anomaly(&self) -> &AnomalyDetector;
    fn ip_intelligence(&self) -> &IpIntelligenceAggregator;
    fn geoip(&self) -> &GeoIpChain;
    fn captcha_gate(&self) -> &CaptchaGate;
    fn captcha_provider(&self) -> &dyn CaptchaProvider;

    /// Record a rule's reaction for `account` (best effort).
    async fn security_event(
        &self,
        account: &str,
        rule: &str,
        reaction: &str,
        reason: &str,
        client_ip: Option<IpAddr>,
    );

    /// Record a successful sign-in from `ip` for its reputation.
    async fn record_ip_reputation(&self, ip: &str) -> sid_core::Result<()>;
}

/// The device a User-Agent names: the first 16 bytes of its SHA-256, shaped
/// as a version-4 UUID. The same User-Agent always names the same device.
pub fn device_id(user_agent: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(user_agent.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

fn unavailable<E: From<SignInRefusal>>(e: impl Display) -> E {
    SignInRefusal::Unavailable(e.to_string()).into()
}

/// Run the rules for `owner`'s verified sign-in under `requirements`, the
/// login requirements the host's policy states for it, and record the
/// admitted sign-in as evidence for later ones.
pub async fn evaluate<H: SignInSecurityHost>(
    host: &H,
    owner: &H::Owner,
    attempt: SignInAttempt<'_>,
    requirements: &LoginRequirements,
) -> Result<(), H::Error> {
    let client_ip = attempt.client_ip;
    let geo_location = judge(host, owner, attempt, requirements, None).await?;
    record_evidence(host, owner, client_ip, geo_location.as_ref()).await;
    Ok(())
}

/// Run the same rules as [`evaluate`] without recording anything: for a
/// repeat of `owner`'s sign-in already admitted and recorded from
/// `admitted_from`, which must still meet the rules of its own request but
/// is no further sign-in. That admission answers a CAPTCHA requirement for
/// a repeat from the same address, as a pass answers it for the sign-in it
/// was solved for; every other rule applies as it stands now.
pub async fn check<H: SignInSecurityHost>(
    host: &H,
    owner: &H::Owner,
    attempt: SignInAttempt<'_>,
    requirements: &LoginRequirements,
    admitted_from: Option<IpAddr>,
) -> Result<(), H::Error> {
    judge(host, owner, attempt, requirements, Some(admitted_from))
        .await
        .map(|_| ())
}

/// The rules themselves, for a repeat of a sign-in admitted from `admitted`
/// when given; the client's location when it was resolved.
async fn judge<H: SignInSecurityHost>(
    host: &H,
    owner: &H::Owner,
    attempt: SignInAttempt<'_>,
    requirements: &LoginRequirements,
    admitted: Option<Option<IpAddr>>,
) -> Result<Option<sid_plugin::geoip::GeoLocation>, H::Error> {
    let identity = owner.to_string();
    let client_ip = attempt.client_ip;

    let geo_location = match client_ip {
        Some(ip) => host.geoip().resolve(ip).await,
        None => None,
    };
    let country = geo_location.as_ref().map(|g| g.country.clone());

    // A provider that cannot answer refuses the sign-in: an unknown address
    // would pass the blocklist it could not check.
    let ip_classification = match client_ip {
        Some(ip) => host
            .ip_intelligence()
            .classify(ip)
            .await
            .map_err(unavailable)?,
        None => Default::default(),
    };

    // An unreadable history refuses like unreadable attempt state: an empty
    // one would switch the travel and location checks off.
    let history = host.history();
    let previous = history
        .get_most_recent_session_ip(owner.clone())
        .await
        .map_err(unavailable)?;
    let prev_login_at = previous.as_ref().map(|(_, at)| *at);

    let new_ip = match client_ip {
        Some(ip) => !history
            .has_recent_session_from_ip(owner.clone(), &ip.to_string(), SEEN_WINDOW)
            .await
            .map_err(unavailable)?,
        None => false,
    };

    // The previous session's location, resolved only with a current one to
    // compare against.
    let (prev_latitude, prev_longitude, prev_country) = match (&geo_location, &previous) {
        (Some(_), Some((prev_ip, _))) => match prev_ip.parse::<IpAddr>() {
            Ok(prev_ip) => match host.geoip().resolve(prev_ip).await {
                Some(prev) => (
                    Some(prev.latitude),
                    Some(prev.longitude),
                    Some(prev.country),
                ),
                None => (None, None, None),
            },
            Err(_) => (None, None, None),
        },
        _ => (None, None, None),
    };

    let designated_countries = history
        .get_designated_countries(owner.clone())
        .await
        .map_err(unavailable)?;

    let new_device = match attempt.user_agent {
        Some(ua) => !history
            .has_recent_session_from_device(owner.clone(), device_id(ua), SEEN_WINDOW)
            .await
            .map_err(unavailable)?,
        None => false,
    };

    let ctx = LoginContext {
        identity: identity.clone(),
        ip: client_ip,
        country,
        failed: false, // evaluated after the credential was verified
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

    // Every rule runs on every sign-in; a solved CAPTCHA answers only a
    // CAPTCHA requirement, never a lockout or a block. Rules that cannot read
    // the shared attempt state refuse rather than skip the lockout.
    let rule_match = if attempt.authentication.answers_step_up() {
        host.anomaly().evaluate_answered(&ctx).await
    } else {
        host.anomaly().evaluate(&ctx).await
    }
    .map_err(unavailable)?;
    let event = |reaction: &'static str| {
        host.security_event(
            &identity,
            rule_match.rule,
            reaction,
            &rule_match.reason,
            client_ip,
        )
    };
    match rule_match.reaction {
        RuleReaction::Allow => {
            if rule_match.rule == "location_switch" {
                info!(
                    account = %identity,
                    rule = "location_switch",
                    reason = %rule_match.reason,
                    "Impossible travel suppressed: both locations are designated"
                );
                event("allow").await;
            } else if rule_match.rule != "none" {
                info!(account = %identity, rule = rule_match.rule, "Anomaly: step-up answered by the sign-in");
                event("allow").await;
            }
        }
        RuleReaction::HardNo => {
            warn!(account = %identity, rule = rule_match.rule, reason = %rule_match.reason, "Anomaly: HardNo, sign-in denied");
            event(rule_match.reaction.as_str()).await;
            return Err(SignInRefusal::Refused.into());
        }
        RuleReaction::Block => {
            warn!(account = %identity, rule = rule_match.rule, reason = %rule_match.reason, "Anomaly: Block, sign-in denied");
            event(rule_match.reaction.as_str()).await;
            return Err(SignInRefusal::TooManyAttempts(host.anomaly().lockout_duration()).into());
        }
        RuleReaction::RequireCaptcha => {
            let subject = CaptchaSubject {
                account: identity.clone(),
                client_ip,
            };
            // The admission being repeated was itself judged from that
            // address: no pass is spent on its repeat.
            let answered = match attempt.captcha_pass {
                _ if admitted == Some(client_ip) => true,
                Some(pass) => host
                    .captcha_gate()
                    .redeem(pass, &subject)
                    .await
                    .map_err(unavailable)?,
                None => false,
            };
            if answered {
                info!(account = %identity, rule = rule_match.rule, "Anomaly: RequireCaptcha answered by a solved challenge");
            } else {
                warn!(account = %identity, rule = rule_match.rule, reason = %rule_match.reason, "Anomaly: RequireCaptcha, issuing a CAPTCHA challenge");
                event(rule_match.reaction.as_str()).await;
                // The challenge is recorded for this sign-in, so solving it
                // earns a pass only for this account from this client.
                let challenge = host.captcha_provider().create_challenge();
                host.captcha_gate()
                    .asked(&challenge.challenge_id, &subject)
                    .await
                    .map_err(unavailable)?;
                return Err(SignInRefusal::CaptchaRequired(challenge).into());
            }
        }
        RuleReaction::StepUp => {
            warn!(account = %identity, rule = rule_match.rule, reason = %rule_match.reason, "Anomaly: StepUp required");
            event(rule_match.reaction.as_str()).await;
            return Err(SignInRefusal::StepUpAfterAnomaly(rule_match.rule).into());
        }
    }

    // The login requirements, checked on a probe of the session the sign-in
    // would create: the real one does not exist yet.
    let now = chrono::Utc::now();
    let probe = match attempt.authentication {
        AttemptAuthentication::Local { assurance, amr, .. } => {
            crate::login_policy::local_authentication(owner.clone(), assurance, amr, now)
        }
        // An accepted authentication keeps the time and elevation its issuer
        // stated.
        AttemptAuthentication::Accepted(accepted) => {
            let mut probe = crate::login_policy::local_authentication(
                owner.clone(),
                accepted.assurance_level,
                &accepted.amr,
                now,
            );
            probe.elevation = accepted.elevation;
            probe.authenticated_at = accepted.authenticated_at;
            probe
        }
    };
    let method = attempt.authentication.method();
    match requirements.decide(&probe, now) {
        LoginDecision::Allow { audited } if !audited.is_empty() => {
            info!(account = %identity, method, unmet = ?audited, "Login requirements unmet, allowed by audit enforcement");
        }
        LoginDecision::Allow { .. } => {}
        LoginDecision::StepUp(unmet) => {
            info!(account = %identity, method, ?unmet, "Login requirements: step-up required");
            return Err(SignInRefusal::StepUp(unmet).into());
        }
    }
    Ok(geo_location)
}

/// Record `owner`'s sign-in from `client_ip` that the rules admitted and a
/// further factor then completed: the evidence [`evaluate`] records for a
/// sign-in it admits outright.
pub async fn record_completed_sign_in<H: SignInSecurityHost>(
    host: &H,
    owner: &H::Owner,
    client_ip: Option<IpAddr>,
) {
    let geo_location = match client_ip {
        Some(ip) => host.geoip().resolve(ip).await,
        None => None,
    };
    record_evidence(host, owner, client_ip, geo_location.as_ref()).await;
}

/// Evidence for later sign-ins, not limits on this one: the address's
/// reputation and the login location. A failed write is reported and the
/// sign-in proceeds.
async fn record_evidence<H: SignInSecurityHost>(
    host: &H,
    owner: &H::Owner,
    client_ip: Option<IpAddr>,
    geo_location: Option<&sid_plugin::geoip::GeoLocation>,
) {
    if let Some(ip) = client_ip
        && let Err(e) = host.record_ip_reputation(&ip.to_string()).await
    {
        warn!(error = %e, "failed to record IP reputation event");
    }
    if let Some(geo) = geo_location
        && let Err(e) = host
            .history()
            .record_login_location(
                owner.clone(),
                &geo.country,
                geo.latitude,
                geo.longitude,
                DESIGNATED_THRESHOLD,
            )
            .await
    {
        warn!(error = %e, "failed to record login location");
    }
}

#[cfg(test)]
mod tests;
