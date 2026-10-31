// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;

use chrono::Utc;
use sid_core::models::ProfileId;
use sid_core::models::SecurityPolicy;
use sid_plugin::CacheBackend;
use sid_plugin::cache::InMemoryCacheBackend;

use super::*;
use crate::captcha::SidPowProvider;
use crate::ip_intelligence::{IpClassification, IpIntelError, IpIntelligenceProvider, IpLabel};
use crate::login_policy::{FixedLoginPolicy, LoginPolicySource};

const CLIENT: &str = "203.0.113.7";

/// An account that signed in before, from another address and device: the
/// new-device rule asks every sign-in here for a stronger one.
struct KnownElsewhere;

#[async_trait]
impl SignInHistoryStore for KnownElsewhere {
    type Owner = ProfileId;

    async fn get_most_recent_session_ip(
        &self,
        _: ProfileId,
    ) -> sid_core::Result<Option<(String, chrono::DateTime<Utc>)>> {
        Ok(Some(("198.51.100.1".to_owned(), Utc::now())))
    }

    async fn has_recent_session_from_ip(
        &self,
        _: ProfileId,
        _: &str,
        _: Duration,
    ) -> sid_core::Result<bool> {
        Ok(false)
    }

    async fn has_recent_session_from_device(
        &self,
        _: ProfileId,
        _: uuid::Uuid,
        _: Duration,
    ) -> sid_core::Result<bool> {
        Ok(false)
    }

    async fn record_login_location(
        &self,
        _: ProfileId,
        _: &str,
        _: f64,
        _: f64,
        _: u32,
    ) -> sid_core::Result<()> {
        Ok(())
    }

    async fn get_designated_countries(&self, _: ProfileId) -> sid_core::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Puts every address on a threat blocklist.
struct Blocklist;

#[async_trait]
impl IpIntelligenceProvider for Blocklist {
    async fn classify(&self, _: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(Some(IpClassification {
            labels: vec![IpLabel::Blocklisted],
            risk_score: None,
            source: "test".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }

    fn source_name(&self) -> &str {
        "test"
    }
}

struct Host {
    history: KnownElsewhere,
    anomaly: AnomalyDetector,
    intelligence: IpIntelligenceAggregator,
    geoip: GeoIpChain,
    gate: CaptchaGate,
    captcha: SidPowProvider,
    /// The rule and reaction of each security event.
    events: std::sync::Mutex<Vec<(String, String)>>,
}

impl Host {
    fn new(providers: Vec<Arc<dyn IpIntelligenceProvider>>) -> (Self, Arc<dyn CacheBackend>) {
        let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
        let host = Self {
            history: KnownElsewhere,
            anomaly: AnomalyDetector::ce_default(cache.clone()),
            intelligence: IpIntelligenceAggregator::new(
                providers,
                cache.clone(),
                Duration::from_secs(60),
            ),
            geoip: GeoIpChain::empty(cache.clone()),
            gate: CaptchaGate::new(cache.clone(), crate::test_support::key_manager()),
            captcha: SidPowProvider::new([0; 32], 1, 60),
            events: Default::default(),
        };
        (host, cache)
    }
}

#[derive(Debug)]
struct Refused(SignInRefusal);

impl From<SignInRefusal> for Refused {
    fn from(refusal: SignInRefusal) -> Self {
        Self(refusal)
    }
}

#[async_trait]
impl SignInSecurityHost for Host {
    type Owner = ProfileId;
    type Error = Refused;

    fn history(&self) -> &dyn SignInHistoryStore<Owner = ProfileId> {
        &self.history
    }
    fn anomaly(&self) -> &AnomalyDetector {
        &self.anomaly
    }
    fn ip_intelligence(&self) -> &IpIntelligenceAggregator {
        &self.intelligence
    }
    fn geoip(&self) -> &GeoIpChain {
        &self.geoip
    }
    fn captcha_gate(&self) -> &CaptchaGate {
        &self.gate
    }
    fn captcha_provider(&self) -> &dyn CaptchaProvider {
        &self.captcha
    }
    async fn security_event(
        &self,
        _: &str,
        rule: &str,
        reaction: &str,
        _: &str,
        _: Option<IpAddr>,
    ) {
        self.events
            .lock()
            .unwrap()
            .push((rule.to_owned(), reaction.to_owned()));
    }
    async fn record_ip_reputation(&self, _: &str) -> sid_core::Result<()> {
        Ok(())
    }
}

fn accepted(assurance_level: AuthLevel, amr: &[&str]) -> SessionAuthentication {
    SessionAuthentication {
        assurance_level,
        elevation: None,
        authenticated_at: Utc::now(),
        amr: amr.iter().map(|m| (*m).to_owned()).collect(),
    }
}

/// The rules' answer to `authentication` from a new device and address.
async fn judged(
    host: &Host,
    owner: ProfileId,
    authentication: AttemptAuthentication<'_>,
) -> Result<(), Refused> {
    let requirements = FixedLoginPolicy::of(&SecurityPolicy::ce_default())
        .requirements(None)
        .await
        .unwrap();
    evaluate(
        host,
        &owner,
        SignInAttempt {
            client_ip: CLIENT.parse().ok(),
            authentication,
            captcha_pass: None,
            user_agent: Some("a new browser"),
        },
        &requirements,
    )
    .await
}

/// A passkey with user verification signs in at the multi-factor level by
/// itself: what the rule asks for is already there, on any path.
#[tokio::test]
async fn a_verified_passkey_answers_the_rule() {
    let (host, _) = Host::new(Vec::new());
    let amr = vec!["hwk".to_owned(), "user".to_owned()];
    let local = AttemptAuthentication::Local {
        method: "webauthn",
        assurance: implied_auth_level("webauthn", true, true),
        amr: &amr,
    };
    judged(&host, ProfileId::generate(), local).await.unwrap();
}

/// An issuer's accepted second factor answers it the same way.
#[tokio::test]
async fn accepted_multi_factor_evidence_answers_the_rule() {
    let (host, _) = Host::new(Vec::new());
    for level in [
        AuthLevel::Standard,
        AuthLevel::Elevated,
        AuthLevel::Critical,
    ] {
        let evidence = accepted(level, &["pwd", "otp"]);
        judged(
            &host,
            ProfileId::generate(),
            AttemptAuthentication::Accepted(&evidence),
        )
        .await
        .unwrap();
    }
}

/// One factor answers nothing, whatever the method names say: the level is
/// what was established.
#[tokio::test]
async fn one_factor_does_not() {
    let (host, _) = Host::new(Vec::new());
    let evidence = accepted(AuthLevel::Basic, &["pwd", "mfa"]);
    let amr = vec!["pwd".to_owned()];
    let password = AttemptAuthentication::Local {
        method: "opaque",
        assurance: implied_auth_level("opaque", true, false),
        amr: &amr,
    };
    let passkey = AttemptAuthentication::Local {
        method: "webauthn",
        assurance: implied_auth_level("webauthn", true, false),
        amr: &amr,
    };
    for attempt in [
        AttemptAuthentication::Accepted(&evidence),
        password,
        passkey,
    ] {
        let refused = judged(&host, ProfileId::generate(), attempt).await;
        assert!(matches!(
            refused,
            Err(Refused(SignInRefusal::StepUpAfterAnomaly("new_device_ip")))
        ));
    }
}

/// A policy that passes a new device admits a single factor and keeps the
/// sign-in visible: the event is recorded, as the refused one's would be.
#[tokio::test]
async fn a_passed_new_device_is_admitted_and_recorded() {
    let (host, _) = Host::new(Vec::new());
    let mut requirements = FixedLoginPolicy::of(&SecurityPolicy::ce_default())
        .requirements(None)
        .await
        .unwrap();
    requirements.new_device = RuleReaction::Allow;
    let amr = vec!["pwd".to_owned()];
    evaluate(
        &host,
        &ProfileId::generate(),
        SignInAttempt {
            client_ip: CLIENT.parse().ok(),
            authentication: AttemptAuthentication::Local {
                method: "opaque",
                assurance: AuthLevel::Basic,
                amr: &amr,
            },
            captcha_pass: None,
            user_agent: Some("a new browser"),
        },
        &requirements,
    )
    .await
    .unwrap();
    assert_eq!(
        *host.events.lock().unwrap(),
        [("new_device_ip".to_owned(), "allow".to_owned())]
    );
}

/// A CAPTCHA answered by the admission a repeat stands on leaves the rules
/// after it in force: the address's stuffing limit is passed, and the new
/// device and address still ask for a stronger sign-in.
#[tokio::test]
async fn a_solved_captcha_does_not_pass_the_next_rule() {
    let (host, _) = Host::new(Vec::new());
    let client: IpAddr = CLIENT.parse().unwrap();
    for _ in 0..=host.anomaly.config().credential_stuffing_threshold {
        host.anomaly.record_ip_attempt(client).await.unwrap();
    }
    let requirements = FixedLoginPolicy::of(&SecurityPolicy::ce_default())
        .requirements(None)
        .await
        .unwrap();
    let amr = vec!["pwd".to_owned()];
    let refused = check(
        &host,
        &ProfileId::generate(),
        SignInAttempt {
            client_ip: Some(client),
            authentication: AttemptAuthentication::Local {
                method: "opaque",
                assurance: AuthLevel::Basic,
                amr: &amr,
            },
            captcha_pass: None,
            user_agent: Some("a new browser"),
        },
        &requirements,
        Some(client),
    )
    .await;
    assert!(matches!(
        refused,
        Err(Refused(SignInRefusal::StepUpAfterAnomaly("new_device_ip")))
    ));
}

/// A rule that refuses outright is no step-up: a second factor does not pass
/// a blocklist.
#[tokio::test]
async fn a_blocklisted_address_is_refused_whatever_the_evidence() {
    let (host, _) = Host::new(vec![Arc::new(Blocklist)]);
    let evidence = accepted(AuthLevel::Critical, &["pwd", "otp"]);
    let refused = judged(
        &host,
        ProfileId::generate(),
        AttemptAuthentication::Accepted(&evidence),
    )
    .await;
    assert!(matches!(refused, Err(Refused(SignInRefusal::Refused))));
}

/// Nor a lockout.
#[tokio::test]
async fn a_lockout_holds_whatever_the_evidence() {
    let (host, cache) = Host::new(Vec::new());
    let owner = ProfileId::generate();
    cache
        .set(
            &format!("rate:brute:lockout:{owner}"),
            b"1",
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let evidence = accepted(AuthLevel::Critical, &["pwd", "otp"]);
    let refused = judged(&host, owner, AttemptAuthentication::Accepted(&evidence)).await;
    assert!(matches!(
        refused,
        Err(Refused(SignInRefusal::TooManyAttempts(_)))
    ));
}
