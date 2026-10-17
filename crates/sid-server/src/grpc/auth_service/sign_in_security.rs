// SPDX-License-Identifier: AGPL-3.0-only
//! The fixed sign-in rules, run by the shared engine with this server's
//! storage and its Profile accounts.

use sid_authn::anomaly::AnomalyDetector;
use sid_authn::captcha::{CaptchaGate, CaptchaProvider};
use sid_authn::geoip::GeoIpChain;
use sid_authn::ip_intelligence::IpIntelligenceAggregator;
use sid_authn::sign_in_security::{SignInRefusal, SignInSecurityHost};
use sid_core::models::enforcement::EnforcementDecision;
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{ProfileId, Session};
use sid_plugin::SignInHistoryStore;
use tonic::Status;

use super::AuthServiceImpl;
use super::refusal::{
    anomaly_unavailable, captcha_required, sign_in_refused, step_up_after_anomaly, step_up_to_acr,
    too_many_attempts,
};

/// A refusal of the rules as this server answers it.
pub(super) struct SecurityStatus(pub(super) Status);

impl From<SignInRefusal> for SecurityStatus {
    fn from(r: SignInRefusal) -> Self {
        Self(match r {
            SignInRefusal::Refused => sign_in_refused(),
            SignInRefusal::TooManyAttempts(retry_after) => too_many_attempts(retry_after),
            SignInRefusal::CaptchaRequired(challenge) => match captcha_required(&challenge) {
                Ok(refusal) | Err(refusal) => refusal.into(),
            },
            SignInRefusal::StepUpAfterAnomaly(rule) => step_up_after_anomaly(rule).into(),
            SignInRefusal::StepUpToAcr(acr) => step_up_to_acr(acr).into(),
            SignInRefusal::Unavailable(cause) => anomaly_unavailable(cause),
        })
    }
}

/// The rules' view of one sign-in of a local Profile.
pub(super) struct ProfileSecurity<'a> {
    pub(super) service: &'a AuthServiceImpl,
}

#[async_trait::async_trait]
impl SignInSecurityHost for ProfileSecurity<'_> {
    type Owner = ProfileId;
    type Error = SecurityStatus;

    fn history(&self) -> &dyn SignInHistoryStore<Owner = ProfileId> {
        self.service.storage.as_ref()
    }
    fn anomaly(&self) -> &AnomalyDetector {
        &self.service.anomaly_detector
    }
    fn ip_intelligence(&self) -> &IpIntelligenceAggregator {
        &self.service.ip_intelligence
    }
    fn geoip(&self) -> &GeoIpChain {
        &self.service.geoip
    }
    fn captcha_gate(&self) -> &CaptchaGate {
        &self.service.captcha_gate
    }
    fn captcha_provider(&self) -> &dyn CaptchaProvider {
        self.service.captcha_provider.as_ref()
    }
    fn policy(&self) -> &SecurityPolicy {
        &self.service.security_policy
    }

    fn policy_decision(&self, probe: &Session<ProfileId>) -> EnforcementDecision {
        sid_authz::conditional_access::ConditionalAccessEngine::check(
            &self.service.security_policy,
            None, // the per-app client override is checked at authorize time
            None,
            probe,
        )
    }

    async fn security_event(
        &self,
        account: &str,
        rule: &str,
        reaction: &str,
        reason: &str,
        client_ip: Option<std::net::IpAddr>,
    ) {
        self.service
            .publish_security_event(account, rule, reaction, reason, client_ip)
            .await;
    }

    async fn record_ip_reputation(&self, ip: &str) -> sid_core::Result<()> {
        self.service
            .storage
            .record_ip_reputation_event(ip, true)
            .await
    }
}
