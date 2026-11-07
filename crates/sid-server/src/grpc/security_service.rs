// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC SecurityService implementation (CE).
//!
//! The policy of the engine (password, lockout, authentication, network,
//! anomaly rules and events, application overrides, enforcement evaluation,
//! the IP allowlist) is answered through [`sid::security`]; the server's own
//! HTTP headers, rate limits, CAPTCHA, breach provider and the integrity
//! check are reported here. Update RPCs are not part of this build.
//! All RPCs require the administrator role.

use sid::security::{Security, SecurityError};
use sid_admin::integrity::{IntegrityCheckRequest, IntegrityService, VerificationLayer};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    dependency_unavailable, invalid_field, missing_field, not_found, not_in_this_build,
    storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::audit::AuditLog;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::{self as pb, security_service_server::SecurityService};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

/// The status a security refusal answers with.
fn refusal(e: SecurityError) -> Status {
    match e {
        SecurityError::Caller(e) => e.into_status(),
        SecurityError::Operation(e) => e.into_status(),
        SecurityError::Store(e) => storage_failure(e),
        SecurityError::Internal => ApiError::internal().into(),
        SecurityError::MissingField(field) => missing_field(field),
        SecurityError::InvalidField { field, reason } => invalid_field(field, reason),
        SecurityError::ProfileNotFound(id) => {
            not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
        }
        SecurityError::ClientNotFound(id) => {
            not_found(ErrorReason::ApplicationNotFound, "OAuthClient", id)
        }
    }
}

pub struct SecurityServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    audit_log: Arc<dyn AuditLog>,
    rate_limit_stats: crate::rate_limit::RateLimitStats,
    security: Security,
}

impl SecurityServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        audit_log: Arc<dyn AuditLog>,
        cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    ) -> Self {
        Self {
            security: Security::new(storage.clone()),
            storage,
            jwt,
            revocation,
            audit_log,
            rate_limit_stats: crate::rate_limit::RateLimitStats::new(cache),
        }
    }

    async fn caller<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation).await
    }

    /// The authenticated administrator, for what the server reports itself.
    async fn require_admin<T>(&self, req: &Request<T>) -> Result<(), Status> {
        self.caller(req)
            .await?
            .require_admin()
            .map_err(|e| e.into_status())
    }
}

#[tonic::async_trait]
impl SecurityService for SecurityServiceImpl {
    #[instrument(skip_all, name = "security.get_password_policy")]
    async fn get_password_policy(
        &self,
        request: Request<pb::GetPasswordPolicyRequest>,
    ) -> Result<Response<pb::PasswordPolicy>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .password_policy(&caller)
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.update_password_policy")]
    async fn update_password_policy(
        &self,
        request: Request<pb::PasswordPolicy>,
    ) -> Result<Response<pb::PasswordPolicy>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("password_policy"))
    }

    #[instrument(skip_all, name = "security.get_brute_force_config")]
    async fn get_brute_force_config(
        &self,
        request: Request<pb::GetBruteForceConfigRequest>,
    ) -> Result<Response<pb::BruteForceConfig>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .brute_force_config(&caller)
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.update_brute_force_config")]
    async fn update_brute_force_config(
        &self,
        request: Request<pb::BruteForceConfig>,
    ) -> Result<Response<pb::BruteForceConfig>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("brute_force_config"))
    }

    #[instrument(skip_all, name = "security.get_security_headers")]
    async fn get_security_headers(
        &self,
        request: Request<pb::GetSecurityHeadersRequest>,
    ) -> Result<Response<pb::SecurityHeaders>, Status> {
        self.require_admin(&request).await?;
        Ok(Response::new(pb::SecurityHeaders {
            x_frame_options: "DENY".into(),
            content_security_policy: "default-src 'self'; frame-ancestors 'none'".into(),
            x_content_type_options_nosniff: true,
            hsts_max_age: 31_536_000, // 365 days
            hsts_include_subdomains: true,
            hsts_preload: false,
            x_xss_protection: true,
            referrer_policy: "strict-origin-when-cross-origin".into(),
        }))
    }

    #[instrument(skip_all, name = "security.update_security_headers")]
    async fn update_security_headers(
        &self,
        request: Request<pb::SecurityHeaders>,
    ) -> Result<Response<pb::SecurityHeaders>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("security_headers"))
    }

    #[instrument(skip_all, name = "security.get_rate_limit_config")]
    async fn get_rate_limit_config(
        &self,
        request: Request<pb::GetRateLimitConfigRequest>,
    ) -> Result<Response<pb::RateLimitConfig>, Status> {
        self.require_admin(&request).await?;
        let rule = |endpoint: &str, max_requests, window_seconds| pb::RateLimitRule {
            endpoint: endpoint.into(),
            max_requests,
            window_seconds,
            scope: "ip".into(),
        };
        Ok(Response::new(pb::RateLimitConfig {
            rules: vec![
                rule("login", 10, 60),
                rule("register", 5, 60),
                rule("token", 30, 60),
                rule("password_reset", 3, 300),
            ],
            overrides: Vec::new(),
            ip_allowlist: Vec::new(),
        }))
    }

    #[instrument(skip_all, name = "security.get_rate_limit_dashboard")]
    async fn get_rate_limit_dashboard(
        &self,
        request: Request<pb::GetRateLimitDashboardRequest>,
    ) -> Result<Response<pb::RateLimitDashboard>, Status> {
        self.require_admin(&request).await?;
        let data = self
            .rate_limit_stats
            .get_dashboard()
            .await
            .map_err(|e| dependency_unavailable("rate limit statistics", e))?;
        let entries = |v: Vec<(String, i32)>| {
            v.into_iter()
                .map(|(key, count)| pb::RateLimitTopEntry { key, count })
                .collect()
        };
        Ok(Response::new(pb::RateLimitDashboard {
            total_blocked_last_hour: data.total_blocked_last_hour,
            total_blocked_last_day: data.total_blocked_last_day,
            top_blocked_ips: entries(data.top_blocked_ips),
            top_blocked_endpoints: entries(data.top_blocked_endpoints),
        }))
    }

    #[instrument(skip_all, name = "security.list_anomaly_rules")]
    async fn list_anomaly_rules(
        &self,
        request: Request<pb::ListAnomalyRulesRequest>,
    ) -> Result<Response<pb::ListAnomalyRulesResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .anomaly_rules(&caller)
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.get_anomaly_event_log")]
    async fn get_anomaly_event_log(
        &self,
        request: Request<pb::GetAnomalyEventLogRequest>,
    ) -> Result<Response<pb::AnomalyEventLog>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .anomaly_event_log(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.get_captcha_config")]
    async fn get_captcha_config(
        &self,
        request: Request<pb::GetCaptchaConfigRequest>,
    ) -> Result<Response<pb::CaptchaConfig>, Status> {
        self.require_admin(&request).await?;
        // CE: CAPTCHA disabled by default.
        Ok(Response::new(pb::CaptchaConfig {
            enabled: false,
            provider: pb::CaptchaProvider::Unspecified.into(),
            site_key: String::new(),
            secret_key: String::new(),
            score_threshold: 0.0,
            triggers: Vec::new(),
        }))
    }

    #[instrument(skip_all, name = "security.update_captcha_config")]
    async fn update_captcha_config(
        &self,
        request: Request<pb::CaptchaConfig>,
    ) -> Result<Response<pb::CaptchaConfig>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("captcha_config"))
    }

    #[instrument(skip_all, name = "security.test_captcha_provider")]
    async fn test_captcha_provider(
        &self,
        request: Request<pb::TestCaptchaProviderRequest>,
    ) -> Result<Response<pb::TestCaptchaProviderResponse>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("captcha_provider_test"))
    }

    #[instrument(skip_all, name = "security.get_security_policy")]
    async fn get_security_policy(
        &self,
        request: Request<pb::GetSecurityPolicyRequest>,
    ) -> Result<Response<pb::SecurityPolicyResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .security_policy(&caller)
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.list_application_overrides")]
    async fn list_application_overrides(
        &self,
        request: Request<pb::ListApplicationOverridesRequest>,
    ) -> Result<Response<pb::ListApplicationOverridesResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .application_overrides(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.get_effective_policy")]
    async fn get_effective_policy(
        &self,
        request: Request<pb::GetEffectivePolicyRequest>,
    ) -> Result<Response<pb::SecurityPolicyResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .effective_policy(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.evaluate_enforcement")]
    async fn evaluate_enforcement(
        &self,
        request: Request<pb::EvaluateEnforcementRequest>,
    ) -> Result<Response<pb::EvaluateEnforcementResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .evaluate_enforcement(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.get_network_policy")]
    async fn get_network_policy(
        &self,
        request: Request<pb::GetNetworkPolicyRequest>,
    ) -> Result<Response<pb::NetworkPolicy>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .network_policy(&caller)
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.update_network_policy")]
    async fn update_network_policy(
        &self,
        request: Request<pb::NetworkPolicy>,
    ) -> Result<Response<pb::NetworkPolicy>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("network_policy"))
    }

    #[instrument(skip_all, name = "security.get_breach_detection_config")]
    async fn get_breach_detection_config(
        &self,
        request: Request<pb::GetBreachDetectionConfigRequest>,
    ) -> Result<Response<pb::BreachDetectionConfig>, Status> {
        self.require_admin(&request).await?;
        Ok(Response::new(pb::BreachDetectionConfig {
            enabled: true,
            check_on_login: true,
            check_on_password_change: true,
            force_password_change_on_breach: false,
            provider: "hibp".into(),
        }))
    }

    #[instrument(skip_all, name = "security.update_breach_detection_config")]
    async fn update_breach_detection_config(
        &self,
        request: Request<pb::BreachDetectionConfig>,
    ) -> Result<Response<pb::BreachDetectionConfig>, Status> {
        self.require_admin(&request).await?;
        Err(not_in_this_build("breach_detection_config"))
    }

    #[instrument(skip_all, name = "security.run_integrity_check")]
    async fn run_integrity_check(
        &self,
        request: Request<pb::RunIntegrityCheckRequest>,
    ) -> Result<Response<pb::IntegrityCheckResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();

        // Parse requested layers (empty = all).
        let layers: Vec<VerificationLayer> = if req.layers.is_empty() {
            IntegrityService::all_layers()
        } else {
            req.layers
                .iter()
                .filter_map(|l| match l.as_str() {
                    "merkle_tree" => Some(VerificationLayer::MerkleTree),
                    "audit_chain" => Some(VerificationLayer::AuditChain),
                    "blob_integrity" => Some(VerificationLayer::BlobIntegrity),
                    "graph_consistency" => Some(VerificationLayer::GraphConsistency),
                    "ca_chain" => Some(VerificationLayer::CaChain),
                    _ => None,
                })
                .collect()
        };

        let integrity_svc = IntegrityService::new(self.audit_log.clone(), self.storage.clone());
        let report = integrity_svc
            .run_check(&IntegrityCheckRequest {
                layers,
                max_entities: 0,
                auto_repair: false,
            })
            .await;
        let duration_ms = (report.completed_at - report.started_at)
            .num_milliseconds()
            .max(0);

        Ok(Response::new(pb::IntegrityCheckResponse {
            passed: report.passed,
            total_entities_checked: report.total_entities_checked as i64,
            total_issues_found: report.total_issues_found as i64,
            duration_ms,
            layers: report
                .layers
                .iter()
                .map(|l| pb::IntegrityLayerResult {
                    layer: l.layer.to_string(),
                    entities_checked: l.entities_checked as i64,
                    entities_passed: l.entities_passed as i64,
                    issues_found: l.issues_found as i64,
                    duration_ms: l.duration_ms as i64,
                    issues: l
                        .issues
                        .iter()
                        .map(|i| pb::IntegrityIssue {
                            layer: i.layer.to_string(),
                            severity: format!("{:?}", i.severity).to_lowercase(),
                            entity_type: i.entity_type.clone(),
                            entity_id: i.entity_id.clone(),
                            description: i.description.clone(),
                            auto_repairable: i.auto_repairable,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }

    // ── IP Allowlist ──

    #[instrument(skip_all, name = "security.list_ip_allowlist")]
    async fn list_ip_allowlist_entries(
        &self,
        request: Request<pb::ListIpAllowlistEntriesRequest>,
    ) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.security
            .ip_allowlist(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.add_ip_allowlist")]
    async fn add_ip_allowlist_entry(
        &self,
        request: Request<pb::AddIpAllowlistEntryRequest>,
    ) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        let operation = context(&request)?;
        self.security
            .add_ip_allowlist_entry(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "security.remove_ip_allowlist")]
    async fn remove_ip_allowlist_entry(
        &self,
        request: Request<pb::RemoveIpAllowlistEntryRequest>,
    ) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        let operation = context(&request)?;
        self.security
            .remove_ip_allowlist_entry(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
