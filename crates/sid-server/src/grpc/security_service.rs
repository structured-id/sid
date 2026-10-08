// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC SecurityService implementation (CE).
//!
//! CE returns hardcoded security policy defaults (read-only).
//! Update RPCs return PermissionDenied — configurable policies are EE-only.
//! All RPCs require admin role.

use sid_admin::integrity::{IntegrityCheckRequest, IntegrityService, VerificationLayer};
use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::security_policy::{
    CE_PASSWORD_MAX_AGE_DAYS, CE_PASSWORD_MIN_DIGITS, CE_PASSWORD_MIN_LENGTH,
    CE_PASSWORD_MIN_LOWERCASE, CE_PASSWORD_MIN_SYMBOLS, CE_PASSWORD_MIN_UPPERCASE,
    CE_REQUIRE_PHISHING_RESISTANT, CE_SESSION_IDLE_TIMEOUT_HOURS, CE_SESSION_MAX_CONCURRENT,
    CE_SESSION_MAX_LIFETIME_HOURS, EnforcementMode, MfaEnforcement, SecurityPolicy,
};
use sid_plugin::audit::AuditLog;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::{self as pb, security_service_server::SecurityService};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

use sid_core::grpc_error::ErrorReason;

use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, missing_field, not_found, not_in_this_build,
};

pub struct SecurityServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    audit_log: Arc<dyn AuditLog>,
    rate_limit_stats: crate::rate_limit::RateLimitStats,
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
            storage,
            jwt,
            revocation,
            audit_log,
            rate_limit_stats: crate::rate_limit::RateLimitStats::new(cache),
        }
    }

    #[allow(clippy::result_large_err)]
    async fn require_admin<T>(&self, req: &Request<T>) -> Result<(), Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation)
            .await?
            .require_admin()
    }
}

// ── Helper: build CE password policy rules ──

fn ce_password_policy() -> pb::PasswordPolicy {
    pb::PasswordPolicy {
        rules: vec![
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::MinLength.into(),
                value: CE_PASSWORD_MIN_LENGTH as i32,
                pattern: String::new(),
            },
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::Uppercase.into(),
                value: CE_PASSWORD_MIN_UPPERCASE as i32,
                pattern: String::new(),
            },
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::Lowercase.into(),
                value: CE_PASSWORD_MIN_LOWERCASE as i32,
                pattern: String::new(),
            },
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::Digits.into(),
                value: CE_PASSWORD_MIN_DIGITS as i32,
                pattern: String::new(),
            },
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::SpecialChars.into(),
                value: CE_PASSWORD_MIN_SYMBOLS as i32,
                pattern: String::new(),
            },
            pb::PasswordPolicyRule {
                r#type: pb::PasswordPolicyRuleType::MaxAgeDays.into(),
                value: CE_PASSWORD_MAX_AGE_DAYS as i32,
                pattern: String::new(),
            },
        ],
    }
}

// ── Helper: build CE security policy response ──

fn ce_security_policy_response() -> pb::SecurityPolicyResponse {
    let ce = SecurityPolicy::ce_default();
    pb::SecurityPolicyResponse {
        enforcement_mode: EnforcementMode::Hard.as_str().to_string(),
        rate_limits_enabled: true,
        anomaly_detection_enabled: true,
        captcha_enabled: false,
        breach_detection_enabled: true,
        enrollment_enabled: true,
        min_auth_level: ce.auth.min_acr.as_str().to_string(),
        mfa_enforcement: ce.auth.mfa_enforcement.as_str().to_string(),
        allowed_mfa_methods: ce
            .auth
            .allowed_mfa_methods
            .iter()
            .map(|m| m.as_str().to_string())
            .collect(),
        require_phishing_resistant: CE_REQUIRE_PHISHING_RESISTANT,
        password_min_length: CE_PASSWORD_MIN_LENGTH as i32,
        password_max_age_days: CE_PASSWORD_MAX_AGE_DAYS as i32,
        session_max_lifetime_hours: CE_SESSION_MAX_LIFETIME_HOURS as i32,
        session_idle_timeout_hours: CE_SESSION_IDLE_TIMEOUT_HOURS as i32,
        session_max_concurrent: CE_SESSION_MAX_CONCURRENT as i32,
        network: Some(pb::NetworkPolicy {
            allowed_countries: Vec::new(),
            blocked_countries: Vec::new(),
            block_tor: false,
            block_datacenter_ips: false,
            violation_reaction: pb::NetworkViolationReaction::Block.into(),
        }),
        read_only: true,
        passkey_satisfies_mfa: ce.auth.passkey_satisfies_mfa,
    }
}

// ── Helper: built-in anomaly rules (8 rules) ──

fn ce_anomaly_rules() -> Vec<pb::AnomalyRule> {
    vec![
        pb::AnomalyRule {
            id: "impossible_travel".into(),
            name: "Impossible Travel".into(),
            description: "Detects logins from geographically impossible locations within a short time window".into(),
            r#type: pb::AnomalyRuleType::ImpossibleTravel.into(),
            enabled: true,
            weight: 80,
        },
        pb::AnomalyRule {
            id: "new_device".into(),
            name: "New Device".into(),
            description: "Flags authentication from a previously unseen device or browser fingerprint".into(),
            r#type: pb::AnomalyRuleType::NewDevice.into(),
            enabled: true,
            weight: 30,
        },
        pb::AnomalyRule {
            id: "new_country".into(),
            name: "New Country".into(),
            description: "Flags authentication from a country not seen in the user's login history".into(),
            r#type: pb::AnomalyRuleType::NewCountry.into(),
            enabled: true,
            weight: 50,
        },
        pb::AnomalyRule {
            id: "credential_stuffing".into(),
            name: "Credential Stuffing".into(),
            description: "Detects patterns consistent with automated credential stuffing attacks across multiple accounts".into(),
            r#type: pb::AnomalyRuleType::CredentialStuffing.into(),
            enabled: true,
            weight: 90,
        },
        pb::AnomalyRule {
            id: "brute_force".into(),
            name: "Brute Force".into(),
            description: "Detects repeated failed login attempts targeting a single account".into(),
            r#type: pb::AnomalyRuleType::BruteForce.into(),
            enabled: true,
            weight: 95,
        },
        pb::AnomalyRule {
            id: "token_abuse".into(),
            name: "Token Abuse".into(),
            description: "Detects abnormal token usage patterns such as replay, concurrent use from different IPs, or excessive refresh".into(),
            r#type: pb::AnomalyRuleType::TokenAbuse.into(),
            enabled: true,
            weight: 70,
        },
        pb::AnomalyRule {
            id: "session_anomaly".into(),
            name: "Session Anomaly".into(),
            description: "Detects unusual session behavior such as sudden user-agent changes or impossible concurrency".into(),
            r#type: pb::AnomalyRuleType::SessionAnomaly.into(),
            enabled: true,
            weight: 60,
        },
        pb::AnomalyRule {
            id: "password_spray".into(),
            name: "Password Spray".into(),
            description: "Detects low-and-slow password guessing spread across many accounts from the same source".into(),
            r#type: pb::AnomalyRuleType::CredentialStuffing.into(),
            enabled: true,
            weight: 85,
        },
    ]
}

// ── Service implementation ──

#[tonic::async_trait]
impl SecurityService for SecurityServiceImpl {
    #[instrument(skip_all, name = "security.get_password_policy")]
    async fn get_password_policy(
        &self,
        request: Request<pb::GetPasswordPolicyRequest>,
    ) -> Result<Response<pb::PasswordPolicy>, Status> {
        self.require_admin(&request).await?;
        Ok(Response::new(ce_password_policy()))
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
        self.require_admin(&request).await?;
        // The CE limits the anomaly detector enforces: a fixed-length
        // lockout, no progression and no quick-login check.
        let enforced = sid_authn::anomaly::AnomalyConfig::default();
        // The defaults are small constants; one that does not fit the wire
        // type is a defect of this build.
        let out_of_range = |_| internal("brute-force limit", "limit out of range");
        let seconds = |s: u64| i32::try_from(s).map_err(out_of_range);
        Ok(Response::new(pb::BruteForceConfig {
            enabled: true,
            mode: pb::BruteForceLockoutMode::Temporary.into(),
            max_login_failures: i32::try_from(enforced.brute_force_max_attempts)
                .map_err(out_of_range)?,
            lockout_duration_seconds: seconds(enforced.brute_force_lockout_secs)?,
            max_lockout_duration_seconds: seconds(enforced.brute_force_lockout_secs)?,
            failure_reset_seconds: seconds(enforced.brute_force_window_secs)?,
            quick_login_check_ms: 0,
        }))
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
        Ok(Response::new(pb::RateLimitConfig {
            rules: vec![
                pb::RateLimitRule {
                    endpoint: "login".into(),
                    max_requests: 10,
                    window_seconds: 60,
                    scope: "ip".into(),
                },
                pb::RateLimitRule {
                    endpoint: "register".into(),
                    max_requests: 5,
                    window_seconds: 60,
                    scope: "ip".into(),
                },
                pb::RateLimitRule {
                    endpoint: "token".into(),
                    max_requests: 30,
                    window_seconds: 60,
                    scope: "ip".into(),
                },
                pb::RateLimitRule {
                    endpoint: "password_reset".into(),
                    max_requests: 3,
                    window_seconds: 300,
                    scope: "ip".into(),
                },
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

        Ok(Response::new(pb::RateLimitDashboard {
            total_blocked_last_hour: data.total_blocked_last_hour,
            total_blocked_last_day: data.total_blocked_last_day,
            top_blocked_ips: data
                .top_blocked_ips
                .into_iter()
                .map(|(k, c)| pb::RateLimitTopEntry { key: k, count: c })
                .collect(),
            top_blocked_endpoints: data
                .top_blocked_endpoints
                .into_iter()
                .map(|(k, c)| pb::RateLimitTopEntry { key: k, count: c })
                .collect(),
        }))
    }

    #[instrument(skip_all, name = "security.list_anomaly_rules")]
    async fn list_anomaly_rules(
        &self,
        request: Request<pb::ListAnomalyRulesRequest>,
    ) -> Result<Response<pb::ListAnomalyRulesResponse>, Status> {
        self.require_admin(&request).await?;
        Ok(Response::new(pb::ListAnomalyRulesResponse {
            rules: ce_anomaly_rules(),
        }))
    }

    #[instrument(skip_all, name = "security.get_anomaly_event_log")]
    async fn get_anomaly_event_log(
        &self,
        request: Request<pb::GetAnomalyEventLogRequest>,
    ) -> Result<Response<pb::AnomalyEventLog>, Status> {
        self.require_admin(&request).await?;

        let req = request.into_inner();
        let page_size = req.page_size.clamp(1, 100);
        // An empty token is the first page; any other token is one this
        // service issued (a non-negative offset), never silently reset.
        let offset = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse::<i32>()
                .ok()
                .filter(|o| *o >= 0)
                .ok_or_else(|| invalid_field("page_token", "not a token this service issued"))?
        };

        let records = self
            .storage
            .list_anomaly_events(req.rule_id.as_deref(), page_size, offset)
            .await
            .map_err(|e| internal("list anomaly events", e))?;

        let next_token = if records.len() as i32 == page_size {
            (offset + page_size).to_string()
        } else {
            String::new()
        };

        let events = records
            .into_iter()
            .map(|r| pb::AnomalyEvent {
                id: r.id.0.to_string(),
                rule_id: r.rule_id,
                profile_id: r.profile_id,
                ip_address: r.ip_address,
                description: r.description,
                risk_score: r.risk_score,
                timestamp: Some(prost_types::Timestamp {
                    seconds: r.timestamp.timestamp(),
                    nanos: 0,
                }),
            })
            .collect();

        Ok(Response::new(pb::AnomalyEventLog {
            events,
            next_page_token: next_token,
        }))
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
        self.require_admin(&request).await?;
        Ok(Response::new(ce_security_policy_response()))
    }

    #[instrument(skip_all, name = "security.list_application_overrides")]
    async fn list_application_overrides(
        &self,
        request: Request<pb::ListApplicationOverridesRequest>,
    ) -> Result<Response<pb::ListApplicationOverridesResponse>, Status> {
        self.require_admin(&request).await?;

        // Query storage for OAuth2 clients that have security overrides.
        let clients = self
            .storage
            .list_oauth2_clients(0, 1000)
            .await
            .map_err(|e| internal("list clients", e))?;

        let overrides: Vec<pb::ApplicationOverride> = clients
            .iter()
            .filter(|c| {
                c.required_acr.is_some() || c.enforcement_mode != EnforcementMode::default()
            })
            .map(|c| pb::ApplicationOverride {
                application_id: c.client_id.clone(),
                application_name: c.client_name.clone(),
                min_auth_level: c.required_acr.as_ref().map(|l| l.as_str().to_string()),
                enforcement_mode: if c.enforcement_mode != EnforcementMode::default() {
                    Some(c.enforcement_mode.as_str().to_string())
                } else {
                    None
                },
                required_amr: c.required_amr.clone(),
            })
            .collect();

        Ok(Response::new(pb::ListApplicationOverridesResponse {
            overrides,
        }))
    }

    #[instrument(skip_all, name = "security.get_effective_policy")]
    async fn get_effective_policy(
        &self,
        request: Request<pb::GetEffectivePolicyRequest>,
    ) -> Result<Response<pb::SecurityPolicyResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();

        if req.client_id.is_empty() {
            return Err(missing_field("client_id"));
        }

        // Start with CE defaults.
        let mut policy = ce_security_policy_response();

        // Merge client-level overrides if the client exists; a storage failure
        // is an error, not a report of the defaults.
        let client = self
            .storage
            .get_oauth2_client(&req.client_id)
            .await
            .map_err(|e| internal("get client", e))?;
        if let Some(client) = client {
            if let Some(ref level) = client.required_acr {
                policy.min_auth_level = level.as_str().to_string();
            }
            if client.enforcement_mode != EnforcementMode::default() {
                policy.enforcement_mode = client.enforcement_mode.as_str().to_string();
            }
        }

        Ok(Response::new(policy))
    }

    #[instrument(skip_all, name = "security.evaluate_enforcement")]
    async fn evaluate_enforcement(
        &self,
        request: Request<pb::EvaluateEnforcementRequest>,
    ) -> Result<Response<pb::EvaluateEnforcementResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();

        if req.profile_id.is_empty() {
            return Err(missing_field("profile_id"));
        }
        if req.client_id.is_empty() {
            return Err(missing_field("client_id"));
        }

        let profile_id = sid_core::models::ProfileId::parse(&req.profile_id)
            .map_err(|_| invalid_field("profile_id", "not a profile identifier"))?;

        // Verify the profile exists.
        let _profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(|e| internal("get profile", e))?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProfileNotFound,
                    "Profile",
                    req.profile_id.clone(),
                )
            })?;

        // Get the effective policy for this client.
        let ce = SecurityPolicy::ce_default();
        let mut min_auth_level = ce.auth.min_acr;
        let enforcement = ce.enforcement.mode;

        let client = self
            .storage
            .get_oauth2_client(&req.client_id)
            .await
            .map_err(|e| internal("get client", e))?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ApplicationNotFound,
                    "OAuthClient",
                    req.client_id.clone(),
                )
            })?;
        if let Some(level) = client.required_acr {
            min_auth_level = level;
        }

        // Evaluate violations.
        let mut violations = Vec::new();
        let mut required_actions = Vec::new();

        // Check MFA enrollment (if required).
        if ce.auth.mfa_enforcement == MfaEnforcement::Required {
            // Check for WebAuthn or TOTP credentials as MFA factors.
            let webauthn_creds = self
                .storage
                .get_credentials_by_profile(
                    profile_id,
                    Some(sid_core::models::credential::CredentialType::WebAuthn),
                )
                .await
                .map_err(|e| internal("list passkeys", e))?;
            let totp_creds = self
                .storage
                .get_credentials_by_profile(
                    profile_id,
                    Some(sid_core::models::credential::CredentialType::Totp),
                )
                .await
                .map_err(|e| internal("list TOTP credentials", e))?;
            let has_mfa = !webauthn_creds.is_empty() || !totp_creds.is_empty();
            if !has_mfa {
                violations.push(pb::PolicyViolation {
                    requirement: "mfa_required".into(),
                    current: "none".into(),
                    required: "at least one MFA factor".into(),
                });
                required_actions.push(pb::PolicyRequiredAction {
                    action_type: "enroll_mfa".into(),
                    description: "Enroll at least one MFA factor (WebAuthn, TOTP, or SMS)".into(),
                });
            }
        }

        // Check auth level — in CE with Hard enforcement, basic is always met after
        // successful password login, so this only fires if a client override raises it.
        if min_auth_level > ce.auth.min_acr {
            violations.push(pb::PolicyViolation {
                requirement: "min_auth_level".into(),
                current: ce.auth.min_acr.as_str().to_string(),
                required: min_auth_level.as_str().to_string(),
            });
            required_actions.push(pb::PolicyRequiredAction {
                action_type: "step_up_auth".into(),
                description: format!(
                    "Step-up authentication to {} required",
                    min_auth_level.as_str()
                ),
            });
        }

        // Determine enforcement action.
        let action = if violations.is_empty() {
            pb::EnforcementAction::Allow
        } else {
            match enforcement {
                EnforcementMode::Audit => pb::EnforcementAction::Allow,
                EnforcementMode::Soft => pb::EnforcementAction::Grace,
                EnforcementMode::Hard => {
                    // If only step-up needed, use StepUp; otherwise Block.
                    if required_actions
                        .iter()
                        .all(|a| a.action_type == "step_up_auth")
                    {
                        pb::EnforcementAction::StepUp
                    } else {
                        pb::EnforcementAction::Block
                    }
                }
            }
        };

        Ok(Response::new(pb::EvaluateEnforcementResponse {
            action: action.into(),
            violations,
            required_actions,
        }))
    }

    #[instrument(skip_all, name = "security.get_network_policy")]
    async fn get_network_policy(
        &self,
        request: Request<pb::GetNetworkPolicyRequest>,
    ) -> Result<Response<pb::NetworkPolicy>, Status> {
        self.require_admin(&request).await?;
        Ok(Response::new(pb::NetworkPolicy {
            allowed_countries: Vec::new(),
            blocked_countries: Vec::new(),
            block_tor: false,
            block_datacenter_ips: false,
            violation_reaction: pb::NetworkViolationReaction::Block.into(),
        }))
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

        let check_request = IntegrityCheckRequest {
            layers,
            max_entities: 0,
            auto_repair: false,
        };

        let report = integrity_svc.run_check(&check_request).await;

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
        self.require_admin(&request).await?;
        self.allowlist_response().await
    }

    #[instrument(skip_all, name = "security.add_ip_allowlist")]
    async fn add_ip_allowlist_entry(
        &self,
        request: Request<pb::AddIpAllowlistEntryRequest>,
    ) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();

        if req.cidr.is_empty() {
            return Err(missing_field("cidr"));
        }

        // Validate CIDR format.
        let _valid = req
            .cidr
            .parse::<ipnet::IpNet>()
            .or_else(|_| {
                req.cidr.parse::<std::net::IpAddr>().map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::from(v4)),
                    std::net::IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::from(v6)),
                })
            })
            .map_err(|_| invalid_field("cidr", "not an IP address or CIDR block"))?;

        self.storage
            .add_ip_allowlist_entry(&req.cidr, &req.description)
            .await
            .map_err(|e| internal("add", e))?;

        self.allowlist_response().await
    }

    #[instrument(skip_all, name = "security.remove_ip_allowlist")]
    async fn remove_ip_allowlist_entry(
        &self,
        request: Request<pb::RemoveIpAllowlistEntryRequest>,
    ) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        self.require_admin(&request).await?;
        let req = request.into_inner();

        if req.cidr.is_empty() {
            return Err(missing_field("cidr"));
        }

        self.storage
            .remove_ip_allowlist_entry(&req.cidr)
            .await
            .map_err(|e| internal("remove", e))?;

        self.allowlist_response().await
    }
}

impl SecurityServiceImpl {
    /// The current allowlist, for a caller already authorized by its handler.
    async fn allowlist_response(&self) -> Result<Response<pb::IpAllowlistResponse>, Status> {
        let entries = self
            .storage
            .list_ip_allowlist_entries()
            .await
            .map_err(|e| internal("list", e))?;
        Ok(Response::new(pb::IpAllowlistResponse {
            entries: entries
                .into_iter()
                .map(|(cidr, description, created_at)| pb::IpAllowlistEntry {
                    cidr,
                    description,
                    created_at: Some(prost_types::Timestamp {
                        seconds: created_at.timestamp(),
                        nanos: created_at.timestamp_subsec_nanos() as i32,
                    }),
                })
                .collect(),
        }))
    }
}
