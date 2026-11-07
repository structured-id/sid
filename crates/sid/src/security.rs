// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's security policy as an administrator reads it: the
//! fixed CE password, lockout, authentication and network policy, the
//! built-in anomaly rules and the events they recorded, the per-application
//! overrides and the policy one application's sign-in is held to, and the IP
//! allowlist. Every operation is instance administration.

use std::sync::Arc;

use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::security_policy::{
    CE_PASSWORD_MAX_AGE_DAYS, CE_PASSWORD_MIN_DIGITS, CE_PASSWORD_MIN_LENGTH,
    CE_PASSWORD_MIN_LOWERCASE, CE_PASSWORD_MIN_SYMBOLS, CE_PASSWORD_MIN_UPPERCASE,
    CE_REQUIRE_PHISHING_RESISTANT, CE_SESSION_IDLE_TIMEOUT_HOURS, CE_SESSION_MAX_CONCURRENT,
    CE_SESSION_MAX_LIFETIME_HOURS, EnforcementMode, MfaEnforcement, SecurityPolicy,
};
use sid_core::models::{AuditEntry, MutationContext, OperationContext, ProfileId};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::security_service as keyed;
use sid_proto::sid::v1::admin as pb;

use crate::wire::{FieldError, wire_id};

/// Why a security operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a broken invariant); its cause is in
    /// the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("profile {0} not found")]
    ProfileNotFound(ProfileId),
    /// No OAuth client with this id.
    #[error("client {0} not found")]
    ClientNotFound(String),
}

impl From<SecurityError> for Effect<SecurityError> {
    fn from(e: SecurityError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<SecurityError>> for SecurityError {
    fn from(e: CommandError<SecurityError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for SecurityError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> SecurityError {
    tracing::error!(operation, error = %cause, "internal failure");
    SecurityError::Internal
}

/// An IP allowlist entry as stored: CIDR, description and creation time.
type AllowlistEntry = (String, String, chrono::DateTime<chrono::Utc>);

/// The security policy of one installation.
pub struct Security {
    storage: Arc<dyn StorageBackend>,
}

impl Security {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    pub fn password_policy(&self, caller: &Caller) -> Result<pb::PasswordPolicy, SecurityError> {
        caller.require_admin()?;
        Ok(ce_password_policy())
    }

    /// The CE limits the anomaly detector enforces: a fixed-length lockout,
    /// no progression and no quick-login check.
    pub fn brute_force_config(
        &self,
        caller: &Caller,
    ) -> Result<pb::BruteForceConfig, SecurityError> {
        caller.require_admin()?;
        let enforced = sid_authn::anomaly::AnomalyConfig::default();
        // The defaults are small constants; one that does not fit the wire
        // type is a defect of this build.
        let out_of_range = |_| internal("brute-force limit", "limit out of range");
        let seconds = |s: u64| i32::try_from(s).map_err(out_of_range);
        Ok(pb::BruteForceConfig {
            enabled: true,
            mode: pb::BruteForceLockoutMode::Temporary.into(),
            max_login_failures: i32::try_from(enforced.brute_force_max_attempts)
                .map_err(out_of_range)?,
            lockout_duration_seconds: seconds(enforced.brute_force_lockout_secs)?,
            max_lockout_duration_seconds: seconds(enforced.brute_force_lockout_secs)?,
            failure_reset_seconds: seconds(enforced.brute_force_window_secs)?,
            quick_login_check_ms: 0,
        })
    }

    pub fn security_policy(
        &self,
        caller: &Caller,
    ) -> Result<pb::SecurityPolicyResponse, SecurityError> {
        caller.require_admin()?;
        Ok(ce_security_policy_response())
    }

    pub fn network_policy(&self, caller: &Caller) -> Result<pb::NetworkPolicy, SecurityError> {
        caller.require_admin()?;
        Ok(ce_network_policy())
    }

    pub fn anomaly_rules(
        &self,
        caller: &Caller,
    ) -> Result<pb::ListAnomalyRulesResponse, SecurityError> {
        caller.require_admin()?;
        Ok(pb::ListAnomalyRulesResponse {
            rules: ce_anomaly_rules(),
        })
    }

    /// The recorded anomaly events, newest first, a page at a time. An empty
    /// token is the first page; any other is one this engine issued (a
    /// non-negative offset), never silently reset.
    pub async fn anomaly_event_log(
        &self,
        caller: &Caller,
        req: pb::GetAnomalyEventLogRequest,
    ) -> Result<pb::AnomalyEventLog, SecurityError> {
        caller.require_admin()?;
        let page_size = req.page_size.clamp(1, 100);
        let offset = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse::<i32>()
                .ok()
                .filter(|o| *o >= 0)
                .ok_or_else(|| SecurityError::InvalidField {
                    field: "page_token",
                    reason: "not a token this service issued".into(),
                })?
        };
        let records = self
            .storage
            .list_anomaly_events(req.rule_id.as_deref(), page_size, offset)
            .await?;
        // A full page may have a next one; an offset past i32 has none.
        let next_page_token = offset
            .checked_add(page_size)
            .filter(|_| records.len() as i32 == page_size)
            .map(|next| next.to_string())
            .unwrap_or_default();
        let events = records
            .into_iter()
            .map(|r| pb::AnomalyEvent {
                id: r.id.0.to_string(),
                rule_id: r.rule_id,
                profile_id: r.profile_id,
                ip_address: r.ip_address.map(|ip| ip.to_string()).unwrap_or_default(),
                description: r.description,
                risk_score: r.risk_score,
                timestamp: Some(prost_types::Timestamp {
                    seconds: r.timestamp.timestamp(),
                    nanos: 0,
                }),
            })
            .collect();
        Ok(pb::AnomalyEventLog {
            events,
            next_page_token,
        })
    }

    /// The applications whose sign-in policy differs from the installation's.
    pub async fn application_overrides(
        &self,
        caller: &Caller,
    ) -> Result<pb::ListApplicationOverridesResponse, SecurityError> {
        caller.require_admin()?;
        let clients = self.storage.list_oauth2_clients(0, 1000).await?;
        let overrides = clients
            .iter()
            .filter(|c| {
                c.required_acr.is_some() || c.enforcement_mode != EnforcementMode::default()
            })
            .map(|c| pb::ApplicationOverride {
                client_id: c.client_id.clone(),
                application_name: c.client_name.clone(),
                min_auth_level: c.required_acr.as_ref().map(|l| l.as_str().to_string()),
                enforcement_mode: (c.enforcement_mode != EnforcementMode::default())
                    .then(|| c.enforcement_mode.as_str().to_string()),
                required_amr: c.required_amr.clone(),
            })
            .collect();
        Ok(pb::ListApplicationOverridesResponse { overrides })
    }

    /// The installation's policy with one client's overrides applied; an
    /// unknown client has none.
    pub async fn effective_policy(
        &self,
        caller: &Caller,
        req: pb::GetEffectivePolicyRequest,
    ) -> Result<pb::SecurityPolicyResponse, SecurityError> {
        caller.require_admin()?;
        if req.client_id.is_empty() {
            return Err(SecurityError::MissingField("client_id"));
        }
        let mut policy = ce_security_policy_response();
        // A storage failure is an error, not a report of the defaults.
        if let Some(client) = self.storage.get_oauth2_client(&req.client_id).await? {
            if let Some(ref level) = client.required_acr {
                policy.min_auth_level = level.as_str().to_string();
            }
            if client.enforcement_mode != EnforcementMode::default() {
                policy.enforcement_mode = client.enforcement_mode.as_str().to_string();
            }
        }
        Ok(policy)
    }

    /// What signing in to a client would demand of a Profile under the
    /// policy in force: its violations, the actions that clear them and the
    /// enforcement that follows.
    pub async fn evaluate_enforcement(
        &self,
        caller: &Caller,
        req: pb::EvaluateEnforcementRequest,
    ) -> Result<pb::EvaluateEnforcementResponse, SecurityError> {
        caller.require_admin()?;
        let profile_id: ProfileId = wire_id(req.profile_id.as_ref(), "profile_id")?;
        if req.client_id.is_empty() {
            return Err(SecurityError::MissingField("client_id"));
        }
        self.storage
            .get_profile(profile_id)
            .await?
            .ok_or(SecurityError::ProfileNotFound(profile_id))?;
        let ce = SecurityPolicy::ce_default();
        let enforcement = ce.enforcement.mode;
        let client = self
            .storage
            .get_oauth2_client(&req.client_id)
            .await?
            .ok_or_else(|| SecurityError::ClientNotFound(req.client_id.clone()))?;
        let min_auth_level = client.required_acr.unwrap_or(ce.auth.min_acr);

        let mut violations = Vec::new();
        let mut required_actions = Vec::new();
        if ce.auth.mfa_enforcement == MfaEnforcement::Required {
            use sid_core::models::credential::CredentialType;
            let passkeys = self
                .storage
                .get_credentials_by_profile(profile_id, Some(CredentialType::WebAuthn))
                .await?;
            let totp = self
                .storage
                .get_credentials_by_profile(profile_id, Some(CredentialType::Totp))
                .await?;
            if passkeys.is_empty() && totp.is_empty() {
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
        // A password sign-in meets the installation's level; only a client
        // that raises it asks for more.
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
        let action = enforcement_action(enforcement, &violations, &required_actions);
        Ok(pb::EvaluateEnforcementResponse {
            action: action.into(),
            violations,
            required_actions,
        })
    }

    pub async fn ip_allowlist(
        &self,
        caller: &Caller,
    ) -> Result<pb::IpAllowlistResponse, SecurityError> {
        caller.require_admin()?;
        Ok(allowlist_response(
            self.storage.list_ip_allowlist_entries().await?,
        ))
    }

    /// Allow an address or CIDR block. A retry of a completed addition
    /// answers with the allowlist as it left it and never adds back an entry
    /// removed since.
    pub async fn add_ip_allowlist_entry(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::AddIpAllowlistEntryRequest,
    ) -> Result<pb::IpAllowlistResponse, SecurityError> {
        caller.require_admin()?;
        if req.cidr.is_empty() {
            return Err(SecurityError::MissingField("cidr"));
        }
        parse_cidr(&req.cidr)?;
        let admin = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::AddIpAllowlistEntry>(admin, operation, &req);
        let left: Vec<AllowlistEntry> = command
            .execute_recorded(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::admin(
                    admin.to_string(),
                    "ip_allowlist.add",
                    req.cidr.clone(),
                ))
                .with_operation(command.effect_completion());
                self.storage
                    .add_ip_allowlist_entry(&req.cidr, &req.description, ctx)
                    .await?;
                // The allowlist as this commit left it, whatever changed since.
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::<SecurityError>::refusal)?;
        Ok(allowlist_response(left))
    }

    /// Remove an allowlist entry. A retry of a completed removal answers
    /// with the allowlist as it left it and never removes an entry added
    /// again since.
    pub async fn remove_ip_allowlist_entry(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::RemoveIpAllowlistEntryRequest,
    ) -> Result<pb::IpAllowlistResponse, SecurityError> {
        caller.require_admin()?;
        if req.cidr.is_empty() {
            return Err(SecurityError::MissingField("cidr"));
        }
        let admin = caller.profile_id;
        let command =
            KeyedCommand::by_profile::<keyed::RemoveIpAllowlistEntry>(admin, operation, &req);
        let left: Vec<AllowlistEntry> = command
            .execute_recorded(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::admin(
                    admin.to_string(),
                    "ip_allowlist.remove",
                    req.cidr.clone(),
                ))
                .with_operation(command.effect_completion());
                self.storage
                    .remove_ip_allowlist_entry(&req.cidr, ctx)
                    .await?;
                Ok(command.recorded_effect(&*self.storage).await?)
            })
            .await
            .map_err(CommandError::<SecurityError>::refusal)?;
        Ok(allowlist_response(left))
    }
}

/// An IP address (a single-host block) or a CIDR block.
fn parse_cidr(cidr: &str) -> Result<ipnet::IpNet, SecurityError> {
    cidr.parse::<ipnet::IpNet>()
        .or_else(|_| cidr.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
        .map_err(|_| SecurityError::InvalidField {
            field: "cidr",
            reason: "not an IP address or CIDR block".into(),
        })
}

/// The enforcement that follows `violations`: none allows; otherwise audit
/// allows, soft grants grace, and hard asks for a step-up when that alone
/// clears them and blocks otherwise.
fn enforcement_action(
    enforcement: EnforcementMode,
    violations: &[pb::PolicyViolation],
    required_actions: &[pb::PolicyRequiredAction],
) -> pb::EnforcementAction {
    if violations.is_empty() {
        return pb::EnforcementAction::Allow;
    }
    match enforcement {
        EnforcementMode::Audit => pb::EnforcementAction::Allow,
        EnforcementMode::Soft => pb::EnforcementAction::Grace,
        EnforcementMode::Hard
            if required_actions
                .iter()
                .all(|a| a.action_type == "step_up_auth") =>
        {
            pb::EnforcementAction::StepUp
        }
        EnforcementMode::Hard => pb::EnforcementAction::Block,
    }
}

/// The answer listing `entries`.
fn allowlist_response(entries: Vec<AllowlistEntry>) -> pb::IpAllowlistResponse {
    pb::IpAllowlistResponse {
        entries: entries
            .into_iter()
            .map(|(cidr, description, created_at)| pb::IpAllowlistEntry {
                cidr,
                description,
                created_at: Some(crate::wire::to_timestamp(created_at)),
            })
            .collect(),
    }
}

fn ce_password_policy() -> pb::PasswordPolicy {
    let rule = |kind: pb::PasswordPolicyRuleType, value: i32| pb::PasswordPolicyRule {
        r#type: kind.into(),
        value,
        pattern: String::new(),
    };
    pb::PasswordPolicy {
        rules: vec![
            rule(
                pb::PasswordPolicyRuleType::MinLength,
                CE_PASSWORD_MIN_LENGTH as i32,
            ),
            rule(
                pb::PasswordPolicyRuleType::Uppercase,
                CE_PASSWORD_MIN_UPPERCASE as i32,
            ),
            rule(
                pb::PasswordPolicyRuleType::Lowercase,
                CE_PASSWORD_MIN_LOWERCASE as i32,
            ),
            rule(
                pb::PasswordPolicyRuleType::Digits,
                CE_PASSWORD_MIN_DIGITS as i32,
            ),
            rule(
                pb::PasswordPolicyRuleType::SpecialChars,
                CE_PASSWORD_MIN_SYMBOLS as i32,
            ),
            rule(
                pb::PasswordPolicyRuleType::MaxAgeDays,
                CE_PASSWORD_MAX_AGE_DAYS as i32,
            ),
        ],
    }
}

fn ce_network_policy() -> pb::NetworkPolicy {
    pb::NetworkPolicy {
        allowed_countries: Vec::new(),
        blocked_countries: Vec::new(),
        block_tor: false,
        block_datacenter_ips: false,
        violation_reaction: pb::NetworkViolationReaction::Block.into(),
    }
}

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
        native_refresh_generation_size: ce.session.native_refresh_generation_size,
        native_redelivery_window_seconds: ce.session.native_redelivery_window_seconds,
        network: Some(ce_network_policy()),
        read_only: true,
        passkey_satisfies_mfa: ce.auth.passkey_satisfies_mfa,
    }
}

/// The built-in anomaly rules.
fn ce_anomaly_rules() -> Vec<pb::AnomalyRule> {
    let rule = |id: &str, name: &str, description: &str, kind: pb::AnomalyRuleType, weight| {
        pb::AnomalyRule {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            r#type: kind.into(),
            enabled: true,
            weight,
        }
    };
    vec![
        rule(
            "impossible_travel",
            "Impossible Travel",
            "Detects logins from geographically impossible locations within a short time window",
            pb::AnomalyRuleType::ImpossibleTravel,
            80,
        ),
        rule(
            "new_device",
            "New Device",
            "Flags authentication from a previously unseen device or browser fingerprint",
            pb::AnomalyRuleType::NewDevice,
            30,
        ),
        rule(
            "new_country",
            "New Country",
            "Flags authentication from a country not seen in the user's login history",
            pb::AnomalyRuleType::NewCountry,
            50,
        ),
        rule(
            "credential_stuffing",
            "Credential Stuffing",
            "Detects patterns consistent with automated credential stuffing attacks across multiple accounts",
            pb::AnomalyRuleType::CredentialStuffing,
            90,
        ),
        rule(
            "brute_force",
            "Brute Force",
            "Detects repeated failed login attempts targeting a single account",
            pb::AnomalyRuleType::BruteForce,
            95,
        ),
        rule(
            "token_abuse",
            "Token Abuse",
            "Detects abnormal token usage patterns such as replay, concurrent use from different IPs, or excessive refresh",
            pb::AnomalyRuleType::TokenAbuse,
            70,
        ),
        rule(
            "session_anomaly",
            "Session Anomaly",
            "Detects unusual session behavior such as sudden user-agent changes or impossible concurrency",
            pb::AnomalyRuleType::SessionAnomaly,
            60,
        ),
        rule(
            "password_spray",
            "Password Spray",
            "Detects low-and-slow password guessing spread across many accounts from the same source",
            pb::AnomalyRuleType::CredentialStuffing,
            85,
        ),
    ]
}

#[cfg(test)]
mod tests;
