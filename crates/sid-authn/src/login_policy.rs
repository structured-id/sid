// SPDX-License-Identifier: AGPL-3.0-only
//! What an authentication must have achieved before a session is admitted or
//! an authorization code issued over it: a minimum assurance, the methods it
//! used (`amr`, RFC 8176) and how long ago it happened. A host reads them
//! from its policy through a [`LoginPolicySource`], a read-only data source;
//! this installation's fixed baseline is one. The evaluation here is the one
//! shared check every sign-in and authorization runs, with the unmet
//! requirements named by kind. A host whose policy changes over time states
//! the fence its requirements were read under, so the session or code commits
//! only while they are still current.

use std::collections::BTreeSet;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::ActorFence;
use sid_core::models::oauth2_client::OAuth2Client;
use sid_core::models::security_policy::{EnforcementMode, SecurityPolicy};
use sid_core::models::session::{AuthLevel, Session};

/// The requirements an admitted authentication must meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequirements {
    /// The lowest assurance in force.
    pub min_acr: AuthLevel,
    /// Methods the authentication must have used, every one of them.
    pub required_amr: BTreeSet<String>,
    /// The longest time since the authentication itself; none bounds only
    /// what the session's own validity bounds.
    pub max_authentication_age: Option<Duration>,
    /// How an unmet requirement is enforced.
    pub enforcement: EnforcementMode,
    /// The policy state these were read under: what is decided on them
    /// commits only while it holds. None for a policy that never changes.
    pub fence: Option<ActorFence>,
}

/// The source could not state the requirements: nothing is admitted under
/// assumed ones.
#[derive(Debug, thiserror::Error)]
#[error("the login policy is unavailable: {0}")]
pub struct LoginPolicyUnavailable(pub String);

/// Where a host's login requirements come from.
#[async_trait]
pub trait LoginPolicySource: Send + Sync {
    /// The requirements of an authentication for the application `client_id`,
    /// or of the organization itself when no application is named yet (a
    /// sign-in admitted before it continues to one).
    async fn requirements(
        &self,
        client_id: Option<&str>,
    ) -> Result<LoginRequirements, LoginPolicyUnavailable>;
}

/// A policy that never changes: the same requirements for every application,
/// with no fence.
#[derive(Debug, Clone)]
pub struct FixedLoginPolicy(LoginRequirements);

impl FixedLoginPolicy {
    /// The authentication requirements of `policy`.
    pub fn of(policy: &SecurityPolicy) -> Self {
        Self(LoginRequirements {
            min_acr: policy.auth.min_acr,
            required_amr: policy.auth.required_amr.iter().cloned().collect(),
            max_authentication_age: None,
            enforcement: policy.enforcement.mode,
            fence: None,
        })
    }
}

#[async_trait]
impl LoginPolicySource for FixedLoginPolicy {
    async fn requirements(
        &self,
        _client_id: Option<&str>,
    ) -> Result<LoginRequirements, LoginPolicyUnavailable> {
        Ok(self.0.clone())
    }
}

/// What an authentication did not meet, by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unmet {
    /// The assurance it must reach, when below.
    pub acr: Option<AuthLevel>,
    /// Methods it did not use.
    pub amr: Vec<String>,
    /// The authentication age it must not exceed, when it is older.
    pub max_authentication_age: Option<Duration>,
}

impl Unmet {
    pub fn is_empty(&self) -> bool {
        self.acr.is_none() && self.amr.is_empty() && self.max_authentication_age.is_none()
    }
}

/// What the requirements decide about an authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginDecision {
    /// Met, or unmet under audit enforcement (`audited` is then not empty).
    Allow { audited: Unmet },
    /// The user authenticates further: each unmet requirement is named.
    StepUp(Unmet),
}

impl LoginRequirements {
    /// These requirements with `client`'s and the authorization request's
    /// (`acr_values`, OpenID Connect Core 1.0 §3.1.2.1): each field takes the
    /// stricter value (a higher level, more methods, a harder enforcement),
    /// never a weaker one.
    pub fn with_client(mut self, client: &OAuth2Client, requested: Option<AuthLevel>) -> Self {
        if let Some(level) = client.required_acr {
            self.min_acr = self.min_acr.max(level);
        }
        if let Some(level) = requested {
            self.min_acr = self.min_acr.max(level);
        }
        self.required_amr
            .extend(client.required_amr.iter().cloned());
        self.enforcement = self.enforcement.max(client.enforcement_mode);
        self
    }

    /// What `session`'s authentication leaves unmet at `now`: the level in
    /// force then (a lapsed step-up no longer counts), the methods it used and
    /// its age from when it happened.
    pub fn unmet<O>(&self, session: &Session<O>, now: DateTime<Utc>) -> Unmet {
        let assurance = session.assurance_at(now);
        let acr = (assurance < self.min_acr).then_some(self.min_acr);
        let amr = self
            .required_amr
            .iter()
            .filter(|m| !session.amr.contains(m))
            .cloned()
            .collect();
        let max_authentication_age = self.max_authentication_age.filter(|max| {
            authentication_age(session.authenticated_at, now).is_none_or(|age| age > *max)
        });
        Unmet {
            acr,
            amr,
            max_authentication_age,
        }
    }

    /// The decision on `session` at `now`: met is allowed; unmet is a step-up
    /// under soft or hard enforcement and is allowed, but reported, under
    /// audit.
    pub fn decide<O>(&self, session: &Session<O>, now: DateTime<Utc>) -> LoginDecision {
        let unmet = self.unmet(session, now);
        if unmet.is_empty() || self.enforcement == EnforcementMode::Audit {
            LoginDecision::Allow { audited: unmet }
        } else {
            LoginDecision::StepUp(unmet)
        }
    }
}

/// The session a local authentication of `owner` completing at `now` would
/// create, as the requirements see it before it exists: authenticated at
/// `now` itself, at `assurance` with `amr`.
pub fn local_authentication<O>(
    owner: O,
    assurance: AuthLevel,
    amr: &[String],
    now: DateTime<Utc>,
) -> Session<O> {
    let mut probe = Session::new(owner, "probe".to_string(), now + chrono::Duration::hours(1));
    probe.assurance_level = assurance;
    probe.amr = amr.to_vec();
    probe.authenticated_at = now;
    probe
}

/// How long ago `at` was at `now`; none when `at` is in the future, which no
/// authentication age can be trusted from.
fn authentication_age(at: DateTime<Utc>, now: DateTime<Utc>) -> Option<Duration> {
    (now - at).to_std().ok()
}

#[cfg(test)]
mod tests;
