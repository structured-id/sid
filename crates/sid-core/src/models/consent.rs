// SPDX-License-Identifier: AGPL-3.0-only
//! Consent and Claim Grant domain models.
//!
//! Tracks user consent for data sharing with external sites/services.
//! Every claim shared requires explicit consent; users can revoke at any time.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ClaimSharing, ProfileId, ResourceId};

/// Unique identifier for a consent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsentId(pub Uuid);

impl core::fmt::Display for ConsentId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl ConsentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ConsentId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a claim grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimGrantId(pub Uuid);

impl core::fmt::Display for ClaimGrantId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl ClaimGrantId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ClaimGrantId {
    fn default() -> Self {
        Self::new()
    }
}

/// How critical a claim is for login (authz/consent-flow.md, request level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLevel {
    /// Login fails without this claim.
    Required,
    /// The site justifies it; the user may deny it and still log in.
    Demanded,
    /// The user may skip it freely.
    Optional,
}

impl ClaimLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Demanded => "demanded",
            Self::Optional => "optional",
        }
    }
}

parse_stored!(ClaimLevel, "claim level", [Required, Demanded, Optional]);

/// Whether the site needs a claim's later changes (authz/consent-flow.md,
/// subscription).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSubscription {
    /// Shared only with updates, or not at all.
    Required,
    /// Updates recommended; a snapshot is accepted.
    Preferred,
    /// The current value only.
    None,
}

impl ClaimSubscription {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::None => "none",
        }
    }
}

parse_stored!(
    ClaimSubscription,
    "claim subscription",
    [Required, Preferred, None]
);

impl std::fmt::Display for ClaimLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the site requests the actual data or just an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    /// Site receives the actual value (e.g., `email: alice@example.com`).
    Data,
    /// Site receives only verification status (e.g., `passport_verified: true`).
    Attestation,
}

impl ClaimType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Attestation => "attestation",
        }
    }
}

impl std::str::FromStr for ClaimType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "data" => Ok(Self::Data),
            "attestation" => Ok(Self::Attestation),
            other => Err(format!("unknown claim type: {other}")),
        }
    }
}

impl std::fmt::Display for ClaimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a granted claim reaches the client (authz/consent-flow.md, claim
/// update propagation): the user's choice within the site's subscription.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// The value at grant time; a later edit shows as stale.
    #[default]
    Static,
    /// The value and its later changes.
    Subscribed,
}

impl ConsentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Subscribed => "subscribed",
        }
    }

    /// The sharing choice this mode was granted as.
    pub fn sharing(self) -> ClaimSharing {
        match self {
            Self::Static => ClaimSharing::Static,
            Self::Subscribed => ClaimSharing::Subscribed,
        }
    }
}

parse_stored!(ConsentMode, "consent mode", [Static, Subscribed]);

impl std::fmt::Display for ConsentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The scopes a consent grants its client for one protected resource
/// (authz/consent-flow.md: authorization of the exact client for its
/// resource/scopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub resource_id: ResourceId,
    /// Granted scope values, each once.
    pub scopes: Vec<String>,
    /// When a scope was last added.
    pub granted_at: Timestamp,
}

/// Consent status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    /// Consent requested by site — awaiting user decision.
    #[default]
    Requested,
    /// User granted consent — claims are being shared.
    Active,
    /// User revoked consent — site must delete data.
    Revoked,
    /// Consent expired (TTL-based).
    Expired,
}

impl ConsentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_requested(&self) -> bool {
        matches!(self, Self::Requested)
    }
}

impl std::str::FromStr for ConsentStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "requested" => Ok(Self::Requested),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown consent status: {other}")),
        }
    }
}

impl std::fmt::Display for ConsentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Claim request: what a site asks for at client registration, along the two
/// orthogonal dimensions of authz/consent-flow.md (structured claim requests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Claim name (e.g., "email", "phone", "passport_verified").
    pub claim_name: String,

    /// How critical the claim is for login.
    pub level: ClaimLevel,

    /// Whether the site needs the claim's later changes.
    pub subscription: ClaimSubscription,

    /// Whether this is a data request or attestation request.
    pub claim_type: ClaimType,

    /// The site's reason, shown to the user; required for a demanded claim.
    pub justification: Option<String>,
}

impl ClaimRequest {
    pub fn required(name: impl Into<String>, claim_type: ClaimType) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::Required,
            subscription: ClaimSubscription::None,
            claim_type,
            justification: None,
        }
    }

    pub fn optional(name: impl Into<String>, claim_type: ClaimType) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::Optional,
            subscription: ClaimSubscription::None,
            claim_type,
            justification: None,
        }
    }

    pub fn demanded(
        name: impl Into<String>,
        claim_type: ClaimType,
        justification: impl Into<String>,
    ) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::Demanded,
            subscription: ClaimSubscription::None,
            claim_type,
            justification: Some(justification.into()),
        }
    }

    /// Whether an approval may share this claim as `sharing`: a required
    /// subscription admits only updates, none admits no updates, and a
    /// required claim cannot be left unshared in an approval (the user denies
    /// instead).
    pub fn admits(&self, sharing: ClaimSharing) -> bool {
        match sharing {
            ClaimSharing::None => self.level != ClaimLevel::Required,
            ClaimSharing::Static => self.subscription != ClaimSubscription::Required,
            ClaimSharing::Subscribed => self.subscription != ClaimSubscription::None,
        }
    }
}

/// Claim grant — user's decision to share a specific claim with a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimGrant {
    pub id: ClaimGrantId,

    /// Consent record this grant belongs to.
    pub consent_id: ConsentId,

    /// Claim name being granted.
    pub claim_name: String,

    /// Whether this grants data or attestation access.
    pub claim_type: ClaimType,

    /// Whether later changes of the claim reach the client.
    pub mode: ConsentMode,

    /// When this grant was given.
    pub granted_at: Timestamp,

    /// When this grant was revoked (if revoked).
    pub revoked_at: Option<Timestamp>,

    /// What the recipient receives for this claim: the value the holder
    /// reviewed and approved, from one version of the selected Profile
    /// (identity-model.md, recipient disclosure). Delivery reads it, never
    /// the current Profile. Absent for a grant recorded without a reviewed
    /// value, which then discloses nothing.
    #[serde(default)]
    pub disclosed: Option<DisclosedValue>,
}

/// A claim value as disclosed to a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DisclosedValue {
    /// The value itself; for an attestation grant, empty: only the
    /// verification is disclosed.
    pub value: String,
    /// Whether the value was verified when it was approved, for a claim the
    /// protocol pairs with a verification flag (`email_verified`,
    /// `phone_number_verified`, OIDC Core 1.0 §5.1).
    pub verified: Option<bool>,
}

/// The claims an OIDC request asks for through its scopes, OIDC Core 1.0
/// §5.4: those of the `profile`, `email` and `phone` scopes. `openid` alone
/// asks for none.
pub fn scope_claims(scopes: &[String]) -> Vec<&'static str> {
    let mut claims = Vec::new();
    for scope in scopes {
        claims.extend_from_slice(match scope.as_str() {
            "profile" => &[
                "name",
                "given_name",
                "family_name",
                "middle_name",
                "preferred_username",
            ][..],
            "email" => &["email"][..],
            "phone" => &["phone_number"][..],
            _ => &[][..],
        });
    }
    claims
}

/// The claims a disclosure review covers for a client that registered
/// `registered` and asks for `scopes`, with `held` the grants of the
/// disclosure the recipient holds now: the registered requests, then each
/// claim the scopes ask for that it did not register, as voluntary and
/// without updates (consent-flow.md, OIDC scope requests), then every claim
/// disclosed before, so the whole disclosure is reviewed (identity-model.md,
/// recipient disclosure). Each claim once.
pub fn review_requests(
    registered: &[ClaimRequest],
    scopes: &[String],
    held: &[ClaimGrant],
) -> Vec<ClaimRequest> {
    let mut requests = registered.to_vec();
    let mut add = |request: ClaimRequest| {
        if !requests.iter().any(|r| r.claim_name == request.claim_name) {
            requests.push(request);
        }
    };
    for name in scope_claims(scopes) {
        add(ClaimRequest::optional(name, ClaimType::Data));
    }
    for grant in held.iter().filter(|g| g.is_active()) {
        add(ClaimRequest::optional(
            grant.claim_name.clone(),
            grant.claim_type,
        ));
    }
    requests
}

/// The sharing choices a claim request admits, in the order shown, when the
/// Profile holds a value for it; without one, only not sharing.
pub fn allowed_sharing(request: &ClaimRequest, has_value: bool) -> Vec<ClaimSharing> {
    [
        ClaimSharing::None,
        ClaimSharing::Static,
        ClaimSharing::Subscribed,
    ]
    .into_iter()
    .filter(|sharing| request.admits(*sharing))
    .filter(|sharing| has_value || *sharing == ClaimSharing::None)
    .collect()
}

/// The value each claim this issuer discloses has in `profile` with its
/// primary `email` and `phone`: its names, its username and those contacts
/// (OIDC Core 1.0 §5.1). A claim without a value is absent.
pub fn claim_values(
    profile: &super::Profile,
    email: Option<&super::ProfileEmail>,
    phone: Option<&super::ProfilePhone>,
) -> Vec<(&'static str, DisclosedValue)> {
    let text = |value: Option<String>| {
        value.map(|value| DisclosedValue {
            value,
            verified: None,
        })
    };
    let mut values: Vec<(&'static str, DisclosedValue)> = [
        ("name", text(profile.formatted_name())),
        ("given_name", text(profile.given_name.clone())),
        ("family_name", text(profile.family_name.clone())),
        ("middle_name", text(profile.middle_name.clone())),
        ("preferred_username", text(profile.username.clone())),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name, value)))
    .collect();
    if let Some(email) = email {
        values.push((
            "email",
            DisclosedValue {
                value: email.email.clone(),
                verified: Some(email.verified),
            },
        ));
    }
    if let Some(phone) = phone {
        values.push((
            "phone_number",
            DisclosedValue {
                value: phone.formatted_e164(),
                verified: Some(phone.verified),
            },
        ));
    }
    values
}

/// The value `request` discloses from `values` ([`claim_values`]): the value
/// itself for a data request, only its verification for an attestation.
pub fn disclosed_for(
    request: &ClaimRequest,
    values: &[(&'static str, DisclosedValue)],
) -> Option<DisclosedValue> {
    let (_, value) = values
        .iter()
        .find(|(name, _)| *name == request.claim_name)?;
    Some(match request.claim_type {
        ClaimType::Data => value.clone(),
        ClaimType::Attestation => DisclosedValue {
            value: String::new(),
            verified: value.verified,
        },
    })
}

/// One subscribed claim's delivered value: `next` replaces `prior` only
/// while the grant still holds `prior`, so a delivery computed from an older
/// Profile version never overwrites a newer one. `next` absent: the field
/// was cleared and is no longer disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureUpdate {
    pub claim_name: String,
    pub prior: Option<DisclosedValue>,
    pub next: Option<DisclosedValue>,
}

impl ClaimGrant {
    pub fn new(
        consent_id: ConsentId,
        claim_name: impl Into<String>,
        claim_type: ClaimType,
        mode: ConsentMode,
    ) -> Self {
        Self {
            id: ClaimGrantId::new(),
            consent_id,
            claim_name: claim_name.into(),
            claim_type,
            mode,
            granted_at: Timestamp::now(),
            revoked_at: None,
            disclosed: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn revoke(&mut self) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(Timestamp::now());
        }
    }
}

/// Consent record — top-level consent decision for a profile→site relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub id: ConsentId,

    /// Profile granting consent.
    pub profile_id: ProfileId,

    /// OIDC client_id of the site receiving data.
    pub client_id: String,

    pub status: ConsentStatus,

    /// Individual claim grants within this consent.
    pub grants: Vec<ClaimGrant>,

    /// The scopes granted to the client, per protected resource.
    pub scope_grants: Vec<ScopeGrant>,

    /// When consent was first given.
    pub consented_at: Timestamp,

    /// When consent was fully revoked (all claims).
    pub revoked_at: Option<Timestamp>,

    /// When consent was last updated (new grants or revocations).
    pub updated_at: Timestamp,
}

impl ConsentRecord {
    pub fn new(profile_id: ProfileId, client_id: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            id: ConsentId::new(),
            profile_id,
            client_id: client_id.into(),
            status: ConsentStatus::Requested,
            grants: vec![],
            scope_grants: vec![],
            consented_at: now,
            revoked_at: None,
            updated_at: now,
        }
    }

    /// Grant a claim. A claim has one grant: granting a revoked claim again
    /// renews that grant, granting an active one takes the type and mode now
    /// approved.
    pub fn grant_claim(
        &mut self,
        claim_name: impl Into<String>,
        claim_type: ClaimType,
        mode: ConsentMode,
    ) {
        let claim_name = claim_name.into();
        let now = Timestamp::now();
        match self.grants.iter_mut().find(|g| g.claim_name == claim_name) {
            Some(grant)
                if grant.is_active() && grant.mode == mode && grant.claim_type == claim_type =>
            {
                return;
            }
            Some(grant) if grant.is_active() => {
                grant.claim_type = claim_type;
                grant.mode = mode;
            }
            Some(grant) => {
                grant.claim_type = claim_type;
                grant.mode = mode;
                grant.granted_at = now;
                grant.revoked_at = None;
            }
            None => self
                .grants
                .push(ClaimGrant::new(self.id, claim_name, claim_type, mode)),
        }
        self.updated_at = now;
    }

    /// Add `scopes` for `resource` to what the client is granted; scopes
    /// already granted stay as they are.
    pub fn grant_scopes(&mut self, resource: ResourceId, scopes: &[String]) {
        let now = Timestamp::now();
        let grant = match self
            .scope_grants
            .iter_mut()
            .position(|g| g.resource_id == resource)
        {
            Some(i) => &mut self.scope_grants[i],
            None => {
                self.scope_grants.push(ScopeGrant {
                    resource_id: resource,
                    scopes: Vec::new(),
                    granted_at: now,
                });
                let last = self.scope_grants.len() - 1;
                &mut self.scope_grants[last]
            }
        };
        let mut added = false;
        for scope in scopes {
            if !grant.scopes.contains(scope) {
                grant.scopes.push(scope.clone());
                added = true;
            }
        }
        if added {
            grant.granted_at = now;
            self.updated_at = now;
        }
    }

    /// Whether this consent, active, already grants every one of `scopes`
    /// for `resource` and every one of `claims` as requested now: the same
    /// claim type, in a sharing mode the request admits (consent-flow.md:
    /// skip the screen only when current consent covers the request).
    pub fn covers(
        &self,
        resource: ResourceId,
        scopes: &[String],
        claims: &[&ClaimRequest],
    ) -> bool {
        if !self.status.is_active() {
            return false;
        }
        let Some(granted) = self.scope_grants.iter().find(|g| g.resource_id == resource) else {
            return scopes.is_empty() && self.covers_claims(claims);
        };
        scopes.iter().all(|s| granted.scopes.contains(s)) && self.covers_claims(claims)
    }

    /// A grant covers a request only with the value the holder approved: one
    /// re-enabled without a reviewed value discloses nothing yet.
    fn covers_claims(&self, claims: &[&ClaimRequest]) -> bool {
        claims.iter().all(|request| {
            self.grants.iter().any(|g| {
                g.is_active()
                    && g.disclosed.is_some()
                    && g.claim_name == request.claim_name
                    && g.claim_type == request.claim_type
                    && request.admits(g.mode.sharing())
            })
        })
    }

    /// What this consent's subscriptions deliver after a Profile edit, with
    /// `next` the value each active grant would disclose from the current
    /// Profile version: the changed grants with their new values, when every
    /// one of them is subscribed; nothing when no value changed or a changed
    /// field is static, whose new value awaits the holder's review, so the
    /// whole snapshot stays and old and new values are never combined
    /// (identity-model.md, recipient disclosure; consent-flow.md, claim
    /// update propagation).
    pub fn subscribed_delivery(
        &self,
        next: impl Fn(&ClaimGrant) -> Option<DisclosedValue>,
    ) -> Option<Vec<DisclosureUpdate>> {
        if !self.status.is_active() {
            return None;
        }
        let mut updates = Vec::new();
        for grant in self.grants.iter().filter(|g| g.is_active()) {
            let value = next(grant);
            if value == grant.disclosed {
                continue;
            }
            if grant.mode != ConsentMode::Subscribed {
                return None;
            }
            updates.push(DisclosureUpdate {
                claim_name: grant.claim_name.clone(),
                prior: grant.disclosed.clone(),
                next: value,
            });
        }
        (!updates.is_empty()).then_some(updates)
    }

    /// Whether `other` is this consent in the same state: the same status,
    /// claim grants (each with its type, mode, revocation and disclosed
    /// value) and scope grants, in any order. Its revision time is not
    /// compared: writers stamp it from different clocks, so equal times do
    /// not prove an unchanged record, and the state itself does.
    pub fn same_state(&self, other: &ConsentRecord) -> bool {
        fn claims(c: &ConsentRecord) -> Vec<&ClaimGrant> {
            let mut grants: Vec<_> = c.grants.iter().collect();
            grants.sort_by(|a, b| a.claim_name.cmp(&b.claim_name));
            grants
        }
        fn scopes(c: &ConsentRecord) -> Vec<&ScopeGrant> {
            let mut grants: Vec<_> = c.scope_grants.iter().collect();
            grants.sort_by_key(|g| g.resource_id);
            grants
        }
        self.id == other.id
            && self.status == other.status
            && self.revoked_at == other.revoked_at
            && claims(self) == claims(other)
            && scopes(self) == scopes(other)
    }

    /// This consent with `updates` delivered: their values on the active
    /// grants, and a revision (`updated_at`) later than this one, in whole
    /// microseconds as every store keeps it, so a store can tell the
    /// delivered record from the one delivered over.
    pub fn with_delivery(&self, updates: &[DisclosureUpdate]) -> ConsentRecord {
        let mut next = self.clone();
        for update in updates {
            if let Some(grant) = next
                .grants
                .iter_mut()
                .find(|g| g.is_active() && g.claim_name == update.claim_name)
            {
                grant.disclosed = update.next.clone();
            }
        }
        let latest = Timestamp::now().max(self.updated_at);
        // Truncation to whole microseconds plus one is always later than
        // `latest`.
        let micros = latest.as_microsecond() + 1;
        next.updated_at = Timestamp::from_microsecond(micros).unwrap_or(latest);
        next
    }

    /// Withdraw every grant: a consent approved again after its revocation
    /// starts from what the new approval grants, never from what was revoked.
    pub fn clear_grants(&mut self) {
        self.grants.clear();
        self.scope_grants.clear();
        self.updated_at = Timestamp::now();
    }

    /// Gateway: obtain typed wrapper if consent is Requested (awaiting user decision).
    pub fn as_requested(&mut self) -> Option<RequestedConsent<'_>> {
        if self.status == ConsentStatus::Requested {
            Some(RequestedConsent(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if consent is Active.
    pub fn as_active(&mut self) -> Option<ActiveConsent<'_>> {
        if self.status == ConsentStatus::Active {
            Some(ActiveConsent(self))
        } else {
            None
        }
    }

    /// Active (non-revoked) grants.
    pub fn active_grants(&self) -> Vec<&ClaimGrant> {
        self.grants.iter().filter(|g| g.is_active()).collect()
    }

    /// Whether this consent has any active grants.
    pub fn has_active_grants(&self) -> bool {
        self.grants.iter().any(|g| g.is_active())
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> ConsentStatus {
        self.status
    }
}

/// A user's decision on one claim of an active consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDecision {
    /// Share the claim, as data or as an attestation.
    Grant(ClaimType),
    /// Stop sharing it.
    Revoke,
}

/// Outcome of a [`ClaimDecision`] on a stored consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimGrantChange {
    /// The claim was granted or revoked.
    Changed,
    /// It already was: nothing written and nothing owed.
    Unchanged,
    /// The consent is gone or not active (awaiting a decision, revoked,
    /// expired): no claim of it changes.
    ConsentNotActive,
}

/// Typed wrapper for a Requested consent record (awaiting user decision).
pub struct RequestedConsent<'a>(&'a mut ConsentRecord);

impl<'a> RequestedConsent<'a> {
    /// User grants consent — transition to Active. Consumes wrapper.
    pub fn grant(self) {
        self.0.status = ConsentStatus::Active;
        self.0.updated_at = Timestamp::now();
    }

    /// User denies consent — transition to Revoked. Consumes wrapper.
    pub fn deny(self) {
        self.0.status = ConsentStatus::Revoked;
        self.0.revoked_at = Some(Timestamp::now());
        self.0.updated_at = Timestamp::now();
    }

    pub fn inner(&self) -> &ConsentRecord {
        self.0
    }
}

/// Typed wrapper for an Active consent record.
pub struct ActiveConsent<'a>(&'a mut ConsentRecord);

impl<'a> ActiveConsent<'a> {
    /// Revoke all claims — fully disconnect from site. Consumes wrapper.
    pub fn revoke_all(self) {
        for grant in &mut self.0.grants {
            grant.revoke();
        }
        self.0.status = ConsentStatus::Revoked;
        self.0.revoked_at = Some(Timestamp::now());
        self.0.updated_at = Timestamp::now();
    }

    /// Revoke a specific claim by name.
    pub fn revoke_claim(&mut self, claim_name: &str) {
        for grant in &mut self.0.grants {
            if grant.claim_name == claim_name && grant.is_active() {
                grant.revoke();
            }
        }
        self.0.updated_at = Timestamp::now();
    }

    pub fn inner(&self) -> &ConsentRecord {
        self.0
    }
}

#[cfg(test)]
mod tests;
