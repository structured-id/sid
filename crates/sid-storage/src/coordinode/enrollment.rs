// SPDX-License-Identifier: AGPL-3.0-only
//! How accounts come to exist, in CoordiNode: the enrollment policy, the
//! bootstrap policy and the first-administrator claim, invites and the
//! registrations that used them, registration sources, and registration.
//!
//! The enrollment and bootstrap policies are one node each from the start,
//! so what a registration or a claim decides by is held for its commit: a
//! policy changed meanwhile refuses it. Consuming the claim deletes its
//! node, so of concurrent consumers one commits. Spending an invite moves
//! its use count, so concurrent registrations spend it exactly.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::enrollment::EnrollmentDenialReason;
use sid_core::models::{
    AuditEntry, BootstrapPolicy, CentralAdoption, CredentialId, EnrollmentGate, EnrollmentPolicy,
    InstanceSecret, Invite, InviteConfig, InviteCreator, InviteFilter, InviteId, InviteRedemption,
    MachineUserId, ModeWrite, MutationContext, NewRegistration, ProfileId, RegistrationSource,
    RegistrationSourceType, SourceRecording, UtmParams,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_id, get_int, get_opt_bytes, get_opt_text, get_opt_time, get_opt_uuid,
    get_parsed, get_text, get_texts, get_time, get_uuid, hold_first, key, opt_text, opt_time,
    sorted_page, texts, time, uuid,
};

/// The scope both installation policies are recorded under.
const SCOPE: &str = "installation";

const INVITE: &str = "i.id AS id, i.code AS code, i.created_by AS created_by,
    i.created_by_machine AS created_by_machine, i.created_by_name AS created_by_name,
    i.metadata_keys AS metadata_keys, i.metadata_values AS metadata_values,
    i.max_uses AS max_uses, i.use_count AS use_count, i.expires_at AS expires_at,
    i.active AS active, i.created_at AS created_at";

const SOURCE: &str = "s.profile_id AS profile_id, s.source_type AS source_type,
    s.source_id AS source_id, s.referrer_id AS referrer_id, s.utm_source AS utm_source,
    s.utm_medium AS utm_medium, s.utm_campaign AS utm_campaign, s.utm_term AS utm_term,
    s.utm_content AS utm_content, s.client_id AS client_id, s.created_at AS created_at";

fn scope() -> Value {
    Value::String(SCOPE.into())
}

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn count(value: i64, name: &str) -> SidResult<u32> {
    u32::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
}

/// Create the installation's policy nodes of an empty store: the enrollment
/// policy not yet set, the installation self-managed.
pub(super) fn init_policies(tx: &Statements<'_>) -> SidResult<Decision<()>> {
    let mut created = false;
    for (label, properties) in [
        ("SidEnrollmentPolicy", "stored: false"),
        ("SidBootstrapPolicy", "central: false"),
    ] {
        let found = tx.run(
            &format!("MATCH (p:{label}) WHERE p.scope = $scope RETURN p.scope AS scope"),
            Params::default().with("scope", scope()),
        )?;
        if found.is_empty() {
            tx.run(
                &format!("CREATE (p:{label} {{scope: $scope, {properties}}})"),
                Params::default().with("scope", scope()),
            )?;
            created = true;
        }
    }
    Ok(if created {
        Decision::Commit(())
    } else {
        Decision::Abandon(())
    })
}

// === Policies ===

/// The stored enrollment policy, held for the open transaction: a change
/// committed meanwhile refuses what was decided by it. `None` while it was
/// never set, which is the defaults.
fn held_enrollment_policy(tx: &Statements<'_>) -> SidResult<Option<EnrollmentPolicy>> {
    let rows = tx.run(
        "MATCH (p:SidEnrollmentPolicy) WHERE p.scope = $scope
         RETURN id(p) AS node, p.stored AS stored, p.mode AS mode,
                p.allowed_domains AS allowed_domains, p.track_source AS track_source,
                p.invite_default_max_uses AS max_uses,
                p.invite_default_expiry_hours AS expiry_hours",
        Params::default().with("scope", scope()),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(SidError::Storage("enrollment policy node missing".into()));
    }
    let row = &rows[0];
    if !get_bool(row, "stored")? {
        return Ok(None);
    }
    Ok(Some(EnrollmentPolicy {
        mode: get_parsed(row, "mode")?,
        invite: InviteConfig {
            default_max_uses: count(get_int(row, "max_uses")?, "invite max uses")?,
            default_expiry_hours: count(get_int(row, "expiry_hours")?, "invite expiry")?,
        },
        allowed_domains: get_texts(row, "allowed_domains")?,
        track_source: get_bool(row, "track_source")?,
    }))
}

/// Whether the installation is centrally managed, held for the open
/// transaction: an adoption committed meanwhile refuses what was decided.
fn held_central(tx: &Statements<'_>) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (p:SidBootstrapPolicy) WHERE p.scope = $scope
         RETURN id(p) AS node, p.central AS central",
        Params::default().with("scope", scope()),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(SidError::Storage("bootstrap policy node missing".into()));
    }
    get_bool(&rows[0], "central")
}

/// Refuse storing an administrator claim on a centrally managed
/// installation, held for the commit: it never offers a local claim.
pub(super) fn check_claim_allowed(tx: &Statements<'_>, secret: InstanceSecret) -> SidResult<()> {
    if secret == InstanceSecret::AdminClaim && held_central(tx)? {
        return Err(SidError::InvalidState(
            "centrally managed installation: no administrator claim".into(),
        ));
    }
    Ok(())
}

/// Consume the stored administrator claim when it is `sealed` and the
/// installation is self-managed; whether it was consumed.
fn consume_claim(tx: &Statements<'_>, sealed: &[u8]) -> SidResult<bool> {
    if held_central(tx)? {
        return Ok(false);
    }
    let rows = tx.run(
        "MATCH (s:SidInstanceSecret) WHERE s.name = $name RETURN s.sealed AS sealed",
        Params::default().with(
            "name",
            Value::String(InstanceSecret::AdminClaim.as_str().into()),
        ),
    )?;
    let matches = rows
        .first()
        .map(|row| get_bytes(row, "sealed"))
        .transpose()?
        .is_some_and(|stored| stored == sealed);
    if !matches {
        return Ok(false);
    }
    delete_claim(tx)?;
    Ok(true)
}

fn delete_claim(tx: &Statements<'_>) -> SidResult<()> {
    tx.run(
        "MATCH (s:SidInstanceSecret) WHERE s.name = $name DETACH DELETE s",
        Params::default().with(
            "name",
            Value::String(InstanceSecret::AdminClaim.as_str().into()),
        ),
    )?;
    Ok(())
}

// === Invites ===

fn invite(row: &Row) -> SidResult<Invite> {
    let id = InviteId(get_uuid(row, "id")?);
    let created_by = match (
        get_opt_bytes(row, "created_by")?,
        get_opt_bytes(row, "created_by_machine")?,
    ) {
        (Some(profile), None) => InviteCreator::Profile(
            ProfileId::from_slice(&profile)
                .map_err(|e| SidError::Storage(format!("invite creator: {e}")))?,
        ),
        (None, Some(machine)) => InviteCreator::MachineUser(
            MachineUserId::from_slice(&machine)
                .map_err(|e| SidError::Storage(format!("invite creator: {e}")))?,
        ),
        _ => {
            return Err(SidError::Storage(format!(
                "invite {} names no single creator",
                id.0
            )));
        }
    };
    let (keys, values) = (
        get_texts(row, "metadata_keys")?,
        get_texts(row, "metadata_values")?,
    );
    if keys.len() != values.len() {
        return Err(SidError::Storage(format!("invite {} metadata", id.0)));
    }
    Ok(Invite {
        id,
        code: get_text(row, "code")?,
        created_by,
        created_by_name: get_text(row, "created_by_name")?,
        metadata: keys.into_iter().zip(values).collect(),
        max_uses: count(get_int(row, "max_uses")?, "max_uses")?,
        use_count: count(get_int(row, "use_count")?, "use_count")?,
        expires_at: get_opt_time(row, "expires_at")?,
        active: get_bool(row, "active")?,
        created_at: get_time(row, "created_at")?,
    })
}

/// The invite whose code is `code`, ignoring case and surrounding space.
fn invite_by_code(tx: &Statements<'_>, code: &str) -> SidResult<Option<Invite>> {
    let rows = tx.run(
        &format!("MATCH (i:SidInvite) WHERE i.code_key = $code RETURN {INVITE}"),
        Params::default().with("code", Value::String(code.trim().to_uppercase())),
    )?;
    rows.first().map(invite).transpose()
}

/// Spend one use of the invite `filter` (over `i`, with `$value`) selects
/// while it is usable; the invite after the use, or `None` when it was not.
fn spend(tx: &Statements<'_>, filter: &str, value: Value) -> SidResult<Option<Invite>> {
    let rows = tx.run(
        &format!("MATCH (i:SidInvite) WHERE {filter} RETURN {INVITE}"),
        Params::default().with("value", value),
    )?;
    let Some(stored) = rows.first().map(invite).transpose()? else {
        return Ok(None);
    };
    if !stored.is_usable() {
        return Ok(None);
    }
    // Written at the read count: a use committed meanwhile conflicts.
    let used = tx.run(
        &format!(
            "MATCH (i:SidInvite) WHERE i.id = $id AND i.use_count = $count
             SET i.use_count = i.use_count + 1 RETURN {INVITE}"
        ),
        Params::default()
            .with("id", uuid(&stored.id.0))
            .with("count", Value::Int(i64::from(stored.use_count))),
    )?;
    used.first().map(invite).transpose()
}

/// Admit a self-registration in `tx`: decide it by the policy stored now
/// and spend its invite when the mode asks for one, recording that use in
/// the invite's audit chain as `registration`'s actor; returns the source
/// that policy records and the invite spent.
fn admit(
    tx: &Statements<'_>,
    gate: &EnrollmentGate,
    registration: &AuditEntry,
) -> SidResult<(Option<RegistrationSource>, Option<InviteId>)> {
    let admission = gate
        .admit(held_enrollment_policy(tx)?)
        .map_err(SidError::RegistrationRestricted)?;
    let Some(code) = admission.invite else {
        return Ok((admission.source(), None));
    };
    let Some(spent) = spend(
        tx,
        "i.code_key = $value",
        Value::String(code.trim().to_uppercase()),
    )?
    else {
        return Err(SidError::RegistrationRestricted(
            EnrollmentDenialReason::InviteInvalid,
        ));
    };
    super::audit::append(
        tx,
        &format!("invite:{}", spent.id.0),
        crate::invite_use_entry(registration, spent.id.0),
        Utc::now(),
    )?;
    Ok((admission.source(), Some(spent.id)))
}

// === Registration sources ===

fn source(row: &Row) -> SidResult<RegistrationSource> {
    Ok(RegistrationSource {
        source_type: get_parsed(row, "source_type")?,
        source_id: get_text(row, "source_id")?,
        referrer_id: get_opt_bytes(row, "referrer_id")?
            .map(|b| ProfileId::from_slice(&b))
            .transpose()
            .map_err(|e| SidError::Storage(format!("referrer: {e}")))?,
        utm: UtmParams {
            source: get_text(row, "utm_source")?,
            medium: get_text(row, "utm_medium")?,
            campaign: get_text(row, "utm_campaign")?,
            term: get_text(row, "utm_term")?,
            content: get_text(row, "utm_content")?,
        },
        client_id: get_opt_text(row, "client_id")?,
        created_at: get_time(row, "created_at")?,
    })
}

/// Record where `profile` came from in `tx`; a referrer that is not stored
/// is refused, and held for the commit when it is.
fn insert_source(tx: &Statements<'_>, profile: ProfileId, s: &RegistrationSource) -> SidResult<()> {
    if let Some(referrer) = s.referrer_id {
        let held = tx.run(
            "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
            Params::default().with("id", bin(referrer.as_bytes())),
        )?;
        if !hold_first(tx, &held)? {
            return Err(SidError::NotFound(format!("referrer {referrer}")));
        }
    }
    tx.run(
        "CREATE (s:SidRegistrationSource {profile_id: $profile_id, source_type: $source_type,
            source_id: $source_id, referrer_id: $referrer_id, utm_source: $utm_source,
            utm_medium: $utm_medium, utm_campaign: $utm_campaign, utm_term: $utm_term,
            utm_content: $utm_content, client_id: $client_id, created_at: $created_at})",
        Params::default()
            .with("profile_id", bin(profile.as_bytes()))
            .with("source_type", Value::String(s.source_type.as_str().into()))
            .with("source_id", Value::String(s.source_id.clone()))
            .with(
                "referrer_id",
                s.referrer_id.map_or(Value::Null, |r| bin(r.as_bytes())),
            )
            .with("utm_source", Value::String(s.utm.source.clone()))
            .with("utm_medium", Value::String(s.utm.medium.clone()))
            .with("utm_campaign", Value::String(s.utm.campaign.clone()))
            .with("utm_term", Value::String(s.utm.term.clone()))
            .with("utm_content", Value::String(s.utm.content.clone()))
            .with("client_id", opt_text(s.client_id.as_deref()))
            .with("created_at", time(s.created_at)),
    )?;
    Ok(())
}

/// Delete in `tx` where `profile` came from and the invite uses it made.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for query in [
        "MATCH (s:SidRegistrationSource) WHERE s.profile_id = $id DETACH DELETE s",
        "MATCH (r:SidInviteRedemption) WHERE r.profile_id = $id DETACH DELETE r",
    ] {
        tx.run(query, Params::default().with("id", bin(profile.as_bytes())))?;
    }
    Ok(())
}

/// The sources recorded since `since`.
fn sources_since(tx: &Statements<'_>, since: DateTime<Utc>) -> SidResult<Vec<RegistrationSource>> {
    let rows = tx.run(
        &format!("MATCH (s:SidRegistrationSource) WHERE s.created_at >= $since RETURN {SOURCE}"),
        Params::default().with("since", time(since)),
    )?;
    rows.iter().map(source).collect()
}

// === Registration ===

/// Commit `registration` in `tx`, as the storage contract states it.
fn register(
    tx: &Statements<'_>,
    registration: &NewRegistration,
    audit: &AuditEntry,
) -> SidResult<()> {
    let NewRegistration {
        profile,
        principal,
        email,
        phone,
        credential,
        source,
        instance_claim,
        history,
        enrollment,
        source_recording,
    } = registration;
    if principal.profile_id != profile.id {
        return Err(SidError::Validation(
            "a registration's principal names its own profile".into(),
        ));
    }
    // A self-registration records the source its admitting policy decides;
    // one recorded while tracked asks the policy in force now.
    let (source, spent) = match (enrollment, source_recording) {
        (Some(gate), _) => admit(tx, gate, audit)?,
        (None, SourceRecording::WhilePolicyTracks) => {
            let tracks = held_enrollment_policy(tx)?.map_or(
                sid_core::models::security_policy::CE_ENROLLMENT_TRACK_SOURCE,
                |p| p.track_source,
            );
            (source.clone().filter(|_| tracks), None)
        }
        (None, SourceRecording::AsGiven) => (source.clone(), None),
    };

    // The first administrator's registration consumes the claim first; a
    // refusal drops the transaction with nothing written.
    if let Some(claim) = instance_claim
        && (!consume_claim(tx, claim)? || super::rbac::administrator_exists(tx, None)?)
    {
        return Err(SidError::InvalidState(
            "the installation has no open administrator claim".into(),
        ));
    }

    // The principal decides a registration race: a taken identifier drops
    // the transaction with nothing written.
    if super::principal::by_value(tx, principal.principal_type, &principal.value)?.is_some() {
        return Err(SidError::Conflict("principal already registered".into()));
    }
    super::profile::insert(tx, profile)?;
    if instance_claim.is_some() {
        super::rbac::grant_installation_administrator(tx, profile.id, Some(profile.id))?;
    }
    if let Some(email) = email {
        super::profile::insert_email(tx, email)?;
    }
    if let Some(phone) = phone {
        super::profile::insert_phone(tx, phone)?;
    }
    // A new identifier is first used here: it is assigned to the registrant.
    super::principal::bind(tx, principal)?;
    if let Some(credential) = credential {
        super::credential::insert(tx, credential)?;
    }
    // The invite this registration spent names the Profile it created and
    // the credential it installed.
    if let Some(invite) = spent {
        tx.run(
            "CREATE (r:SidInviteRedemption {pair: $pair, invite_id: $invite,
                profile_id: $profile, credential_id: $credential, redeemed_at: $now})",
            Params::default()
                .with("pair", key(&[invite.0.as_bytes(), profile.id.as_bytes()])?)
                .with("invite", uuid(&invite.0))
                .with("profile", bin(profile.id.as_bytes()))
                .with(
                    "credential",
                    credential.as_ref().map_or(Value::Null, |c| uuid(&c.id.0)),
                )
                .with("now", time(Utc::now())),
        )?;
    }
    // A new owner has no history: nothing can have moved it, so a refusal
    // here is the caller's error, not a lost race.
    if let Some(history) = history
        && !super::credential::apply_history(tx, history)?
    {
        return Err(SidError::Conflict(
            "the new profile already has password history".into(),
        ));
    }
    if let Some(source) = &source {
        insert_source(tx, profile.id, source)?;
    }
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn register_profile(
        &self,
        registration: &NewRegistration,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let registration = registration.clone();
        let chain = format!("profile:{}", registration.profile.id);
        self.transaction(move |tx| {
            register(tx, &registration, &ctx.audit)?;
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    // === Policies and the claim ===

    pub(super) async fn bootstrap_policy(&self) -> SidResult<BootstrapPolicy> {
        self.read(|tx| {
            Ok(if held_central(tx)? {
                BootstrapPolicy::CentrallyManaged
            } else {
                BootstrapPolicy::SelfManaged
            })
        })
        .await
    }

    pub(super) async fn adopt_central_management(
        &self,
        ctx: MutationContext,
    ) -> SidResult<CentralAdoption> {
        self.transaction(move |tx| {
            delete_claim(tx)?;
            if held_central(tx)? {
                // The removal of a stale claim stands either way.
                return Ok(Decision::Commit(CentralAdoption::AlreadyCentral));
            }
            if super::rbac::administrator_exists(tx, None)? {
                return Ok(Decision::Abandon(CentralAdoption::LocalAdministrator));
            }
            tx.run(
                "MATCH (p:SidBootstrapPolicy) WHERE p.scope = $scope
                 SET p.central = true, p.adopted_at = $now",
                Params::default()
                    .with("scope", scope())
                    .with("now", time(Utc::now())),
            )?;
            finalize(tx, "installation:bootstrap_policy", ctx.clone())?;
            Ok(Decision::Commit(CentralAdoption::Adopted))
        })
        .await
    }

    pub(super) async fn enrollment_policy(&self) -> SidResult<Option<EnrollmentPolicy>> {
        self.read(held_enrollment_policy).await
    }

    pub(super) async fn set_enrollment_policy(
        &self,
        policy: &EnrollmentPolicy,
        mode: ModeWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if policy.mode == sid_core::models::EnrollmentMode::DomainRestricted
            && policy.allowed_domains.is_empty()
        {
            return Err(SidError::Validation(
                "a domain-restricted enrollment mode needs an allowed domain".into(),
            ));
        }
        let policy = policy.clone();
        self.mutate(
            "installation:enrollment_policy".to_owned(),
            ctx,
            move |tx| {
                // The stored mode, read in this write, stays when asked to.
                let written = match (mode, held_enrollment_policy(tx)?) {
                    (ModeWrite::KeepStored, Some(stored)) => stored.mode,
                    _ => policy.mode,
                };
                if written == sid_core::models::EnrollmentMode::DomainRestricted
                    && policy.allowed_domains.is_empty()
                {
                    return Err(SidError::Validation(
                        "a domain-restricted enrollment mode needs an allowed domain".into(),
                    ));
                }
                tx.run(
                    "MATCH (p:SidEnrollmentPolicy) WHERE p.scope = $scope
                 SET p.stored = true, p.mode = $mode, p.allowed_domains = $domains,
                     p.track_source = $track_source, p.invite_default_max_uses = $max_uses,
                     p.invite_default_expiry_hours = $expiry_hours, p.updated_at = $now",
                    Params::default()
                        .with("scope", scope())
                        .with("mode", Value::String(written.as_str().into()))
                        .with("domains", texts(&policy.allowed_domains))
                        .with("track_source", Value::Bool(policy.track_source))
                        .with(
                            "max_uses",
                            Value::Int(i64::from(policy.invite.default_max_uses)),
                        )
                        .with(
                            "expiry_hours",
                            Value::Int(i64::from(policy.invite.default_expiry_hours)),
                        )
                        .with("now", time(Utc::now())),
                )?;
                Ok(())
            },
        )
        .await
    }

    pub(super) async fn claim_first_admin(
        &self,
        sealed: &[u8],
        profile: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let sealed = sealed.to_vec();
        self.transaction(move |tx| {
            if !consume_claim(tx, &sealed)? {
                return Ok(Decision::Abandon(false));
            }
            if super::rbac::administrator_exists(tx, None)? {
                // A claim left beside an administrator grants nothing: drop it.
                return Ok(Decision::Commit(false));
            }
            let held = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", bin(profile.as_bytes())),
            )?;
            // Claimed: the role assignment is the profile's, deleted with it.
            if !claim_first(tx, &held)? {
                // Dropped: the claim stays for a stored claimer.
                return Ok(Decision::Abandon(false));
            }
            super::rbac::grant_installation_administrator(tx, profile, None)?;
            finalize(tx, &format!("profile:{profile}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Invites ===

    pub(super) async fn create_invites(
        &self,
        invites: &[Invite],
        ctx: MutationContext,
    ) -> SidResult<()> {
        let Some(first) = invites.first() else {
            return Ok(());
        };
        let chain = format!("invite:{}", first.id.0);
        let invites = invites.to_vec();
        self.mutate(chain, ctx, move |tx| {
            for i in &invites {
                let (creator, by_profile, by_machine) = match i.created_by {
                    InviteCreator::Profile(p) => ("SidProfile", bin(p.as_bytes()), Value::Null),
                    InviteCreator::MachineUser(m) => {
                        ("SidMachineUser", Value::Null, bin(m.as_bytes()))
                    }
                };
                let held = tx.run(
                    &format!("MATCH (c:{creator}) WHERE c.id = $id RETURN id(c) AS node"),
                    Params::default()
                        .with("id", Value::Binary(i.created_by.id().as_bytes().to_vec())),
                )?;
                if !hold_first(tx, &held)? {
                    return Err(SidError::NotFound("the invite's creator".into()));
                }
                let found = tx.run(
                    "MATCH (i:SidInvite) WHERE i.id = $id RETURN i.id AS id",
                    Params::default().with("id", uuid(&i.id.0)),
                )?;
                if !found.is_empty() {
                    return Err(SidError::Conflict("invite already exists".into()));
                }
                let (keys, values): (Vec<String>, Vec<String>) = i
                    .metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .unzip();
                tx.run(
                    "CREATE (i:SidInvite {id: $id, code: $code, code_key: $code_key,
                        created_by: $created_by, created_by_machine: $created_by_machine,
                        created_by_name: $created_by_name, metadata_keys: $keys,
                        metadata_values: $values, max_uses: $max_uses, use_count: $use_count,
                        expires_at: $expires_at, active: $active, created_at: $created_at})",
                    Params::default()
                        .with("id", uuid(&i.id.0))
                        .with("code", Value::String(i.code.clone()))
                        .with("code_key", Value::String(i.code.trim().to_uppercase()))
                        .with("created_by", by_profile)
                        .with("created_by_machine", by_machine)
                        .with("created_by_name", Value::String(i.created_by_name.clone()))
                        .with("keys", texts(&keys))
                        .with("values", texts(&values))
                        .with("max_uses", Value::Int(i64::from(i.max_uses)))
                        .with("use_count", Value::Int(i64::from(i.use_count)))
                        .with("expires_at", opt_time(i.expires_at))
                        .with("active", Value::Bool(i.active))
                        .with("created_at", time(i.created_at)),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn get_invite(&self, id: InviteId) -> SidResult<Option<Invite>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (i:SidInvite) WHERE i.id = $id RETURN {INVITE}"),
                Params::default().with("id", uuid(&id.0)),
            )?;
            rows.first().map(invite).transpose()
        })
        .await
    }

    pub(super) async fn get_invite_by_code(&self, code: &str) -> SidResult<Option<Invite>> {
        let code = code.to_owned();
        self.read(move |tx| invite_by_code(tx, &code)).await
    }

    /// The invites `filter` selects, newest first, then by id descending.
    async fn filtered_invites(&self, filter: &InviteFilter) -> SidResult<Vec<Invite>> {
        let filter = filter.clone();
        let all = self
            .read(|tx| {
                let rows = tx.run(
                    &format!("MATCH (i:SidInvite) RETURN {INVITE}"),
                    Params::default(),
                )?;
                rows.iter().map(invite).collect::<SidResult<Vec<_>>>()
            })
            .await?;
        // A substring of the code or the creator's name, ignoring ASCII case.
        let search = filter.search.as_deref().map(str::to_ascii_lowercase);
        let selected = all
            .into_iter()
            .filter(|i| filter.status.is_none_or(|s| i.status() == s))
            .filter(|i| {
                search.as_deref().is_none_or(|text| {
                    i.code.to_ascii_lowercase().contains(text)
                        || i.created_by_name.to_ascii_lowercase().contains(text)
                })
            })
            .collect();
        Ok(sorted_page(
            selected,
            |i| (std::cmp::Reverse(i.created_at), std::cmp::Reverse(i.id.0)),
            0,
            u64::MAX,
        ))
    }

    pub(super) async fn list_invites(
        &self,
        filter: &InviteFilter,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Invite>> {
        let all = self.filtered_invites(filter).await?;
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(all.into_iter().skip(offset).take(limit).collect())
    }

    pub(super) async fn count_invites(&self, filter: &InviteFilter) -> SidResult<u64> {
        let all = self.filtered_invites(filter).await?;
        u64::try_from(all.len()).map_err(|_| SidError::Storage("invite count".into()))
    }

    pub(super) async fn list_invite_redemptions(
        &self,
        id: InviteId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<InviteRedemption>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (r:SidInviteRedemption) WHERE r.invite_id = $id
                 RETURN r.profile_id AS profile_id, r.credential_id AS credential_id,
                        r.redeemed_at AS redeemed_at",
                Params::default().with("id", uuid(&id.0)),
            )?;
            let mut redemptions = Vec::with_capacity(rows.len());
            for row in &rows {
                // A credential deleted since names nothing.
                let credential_id = match get_opt_uuid(row, "credential_id")? {
                    Some(c) if super::credential::exists(tx, CredentialId(c))? => {
                        Some(CredentialId(c))
                    }
                    _ => None,
                };
                redemptions.push(InviteRedemption {
                    profile_id: get_id(row, "profile_id")?,
                    credential_id,
                    redeemed_at: get_time(row, "redeemed_at")?,
                });
            }
            Ok(sorted_page(
                redemptions,
                |r| (r.redeemed_at, r.profile_id),
                offset,
                limit,
            ))
        })
        .await
    }

    pub(super) async fn try_use_invite(
        &self,
        id: InviteId,
        ctx: MutationContext,
    ) -> SidResult<Option<Invite>> {
        self.transaction(move |tx| {
            // No use, nothing recorded.
            let Some(used) = spend(tx, "i.id = $value", uuid(&id.0))? else {
                return Ok(Decision::Abandon(None));
            };
            finalize(tx, &format!("invite:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(Some(used)))
        })
        .await
    }

    pub(super) async fn revoke_invite(&self, id: InviteId, ctx: MutationContext) -> SidResult<()> {
        self.mutate(format!("invite:{}", id.0), ctx, move |tx| {
            tx.run(
                "MATCH (i:SidInvite) WHERE i.id = $id SET i.active = false",
                Params::default().with("id", uuid(&id.0)),
            )?;
            Ok(())
        })
        .await
    }

    // === Registration sources ===

    pub(super) async fn get_registration_source(
        &self,
        profile: ProfileId,
    ) -> SidResult<Option<RegistrationSource>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (s:SidRegistrationSource) WHERE s.profile_id = $id RETURN {SOURCE}"
                ),
                Params::default().with("id", bin(profile.as_bytes())),
            )?;
            rows.first().map(source).transpose()
        })
        .await
    }

    pub(super) async fn count_registrations_by_source(
        &self,
        since: DateTime<Utc>,
    ) -> SidResult<Vec<(RegistrationSourceType, u64)>> {
        let sources = self.read(move |tx| sources_since(tx, since)).await?;
        let mut counts =
            std::collections::BTreeMap::<&'static str, (RegistrationSourceType, u64)>::new();
        for s in sources {
            counts
                .entry(s.source_type.as_str())
                .or_insert((s.source_type, 0))
                .1 += 1;
        }
        Ok(counts.into_values().collect())
    }

    pub(super) async fn top_referrers(
        &self,
        since: DateTime<Utc>,
        limit: u64,
    ) -> SidResult<Vec<(ProfileId, u64)>> {
        let sources = self.read(move |tx| sources_since(tx, since)).await?;
        let mut counts = std::collections::BTreeMap::<ProfileId, u64>::new();
        for referrer in sources.iter().filter_map(|s| s.referrer_id) {
            *counts.entry(referrer).or_default() += 1;
        }
        // Most referrals first, then by id.
        Ok(sorted_page(
            counts.into_iter().collect(),
            |(id, n)| (std::cmp::Reverse(*n), *id),
            0,
            limit,
        ))
    }
}
