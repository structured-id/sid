// SPDX-License-Identifier: AGPL-3.0-only
//! Principals and the claims Profiles hold on them, in CoordiNode. A
//! principal is one `SidPrincipal` node, unique by type and value; each
//! claim a `SidPrincipalBinding` node, unique by principal and Profile.
//! Every claim change rewrites its principal's `claims` count, so concurrent
//! changes of one principal conflict: a login handle checked unheld cannot
//! be taken by another Profile in between, and the last claim's removal
//! cannot race a new claim.
//!
//! An email key is written only under the installation's active email
//! policy revision, held for the transaction that writes it.

use coordinode_core::graph::types::Value;
use sid_core::models::{
    EmailKeyDisposition, EmailKeyOutcome, EmailPolicyActivation, MutationContext, Principal,
    PrincipalBinding, PrincipalBindingId, PrincipalEntity, PrincipalId, PrincipalType, Profile,
    ProfileEmail, ProfileEmailId, ProfileId, ProfilePhoneId, QuarantinedPrincipal, StoredPrincipal,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_count, get_id,
    get_int, get_opt_int, get_opt_text, get_opt_time, get_opt_uuid, get_text, get_time, get_uuid,
    key, opt_text, opt_time, opt_uuid, profile, profile::profile_value, time, uuid,
};

const ENTITY: &str = "p.id AS id, p.principal_type AS principal_type, p.value AS value,
    p.verified AS verified, p.verified_at AS verified_at,
    p.verification_expires AS verification_expires,
    p.assigned_profile_id AS assigned_profile_id, p.assignment_revision AS assignment_revision,
    p.email_policy_revision AS email_policy_revision, p.created_at AS created_at,
    p.updated_at AS updated_at";

const BINDING: &str = "b.id AS b_id, b.principal_id AS b_principal_id,
    b.profile_id AS b_profile_id, b.is_primary AS b_is_primary,
    b.source_field AS b_source_field, b.source_email_id AS b_source_email_id,
    b.source_phone_id AS b_source_phone_id, b.created_at AS b_created_at";

/// The scope the installation's email policy revision is recorded under.
const EMAIL_POLICY_SCOPE: &str = "installation";

fn type_value_key(principal_type: PrincipalType, value: &str) -> SidResult<Value> {
    key(&[principal_type.as_str().as_bytes(), value.as_bytes()])
}

fn pair_key(principal: &uuid::Uuid, profile: ProfileId) -> SidResult<Value> {
    key(&[principal.as_bytes(), profile.as_bytes()])
}

fn opt_profile_of(row: &Row, name: &str) -> SidResult<Option<ProfileId>> {
    get_opt_uuid(row, name)?
        .map(ProfileId::from_uuid)
        .transpose()
        .map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

fn entity(row: &Row) -> SidResult<PrincipalEntity> {
    Ok(PrincipalEntity {
        id: PrincipalId(get_uuid(row, "id")?),
        principal_type: get_text(row, "principal_type")?
            .parse()
            .map_err(|e| SidError::Storage(format!("principal: {e}")))?,
        value: get_text(row, "value")?,
        verified: get_bool(row, "verified")?,
        verified_at: get_opt_time(row, "verified_at")?,
        verification_expires: get_opt_time(row, "verification_expires")?,
        assigned_profile_id: opt_profile_of(row, "assigned_profile_id")?,
        assignment_revision: get_int(row, "assignment_revision")?,
        email_policy_revision: get_opt_int(row, "email_policy_revision")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn binding(row: &Row) -> SidResult<PrincipalBinding> {
    Ok(PrincipalBinding {
        id: PrincipalBindingId(get_uuid(row, "b_id")?),
        principal_id: PrincipalId(get_uuid(row, "b_principal_id")?),
        profile_id: get_id(row, "b_profile_id")?,
        is_primary: get_bool(row, "b_is_primary")?,
        source_field: get_opt_text(row, "b_source_field")?,
        source_email_id: get_opt_uuid(row, "b_source_email_id")?.map(ProfileEmailId),
        source_phone_id: get_opt_uuid(row, "b_source_phone_id")?.map(ProfilePhoneId),
        created_at: get_time(row, "b_created_at")?,
    })
}

/// The principal as the Profile holding `claim` sees it.
fn claimed(entity: PrincipalEntity, claim: &PrincipalBinding) -> Principal {
    Principal {
        id: entity.id,
        profile_id: claim.profile_id,
        principal_type: entity.principal_type,
        value: entity.value,
        verified: entity.verified,
        verified_at: entity.verified_at,
        verification_expires: entity.verification_expires,
        assigned_profile_id: entity.assigned_profile_id,
        assignment_revision: entity.assignment_revision,
        email_policy_revision: entity.email_policy_revision,
        is_primary: claim.is_primary,
        source_field: claim.source_field.clone(),
        source_email_id: claim.source_email_id,
        source_phone_id: claim.source_phone_id,
        created_at: entity.created_at,
        updated_at: entity.updated_at,
    }
    .as_seen_by_subject()
}

/// Create the installation's email policy revision of an empty store.
pub(super) fn init_email_policy(tx: &Statements<'_>) -> SidResult<Decision<()>> {
    let stored = tx.run(
        "MATCH (a:SidEmailPolicy) WHERE a.scope = $scope RETURN a.revision AS revision",
        Params::default().with("scope", Value::String(EMAIL_POLICY_SCOPE.into())),
    )?;
    if !stored.is_empty() {
        return Ok(Decision::Abandon(()));
    }
    tx.run(
        "CREATE (a:SidEmailPolicy {scope: $scope, revision: 1, activated_at: $now})",
        Params::default()
            .with("scope", Value::String(EMAIL_POLICY_SCOPE.into()))
            .with("now", time(chrono::Utc::now())),
    )?;
    Ok(Decision::Commit(()))
}

/// The active email policy revision, held for the open transaction: a key
/// written under it commits only while it stays active.
fn active_email_revision(tx: &Statements<'_>) -> SidResult<i64> {
    let rows = tx.run(
        "MATCH (a:SidEmailPolicy) WHERE a.scope = $scope
         RETURN id(a) AS node, a.revision AS revision",
        Params::default().with("scope", Value::String(EMAIL_POLICY_SCOPE.into())),
    )?;
    let row = rows
        .first()
        .ok_or_else(|| SidError::Storage("email policy revision missing".into()))?;
    if !tx.hold(get_int(row, "node")?)? {
        return Err(SidError::Storage("email policy revision vanished".into()));
    }
    get_int(row, "revision")
}

/// Refuse a principal whose email key is not under the active revision, or
/// another type that names one.
fn check_email_fence(
    tx: &Statements<'_>,
    principal_type: PrincipalType,
    revision: Option<i64>,
) -> SidResult<()> {
    let fenced = match (principal_type == PrincipalType::Email, revision) {
        (true, Some(revision)) => revision != active_email_revision(tx)?,
        (false, None) => false,
        _ => true,
    };
    if fenced {
        return Err(SidError::Fenced(
            "principal: email key not under the active policy revision".into(),
        ));
    }
    Ok(())
}

/// The principal of `principal_type` and `value`, read in `tx`.
pub(super) fn by_value(
    tx: &Statements<'_>,
    principal_type: PrincipalType,
    value: &str,
) -> SidResult<Option<PrincipalEntity>> {
    let rows = tx.run(
        &format!("MATCH (p:SidPrincipal) WHERE p.type_value = $key RETURN {ENTITY}"),
        Params::default().with("key", type_value_key(principal_type, value)?),
    )?;
    rows.first().map(entity).transpose()
}

fn by_id(tx: &Statements<'_>, id: PrincipalId) -> SidResult<Option<PrincipalEntity>> {
    let rows = tx.run(
        &format!("MATCH (p:SidPrincipal) WHERE p.id = $id RETURN {ENTITY}"),
        Params::default().with("id", uuid(&id.0)),
    )?;
    rows.first().map(entity).transpose()
}

fn bindings_of(tx: &Statements<'_>, id: PrincipalId) -> SidResult<Vec<PrincipalBinding>> {
    let rows = tx.run(
        &format!("MATCH (b:SidPrincipalBinding) WHERE b.principal_id = $id RETURN {BINDING}"),
        Params::default().with("id", uuid(&id.0)),
    )?;
    let all = rows.iter().map(binding).collect::<SidResult<Vec<_>>>()?;
    Ok(super::sorted_page(
        all,
        |b| (b.created_at, b.id.0),
        0,
        u64::MAX,
    ))
}

fn claim_of(
    tx: &Statements<'_>,
    id: PrincipalId,
    holder: ProfileId,
) -> SidResult<Option<PrincipalBinding>> {
    let rows = tx.run(
        &format!("MATCH (b:SidPrincipalBinding) WHERE b.pair = $pair RETURN {BINDING}"),
        Params::default().with("pair", pair_key(&id.0, holder)?),
    )?;
    rows.first().map(binding).transpose()
}

/// Record the number of claims `id` holds now: every claim change writes
/// its principal, so concurrent changes of one principal conflict.
fn count_claims(tx: &Statements<'_>, id: PrincipalId) -> SidResult<u64> {
    let claims = get_count(&tx.run(
        "MATCH (b:SidPrincipalBinding) WHERE b.principal_id = $id RETURN count(b) AS n",
        Params::default().with("id", uuid(&id.0)),
    )?)?;
    tx.run(
        "MATCH (p:SidPrincipal) WHERE p.id = $id SET p.claims = $claims",
        Params::default().with("id", uuid(&id.0)).with(
            "claims",
            Value::Int(i64::try_from(claims).map_err(|_| SidError::Storage("claims".into()))?),
        ),
    )?;
    Ok(claims)
}

/// Record `p`'s claim in `tx`: a value never used before is created and
/// assigned to the claimant with the proof `p` carries; an existing one
/// gains the claim and keeps its assignment and proof. A login handle is
/// never shared: held by another Profile it is `Conflict`.
pub(super) fn bind(tx: &Statements<'_>, p: &Principal) -> SidResult<PrincipalId> {
    let id = match by_value(tx, p.principal_type, &p.value)? {
        Some(existing) => existing.id,
        None => {
            check_email_fence(tx, p.principal_type, p.email_policy_revision)?;
            tx.run(
                "CREATE (p:SidPrincipal {id: $id, type_value: $key, principal_type: $type,
                    value: $value, verified: $verified, verified_at: $verified_at,
                    verification_expires: $expires, assigned_profile_id: $assigned,
                    assignment_revision: 1, email_policy_revision: $email_revision,
                    claims: 0, created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", uuid(&p.id.0))
                    .with("key", type_value_key(p.principal_type, &p.value)?)
                    .with("type", Value::String(p.principal_type.as_str().into()))
                    .with("value", Value::String(p.value.clone()))
                    .with("verified", Value::Bool(p.verified))
                    .with("verified_at", opt_time(p.verified_at))
                    .with("expires", opt_time(p.verification_expires))
                    .with("assigned", profile_value(p.profile_id))
                    .with(
                        "email_revision",
                        p.email_policy_revision.map_or(Value::Null, Value::Int),
                    )
                    .with("created_at", time(p.created_at))
                    .with("updated_at", time(p.updated_at)),
            )?;
            p.id
        }
    };
    if !p.principal_type.is_contestable()
        && bindings_of(tx, id)?
            .iter()
            .any(|b| b.profile_id != p.profile_id)
    {
        return Err(SidError::Conflict("login handle already exists".into()));
    }
    let params = Params::default()
        .with("pair", pair_key(&id.0, p.profile_id)?)
        .with("is_primary", Value::Bool(p.is_primary))
        .with("source_field", opt_text(p.source_field.as_deref()))
        .with(
            "source_email_id",
            opt_uuid(p.source_email_id.as_ref().map(|e| &e.0)),
        )
        .with(
            "source_phone_id",
            opt_uuid(p.source_phone_id.as_ref().map(|e| &e.0)),
        );
    let updated = tx.run(
        "MATCH (b:SidPrincipalBinding) WHERE b.pair = $pair
         SET b.is_primary = $is_primary, b.source_field = $source_field,
             b.source_email_id = $source_email_id, b.source_phone_id = $source_phone_id
         RETURN b.id AS id",
        params.clone(),
    )?;
    if updated.is_empty() {
        tx.run(
            "CREATE (b:SidPrincipalBinding {id: $binding, pair: $pair, principal_id: $principal,
                profile_id: $profile, is_primary: $is_primary, source_field: $source_field,
                source_email_id: $source_email_id, source_phone_id: $source_phone_id,
                created_at: $created_at})",
            params
                .with("binding", uuid(&uuid::Uuid::now_v7()))
                .with("principal", uuid(&id.0))
                .with("profile", profile_value(p.profile_id))
                .with("created_at", time(p.created_at)),
        )?;
    }
    count_claims(tx, id)?;
    Ok(id)
}

/// Remove `holder`'s claim on `id` in `tx`; the principal goes with its last
/// claim. The assigned Profile releasing its claim clears the assignment and
/// its proof without electing another claimant. False when there was no
/// such claim.
pub(super) fn unbind(tx: &Statements<'_>, id: PrincipalId, holder: ProfileId) -> SidResult<bool> {
    let removed = tx.run(
        "MATCH (b:SidPrincipalBinding) WHERE b.pair = $pair DETACH DELETE b RETURN count(*) AS n",
        Params::default().with("pair", pair_key(&id.0, holder)?),
    )?;
    if get_count(&removed)? == 0 {
        return Ok(false);
    }
    if count_claims(tx, id)? == 0 {
        for query in [
            "MATCH (d:SidEmailDisposition) WHERE d.principal_id = $id DETACH DELETE d",
            "MATCH (p:SidPrincipal) WHERE p.id = $id DETACH DELETE p",
        ] {
            tx.run(query, Params::default().with("id", uuid(&id.0)))?;
        }
        return Ok(true);
    }
    tx.run(
        "MATCH (p:SidPrincipal) WHERE p.id = $id AND p.assigned_profile_id = $holder
         SET p.assigned_profile_id = null, p.assignment_revision = p.assignment_revision + 1,
             p.verified = false, p.verified_at = null, p.verification_expires = null,
             p.updated_at = $now",
        Params::default()
            .with("id", uuid(&id.0))
            .with("holder", profile_value(holder))
            .with("now", time(chrono::Utc::now())),
    )?;
    Ok(true)
}

/// The principals `holder` claims, as it holds each, oldest claim first.
pub(super) fn held_by(tx: &Statements<'_>, holder: ProfileId) -> SidResult<Vec<Principal>> {
    let rows = tx.run(
        &format!("MATCH (b:SidPrincipalBinding) WHERE b.profile_id = $holder RETURN {BINDING}"),
        Params::default().with("holder", profile_value(holder)),
    )?;
    let claims = rows.iter().map(binding).collect::<SidResult<Vec<_>>>()?;
    let claims = super::sorted_page(claims, |b| (b.created_at, b.id.0), 0, u64::MAX);
    let mut principals = Vec::with_capacity(claims.len());
    for claim in &claims {
        if let Some(entity) = by_id(tx, claim.principal_id)? {
            principals.push(claimed(entity, claim));
        }
    }
    Ok(principals)
}

/// `holder`'s claim on `id` as it holds it in `tx`.
fn as_held(tx: &Statements<'_>, id: PrincipalId, holder: ProfileId) -> SidResult<Principal> {
    let entity = by_id(tx, id)?.ok_or_else(|| SidError::Storage("principal vanished".into()))?;
    let claim =
        claim_of(tx, id, holder)?.ok_or_else(|| SidError::Storage("claim vanished".into()))?;
    Ok(claimed(entity, &claim))
}

impl CoordinodeBackend {
    pub(super) async fn get_principal(&self, id: PrincipalId) -> SidResult<Option<Principal>> {
        self.transaction(move |tx| {
            let Some(entity) = by_id(tx, id)? else {
                return Ok(Decision::Abandon(None));
            };
            // As its first claimant sees it; a principal goes with its last
            // claim, so a stored one has one.
            let claim = bindings_of(tx, id)?
                .into_iter()
                .next()
                .ok_or_else(|| SidError::Storage("principal without a claim".into()))?;
            Ok(Decision::Abandon(Some(claimed(entity, &claim))))
        })
        .await
    }

    pub(super) async fn get_principals_by_profile(
        &self,
        holder: ProfileId,
    ) -> SidResult<Vec<Principal>> {
        self.read(move |tx| held_by(tx, holder)).await
    }

    pub(super) async fn get_profile_by_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<Profile>> {
        let value = value.to_owned();
        self.transaction(move |tx| {
            // The assigned Profile, while it still holds its claim; a claim
            // alone resolves nobody.
            let Some(entity) = by_value(tx, principal_type, &value)? else {
                return Ok(Decision::Abandon(None));
            };
            let Some(assigned) = entity.assigned_profile_id else {
                return Ok(Decision::Abandon(None));
            };
            if claim_of(tx, entity.id, assigned)?.is_none() {
                return Ok(Decision::Abandon(None));
            }
            Ok(Decision::Abandon(profile::get(tx, assigned)?))
        })
        .await
    }

    pub(super) async fn save_principal(
        &self,
        p: &Principal,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let p = p.clone();
        self.transaction(move |tx| {
            let id = bind(tx, &p)?;
            let mut ctx = ctx.clone();
            if ctx.operation.is_some() {
                // The holder's claim as stored: its id is the principal's,
                // which an earlier holder may have created.
                ctx.record_effect(&as_held(tx, id, p.profile_id)?)?;
            }
            finalize(tx, &format!("principal:{}", p.id.0), ctx)?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn unbind_principal(
        &self,
        id: PrincipalId,
        holder: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            if !unbind(tx, id, holder)? {
                return Ok(Decision::Abandon(false));
            }
            finalize(
                tx,
                &format!("principal_binding:{}:{holder}", id.0),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn count_active_principal_bindings(&self, id: PrincipalId) -> SidResult<i64> {
        self.transaction(move |tx| {
            let mut active = 0i64;
            for claim in bindings_of(tx, id)? {
                if profile::get(tx, claim.profile_id)?
                    .is_some_and(|p| p.status == sid_core::models::ProfileStatus::Active)
                {
                    // At most the claims of one principal: far inside i64.
                    active += 1;
                }
            }
            Ok(Decision::Abandon(active))
        })
        .await
    }

    pub(super) async fn get_principal_bindings(
        &self,
        id: PrincipalId,
    ) -> SidResult<Vec<PrincipalBinding>> {
        self.transaction(move |tx| bindings_of(tx, id).map(Decision::Abandon))
            .await
    }

    pub(super) async fn get_principal_by_value(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<PrincipalEntity>> {
        let value = value.to_owned();
        self.transaction(move |tx| by_value(tx, principal_type, &value).map(Decision::Abandon))
            .await
    }

    pub(super) async fn expire_principal_verifications(&self) -> SidResult<i64> {
        self.transaction(|tx| {
            let now = chrono::Utc::now();
            let rows = tx.run(
                "MATCH (p:SidPrincipal) WHERE p.verified = true
                   AND p.verification_expires IS NOT NULL AND p.verification_expires < $now
                 SET p.verified = false, p.updated_at = $now
                 RETURN count(*) AS n",
                Params::default().with("now", time(now)),
            )?;
            let expired = i64::try_from(get_count(&rows)?)
                .map_err(|_| SidError::Storage("expired count".into()))?;
            Ok(if expired == 0 {
                Decision::Abandon(0)
            } else {
                Decision::Commit(expired)
            })
        })
        .await
    }

    pub(super) async fn reconcile_email_key(
        &self,
        id: PrincipalId,
        holder: ProfileId,
        contact: &ProfileEmail,
        reason: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if contact.profile_id != holder {
            return Err(SidError::Validation(
                "the evidence is a contact of another profile".into(),
            ));
        }
        let (contact, reason) = (contact.clone(), reason.to_owned());
        self.transaction(move |tx| {
            // The key leaves quarantine only while it still is quarantined
            // and assigned to this profile.
            let Some(entity) = by_id(tx, id)? else {
                return Ok(Decision::Abandon(false));
            };
            let quarantined = !tx
                .run(
                    "MATCH (d:SidEmailDisposition) WHERE d.principal_id = $id
                       AND d.disposition = 'quarantined'
                     RETURN d.principal_id AS id",
                    Params::default().with("id", uuid(&id.0)),
                )?
                .is_empty();
            if entity.principal_type != PrincipalType::Email
                || entity.assigned_profile_id != Some(holder)
                || !quarantined
            {
                return Ok(Decision::Abandon(false));
            }
            let active = active_email_revision(tx)?;
            let now = time(chrono::Utc::now());
            tx.run(
                "MATCH (p:SidPrincipal) WHERE p.id = $id
                 SET p.email_policy_revision = $revision, p.updated_at = $now",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("revision", Value::Int(active))
                    .with("now", now.clone()),
            )?;
            super::profile::claim_profile(tx, holder)?;
            super::profile::upsert_email(tx, &contact)?;
            tx.run(
                "MATCH (b:SidPrincipalBinding) WHERE b.pair = $pair
                 SET b.source_field = 'email', b.source_email_id = $email",
                Params::default()
                    .with("pair", pair_key(&id.0, holder)?)
                    .with("email", uuid(&contact.id.0)),
            )?;
            tx.run(
                "MATCH (d:SidEmailDisposition) WHERE d.principal_id = $id
                 SET d.to_revision = $revision, d.disposition = 'migrated', d.reason = $reason,
                     d.recorded_at = $now",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("revision", Value::Int(active))
                    .with("reason", Value::String(reason.clone()))
                    .with("now", now),
            )?;
            let mut ctx = ctx.clone();
            if ctx.operation.is_some() {
                ctx.record_effect(&as_held(tx, id, holder)?)?;
            }
            finalize(tx, &format!("principal:{}", id.0), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Quarantine ===

    pub(super) async fn quarantine_principal(
        &self,
        hash: &str,
        principal_type: &str,
        until: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let (hash, principal_type) = (hash.to_owned(), principal_type.to_owned());
        self.mutate("quarantine".to_owned(), ctx, move |tx| {
            let params = Params::default()
                .with("hash", Value::String(hash.clone()))
                .with("until", time(until));
            let updated = tx.run(
                "MATCH (q:SidPrincipalQuarantine) WHERE q.hash = $hash
                 SET q.until = $until RETURN q.hash AS hash",
                params.clone(),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (q:SidPrincipalQuarantine {hash: $hash, principal_type: $type,
                        until: $until, created_at: $now})",
                    params
                        .with("type", Value::String(principal_type.clone()))
                        .with("now", time(chrono::Utc::now())),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn is_principal_quarantined(&self, hash: &str) -> SidResult<bool> {
        let hash = hash.to_owned();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (q:SidPrincipalQuarantine) WHERE q.hash = $hash AND q.until > $now
                 RETURN q.hash AS hash",
                Params::default()
                    .with("hash", Value::String(hash.clone()))
                    .with("now", time(chrono::Utc::now())),
            )?;
            Ok(Decision::Abandon(!rows.is_empty()))
        })
        .await
    }

    pub(super) async fn cleanup_expired_quarantine(&self, ctx: MutationContext) -> SidResult<u64> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (q:SidPrincipalQuarantine) WHERE q.until <= $now
                 DETACH DELETE q RETURN count(*) AS n",
                Params::default().with("now", time(chrono::Utc::now())),
            )?;
            let removed = get_count(&rows)?;
            if removed == 0 && ctx.work.is_empty() && ctx.operation.is_none() {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, "quarantine:cleanup", ctx.clone())?;
            Ok(Decision::Commit(removed))
        })
        .await
    }

    // === Moving principals ===

    pub(super) async fn export_principals(
        &self,
        after: Option<PrincipalId>,
        limit: u32,
    ) -> SidResult<Vec<StoredPrincipal>> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (p:SidPrincipal) RETURN p.id AS id",
                Params::default(),
            )?;
            let mut ids = rows
                .iter()
                .map(|r| get_uuid(r, "id"))
                .collect::<SidResult<Vec<_>>>()?;
            ids.sort();
            let mut principals = Vec::new();
            for id in ids
                .into_iter()
                .filter(|id| after.is_none_or(|a| *id > a.0))
                .take(limit as usize)
            {
                if let Some(principal) = stored(tx, PrincipalId(id))? {
                    principals.push(principal);
                }
            }
            Ok(Decision::Abandon(principals))
        })
        .await
    }

    pub(super) async fn import_principal(
        &self,
        principal: &StoredPrincipal,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if principal
            .claims
            .iter()
            .any(|c| c.principal_id != principal.entity.id)
        {
            return Err(SidError::Validation(
                "a claim names another principal than the one it moves with".into(),
            ));
        }
        let mut given = principal.clone();
        given.claims.sort_by_key(|c| c.id.0);
        self.transaction(move |tx| {
            match stored(tx, given.entity.id)? {
                Some(held) if held == given => return Ok(Decision::Abandon(false)),
                Some(_) => {
                    return Err(SidError::Conflict(format!(
                        "another principal {} is stored",
                        given.entity.id.0
                    )));
                }
                None => {}
            }
            let e = &given.entity;
            if by_value(tx, e.principal_type, &e.value)?.is_some() {
                return Err(SidError::Conflict(
                    "another principal holds the same value".into(),
                ));
            }
            if e.email_policy_revision.is_some()
                && e.email_policy_revision != Some(active_email_revision(tx)?)
            {
                return Err(SidError::Conflict(
                    "the email key was written under another policy revision".into(),
                ));
            }
            tx.run(
                "CREATE (p:SidPrincipal {id: $id, type_value: $key, principal_type: $type,
                    value: $value, verified: $verified, verified_at: $verified_at,
                    verification_expires: $expires, assigned_profile_id: $assigned,
                    assignment_revision: $revision, email_policy_revision: $email_revision,
                    claims: 0, created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", uuid(&e.id.0))
                    .with("key", type_value_key(e.principal_type, &e.value)?)
                    .with("type", Value::String(e.principal_type.as_str().into()))
                    .with("value", Value::String(e.value.clone()))
                    .with("verified", Value::Bool(e.verified))
                    .with("verified_at", opt_time(e.verified_at))
                    .with("expires", opt_time(e.verification_expires))
                    .with(
                        "assigned",
                        e.assigned_profile_id.map_or(Value::Null, profile_value),
                    )
                    .with("revision", Value::Int(e.assignment_revision))
                    .with(
                        "email_revision",
                        e.email_policy_revision.map_or(Value::Null, Value::Int),
                    )
                    .with("created_at", time(e.created_at))
                    .with("updated_at", time(e.updated_at)),
            )?;
            for claim in &given.claims {
                // The claiming Profile is held: its removal takes its claims.
                super::profile::claim_profile(tx, claim.profile_id)?;
                tx.run(
                    "CREATE (b:SidPrincipalBinding {id: $binding, pair: $pair,
                        principal_id: $principal, profile_id: $profile, is_primary: $is_primary,
                        source_field: $source_field, source_email_id: $source_email_id,
                        source_phone_id: $source_phone_id, created_at: $created_at})",
                    Params::default()
                        .with("binding", uuid(&claim.id.0))
                        .with("pair", pair_key(&e.id.0, claim.profile_id)?)
                        .with("principal", uuid(&e.id.0))
                        .with("profile", profile_value(claim.profile_id))
                        .with("is_primary", Value::Bool(claim.is_primary))
                        .with("source_field", opt_text(claim.source_field.as_deref()))
                        .with(
                            "source_email_id",
                            opt_uuid(claim.source_email_id.as_ref().map(|i| &i.0)),
                        )
                        .with(
                            "source_phone_id",
                            opt_uuid(claim.source_phone_id.as_ref().map(|i| &i.0)),
                        )
                        .with("created_at", time(claim.created_at)),
                )?;
            }
            count_claims(tx, e.id)?;
            if let Some(d) = &given.disposition {
                tx.run(
                    "CREATE (d:SidEmailDisposition {principal_id: $id, from_revision: $from,
                        to_revision: $to, disposition: $disposition, reason: $reason,
                        recorded_at: $at})",
                    Params::default()
                        .with("id", uuid(&e.id.0))
                        .with("from", Value::Int(d.from_revision))
                        .with("to", Value::Int(d.to_revision))
                        .with(
                            "disposition",
                            Value::String(disposition_text(d.outcome).into()),
                        )
                        .with("reason", Value::String(d.reason.clone()))
                        .with("at", time(d.recorded_at)),
                )?;
            }
            finalize(tx, &format!("principal:{}", e.id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn email_policy_activation(&self) -> SidResult<EmailPolicyActivation> {
        self.transaction(move |tx| Ok(Decision::Abandon(activation(tx)?)))
            .await
    }

    pub(super) async fn import_email_policy_activation(
        &self,
        given: &EmailPolicyActivation,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let given = *given;
        self.transaction(move |tx| {
            // Held, as every email key write holds it.
            active_email_revision(tx)?;
            if activation(tx)? == given {
                return Ok(Decision::Abandon(false));
            }
            let keys = get_count(&tx.run(
                "MATCH (p:SidPrincipal) WHERE p.principal_type = 'email' RETURN count(p) AS n",
                Params::default(),
            )?)?;
            if keys > 0 {
                return Err(SidError::Conflict(
                    "email keys are stored under another policy revision".into(),
                ));
            }
            tx.run(
                "MATCH (a:SidEmailPolicy) WHERE a.scope = $scope
                 SET a.revision = $revision, a.activated_at = $at",
                Params::default()
                    .with("scope", Value::String(EMAIL_POLICY_SCOPE.into()))
                    .with("revision", Value::Int(given.revision))
                    .with("at", time(given.activated_at)),
            )?;
            finalize(tx, "email_policy", ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn export_principal_quarantine(&self) -> SidResult<Vec<QuarantinedPrincipal>> {
        self.transaction(move |tx| {
            let mut entries = tx
                .run(
                    &format!("MATCH (q:SidPrincipalQuarantine) RETURN {QUARANTINE}"),
                    Params::default(),
                )?
                .iter()
                .map(quarantined)
                .collect::<SidResult<Vec<_>>>()?;
            entries.sort_by(|a, b| a.principal_hash.cmp(&b.principal_hash));
            Ok(Decision::Abandon(entries))
        })
        .await
    }

    pub(super) async fn import_principal_quarantine(
        &self,
        entry: &QuarantinedPrincipal,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let entry = entry.clone();
        self.transaction(move |tx| {
            let held = tx
                .run(
                    &format!(
                        "MATCH (q:SidPrincipalQuarantine) WHERE q.hash = $hash RETURN {QUARANTINE}"
                    ),
                    Params::default().with("hash", Value::String(entry.principal_hash.clone())),
                )?
                .first()
                .map(quarantined)
                .transpose()?;
            match held {
                Some(held) if held == entry => return Ok(Decision::Abandon(false)),
                Some(_) => {
                    return Err(SidError::Conflict(
                        "another quarantine entry of the same principal is stored".into(),
                    ));
                }
                None => {}
            }
            tx.run(
                "CREATE (q:SidPrincipalQuarantine {hash: $hash, principal_type: $type,
                    until: $until, created_at: $created_at})",
                Params::default()
                    .with("hash", Value::String(entry.principal_hash.clone()))
                    .with("type", Value::String(entry.principal_type.clone()))
                    .with("until", time(entry.until))
                    .with("created_at", time(entry.created_at)),
            )?;
            finalize(tx, "quarantine", ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}

const QUARANTINE: &str = "q.hash AS hash, q.principal_type AS principal_type, q.until AS until,
    q.created_at AS created_at";

fn quarantined(row: &Row) -> SidResult<QuarantinedPrincipal> {
    Ok(QuarantinedPrincipal {
        principal_hash: get_text(row, "hash")?,
        principal_type: get_text(row, "principal_type")?,
        until: get_time(row, "until")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn disposition_text(outcome: EmailKeyOutcome) -> &'static str {
    match outcome {
        EmailKeyOutcome::Migrated => "migrated",
        EmailKeyOutcome::Quarantined => "quarantined",
    }
}

/// The installation's email policy activation, read in `tx`.
fn activation(tx: &Statements<'_>) -> SidResult<EmailPolicyActivation> {
    let rows = tx.run(
        "MATCH (a:SidEmailPolicy) WHERE a.scope = $scope
         RETURN a.revision AS revision, a.activated_at AS activated_at",
        Params::default().with("scope", Value::String(EMAIL_POLICY_SCOPE.into())),
    )?;
    let row = rows
        .first()
        .ok_or_else(|| SidError::Storage("email policy revision missing".into()))?;
    Ok(EmailPolicyActivation {
        revision: get_int(row, "revision")?,
        activated_at: get_time(row, "activated_at")?,
    })
}

/// Principal `id` as stored, read in `tx`.
fn stored(tx: &Statements<'_>, id: PrincipalId) -> SidResult<Option<StoredPrincipal>> {
    let Some(entity) = by_id(tx, id)? else {
        return Ok(None);
    };
    let mut claims = bindings_of(tx, id)?;
    claims.sort_by_key(|c| c.id.0);
    let disposition = tx
        .run(
            "MATCH (d:SidEmailDisposition) WHERE d.principal_id = $id
             RETURN d.from_revision AS from_revision, d.to_revision AS to_revision,
                    d.disposition AS disposition, d.reason AS reason,
                    d.recorded_at AS recorded_at",
            Params::default().with("id", uuid(&id.0)),
        )?
        .first()
        .map(|row| {
            Ok::<_, SidError>(EmailKeyDisposition {
                from_revision: get_int(row, "from_revision")?,
                to_revision: get_int(row, "to_revision")?,
                outcome: match get_text(row, "disposition")?.as_str() {
                    "migrated" => EmailKeyOutcome::Migrated,
                    "quarantined" => EmailKeyOutcome::Quarantined,
                    other => {
                        return Err(SidError::Storage(format!("disposition: unknown {other}")));
                    }
                },
                reason: get_text(row, "reason")?,
                recorded_at: get_time(row, "recorded_at")?,
            })
        })
        .transpose()?;
    Ok(Some(StoredPrincipal {
        entity,
        claims,
        disposition,
    }))
}
