// SPDX-License-Identifier: AGPL-3.0-only
//! Sessions, refresh tokens, authorization codes and native session
//! generations in CoordiNode.
//!
//! A session created under the profile's limit writes the profile's
//! `session_turn`: concurrent sign-ins of one profile meet there, so the
//! count they evict by is exact, and a status change committed meanwhile
//! conflicts with them, so a suspended account gets no session. What a
//! sign-in proved (a credential, an assignment) is held for the commit.
//! Redeeming a code, rotating a refresh token or a native generation
//! writes its node: of concurrent attempts one commits, the others run
//! again on what it left. Ending a session takes the sessions it
//! authenticated, its refresh tokens, its codes and its native generations
//! with it.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::session::{Elevation, SECOND_FACTOR_SCOPE};
use sid_core::models::{
    AuthCodeRedemption, AuthLevel, AuthorizationCode, BrowserCsrfToken, BrowserSecretHash,
    GrantAuthentication, MutationContext, NativeExchange, NativeGeneration, NativeGenerationState,
    NativePresented, NativeRotation, NativeRotationOutcome, ProfileId, RefreshToken,
    RevocationReason, Session, SessionAuthentication, SessionEnd, SessionId, SignInProof,
};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::audit::{ip_of, ip_value};
use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_count, get_id, get_int, get_opt_bytes, get_opt_id, get_opt_text, get_opt_time,
    get_opt_uuid, get_text, get_texts, get_time, get_uuid, opt_text, opt_time, opt_uuid,
    profile::profile_value, texts, time, uuid,
};

const SESSION: &str = "s.id AS id, s.profile_id AS profile_id, s.client_id AS client_id,
    s.device_id AS device_id, s.ip AS ip, s.user_agent AS user_agent, s.scopes AS scopes,
    s.assurance_level AS assurance_level, s.elevation_level AS elevation_level,
    s.elevation_until AS elevation_until, s.is_provisional AS is_provisional,
    s.passkey_prompt AS passkey_prompt, s.authenticated_at AS authenticated_at, s.amr AS amr,
    s.policy_grace AS policy_grace, s.grace_deadline AS grace_deadline,
    s.created_at AS created_at, s.expires_at AS expires_at,
    s.last_activity_at AS last_activity_at, s.browser_secret_hash AS browser_secret_hash,
    s.browser_csrf AS browser_csrf, s.authenticated_by AS authenticated_by";

const TOKEN: &str = "t.id AS id, t.token_hash AS token_hash, t.session_id AS session_id,
    t.profile_id AS profile_id, t.client_id AS client_id, t.scopes AS scopes,
    t.resource_id AS resource_id, t.expires_at AS expires_at, t.created_at AS created_at,
    t.revoked AS revoked, t.replaced_by AS replaced_by, t.family_id AS family_id,
    t.grace_expires_at AS grace_expires_at, t.dpop_jkt AS dpop_jkt";

const CODE: &str = "a.code_hash AS code_hash, a.profile_id AS profile_id,
    a.client_id AS client_id, a.redirect_uri AS redirect_uri, a.scopes AS scopes,
    a.resource_id AS resource_id, a.code_challenge AS code_challenge, a.nonce AS nonce,
    a.authorizing_session_id AS authorizing_session_id, a.authenticated_at AS authenticated_at,
    a.amr AS amr, a.assurance_level AS assurance_level, a.elevation_level AS elevation_level,
    a.elevation_until AS elevation_until, a.expires_at AS expires_at,
    a.created_at AS created_at, a.used AS used, a.session_id AS session_id";

const GENERATION: &str = "g.id AS id, g.session_id AS session_id, g.key_jkt AS key_jkt,
    g.expires_at AS expires_at, g.created_at AS created_at, g.exchange AS exchange,
    g.successor_id AS successor_id, g.redeliver_until AS redeliver_until, g.sealed AS sealed";

fn session_value(id: SessionId) -> Value {
    uuid(id.as_uuid())
}

/// A stored assurance level; an unknown one is an error, never `Basic`.
fn level(row: &Row, name: &str) -> SidResult<AuthLevel> {
    let value = get_text(row, name)?;
    AuthLevel::from_acr_value(&value)
        .ok_or_else(|| SidError::Storage(format!("{name}: unknown level {value}")))
}

/// The step-up stored in `elevation_level` / `elevation_until`: both or
/// neither.
fn elevation(row: &Row) -> SidResult<Option<Elevation>> {
    match (
        get_opt_text(row, "elevation_level")?,
        get_opt_time(row, "elevation_until")?,
    ) {
        (Some(_), Some(until)) => Ok(Some(Elevation {
            level: level(row, "elevation_level")?,
            until,
        })),
        (None, None) => Ok(None),
        _ => Err(SidError::Storage(
            "elevation level and time must be stored together".into(),
        )),
    }
}

/// Refuse levels a grant cannot hold: its own level is `Basic` or
/// `Standard`, a step-up is `Elevated` or `Critical` and lapses.
fn check_levels(assurance: AuthLevel, elevation: Option<Elevation>) -> SidResult<()> {
    if assurance > AuthLevel::Standard {
        return Err(SidError::Validation(format!(
            "a session's own level is basic or standard, not {}",
            assurance.as_str()
        )));
    }
    if elevation.is_some_and(|e| e.level < AuthLevel::Elevated) {
        return Err(SidError::Validation(
            "a step-up is to elevated or critical".into(),
        ));
    }
    Ok(())
}

fn elevation_params(params: Params, elevation: Option<Elevation>) -> Params {
    params
        .with(
            "elevation_level",
            elevation.map_or(Value::Null, |e| Value::String(e.level.as_str().into())),
        )
        .with("elevation_until", opt_time(elevation.map(|e| e.until)))
}

pub(super) fn session(row: &Row) -> SidResult<Session> {
    Ok(Session {
        id: get_id(row, "id")?,
        profile_id: get_id(row, "profile_id")?,
        client_id: get_opt_text(row, "client_id")?,
        device_id: get_opt_uuid(row, "device_id")?,
        ip_address: get_opt_bytes(row, "ip")?
            .as_deref()
            .map(ip_of)
            .transpose()?,
        user_agent: get_opt_text(row, "user_agent")?,
        scopes: get_texts(row, "scopes")?,
        assurance_level: level(row, "assurance_level")?,
        elevation: elevation(row)?,
        authenticated_at: get_time(row, "authenticated_at")?,
        amr: get_texts(row, "amr")?,
        is_provisional: get_bool(row, "is_provisional")?,
        passkey_prompt: get_bool(row, "passkey_prompt")?,
        policy_grace: get_bool(row, "policy_grace")?,
        grace_deadline: get_opt_time(row, "grace_deadline")?,
        created_at: get_time(row, "created_at")?,
        expires_at: get_time(row, "expires_at")?,
        last_activity_at: get_opt_time(row, "last_activity_at")?,
        browser_secret_hash: get_opt_bytes(row, "browser_secret_hash")?
            .as_deref()
            .map(BrowserSecretHash::try_from)
            .transpose()?,
        browser_csrf: get_opt_bytes(row, "browser_csrf")?
            .as_deref()
            .map(BrowserCsrfToken::try_from)
            .transpose()?,
        authenticated_by: get_opt_id(row, "authenticated_by")?,
    })
}

/// Store a new session in `tx`; an existing id is `Conflict`.
pub(super) fn insert(tx: &Statements<'_>, session: &Session) -> SidResult<()> {
    check_levels(session.assurance_level, session.elevation)?;
    if get(tx, session.id)?.is_some() {
        return Err(SidError::Conflict("session already exists".into()));
    }
    let params = Params::default()
        .with("id", session_value(session.id))
        .with("profile_id", profile_value(session.profile_id))
        .with("client_id", opt_text(session.client_id.as_deref()))
        .with("device_id", opt_uuid(session.device_id.as_ref()))
        .with("ip", session.ip_address.map_or(Value::Null, ip_value))
        .with("user_agent", opt_text(session.user_agent.as_deref()))
        .with("scopes", texts(&session.scopes))
        .with(
            "assurance_level",
            Value::String(session.assurance_level.as_str().into()),
        )
        .with("is_provisional", Value::Bool(session.is_provisional))
        .with("passkey_prompt", Value::Bool(session.passkey_prompt))
        .with("authenticated_at", time(session.authenticated_at))
        .with("amr", texts(&session.amr))
        .with("policy_grace", Value::Bool(session.policy_grace))
        .with("grace_deadline", opt_time(session.grace_deadline))
        .with("created_at", time(session.created_at))
        .with("expires_at", time(session.expires_at))
        .with("last_activity_at", opt_time(session.last_activity_at))
        .with(
            "browser_secret_hash",
            session
                .browser_secret_hash
                .map_or(Value::Null, |h| Value::Binary(h.as_bytes().to_vec())),
        )
        .with(
            "browser_csrf",
            session
                .browser_csrf
                .map_or(Value::Null, |t| Value::Binary(t.as_bytes().to_vec())),
        )
        .with(
            "authenticated_by",
            opt_uuid(session.authenticated_by.as_ref().map(|s| s.as_uuid())),
        );
    tx.run(
        "CREATE (s:SidSession {id: $id, profile_id: $profile_id, client_id: $client_id,
            device_id: $device_id, ip: $ip, user_agent: $user_agent, scopes: $scopes,
            assurance_level: $assurance_level, elevation_level: $elevation_level,
            elevation_until: $elevation_until, is_provisional: $is_provisional,
            passkey_prompt: $passkey_prompt, authenticated_at: $authenticated_at, amr: $amr,
            policy_grace: $policy_grace, grace_deadline: $grace_deadline,
            created_at: $created_at, expires_at: $expires_at,
            last_activity_at: $last_activity_at, browser_secret_hash: $browser_secret_hash,
            browser_csrf: $browser_csrf, authenticated_by: $authenticated_by})",
        elevation_params(params, session.elevation),
    )?;
    Ok(())
}

fn get(tx: &Statements<'_>, id: SessionId) -> SidResult<Option<Session>> {
    let rows = tx.run(
        &format!("MATCH (s:SidSession) WHERE s.id = $id RETURN {SESSION}"),
        Params::default().with("id", session_value(id)),
    )?;
    rows.first().map(session).transpose()
}

/// Delete what a session owns along with it: its refresh tokens, the codes
/// it authorized and its native generations with their credentials.
fn delete_owned(tx: &Statements<'_>, id: SessionId) -> SidResult<()> {
    let params = || Params::default().with("id", session_value(id));
    let generations = tx.run(
        "MATCH (g:SidNativeGeneration) WHERE g.session_id = $id RETURN g.id AS id",
        params(),
    )?;
    for row in &generations {
        tx.run(
            "MATCH (c:SidNativeCredential) WHERE c.generation_id = $generation DETACH DELETE c",
            Params::default().with("generation", Value::Binary(get_bytes(row, "id")?)),
        )?;
    }
    for query in [
        "MATCH (g:SidNativeGeneration) WHERE g.session_id = $id DETACH DELETE g",
        "MATCH (t:SidRefreshToken) WHERE t.session_id = $id DETACH DELETE t",
        "MATCH (a:SidAuthCode) WHERE a.authorizing_session_id = $id DETACH DELETE a",
    ] {
        tx.run(query, params())?;
    }
    Ok(())
}

/// Delete session `id` and the sessions it authenticated, with what they
/// own, in `tx`; returns every session ended.
fn end_with_dependents(tx: &Statements<'_>, id: SessionId) -> SidResult<Vec<Session>> {
    let mut ended = Vec::new();
    for property in ["id", "authenticated_by"] {
        let rows = tx.run(
            &format!("MATCH (s:SidSession) WHERE s.{property} = $id RETURN {SESSION}"),
            Params::default().with("id", session_value(id)),
        )?;
        for row in &rows {
            ended.push(session(row)?);
        }
    }
    for session in &ended {
        delete_owned(tx, session.id)?;
        tx.run(
            "MATCH (s:SidSession) WHERE s.id = $id DETACH DELETE s",
            Params::default().with("id", session_value(session.id)),
        )?;
    }
    Ok(ended)
}

/// End every session of `profile`, adding what each owes under `end` to
/// `ctx`; returns them.
pub(super) fn end_profile_sessions(
    tx: &Statements<'_>,
    profile: ProfileId,
    end: &SessionEnd,
    ctx: &mut MutationContext,
) -> SidResult<Vec<Session>> {
    let sessions = profile_sessions(tx, profile)?;
    for ended in &sessions {
        delete_owned(tx, ended.id)?;
        tx.run(
            "MATCH (s:SidSession) WHERE s.id = $id DETACH DELETE s",
            Params::default().with("id", session_value(ended.id)),
        )?;
        ctx.work.extend(end.owed_by(ended));
    }
    Ok(sessions)
}

/// Delete everything a deleted profile's sessions held, owing nothing: the
/// account itself is gone.
pub(super) fn delete_profile_grants(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for ended in profile_sessions(tx, profile)? {
        delete_owned(tx, ended.id)?;
    }
    for query in [
        "MATCH (s:SidSession) WHERE s.profile_id = $profile DETACH DELETE s",
        "MATCH (t:SidRefreshToken) WHERE t.profile_id = $profile DETACH DELETE t",
        "MATCH (a:SidAuthCode) WHERE a.profile_id = $profile DETACH DELETE a",
    ] {
        tx.run(
            query,
            Params::default().with("profile", profile_value(profile)),
        )?;
    }
    Ok(())
}

pub(super) fn profile_sessions(tx: &Statements<'_>, profile: ProfileId) -> SidResult<Vec<Session>> {
    let rows = tx.run(
        &format!("MATCH (s:SidSession) WHERE s.profile_id = $profile RETURN {SESSION}"),
        Params::default().with("profile", profile_value(profile)),
    )?;
    let mut sessions = rows.iter().map(session).collect::<SidResult<Vec<_>>>()?;
    // Newest first, in one total order: ids of one instant by id.
    sessions.sort_by(|a, b| (b.created_at, b.id.as_uuid()).cmp(&(a.created_at, a.id.as_uuid())));
    Ok(sessions)
}

/// Hold what `proof` proved for `profile` for the commit, or refuse.
fn hold_proof(tx: &Statements<'_>, profile: ProfileId, proof: SignInProof<'_>) -> SidResult<()> {
    let (rows, refusal) = match proof {
        SignInProof::Credential(fence) => (
            tx.run(
                "MATCH (c:SidCredential) WHERE c.id = $id AND c.profile_id = $profile
                   AND c.status = 'active' AND c.data = $data
                 RETURN id(c) AS node",
                Params::default()
                    .with("id", uuid(&fence.id.0))
                    .with("profile", profile_value(profile))
                    .with("data", Value::Binary(fence.data.expose().to_vec())),
            )?,
            "the credential the sign-in proved changed before its session",
        ),
        SignInProof::Assignment(fence) => {
            if fence.profile != profile {
                return Err(SidError::Fenced(
                    "the assignment the sign-in resolved changed before its session".into(),
                ));
            }
            (
                tx.run(
                    "MATCH (p:SidPrincipal) WHERE p.id = $id AND p.assigned_profile_id = $profile
                       AND p.assignment_revision = $revision
                     RETURN id(p) AS node",
                    Params::default()
                        .with("id", uuid(&fence.principal.0))
                        .with("profile", profile_value(profile))
                        .with("revision", Value::Int(fence.revision)),
                )?,
                "the assignment the sign-in resolved changed before its session",
            )
        }
    };
    match rows.first() {
        Some(row) if tx.hold(get_int(row, "node")?)? => Ok(()),
        _ => Err(SidError::Fenced(refusal.into())),
    }
}

/// Store `session` for its profile under `max_sessions` (0: unlimited),
/// evicting the oldest counted sessions first, in `tx`.
fn create_limited(
    tx: &Statements<'_>,
    session: &Session,
    max_sessions: u32,
    proved_by: Option<SignInProof<'_>>,
    pending: Option<(SessionId, &SessionEnd)>,
    ctx: &mut MutationContext,
) -> SidResult<Vec<SessionId>> {
    // The profile's turn: concurrent sign-ins of one profile and a status
    // change of it conflict here.
    let status = tx.run(
        "MATCH (p:SidProfile) WHERE p.id = $id
         SET p.session_turn = coalesce(p.session_turn, 0) + 1
         RETURN p.status AS status",
        Params::default().with("id", profile_value(session.profile_id)),
    )?;
    let active = sid_core::models::ProfileStatus::Active.as_str();
    if status
        .first()
        .map(|row| get_text(row, "status"))
        .transpose()?
        .as_deref()
        != Some(active)
    {
        return Err(SidError::Fenced(
            "the profile can no longer authenticate".into(),
        ));
    }
    if let Some(proof) = proved_by {
        hold_proof(tx, session.profile_id, proof)?;
    }
    if let Some((pending, end)) = pending {
        let ended = end_with_dependents(tx, pending)?;
        if !ended
            .iter()
            .any(|s| s.id == pending && s.profile_id == session.profile_id)
        {
            return Err(SidError::Fenced("the pending sign-in has ended".into()));
        }
        for ended in &ended {
            ctx.work.extend(end.owed_by(ended));
        }
    }
    let mut evicted = Vec::new();
    // A pending second-factor context takes no place, so it evicts nothing.
    if max_sessions > 0 && !session.awaits_second_factor() {
        let now = Utc::now();
        let mut counted: Vec<Session> = profile_sessions(tx, session.profile_id)?
            .into_iter()
            .filter(|s| {
                s.expires_at > now
                    && !(s.is_provisional && s.scopes.join(" ") == SECOND_FACTOR_SCOPE)
            })
            .collect();
        counted.sort_by_key(|s| s.created_at);
        // One slot is taken by the new session; under the limit nothing is
        // evicted, so the excess bottoms out at zero by definition.
        let excess = (counted.len() + 1).saturating_sub(max_sessions as usize);
        let end = SessionEnd::new(RevocationReason::SessionLimit, "system");
        for oldest in counted.into_iter().take(excess) {
            for ended in end_with_dependents(tx, oldest.id)? {
                ctx.work.extend(end.owed_by(&ended));
                evicted.push(ended.id);
            }
        }
    }
    insert(tx, session)?;
    Ok(evicted)
}

fn token(row: &Row) -> SidResult<RefreshToken> {
    Ok(RefreshToken {
        id: get_uuid(row, "id")?,
        token_hash: get_bytes(row, "token_hash")?,
        session_id: get_id(row, "session_id")?,
        profile_id: get_id(row, "profile_id")?,
        client_id: get_text(row, "client_id")?,
        scopes: get_texts(row, "scopes")?,
        resource: get_id(row, "resource_id")?,
        expires_at: get_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        revoked: get_bool(row, "revoked")?,
        replaced_by: get_opt_uuid(row, "replaced_by")?,
        family_id: get_uuid(row, "family_id")?,
        grace_expires_at: get_opt_time(row, "grace_expires_at")?,
        dpop_jkt: get_opt_text(row, "dpop_jkt")?,
    })
}

/// Store a new refresh token in `tx`; an existing id or hash is `Conflict`.
pub(super) fn insert_token(tx: &Statements<'_>, token: &RefreshToken) -> SidResult<()> {
    if !tx
        .run(
            "MATCH (t:SidRefreshToken) WHERE t.id = $id RETURN t.id AS id",
            Params::default().with("id", uuid(&token.id)),
        )?
        .is_empty()
    {
        return Err(SidError::Conflict("refresh token already exists".into()));
    }
    tx.run(
        "CREATE (t:SidRefreshToken {id: $id, token_hash: $token_hash, session_id: $session_id,
            profile_id: $profile_id, client_id: $client_id, scopes: $scopes,
            resource_id: $resource_id, expires_at: $expires_at, created_at: $created_at,
            revoked: $revoked, replaced_by: $replaced_by, family_id: $family_id,
            grace_expires_at: $grace_expires_at, dpop_jkt: $dpop_jkt})",
        Params::default()
            .with("id", uuid(&token.id))
            .with("token_hash", Value::Binary(token.token_hash.clone()))
            .with("session_id", session_value(token.session_id))
            .with("profile_id", profile_value(token.profile_id))
            .with("client_id", Value::String(token.client_id.clone()))
            .with("scopes", texts(&token.scopes))
            .with("resource_id", uuid(token.resource.as_uuid()))
            .with("expires_at", time(token.expires_at))
            .with("created_at", time(token.created_at))
            .with("revoked", Value::Bool(token.revoked))
            .with("replaced_by", opt_uuid(token.replaced_by.as_ref()))
            .with("family_id", uuid(&token.family_id))
            .with("grace_expires_at", opt_time(token.grace_expires_at))
            .with("dpop_jkt", opt_text(token.dpop_jkt.as_deref())),
    )?;
    Ok(())
}

/// Revoke the tokens `property` names, those in a grace window included:
/// the window ends with them. Returns how many changed.
fn revoke_tokens(tx: &Statements<'_>, property: &str, value: Value) -> SidResult<u64> {
    get_count(&tx.run(
        &format!(
            "MATCH (t:SidRefreshToken) WHERE t.{property} = $value
               AND (t.revoked = false OR t.grace_expires_at IS NOT NULL)
             SET t.revoked = true, t.grace_expires_at = null
             RETURN count(*) AS n"
        ),
        Params::default().with("value", value),
    )?)
}

fn code(row: &Row) -> SidResult<AuthorizationCode> {
    Ok(AuthorizationCode {
        code_hash: get_bytes(row, "code_hash")?,
        profile_id: get_id(row, "profile_id")?,
        client_id: get_text(row, "client_id")?,
        redirect_uri: get_text(row, "redirect_uri")?,
        scopes: get_texts(row, "scopes")?,
        resource: get_id(row, "resource_id")?,
        code_challenge: get_opt_text(row, "code_challenge")?,
        nonce: get_opt_text(row, "nonce")?,
        authentication: GrantAuthentication {
            session: get_id(row, "authorizing_session_id")?,
            authenticated_at: get_time(row, "authenticated_at")?,
            amr: get_texts(row, "amr")?,
            assurance_level: level(row, "assurance_level")?,
            elevation: elevation(row)?,
        },
        expires_at: get_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        used: get_bool(row, "used")?,
        session_id: get_opt_id(row, "session_id")?,
    })
}

fn presented(row: &Row) -> SidResult<NativePresented> {
    let state = match get_opt_bytes(row, "exchange")? {
        None => NativeGenerationState::Current,
        Some(exchange) => NativeGenerationState::Rotated {
            exchange: NativeExchange::from_bytes(&exchange)
                .ok_or_else(|| SidError::Storage("exchange: not 16 bytes".into()))?,
            successor: get_uuid(row, "successor_id")?,
            redeliver_until: get_time(row, "redeliver_until")?,
            sealed: get_opt_bytes(row, "sealed")?,
        },
    };
    Ok(NativePresented {
        generation: get_uuid(row, "id")?,
        session_id: get_id(row, "session_id")?,
        key_jkt: get_text(row, "key_jkt")?,
        expires_at: get_time(row, "expires_at")?,
        state,
    })
}

/// Store `generation` and its credentials in `tx`.
fn insert_generation(tx: &Statements<'_>, generation: &NativeGeneration) -> SidResult<()> {
    tx.run(
        "CREATE (g:SidNativeGeneration {id: $id, session_id: $session_id, key_jkt: $key_jkt,
            expires_at: $expires_at, created_at: $created_at})",
        Params::default()
            .with("id", uuid(&generation.id))
            .with("session_id", session_value(generation.session_id))
            .with("key_jkt", Value::String(generation.key_jkt.clone()))
            .with("expires_at", time(generation.expires_at))
            .with("created_at", time(generation.created_at)),
    )?;
    for hash in &generation.credential_hashes {
        tx.run(
            "CREATE (c:SidNativeCredential {credential_hash: $hash, generation_id: $generation})",
            Params::default()
                .with("hash", Value::Binary(hash.clone()))
                .with("generation", uuid(&generation.id)),
        )?;
    }
    Ok(())
}

/// Whether session `id` exists unexpired, claimed for a record created under
/// it: ending it, which removes what it reads of the session's, conflicts
/// with this transaction either way round.
fn claim_live_session(tx: &Statements<'_>, id: SessionId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (s:SidSession) WHERE s.id = $id AND s.expires_at > $now RETURN id(s) AS node",
        Params::default()
            .with("id", session_value(id))
            .with("now", time(Utc::now())),
    )?;
    claim_first(tx, &rows)
}

/// Whether session `id` exists, claimed as [`claim_live_session`] claims it.
fn claim_session(tx: &Statements<'_>, id: SessionId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (s:SidSession) WHERE s.id = $id RETURN id(s) AS node",
        Params::default().with("id", session_value(id)),
    )?;
    claim_first(tx, &rows)
}

impl CoordinodeBackend {
    pub(super) async fn create_session(
        &self,
        session: &Session,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = session.clone();
        self.mutate(format!("session:{}", session.id), ctx, move |tx| {
            super::profile::claim_profile(tx, stored.profile_id)?;
            insert(tx, &stored)
        })
        .await
    }

    pub(super) async fn record_session_authentication(
        &self,
        id: SessionId,
        expected: &SessionAuthentication,
        new: &SessionAuthentication,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (expected, new) = (expected.clone(), new.clone());
        self.transaction(move |tx| {
            let Some(stored) = get(tx, id)? else {
                return Ok(Decision::Abandon(false));
            };
            let current = SessionAuthentication {
                assurance_level: stored.assurance_level,
                elevation: stored.elevation,
                authenticated_at: stored.authenticated_at,
                amr: stored.amr.clone(),
            };
            if stored.expires_at <= Utc::now() || current != expected {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (s:SidSession) WHERE s.id = $id
                 SET s.assurance_level = $assurance_level, s.elevation_level = $elevation_level,
                     s.elevation_until = $elevation_until, s.authenticated_at = $authenticated_at,
                     s.amr = $amr",
                elevation_params(
                    Params::default()
                        .with("id", session_value(id))
                        .with(
                            "assurance_level",
                            Value::String(new.assurance_level.as_str().into()),
                        )
                        .with("authenticated_at", time(new.authenticated_at))
                        .with("amr", texts(&new.amr)),
                    new.elevation,
                ),
            )?;
            finalize(tx, &format!("session:{id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn create_session_atomic(
        &self,
        session: &Session,
        max_sessions: u32,
        proved_by: Option<SignInProof<'_>>,
        pending: Option<(SessionId, &SessionEnd)>,
        ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let session = session.clone();
        let proof = proved_by.map(OwnedProof::from);
        let pending = pending.map(|(id, end)| (id, end.clone()));
        self.transaction(move |tx| {
            let mut ctx = ctx.clone();
            let evicted = create_limited(
                tx,
                &session,
                max_sessions,
                proof.as_ref().map(OwnedProof::borrow),
                pending.as_ref().map(|(id, end)| (*id, end)),
                &mut ctx,
            )?;
            finalize(tx, &format!("profile:{}", session.profile_id), ctx)?;
            Ok(Decision::Commit(evicted))
        })
        .await
    }

    pub(super) async fn get_session(&self, id: SessionId) -> SidResult<Option<Session>> {
        self.transaction(move |tx| get(tx, id).map(Decision::Abandon))
            .await
    }

    pub(super) async fn get_session_by_browser_secret(
        &self,
        hash: &BrowserSecretHash,
    ) -> SidResult<Option<Session>> {
        let hash = hash.as_bytes().to_vec();
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (s:SidSession) WHERE s.browser_secret_hash = $hash RETURN {SESSION}"
                ),
                Params::default().with("hash", Value::Binary(hash.clone())),
            )?;
            Ok(Decision::Abandon(rows.first().map(session).transpose()?))
        })
        .await
    }

    pub(super) async fn list_sessions(&self, owner: ProfileId) -> SidResult<Vec<Session>> {
        self.transaction(move |tx| profile_sessions(tx, owner).map(Decision::Abandon))
            .await
    }

    pub(super) async fn touch_session(&self, id: SessionId, at: DateTime<Utc>) -> SidResult<()> {
        self.transaction(move |tx| {
            let Some(stored) = get(tx, id)? else {
                return Ok(Decision::Abandon(()));
            };
            // Last activity only moves forward.
            if stored.last_activity_at.is_some_and(|last| last >= at) {
                return Ok(Decision::Abandon(()));
            }
            tx.run(
                "MATCH (s:SidSession) WHERE s.id = $id SET s.last_activity_at = $at",
                Params::default()
                    .with("id", session_value(id))
                    .with("at", time(at)),
            )?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let end = end.clone();
        self.transaction(move |tx| {
            let mut ctx = ctx.clone();
            let ended = end_with_dependents(tx, id)?;
            for session in &ended {
                ctx.work.extend(end.owed_by(session));
            }
            finalize(tx, &format!("session:{id}"), ctx)?;
            Ok(Decision::Commit(ended.into_iter().map(|s| s.id).collect()))
        })
        .await
    }

    pub(super) async fn delete_sessions_by_profile(
        &self,
        profile: ProfileId,
        end: &SessionEnd,
        ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let end = end.clone();
        self.transaction(move |tx| {
            let mut ctx = ctx.clone();
            let sessions = end_profile_sessions(tx, profile, &end, &mut ctx)?;
            ctx.record_effect(&sessions.len())?;
            finalize(tx, &format!("profile:{profile}"), ctx)?;
            Ok(Decision::Commit(sessions))
        })
        .await
    }

    // === Refresh tokens ===

    pub(super) async fn create_refresh_token(
        &self,
        token: &RefreshToken,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = token.clone();
        self.mutate(format!("refresh_token:{}", token.id), ctx, move |tx| {
            // Ending the session removes its tokens: the claim makes that
            // conflict with this creation.
            if !claim_session(tx, stored.session_id)? {
                return Err(SidError::NotFound(format!("session {}", stored.session_id)));
            }
            insert_token(tx, &stored)
        })
        .await
    }

    pub(super) async fn get_refresh_token_by_hash(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<RefreshToken>> {
        let hash = hash.to_vec();
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (t:SidRefreshToken) WHERE t.token_hash = $hash RETURN {TOKEN}"),
                Params::default().with("hash", Value::Binary(hash.clone())),
            )?;
            Ok(Decision::Abandon(rows.first().map(token).transpose()?))
        })
        .await
    }

    pub(super) async fn revoke_refresh_tokens_by_session(
        &self,
        id: SessionId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let revoked = revoke_tokens(tx, "session_id", session_value(id))?;
            finalize(tx, &format!("session:{id}"), ctx.clone())?;
            Ok(Decision::Commit(revoked))
        })
        .await
    }

    pub(super) async fn revoke_refresh_tokens_by_family(
        &self,
        family: Uuid,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let revoked = revoke_tokens(tx, "family_id", uuid(&family))?;
            finalize(tx, &format!("token_family:{family}"), ctx.clone())?;
            Ok(Decision::Commit(revoked))
        })
        .await
    }

    pub(super) async fn rotate_refresh_token(
        &self,
        old: Uuid,
        new: &RefreshToken,
        grace_expires_at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let new = new.clone();
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (t:SidRefreshToken) WHERE t.id = $id RETURN {TOKEN}"),
                Params::default().with("id", uuid(&old)),
            )?;
            let Some(stored) = rows.first().map(token).transpose()? else {
                return Ok(Decision::Abandon(false));
            };
            let now = Utc::now();
            let usable = stored.expires_at > now
                && (!stored.revoked || stored.grace_expires_at.is_some_and(|g| g > now));
            if !usable {
                return Ok(Decision::Abandon(false));
            }
            // An existing grace window is kept.
            let grace = stored.grace_expires_at.unwrap_or(grace_expires_at);
            tx.run(
                "MATCH (t:SidRefreshToken) WHERE t.id = $id
                 SET t.revoked = true, t.replaced_by = $new, t.grace_expires_at = $grace",
                Params::default()
                    .with("id", uuid(&old))
                    .with("new", uuid(&new.id))
                    .with("grace", time(grace)),
            )?;
            insert_token(tx, &new)?;
            finalize(tx, &format!("token_family:{}", new.family_id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Authorization codes ===

    pub(super) async fn create_auth_code(
        &self,
        code: &AuthorizationCode,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let code = code.clone();
        self.mutate(format!("auth_code:{}", code.client_id), ctx, move |tx| {
            if !tx
                .run(
                    "MATCH (a:SidAuthCode) WHERE a.code_hash = $hash RETURN a.code_hash AS h",
                    Params::default().with("hash", Value::Binary(code.code_hash.clone())),
                )?
                .is_empty()
            {
                return Err(SidError::Conflict(
                    "authorization code already exists".into(),
                ));
            }
            let auth = &code.authentication;
            check_levels(auth.assurance_level, auth.elevation)?;
            // A logout racing the authorization either ends the session first,
            // and no code is stored, or conflicts with this commit and finds
            // the code to end with it.
            if !claim_session(tx, auth.session)? {
                return Err(SidError::NotFound(format!("session {}", auth.session)));
            }
            tx.run(
                "CREATE (a:SidAuthCode {code_hash: $hash, profile_id: $profile_id,
                    client_id: $client_id, redirect_uri: $redirect_uri, scopes: $scopes,
                    code_challenge: $code_challenge, nonce: $nonce, expires_at: $expires_at,
                    created_at: $created_at, used: $used, session_id: null,
                    resource_id: $resource_id, authorizing_session_id: $authorizing,
                    authenticated_at: $authenticated_at, amr: $amr,
                    assurance_level: $assurance_level, elevation_level: $elevation_level,
                    elevation_until: $elevation_until})",
                elevation_params(
                    Params::default()
                        .with("hash", Value::Binary(code.code_hash.clone()))
                        .with("profile_id", profile_value(code.profile_id))
                        .with("client_id", Value::String(code.client_id.clone()))
                        .with("redirect_uri", Value::String(code.redirect_uri.clone()))
                        .with("scopes", texts(&code.scopes))
                        .with("code_challenge", opt_text(code.code_challenge.as_deref()))
                        .with("nonce", opt_text(code.nonce.as_deref()))
                        .with("expires_at", time(code.expires_at))
                        .with("created_at", time(code.created_at))
                        .with("used", Value::Bool(code.used))
                        .with("resource_id", uuid(code.resource.as_uuid()))
                        .with("authorizing", session_value(auth.session))
                        .with("authenticated_at", time(auth.authenticated_at))
                        .with("amr", texts(&auth.amr))
                        .with(
                            "assurance_level",
                            Value::String(auth.assurance_level.as_str().into()),
                        ),
                    auth.elevation,
                ),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_auth_code_by_hash(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<AuthorizationCode>> {
        let hash = hash.to_vec();
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (a:SidAuthCode) WHERE a.code_hash = $hash RETURN {CODE}"),
                Params::default().with("hash", Value::Binary(hash.clone())),
            )?;
            Ok(Decision::Abandon(rows.first().map(code).transpose()?))
        })
        .await
    }

    pub(super) async fn redeem_auth_code(
        &self,
        hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> SidResult<AuthCodeRedemption> {
        let (hash, session, refresh_token) =
            (hash.to_vec(), session.clone(), refresh_token.clone());
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (a:SidAuthCode) WHERE a.code_hash = $hash RETURN {CODE}"),
                Params::default().with("hash", Value::Binary(hash.clone())),
            )?;
            let stored = rows.first().map(code).transpose()?;
            match stored {
                Some(stored) if !stored.used => {}
                other => {
                    return Ok(Decision::Abandon(AuthCodeRedemption::AlreadyRedeemed {
                        session_id: other.and_then(|c| c.session_id),
                    }));
                }
            }
            // Concurrent redemptions all write the code: one commits.
            tx.run(
                "MATCH (a:SidAuthCode) WHERE a.code_hash = $hash
                 SET a.used = true, a.session_id = $session",
                Params::default()
                    .with("hash", Value::Binary(hash.clone()))
                    .with("session", session_value(session.id)),
            )?;
            insert(tx, &session)?;
            insert_token(tx, &refresh_token)?;
            finalize(tx, &format!("session:{}", session.id), ctx.clone())?;
            Ok(Decision::Commit(AuthCodeRedemption::Redeemed))
        })
        .await
    }

    // === Native generations ===

    pub(super) async fn issue_native_generation(
        &self,
        generation: &NativeGeneration,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let generation = generation.clone();
        self.mutate(
            format!("session:{}", generation.session_id),
            ctx,
            move |tx| {
                if !claim_live_session(tx, generation.session_id)? {
                    return Err(SidError::Fenced(
                        "the session ended before its native generation".into(),
                    ));
                }
                insert_generation(tx, &generation)
            },
        )
        .await
    }

    pub(super) async fn native_generation_by_credential(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<NativePresented>> {
        let hash = hash.to_vec();
        self.transaction(move |tx| {
            let credential = tx.run(
                "MATCH (c:SidNativeCredential) WHERE c.credential_hash = $hash
                 RETURN c.generation_id AS generation",
                Params::default().with("hash", Value::Binary(hash.clone())),
            )?;
            let Some(row) = credential.first() else {
                return Ok(Decision::Abandon(None));
            };
            let rows = tx.run(
                &format!("MATCH (g:SidNativeGeneration) WHERE g.id = $id RETURN {GENERATION}"),
                Params::default().with("id", Value::Binary(get_bytes(row, "generation")?)),
            )?;
            Ok(Decision::Abandon(rows.first().map(presented).transpose()?))
        })
        .await
    }

    pub(super) async fn rotate_native_generation(
        &self,
        rotation: NativeRotation<'_>,
        ctx: MutationContext,
    ) -> SidResult<NativeRotationOutcome> {
        let (presented_id, exchange, successor, sealed, redeliver_until) = (
            rotation.presented,
            rotation.exchange,
            rotation.successor.clone(),
            rotation.sealed.to_vec(),
            rotation.redeliver_until,
        );
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (g:SidNativeGeneration) WHERE g.id = $id RETURN {GENERATION}"),
                Params::default().with("id", uuid(&presented_id)),
            )?;
            // The generation went with its session.
            let Some(current) = rows.first().map(presented).transpose()? else {
                return Ok(Decision::Abandon(NativeRotationOutcome::Ended));
            };
            if !claim_live_session(tx, current.session_id)? {
                return Ok(Decision::Abandon(NativeRotationOutcome::Ended));
            }
            match current.state {
                NativeGenerationState::Current => {
                    // Its predecessor's redelivery ends now that this one is used.
                    tx.run(
                        "MATCH (g:SidNativeGeneration) WHERE g.successor_id = $id SET g.sealed = null",
                        Params::default().with("id", uuid(&presented_id)),
                    )?;
                    // Concurrent rotations of one generation all write it.
                    tx.run(
                        "MATCH (g:SidNativeGeneration) WHERE g.id = $id
                         SET g.exchange = $exchange, g.successor_id = $successor,
                             g.redeliver_until = $until, g.sealed = $sealed",
                        Params::default()
                            .with("id", uuid(&presented_id))
                            .with("exchange", Value::Binary(exchange.as_bytes().to_vec()))
                            .with("successor", uuid(&successor.id))
                            .with("until", time(redeliver_until))
                            .with("sealed", Value::Binary(sealed.clone())),
                    )?;
                    insert_generation(tx, &successor)?;
                    finalize(tx, &format!("session:{}", current.session_id), ctx.clone())?;
                    Ok(Decision::Commit(NativeRotationOutcome::Rotated))
                }
                NativeGenerationState::Rotated {
                    exchange: rotated_by,
                    redeliver_until: until,
                    sealed: Some(stored),
                    ..
                } if rotated_by == exchange && Utc::now() < until => {
                    Ok(Decision::Abandon(NativeRotationOutcome::Redeliver(stored)))
                }
                NativeGenerationState::Rotated { .. } => {
                    Ok(Decision::Abandon(NativeRotationOutcome::Retired))
                }
            }
        })
        .await
    }
}

/// A sign-in proof the transaction keeps across its runs.
enum OwnedProof {
    Credential(sid_core::models::CredentialFence),
    Assignment(sid_core::models::PrincipalAssignmentFence),
}

impl From<SignInProof<'_>> for OwnedProof {
    fn from(proof: SignInProof<'_>) -> Self {
        match proof {
            SignInProof::Credential(fence) => Self::Credential(fence.clone()),
            SignInProof::Assignment(fence) => Self::Assignment(fence),
        }
    }
}

impl OwnedProof {
    fn borrow(&self) -> SignInProof<'_> {
        match self {
            Self::Credential(fence) => SignInProof::Credential(fence),
            Self::Assignment(fence) => SignInProof::Assignment(*fence),
        }
    }
}
