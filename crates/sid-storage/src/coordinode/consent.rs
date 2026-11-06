// SPDX-License-Identifier: AGPL-3.0-only
//! What a Profile shares and is granted, and where it signs in from, in
//! CoordiNode: consents with their claim grants, profile grants, upstream
//! providers and the identities linked through them.
//!
//! A consent is one node, each of its claim grants another; a decision that
//! changes a grant writes the consent, so it conflicts with the consent's
//! revocation or deletion. One consent per Profile and client, one grant
//! per Profile and project, one identity per Profile and provider and per
//! provider subject: the store keeps each unique.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::consent::{
    ClaimDecision, ClaimGrant, ClaimGrantChange, ClaimGrantId, ConsentId, ConsentRecord,
};
use sid_core::models::{
    MutationContext, ProfileGrant, ProfileGrantId, ProfileId, ProjectId, UpstreamIdentity,
    UpstreamIdentityId, UpstreamLogin, UpstreamProvider, UpstreamProviderId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_keys::EncryptedField;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_int, get_opt_text, get_opt_time, get_parsed, get_text, get_texts, get_time,
    get_uuid, key, opt_text, opt_time, texts, time, uuid,
};

const CONSENT: &str = "c.id AS id, c.profile_id AS profile_id, c.client_id AS client_id,
    c.status AS status, c.consented_at AS consented_at, c.revoked_at AS revoked_at,
    c.updated_at AS updated_at";

const CLAIM: &str = "g.id AS id, g.consent_id AS consent_id, g.claim_name AS claim_name,
    g.claim_type AS claim_type, g.granted_at AS granted_at, g.revoked_at AS revoked_at";

const GRANT: &str = "g.id AS id, g.project_id AS project_id, g.profile_id AS profile_id,
    g.role_keys AS role_keys, g.granted_by AS granted_by, g.expires_at AS expires_at,
    g.created_at AS created_at, g.updated_at AS updated_at";

const PROVIDER: &str = "u.id AS id, u.name AS name, u.protocol AS protocol,
    u.trust_category AS trust_category, u.enabled AS enabled, u.client_id AS client_id,
    u.client_secret AS client_secret, u.discovery_url AS discovery_url,
    u.authorization_endpoint AS authorization_endpoint, u.token_endpoint AS token_endpoint,
    u.userinfo_endpoint AS userinfo_endpoint, u.scopes AS scopes,
    u.show_on_login AS show_on_login, u.display_order AS display_order,
    u.logo_url AS logo_url, u.revision AS revision, u.created_at AS created_at,
    u.updated_at AS updated_at";

const IDENTITY: &str = "i.id AS id, i.profile_id AS profile_id, i.provider_id AS provider_id,
    i.upstream_subject AS upstream_subject, i.upstream_issuer AS upstream_issuer,
    i.upstream_email AS upstream_email, i.upstream_name AS upstream_name,
    i.upstream_picture AS upstream_picture, i.linked_at AS linked_at,
    i.last_login_at AS last_login_at, i.login_count AS login_count";

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn profile_of(row: &Row, name: &str) -> SidResult<ProfileId> {
    ProfileId::from_slice(&get_bytes(row, name)?)
        .map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

/// Claim the node of `label` whose `id` is `value` for a record created
/// under it, or refuse the reference to it.
fn claim_ref(tx: &Statements<'_>, label: &str, value: Value, what: &str) -> SidResult<()> {
    let rows = tx.run(
        &format!("MATCH (n:{label}) WHERE n.id = $id RETURN id(n) AS node"),
        Params::default().with("id", value),
    )?;
    if !claim_first(tx, &rows)? {
        return Err(SidError::NotFound(what.to_owned()));
    }
    Ok(())
}

fn count(value: i64, name: &str) -> SidResult<u64> {
    u64::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
}

// === Consents ===

fn claim(row: &Row) -> SidResult<ClaimGrant> {
    Ok(ClaimGrant {
        id: ClaimGrantId(get_uuid(row, "id")?),
        consent_id: ConsentId(get_uuid(row, "consent_id")?),
        claim_name: get_text(row, "claim_name")?,
        claim_type: get_parsed(row, "claim_type")?,
        granted_at: get_time(row, "granted_at")?,
        revoked_at: get_opt_time(row, "revoked_at")?,
    })
}

fn consent(tx: &Statements<'_>, row: &Row) -> SidResult<ConsentRecord> {
    let id = get_uuid(row, "id")?;
    let rows = tx.run(
        &format!("MATCH (g:SidClaimGrant) WHERE g.consent_id = $id RETURN {CLAIM}"),
        Params::default().with("id", uuid(&id)),
    )?;
    let grants = rows.iter().map(claim).collect::<SidResult<Vec<_>>>()?;
    Ok(ConsentRecord {
        id: ConsentId(id),
        profile_id: profile_of(row, "profile_id")?,
        client_id: get_text(row, "client_id")?,
        status: get_parsed(row, "status")?,
        // Oldest grant first.
        grants: super::sorted_page(grants, |g| (g.granted_at, g.id.0), 0, u64::MAX),
        consented_at: get_time(row, "consented_at")?,
        revoked_at: get_opt_time(row, "revoked_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn consents_where(
    tx: &Statements<'_>,
    filter: &str,
    params: Params,
) -> SidResult<Vec<ConsentRecord>> {
    let rows = tx.run(
        &format!("MATCH (c:SidConsent) WHERE {filter} RETURN {CONSENT}"),
        params,
    )?;
    rows.iter().map(|row| consent(tx, row)).collect()
}

fn claim_pair(consent_id: ConsentId, claim_name: &str) -> SidResult<Value> {
    key(&[consent_id.0.as_bytes(), claim_name.as_bytes()])
}

fn insert_claim(tx: &Statements<'_>, consent_id: ConsentId, g: &ClaimGrant) -> SidResult<()> {
    tx.run(
        "CREATE (g:SidClaimGrant {id: $id, pair: $pair, consent_id: $consent_id,
            claim_name: $claim_name, claim_type: $claim_type, granted_at: $granted_at,
            revoked_at: $revoked_at})",
        Params::default()
            .with("id", uuid(&g.id.0))
            .with("pair", claim_pair(consent_id, &g.claim_name)?)
            .with("consent_id", uuid(&consent_id.0))
            .with("claim_name", Value::String(g.claim_name.clone()))
            .with("claim_type", Value::String(g.claim_type.as_str().into()))
            .with("granted_at", time(g.granted_at))
            .with("revoked_at", opt_time(g.revoked_at)),
    )?;
    Ok(())
}

// === Profile grants ===

fn grant(row: &Row) -> SidResult<ProfileGrant> {
    Ok(ProfileGrant {
        id: ProfileGrantId(get_uuid(row, "id")?),
        project_id: ProjectId::from_slice(&get_bytes(row, "project_id")?)
            .map_err(|e| SidError::Storage(format!("project_id: {e}")))?,
        profile_id: profile_of(row, "profile_id")?,
        role_keys: get_texts(row, "role_keys")?,
        granted_by: get_opt_text(row, "granted_by")?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn grants_where(tx: &Statements<'_>, filter: &str, value: Value) -> SidResult<Vec<ProfileGrant>> {
    let rows = tx.run(
        &format!("MATCH (g:SidProfileGrant) WHERE {filter} RETURN {GRANT}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(grant).collect()
}

// === Upstream providers and identities ===

// A malformed secret, protocol or trust category is an error: never a
// made-up secret, OIDC or social.
fn provider(row: &Row) -> SidResult<UpstreamProvider> {
    let display_order = get_int(row, "display_order")?;
    Ok(UpstreamProvider {
        id: UpstreamProviderId(get_uuid(row, "id")?),
        name: get_text(row, "name")?,
        protocol: get_parsed(row, "protocol")?,
        trust_category: get_parsed(row, "trust_category")?,
        enabled: get_bool(row, "enabled")?,
        client_id: get_text(row, "client_id")?,
        client_secret: EncryptedField::from_bytes(&get_bytes(row, "client_secret")?)
            .map_err(|e| SidError::Storage(format!("client_secret: {e}")))?,
        discovery_url: get_opt_text(row, "discovery_url")?,
        authorization_endpoint: get_opt_text(row, "authorization_endpoint")?,
        token_endpoint: get_opt_text(row, "token_endpoint")?,
        userinfo_endpoint: get_opt_text(row, "userinfo_endpoint")?,
        scopes: get_texts(row, "scopes")?,
        show_on_login: get_bool(row, "show_on_login")?,
        display_order: i32::try_from(display_order)
            .map_err(|_| SidError::Storage(format!("display_order: {display_order}")))?,
        logo_url: get_opt_text(row, "logo_url")?,
        revision: count(get_int(row, "revision")?, "revision")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn provider_params(p: &UpstreamProvider) -> SidResult<Params> {
    Ok(Params::default()
        .with("id", uuid(&p.id.0))
        .with("name", Value::String(p.name.clone()))
        .with("protocol", Value::String(p.protocol.as_str().into()))
        .with(
            "trust_category",
            Value::String(p.trust_category.as_str().into()),
        )
        .with("enabled", Value::Bool(p.enabled))
        .with("client_id", Value::String(p.client_id.clone()))
        .with("client_secret", Value::Binary(p.client_secret.to_bytes()))
        .with("discovery_url", opt_text(p.discovery_url.as_deref()))
        .with(
            "authorization_endpoint",
            opt_text(p.authorization_endpoint.as_deref()),
        )
        .with("token_endpoint", opt_text(p.token_endpoint.as_deref()))
        .with(
            "userinfo_endpoint",
            opt_text(p.userinfo_endpoint.as_deref()),
        )
        .with("scopes", texts(&p.scopes))
        .with("show_on_login", Value::Bool(p.show_on_login))
        .with("display_order", Value::Int(i64::from(p.display_order)))
        .with("logo_url", opt_text(p.logo_url.as_deref()))
        .with(
            "revision",
            Value::Int(
                i64::try_from(p.revision)
                    .map_err(|_| SidError::Validation("provider revision".into()))?,
            ),
        )
        .with("created_at", time(p.created_at))
        .with("updated_at", time(p.updated_at)))
}

fn identity(row: &Row) -> SidResult<UpstreamIdentity> {
    Ok(UpstreamIdentity {
        id: UpstreamIdentityId(get_uuid(row, "id")?),
        profile_id: profile_of(row, "profile_id")?,
        provider_id: UpstreamProviderId(get_uuid(row, "provider_id")?),
        upstream_subject: get_text(row, "upstream_subject")?,
        upstream_issuer: get_opt_text(row, "upstream_issuer")?,
        upstream_email: get_opt_text(row, "upstream_email")?,
        upstream_name: get_opt_text(row, "upstream_name")?,
        upstream_picture: get_opt_text(row, "upstream_picture")?,
        linked_at: get_time(row, "linked_at")?,
        last_login_at: get_opt_time(row, "last_login_at")?,
        login_count: count(get_int(row, "login_count")?, "login_count")?,
    })
}

fn identities_where(
    tx: &Statements<'_>,
    filter: &str,
    params: Params,
) -> SidResult<Vec<UpstreamIdentity>> {
    let rows = tx.run(
        &format!("MATCH (i:SidUpstreamIdentity) WHERE {filter} RETURN {IDENTITY}"),
        params,
    )?;
    rows.iter().map(identity).collect()
}

/// Delete in `tx` the consents, grants and linked identities of `profile`.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (c:SidConsent) WHERE c.profile_id = $id RETURN c.id AS id",
        Params::default().with("id", bin(profile.as_bytes())),
    )?;
    for row in &rows {
        tx.run(
            "MATCH (g:SidClaimGrant) WHERE g.consent_id = $id DETACH DELETE g",
            Params::default().with("id", uuid(&get_uuid(row, "id")?)),
        )?;
    }
    for query in [
        "MATCH (c:SidConsent) WHERE c.profile_id = $id DETACH DELETE c",
        "MATCH (g:SidProfileGrant) WHERE g.profile_id = $id DETACH DELETE g",
        "MATCH (i:SidUpstreamIdentity) WHERE i.profile_id = $id DETACH DELETE i",
    ] {
        tx.run(query, Params::default().with("id", bin(profile.as_bytes())))?;
    }
    Ok(())
}

/// Delete in `tx` the profile grants of `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    tx.run(
        "MATCH (g:SidProfileGrant) WHERE g.project_id = $id DETACH DELETE g",
        Params::default().with("id", bin(project.as_bytes())),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    // === Consents ===

    pub(super) async fn create_consent(
        &self,
        c: &ConsentRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let c = c.clone();
        self.mutate(format!("consent:{}", c.id.0), ctx, move |tx| {
            claim_ref(
                tx,
                "SidProfile",
                bin(c.profile_id.as_bytes()),
                &format!("profile {}", c.profile_id),
            )?;
            if !consents_where(
                tx,
                "c.id = $id",
                Params::default().with("id", uuid(&c.id.0)),
            )?
            .is_empty()
            {
                return Err(SidError::Conflict("consent already exists".into()));
            }
            tx.run(
                "CREATE (c:SidConsent {id: $id, pair: $pair, profile_id: $profile_id,
                    client_id: $client_id, status: $status, consented_at: $consented_at,
                    revoked_at: $revoked_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", uuid(&c.id.0))
                    .with(
                        "pair",
                        key(&[c.profile_id.as_bytes(), c.client_id.as_bytes()])?,
                    )
                    .with("profile_id", bin(c.profile_id.as_bytes()))
                    .with("client_id", Value::String(c.client_id.clone()))
                    .with("status", Value::String(c.status.as_str().into()))
                    .with("consented_at", time(c.consented_at))
                    .with("revoked_at", opt_time(c.revoked_at))
                    .with("updated_at", time(c.updated_at)),
            )?;
            for g in &c.grants {
                insert_claim(tx, c.id, g)?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn change_claim_grant(
        &self,
        id: ConsentId,
        claim_name: &str,
        decision: ClaimDecision,
        ctx: MutationContext,
    ) -> SidResult<ClaimGrantChange> {
        let claim_name = claim_name.to_owned();
        self.transaction(move |tx| {
            let active =
                consents_where(tx, "c.id = $id", Params::default().with("id", uuid(&id.0)))?
                    .pop()
                    .is_some_and(|c| c.status.as_str() == "active");
            if !active {
                return Ok(Decision::Abandon(ClaimGrantChange::ConsentNotActive));
            }
            let now = Utc::now();
            let pair = claim_pair(id, &claim_name)?;
            let stored = tx
                .run(
                    &format!("MATCH (g:SidClaimGrant) WHERE g.pair = $pair RETURN {CLAIM}"),
                    Params::default().with("pair", pair.clone()),
                )?
                .first()
                .map(claim)
                .transpose()?;
            let changed = match (decision, stored) {
                (ClaimDecision::Grant(claim_type), None) => {
                    let g = ClaimGrant {
                        id: ClaimGrantId(uuid::Uuid::now_v7()),
                        consent_id: id,
                        claim_name: claim_name.clone(),
                        claim_type,
                        granted_at: now,
                        revoked_at: None,
                    };
                    insert_claim(tx, id, &g)?;
                    true
                }
                (ClaimDecision::Grant(claim_type), Some(g)) if g.revoked_at.is_some() => {
                    tx.run(
                        "MATCH (g:SidClaimGrant) WHERE g.pair = $pair
                         SET g.claim_type = $claim_type, g.granted_at = $now, g.revoked_at = null",
                        Params::default()
                            .with("pair", pair)
                            .with("claim_type", Value::String(claim_type.as_str().into()))
                            .with("now", time(now)),
                    )?;
                    true
                }
                (ClaimDecision::Revoke, Some(g)) if g.revoked_at.is_none() => {
                    tx.run(
                        "MATCH (g:SidClaimGrant) WHERE g.pair = $pair SET g.revoked_at = $now",
                        Params::default().with("pair", pair).with("now", time(now)),
                    )?;
                    true
                }
                _ => false,
            };
            if !changed {
                return match &ctx.operation {
                    Some(completion) => {
                        super::operation::record(tx, completion)?;
                        Ok(Decision::Commit(ClaimGrantChange::Unchanged))
                    }
                    None => Ok(Decision::Abandon(ClaimGrantChange::Unchanged)),
                };
            }
            // Written: a revocation or deletion of the consent meanwhile
            // conflicts with this decision.
            tx.run(
                "MATCH (c:SidConsent) WHERE c.id = $id SET c.updated_at = $now",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("now", time(now)),
            )?;
            finalize(tx, &format!("consent:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(ClaimGrantChange::Changed))
        })
        .await
    }

    pub(super) async fn get_consent(&self, id: ConsentId) -> SidResult<Option<ConsentRecord>> {
        self.read(move |tx| {
            Ok(consents_where(tx, "c.id = $id", Params::default().with("id", uuid(&id.0)))?.pop())
        })
        .await
    }

    pub(super) async fn get_consent_by_client(
        &self,
        profile: ProfileId,
        client_id: &str,
    ) -> SidResult<Option<ConsentRecord>> {
        let pair = key(&[profile.as_bytes(), client_id.as_bytes()])?;
        self.read(move |tx| {
            Ok(consents_where(
                tx,
                "c.pair = $pair",
                Params::default().with("pair", pair.clone()),
            )?
            .pop())
        })
        .await
    }

    pub(super) async fn list_consents_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<ConsentRecord>> {
        self.read(move |tx| {
            let all = consents_where(
                tx,
                "c.profile_id = $id",
                Params::default().with("id", bin(profile.as_bytes())),
            )?;
            // Newest first.
            Ok(super::sorted_page(
                all,
                |c| (std::cmp::Reverse(c.consented_at), std::cmp::Reverse(c.id.0)),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn revoke_consents_by_profile(
        &self,
        profile: ProfileId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let now = time(Utc::now());
            let consents = consents_where(
                tx,
                "c.profile_id = $id",
                Params::default().with("id", bin(profile.as_bytes())),
            )?;
            let mut revoked = 0u64;
            for c in &consents {
                if c.status.as_str() == "active" {
                    tx.run(
                        "MATCH (c:SidConsent) WHERE c.id = $id
                         SET c.status = 'revoked', c.revoked_at = $now, c.updated_at = $now",
                        Params::default()
                            .with("id", uuid(&c.id.0))
                            .with("now", now.clone()),
                    )?;
                    revoked += 1;
                } else if c.status.as_str() != "revoked" {
                    continue;
                }
                // A revoked consent shares nothing: its grants end with it.
                tx.run(
                    "MATCH (g:SidClaimGrant) WHERE g.consent_id = $id AND g.revoked_at IS NULL
                     SET g.revoked_at = $now",
                    Params::default()
                        .with("id", uuid(&c.id.0))
                        .with("now", now.clone()),
                )?;
            }
            finalize(tx, &format!("profile:{profile}:consents"), ctx.clone())?;
            Ok(Decision::Commit(revoked))
        })
        .await
    }

    pub(super) async fn delete_consent(
        &self,
        id: ConsentId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidConsent) WHERE c.id = $id DETACH DELETE c RETURN count(*) AS n",
                Params::default().with("id", uuid(&id.0)),
            )?;
            if super::get_count(&rows)? == 0 {
                return Ok(Decision::Abandon(false));
            }
            // Its claim grants go with it.
            tx.run(
                "MATCH (g:SidClaimGrant) WHERE g.consent_id = $id DETACH DELETE g",
                Params::default().with("id", uuid(&id.0)),
            )?;
            finalize(tx, &format!("consent:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Profile grants ===

    pub(super) async fn get_profile_grant(
        &self,
        id: ProfileGrantId,
    ) -> SidResult<Option<ProfileGrant>> {
        self.read(move |tx| Ok(grants_where(tx, "g.id = $value", uuid(&id.0))?.pop()))
            .await
    }

    pub(super) async fn create_profile_grant(
        &self,
        g: &ProfileGrant,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let g = g.clone();
        self.mutate(format!("profile_grant:{}", g.id.0), ctx, move |tx| {
            claim_ref(
                tx,
                "SidProject",
                bin(g.project_id.as_bytes()),
                &format!("project {}", g.project_id),
            )?;
            claim_ref(
                tx,
                "SidProfile",
                bin(g.profile_id.as_bytes()),
                &format!("profile {}", g.profile_id),
            )?;
            if !grants_where(tx, "g.id = $value", uuid(&g.id.0))?.is_empty() {
                return Err(SidError::Conflict("profile grant already exists".into()));
            }
            tx.run(
                "CREATE (g:SidProfileGrant {id: $id, pair: $pair, project_id: $project_id,
                    profile_id: $profile_id, role_keys: $role_keys, granted_by: $granted_by,
                    expires_at: $expires_at, created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", uuid(&g.id.0))
                    .with(
                        "pair",
                        key(&[g.project_id.as_bytes(), g.profile_id.as_bytes()])?,
                    )
                    .with("project_id", bin(g.project_id.as_bytes()))
                    .with("profile_id", bin(g.profile_id.as_bytes()))
                    .with("role_keys", texts(&g.role_keys))
                    .with("granted_by", opt_text(g.granted_by.as_deref()))
                    .with("expires_at", opt_time(g.expires_at))
                    .with("created_at", time(g.created_at))
                    .with("updated_at", time(g.updated_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn delete_profile_grant(
        &self,
        id: ProfileGrantId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("profile_grant:{}", id.0), ctx, move |tx| {
            tx.run(
                "MATCH (g:SidProfileGrant) WHERE g.id = $id DETACH DELETE g",
                Params::default().with("id", uuid(&id.0)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list_profile_grants_for_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<ProfileGrant>> {
        self.read(move |tx| grants_where(tx, "g.profile_id = $value", bin(profile.as_bytes())))
            .await
    }

    pub(super) async fn list_profile_grants_for_project(
        &self,
        project: ProjectId,
    ) -> SidResult<Vec<ProfileGrant>> {
        self.read(move |tx| grants_where(tx, "g.project_id = $value", bin(project.as_bytes())))
            .await
    }

    // === Upstream providers ===

    pub(super) async fn get_upstream_provider(
        &self,
        id: UpstreamProviderId,
    ) -> SidResult<Option<UpstreamProvider>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (u:SidUpstreamProvider) WHERE u.id = $id RETURN {PROVIDER}"),
                Params::default().with("id", uuid(&id.0)),
            )?;
            rows.first().map(provider).transpose()
        })
        .await
    }

    pub(super) async fn create_upstream_provider(
        &self,
        p: &UpstreamProvider,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let params = provider_params(p)?;
        self.mutate(format!("upstream_provider:{}", p.id.0), ctx, move |tx| {
            let found = tx.run(
                "MATCH (u:SidUpstreamProvider) WHERE u.id = $id RETURN u.id AS id",
                params.clone(),
            )?;
            if !found.is_empty() {
                return Err(SidError::Conflict(
                    "upstream provider already exists".into(),
                ));
            }
            tx.run(
                "CREATE (u:SidUpstreamProvider {id: $id, name: $name, protocol: $protocol,
                    trust_category: $trust_category, enabled: $enabled, client_id: $client_id,
                    client_secret: $client_secret, discovery_url: $discovery_url,
                    authorization_endpoint: $authorization_endpoint,
                    token_endpoint: $token_endpoint, userinfo_endpoint: $userinfo_endpoint,
                    scopes: $scopes, show_on_login: $show_on_login,
                    display_order: $display_order, logo_url: $logo_url, revision: $revision,
                    created_at: $created_at, updated_at: $updated_at})",
                params.clone(),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn update_upstream_provider(
        &self,
        p: &UpstreamProvider,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (params, chain) = (provider_params(p)?, format!("upstream_provider:{}", p.id.0));
        self.transaction(move |tx| {
            // Over the revision it was read at; the creation time never
            // changes.
            let rows = tx.run(
                "MATCH (u:SidUpstreamProvider) WHERE u.id = $id AND u.revision = $revision
                   AND u.created_at = $created_at
                 SET u.name = $name, u.protocol = $protocol, u.trust_category = $trust_category,
                     u.enabled = $enabled, u.client_id = $client_id,
                     u.client_secret = $client_secret, u.discovery_url = $discovery_url,
                     u.authorization_endpoint = $authorization_endpoint,
                     u.token_endpoint = $token_endpoint, u.userinfo_endpoint = $userinfo_endpoint,
                     u.scopes = $scopes, u.show_on_login = $show_on_login,
                     u.display_order = $display_order, u.logo_url = $logo_url,
                     u.updated_at = $updated_at, u.revision = u.revision + 1
                 RETURN u.id AS id",
                params.clone(),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_upstream_provider(
        &self,
        id: UpstreamProviderId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("upstream_provider:{}", id.0), ctx, move |tx| {
            // Its linked identities go with it.
            for query in [
                "MATCH (i:SidUpstreamIdentity) WHERE i.provider_id = $id DETACH DELETE i",
                "MATCH (u:SidUpstreamProvider) WHERE u.id = $id DETACH DELETE u",
            ] {
                tx.run(query, Params::default().with("id", uuid(&id.0)))?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn list_enabled_upstream_providers(&self) -> SidResult<Vec<UpstreamProvider>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!("MATCH (u:SidUpstreamProvider) WHERE u.enabled = true RETURN {PROVIDER}"),
                Params::default(),
            )?;
            let all = rows.iter().map(provider).collect::<SidResult<Vec<_>>>()?;
            Ok(super::sorted_page(
                all,
                |p| (p.display_order, p.id.0),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    // === Upstream identities ===

    pub(super) async fn get_upstream_identity_by_provider_subject(
        &self,
        provider_id: UpstreamProviderId,
        subject: &str,
    ) -> SidResult<Option<UpstreamIdentity>> {
        let subject_key = key(&[provider_id.0.as_bytes(), subject.as_bytes()])?;
        self.read(move |tx| {
            Ok(identities_where(
                tx,
                "i.subject_key = $key",
                Params::default().with("key", subject_key.clone()),
            )?
            .pop())
        })
        .await
    }

    pub(super) async fn create_upstream_identity(
        &self,
        i: &UpstreamIdentity,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let i = i.clone();
        self.mutate(format!("upstream_identity:{}", i.id.0), ctx, move |tx| {
            claim_ref(
                tx,
                "SidProfile",
                bin(i.profile_id.as_bytes()),
                &format!("profile {}", i.profile_id),
            )?;
            claim_ref(
                tx,
                "SidUpstreamProvider",
                uuid(&i.provider_id.0),
                &format!("upstream provider {}", i.provider_id.0),
            )?;
            if !identities_where(
                tx,
                "i.id = $id",
                Params::default().with("id", uuid(&i.id.0)),
            )?
            .is_empty()
            {
                return Err(SidError::Conflict(
                    "upstream identity already exists".into(),
                ));
            }
            tx.run(
                "CREATE (i:SidUpstreamIdentity {id: $id, profile_key: $profile_key,
                    subject_key: $subject_key, profile_id: $profile_id, provider_id: $provider_id,
                    upstream_subject: $upstream_subject, upstream_issuer: $upstream_issuer,
                    upstream_email: $upstream_email, upstream_name: $upstream_name,
                    upstream_picture: $upstream_picture, linked_at: $linked_at,
                    last_login_at: $last_login_at, login_count: $login_count})",
                Params::default()
                    .with("id", uuid(&i.id.0))
                    .with(
                        "profile_key",
                        key(&[i.profile_id.as_bytes(), i.provider_id.0.as_bytes()])?,
                    )
                    .with(
                        "subject_key",
                        key(&[i.provider_id.0.as_bytes(), i.upstream_subject.as_bytes()])?,
                    )
                    .with("profile_id", bin(i.profile_id.as_bytes()))
                    .with("provider_id", uuid(&i.provider_id.0))
                    .with(
                        "upstream_subject",
                        Value::String(i.upstream_subject.clone()),
                    )
                    .with("upstream_issuer", opt_text(i.upstream_issuer.as_deref()))
                    .with("upstream_email", opt_text(i.upstream_email.as_deref()))
                    .with("upstream_name", opt_text(i.upstream_name.as_deref()))
                    .with("upstream_picture", opt_text(i.upstream_picture.as_deref()))
                    .with("linked_at", time(i.linked_at))
                    .with("last_login_at", opt_time(i.last_login_at))
                    .with(
                        "login_count",
                        Value::Int(
                            i64::try_from(i.login_count)
                                .map_err(|_| SidError::Validation("login count".into()))?,
                        ),
                    ),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn record_upstream_login(
        &self,
        id: UpstreamIdentityId,
        login: &UpstreamLogin,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let login = login.clone();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (i:SidUpstreamIdentity) WHERE i.id = $id
                 SET i.upstream_email = $email, i.upstream_name = $name,
                     i.upstream_picture = $picture, i.last_login_at = $at,
                     i.login_count = i.login_count + 1
                 RETURN i.id AS id",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("email", opt_text(login.email.as_deref()))
                    .with("name", opt_text(login.name.as_deref()))
                    .with("picture", opt_text(login.picture.as_deref()))
                    .with("at", time(login.at)),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("upstream_identity:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn list_upstream_identities_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<UpstreamIdentity>> {
        self.read(move |tx| {
            identities_where(
                tx,
                "i.profile_id = $id",
                Params::default().with("id", bin(profile.as_bytes())),
            )
        })
        .await
    }

    pub(super) async fn delete_upstream_identity(
        &self,
        id: UpstreamIdentityId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("upstream_identity:{}", id.0), ctx, move |tx| {
            tx.run(
                "MATCH (i:SidUpstreamIdentity) WHERE i.id = $id DETACH DELETE i",
                Params::default().with("id", uuid(&id.0)),
            )?;
            Ok(())
        })
        .await
    }
}
