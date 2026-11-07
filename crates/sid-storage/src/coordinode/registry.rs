// SPDX-License-Identifier: AGPL-3.0-only
//! The registry in CoordiNode: OIDC issuers and their signing keys, the
//! installation's organization, applications with their client and
//! resource roles, client-to-resource access and initial access tokens.
//!
//! Every reference a role holds (its project, application, issuer,
//! organization, default resource) is held for the commit, so a removal or
//! retirement committed meanwhile refuses the write that relied on it, as a
//! foreign key would. Uniqueness is the store's: one client role per
//! application, one resource per issuer and indicator, one application per
//! system integration, one instance organization, one issuer per authority
//! and organization. A dynamic registration counts its use on its token's
//! node, so concurrent registrations under one token count exactly.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    Application, ApplicationId, InitialAccessToken, InitialAccessTokenId, IssuerAuthority,
    IssuerHandle, IssuerId, IssuerSigningKey, MutationContext, OAuth2Client, OidcIssuer, OrgId,
    Organization, ProjectId, ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator,
    ResourceState, SystemIntegration,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bool,
    get_bytes, get_count, get_id, get_int, get_opt_bytes, get_opt_id, get_opt_parsed, get_opt_text,
    get_opt_time, get_opt_uuid, get_parsed, get_text, get_texts, get_time, get_uuid, hold_first,
    key, opt_text, opt_time, opt_uuid, page, sorted_page, texts, time, uuid,
};

const ISSUER: &str = "i.id AS id, i.handle AS handle, i.canonical_url AS canonical_url,
    i.authority AS authority, i.recipient_org AS recipient_org, i.created_at AS created_at";

const APPLICATION: &str = "a.id AS id, a.project_id AS project_id, a.name AS name,
    a.system_integration AS system_integration, a.revision AS revision,
    a.created_at AS created_at, a.updated_at AS updated_at";

const RESOURCE: &str = "r.id AS id, r.application_id AS application_id,
    r.issuer_id AS issuer_id, r.indicator AS indicator, r.scopes AS scopes, r.state AS state,
    r.revision AS revision, r.created_at AS created_at, r.updated_at AS updated_at";

const ACCESS: &str = "x.client_id AS client_id, x.resource_id AS resource_id,
    x.scopes AS scopes, x.created_at AS created_at";

const CLIENT: &str = "c.client_id AS client_id, c.project_id AS project_id,
    c.application_id AS application_id, c.default_resource AS default_resource,
    c.application_type AS application_type, c.client_secret_hash AS client_secret_hash,
    c.jwks AS jwks, c.redirect_uris AS redirect_uris, c.allowed_scopes AS allowed_scopes,
    c.grant_types AS grant_types, c.client_name AS client_name, c.logo_uri AS logo_uri,
    c.active AS active, c.token_endpoint_auth_method AS token_endpoint_auth_method,
    c.response_types AS response_types, c.subject_type AS subject_type,
    c.sector_identifier_uri AS sector_identifier_uri, c.contacts AS contacts,
    c.client_id_issued_at AS client_id_issued_at,
    c.client_secret_expires_at AS client_secret_expires_at,
    c.registration_iat AS registration_iat,
    c.registration_access_token_hash AS registration_access_token_hash,
    c.required_acr AS required_acr, c.required_amr AS required_amr,
    c.enforcement_mode AS enforcement_mode, c.min_device_assurance AS min_device_assurance,
    c.require_verified_email AS require_verified_email,
    c.require_verified_phone AS require_verified_phone,
    c.backchannel_logout_uri AS backchannel_logout_uri,
    c.backchannel_logout_session_required AS backchannel_logout_session_required,
    c.post_logout_redirect_uris AS post_logout_redirect_uris,
    c.claim_mappings AS claim_mappings, c.login_strategy AS login_strategy,
    c.show_federation_button AS show_federation_button,
    c.federation_timeout_ms AS federation_timeout_ms, c.unified_input AS unified_input,
    c.org_id AS org_id, c.revision AS revision, c.created_at AS created_at";

const TOKEN: &str = "t.id AS id, t.token_hash AS token_hash, t.project_id AS project_id,
    t.max_clients AS max_clients, t.clients_registered AS clients_registered,
    t.allowed_scopes AS allowed_scopes, t.allowed_grant_types AS allowed_grant_types,
    t.allowed_redirect_patterns AS allowed_redirect_patterns, t.created_by AS created_by,
    t.revoked AS revoked, t.expires_at AS expires_at, t.created_at AS created_at";

fn stored(name: &str) -> impl FnOnce(sid_ids::IdError) -> SidError + '_ {
    move |e| SidError::Storage(format!("{name}: {e}"))
}

fn revision_of(row: &Row) -> SidResult<u64> {
    let value = get_int(row, "revision")?;
    u64::try_from(value).map_err(|_| SidError::Storage(format!("revision: {value}")))
}

fn revision(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation(format!("revision {value} out of range")))
}

fn next_revision(value: u64) -> SidResult<Value> {
    revision(
        value
            .checked_add(1)
            .ok_or_else(|| SidError::Validation("revision exhausted".into()))?,
    )
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

// === Issuers and the instance organization ===

fn issuer(row: &Row) -> SidResult<OidcIssuer> {
    let id = IssuerId::from_uuid(get_uuid(row, "id")?).map_err(stored("issuer id"))?;
    Ok(OidcIssuer {
        id,
        handle: IssuerHandle::parse(&get_text(row, "handle")?)
            .map_err(|e| SidError::Storage(format!("oidc issuer {id}: {e}")))?,
        canonical_url: get_text(row, "canonical_url")?,
        authority: get_parsed(row, "authority")?,
        recipient_org: OrgId::from_uuid(get_uuid(row, "recipient_org")?)
            .map_err(stored("recipient org"))?,
        created_at: get_time(row, "created_at")?,
    })
}

fn authority_key(authority: IssuerAuthority, org: OrgId) -> SidResult<Value> {
    key(&[authority.as_str().as_bytes(), org.as_bytes()])
}

fn organization(row: &Row) -> SidResult<Organization> {
    Ok(Organization {
        id: OrgId::from_uuid(get_uuid(row, "id")?).map_err(stored("org id"))?,
        org_type: get_parsed(row, "org_type")?,
        status: get_parsed(row, "status")?,
        canonical_domain: get_text(row, "canonical_domain")?,
        created_at: get_time(row, "created_at")?,
    })
}

/// Hold the organization `id` for the commit, or refuse a reference to it.
fn hold_org(tx: &Statements<'_>, id: OrgId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (o:SidOrganization) WHERE o.id = $id RETURN id(o) AS node",
        Params::default().with("id", uuid(id.as_uuid())),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(SidError::NotFound(format!("organization {id}")));
    }
    Ok(())
}

/// Create the node of `issuer`; its id, handle, URL and authority key are
/// unique.
fn create_issuer(tx: &Statements<'_>, issuer: &OidcIssuer) -> SidResult<()> {
    tx.run(
        "CREATE (i:SidIssuer {id: $id, handle: $handle, canonical_url: $canonical_url,
            authority: $authority, recipient_org: $recipient_org, authority_key: $key,
            created_at: $created_at})",
        Params::default()
            .with("id", uuid(issuer.id.as_uuid()))
            .with("handle", text(issuer.handle.as_str()))
            .with("canonical_url", text(&issuer.canonical_url))
            .with("authority", text(issuer.authority.as_str()))
            .with("recipient_org", uuid(issuer.recipient_org.as_uuid()))
            .with(
                "key",
                authority_key(issuer.authority, issuer.recipient_org)?,
            )
            .with("created_at", time(issuer.created_at)),
    )?;
    Ok(())
}

/// Create the node of signing key `k`; its issuer and generation are unique.
fn create_issuer_key(tx: &Statements<'_>, k: &IssuerSigningKey) -> SidResult<()> {
    tx.run(
        "CREATE (k:SidIssuerKey {issuer_id: $issuer_id, generation_key: $generation_key,
            generation: $generation, key_id: $key_id, public_key: $public_key,
            sealed_private_key: $sealed, created_at: $created_at})",
        Params::default()
            .with("issuer_id", uuid(k.issuer_id.as_uuid()))
            .with(
                "generation_key",
                key(&[k.issuer_id.as_bytes(), &k.generation.to_be_bytes()])?,
            )
            .with("generation", Value::Int(i64::from(k.generation)))
            .with("key_id", text(&k.key_id))
            .with("public_key", Value::Binary(k.public_key.to_vec()))
            .with("sealed", Value::Binary(k.sealed_private_key.clone()))
            .with("created_at", time(k.created_at)),
    )?;
    Ok(())
}

/// Every signing key of `issuer_id`, ascending by generation.
fn issuer_keys(tx: &Statements<'_>, issuer_id: IssuerId) -> SidResult<Vec<IssuerSigningKey>> {
    let rows = tx.run(
        "MATCH (k:SidIssuerKey) WHERE k.issuer_id = $id
         RETURN k.issuer_id AS issuer_id, k.generation AS generation, k.key_id AS key_id,
                k.public_key AS public_key, k.sealed_private_key AS sealed,
                k.created_at AS created_at
         ORDER BY k.generation",
        Params::default().with("id", uuid(issuer_id.as_uuid())),
    )?;
    rows.iter()
        .map(|row| {
            let generation = get_int(row, "generation")?;
            Ok(IssuerSigningKey {
                issuer_id: IssuerId::from_uuid(get_uuid(row, "issuer_id")?)
                    .map_err(stored("key issuer"))?,
                generation: u32::try_from(generation)
                    .map_err(|_| SidError::Storage(format!("generation: {generation}")))?,
                key_id: get_text(row, "key_id")?,
                public_key: get_bytes(row, "public_key")?
                    .try_into()
                    .map_err(|_| SidError::Storage("public key is not 32 bytes".into()))?,
                sealed_private_key: get_bytes(row, "sealed")?,
                created_at: get_time(row, "created_at")?,
            })
        })
        .collect()
}

// === Applications ===

fn application(row: &Row) -> SidResult<Application> {
    Ok(Application {
        id: ApplicationId::from_uuid(get_uuid(row, "id")?).map_err(stored("application id"))?,
        project_id: ProjectId::from_uuid(get_uuid(row, "project_id")?)
            .map_err(stored("application project"))?,
        name: get_text(row, "name")?,
        system: get_opt_parsed(row, "system_integration")?,
        revision: revision_of(row)?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn get_application(tx: &Statements<'_>, id: ApplicationId) -> SidResult<Option<Application>> {
    let rows = tx.run(
        &format!("MATCH (a:SidApplication) WHERE a.id = $id RETURN {APPLICATION}"),
        Params::default().with("id", uuid(id.as_uuid())),
    )?;
    rows.first().map(application).transpose()
}

/// What the open transaction created itself: references to it commit with
/// it and need no hold (a hold reads committed versions only).
#[derive(Default, Clone, Copy)]
pub(super) struct Created {
    pub(super) application: Option<ApplicationId>,
    pub(super) resource: Option<ResourceId>,
}

/// Claim application `id` of `project` for a role created under it; false
/// when it is not stored there.
fn claim_application(
    tx: &Statements<'_>,
    id: ApplicationId,
    project: ProjectId,
    created: Created,
) -> SidResult<bool> {
    if created.application == Some(id) {
        return Ok(get_application(tx, id)?.is_some_and(|a| a.project_id == project));
    }
    let rows = tx.run(
        "MATCH (a:SidApplication) WHERE a.id = $id AND a.project_id = $project
         RETURN id(a) AS node",
        Params::default()
            .with("id", uuid(id.as_uuid()))
            .with("project", uuid(project.as_uuid())),
    )?;
    claim_first(tx, &rows)
}

/// Store a new application in `tx`, in a project claimed for the commit.
pub(super) fn insert_application(tx: &Statements<'_>, app: &Application) -> SidResult<()> {
    let project = tx.run(
        "MATCH (j:SidProject) WHERE j.id = $id RETURN id(j) AS node",
        Params::default().with("id", uuid(app.project_id.as_uuid())),
    )?;
    if !claim_first(tx, &project)? {
        return Err(SidError::NotFound(format!("project {}", app.project_id)));
    }
    if get_application(tx, app.id)?.is_some() {
        return Err(SidError::Conflict("application already exists".into()));
    }
    tx.run(
        "CREATE (a:SidApplication {id: $id, project_id: $project_id, name: $name,
            system_integration: $system, revision: $revision, created_at: $created_at,
            updated_at: $updated_at})",
        Params::default()
            .with("id", uuid(app.id.as_uuid()))
            .with("project_id", uuid(app.project_id.as_uuid()))
            .with("name", text(&app.name))
            .with(
                "system",
                opt_text(app.system.map(SystemIntegration::as_str)),
            )
            .with("revision", revision(app.revision)?)
            .with("created_at", time(app.created_at))
            .with("updated_at", time(app.updated_at)),
    )?;
    Ok(())
}

// === Protected resources ===

fn resource(row: &Row) -> SidResult<ProtectedResource> {
    Ok(ProtectedResource {
        id: ResourceId::from_uuid(get_uuid(row, "id")?).map_err(stored("resource id"))?,
        application_id: get_opt_uuid(row, "application_id")?
            .map(ApplicationId::from_uuid)
            .transpose()
            .map_err(stored("resource application"))?,
        issuer_id: IssuerId::from_uuid(get_uuid(row, "issuer_id")?)
            .map_err(stored("resource issuer"))?,
        indicator: ResourceIndicator::parse(&get_text(row, "indicator")?)
            .map_err(|e| SidError::Storage(format!("indicator: {e}")))?,
        scopes: get_texts(row, "scopes")?,
        state: get_parsed(row, "state")?,
        revision: revision_of(row)?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn indicator_key(issuer: IssuerId, indicator: &ResourceIndicator) -> SidResult<Value> {
    key(&[issuer.as_bytes(), indicator.as_str().as_bytes()])
}

fn get_resource(tx: &Statements<'_>, id: ResourceId) -> SidResult<Option<ProtectedResource>> {
    let rows = tx.run(
        &format!("MATCH (r:SidResource) WHERE r.id = $id RETURN {RESOURCE}"),
        Params::default().with("id", uuid(id.as_uuid())),
    )?;
    rows.first().map(resource).transpose()
}

/// Store `resource` as given in `tx`, under an issuer held for the commit.
fn write_resource(tx: &Statements<'_>, resource: &ProtectedResource) -> SidResult<()> {
    let issuer = tx.run(
        "MATCH (i:SidIssuer) WHERE i.id = $id RETURN id(i) AS node",
        Params::default().with("id", uuid(resource.issuer_id.as_uuid())),
    )?;
    if !hold_first(tx, &issuer)? {
        return Err(SidError::NotFound(format!(
            "oidc issuer {}",
            resource.issuer_id
        )));
    }
    if (resource.state == ResourceState::Retired) != resource.application_id.is_none() {
        return Err(SidError::Validation(format!(
            "protected resource {} is retired exactly when it has no application",
            resource.id
        )));
    }
    tx.run(
        "CREATE (r:SidResource {id: $id, application_id: $application_id,
            issuer_id: $issuer_id, indicator_key: $indicator_key, indicator: $indicator,
            scopes: $scopes, state: $state, revision: $revision, created_at: $created_at,
            updated_at: $updated_at})",
        Params::default()
            .with("id", uuid(resource.id.as_uuid()))
            .with(
                "application_id",
                opt_uuid(resource.application_id.as_ref().map(|a| a.as_uuid())),
            )
            .with("issuer_id", uuid(resource.issuer_id.as_uuid()))
            .with(
                "indicator_key",
                indicator_key(resource.issuer_id, &resource.indicator)?,
            )
            .with("indicator", text(resource.indicator.as_str()))
            .with("scopes", texts(&resource.scopes))
            .with("state", text(resource.state.as_str()))
            .with("revision", revision(resource.revision)?)
            .with("created_at", time(resource.created_at))
            .with("updated_at", time(resource.updated_at)),
    )?;
    Ok(())
}

/// Add a live resource role to its claimed application in `tx`; a taken
/// indicator of the issuer or a second resource role is `Conflict`.
fn insert_resource(
    tx: &Statements<'_>,
    resource: &ProtectedResource,
    created: Created,
) -> SidResult<()> {
    let Some(app) = resource.application_id else {
        return Err(SidError::Validation(format!(
            "protected resource {} is registered live, under an application",
            resource.id
        )));
    };
    if resource.state == ResourceState::Retired {
        return Err(SidError::Validation(format!(
            "protected resource {} is registered live, under an application",
            resource.id
        )));
    }
    let present = if created.application == Some(app) {
        get_application(tx, app)?.is_some()
    } else {
        let held = tx.run(
            "MATCH (a:SidApplication) WHERE a.id = $id RETURN id(a) AS node",
            Params::default().with("id", uuid(app.as_uuid())),
        )?;
        claim_first(tx, &held)?
    };
    if !present {
        return Err(SidError::NotFound(format!("application {app}")));
    }
    if get_resource(tx, resource.id)?.is_some() {
        return Err(SidError::Conflict(
            "protected resource already exists".into(),
        ));
    }
    write_resource(tx, resource)
}

// === OAuth clients ===

fn client(row: &Row) -> SidResult<OAuth2Client> {
    let federation_timeout_ms = get_int(row, "federation_timeout_ms")?;
    let required_acr = get_opt_text(row, "required_acr")?
        .map(|s| {
            sid_core::models::session::AuthLevel::from_acr_value(&s)
                .ok_or_else(|| SidError::Storage(format!("required_acr: unknown {s:?}")))
        })
        .transpose()?;
    let claim_mappings = match row.get("claim_mappings") {
        None | Some(Value::Null) => Default::default(),
        Some(_) => super::get_document(row, "claim_mappings")?,
    };
    let opt_bool = |name: &str| -> SidResult<Option<bool>> {
        match row.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(_) => get_bool(row, name).map(Some),
        }
    };
    Ok(OAuth2Client {
        client_id: get_text(row, "client_id")?,
        project_id: ProjectId::from_uuid(get_uuid(row, "project_id")?)
            .map_err(stored("client project"))?,
        application_id: ApplicationId::from_uuid(get_uuid(row, "application_id")?)
            .map_err(stored("client application"))?,
        default_resource: get_opt_uuid(row, "default_resource")?
            .map(ResourceId::from_uuid)
            .transpose()
            .map_err(stored("default resource"))?,
        application_type: get_parsed(row, "application_type")?,
        client_secret_hash: get_opt_bytes(row, "client_secret_hash")?,
        jwks: get_opt_text(row, "jwks")?
            .map(|s| {
                sid_core::models::ClientKeySet::from_json(&s)
                    .map_err(|e| SidError::Storage(format!("jwks: {e}")))
            })
            .transpose()?,
        redirect_uris: get_texts(row, "redirect_uris")?,
        allowed_scopes: get_texts(row, "allowed_scopes")?,
        grant_types: get_texts(row, "grant_types")?,
        client_name: get_text(row, "client_name")?,
        logo_uri: get_opt_text(row, "logo_uri")?,
        active: get_bool(row, "active")?,
        token_endpoint_auth_method: get_parsed(row, "token_endpoint_auth_method")?,
        response_types: get_texts(row, "response_types")?,
        subject_type: get_parsed(row, "subject_type")?,
        sector_identifier_uri: get_opt_text(row, "sector_identifier_uri")?,
        contacts: get_texts(row, "contacts")?,
        client_id_issued_at: get_time(row, "client_id_issued_at")?,
        client_secret_expires_at: get_opt_time(row, "client_secret_expires_at")?,
        registration_iat: get_opt_id(row, "registration_iat")?,
        registration_access_token_hash: get_opt_bytes(row, "registration_access_token_hash")?,
        required_acr,
        required_amr: get_texts(row, "required_amr")?,
        enforcement_mode: get_parsed(row, "enforcement_mode")?,
        min_device_assurance: get_opt_parsed(row, "min_device_assurance")?,
        require_verified_email: opt_bool("require_verified_email")?,
        require_verified_phone: opt_bool("require_verified_phone")?,
        backchannel_logout_uri: get_opt_text(row, "backchannel_logout_uri")?,
        backchannel_logout_session_required: get_bool(row, "backchannel_logout_session_required")?,
        post_logout_redirect_uris: get_texts(row, "post_logout_redirect_uris")?,
        claim_mappings,
        login_strategy: get_parsed(row, "login_strategy")?,
        show_federation_button: get_bool(row, "show_federation_button")?,
        federation_timeout_ms: u32::try_from(federation_timeout_ms).map_err(|_| {
            SidError::Storage(format!("federation_timeout_ms: {federation_timeout_ms}"))
        })?,
        unified_input: get_bool(row, "unified_input")?,
        org_id: get_opt_uuid(row, "org_id")?
            .map(OrgId::from_uuid)
            .transpose()
            .map_err(stored("client org"))?,
        revision: revision_of(row)?,
        created_at: get_time(row, "created_at")?,
    })
}

/// Every stored property of `client`, its revision as given.
fn client_params(client: &OAuth2Client) -> SidResult<Params> {
    let claim_mappings = if client.claim_mappings.is_empty() {
        Value::Null
    } else {
        super::document(&client.claim_mappings, "claim mappings")?
    };
    let opt_bool = |v: Option<bool>| v.map_or(Value::Null, Value::Bool);
    Ok(Params::default()
        .with("client_id", text(&client.client_id))
        .with("project_id", uuid(client.project_id.as_uuid()))
        .with("application_id", uuid(client.application_id.as_uuid()))
        .with(
            "default_resource",
            opt_uuid(client.default_resource.as_ref().map(|r| r.as_uuid())),
        )
        .with("application_type", text(client.application_type.as_str()))
        .with(
            "client_secret_hash",
            client
                .client_secret_hash
                .as_ref()
                .map_or(Value::Null, |h| Value::Binary(h.clone())),
        )
        .with(
            "jwks",
            client
                .jwks
                .as_ref()
                .map_or(Value::Null, |k| Value::String(k.to_json())),
        )
        .with("redirect_uris", texts(&client.redirect_uris))
        .with("allowed_scopes", texts(&client.allowed_scopes))
        .with("grant_types", texts(&client.grant_types))
        .with("client_name", text(&client.client_name))
        .with("logo_uri", opt_text(client.logo_uri.as_deref()))
        .with("active", Value::Bool(client.active))
        .with(
            "token_endpoint_auth_method",
            text(client.token_endpoint_auth_method.as_str()),
        )
        .with("response_types", texts(&client.response_types))
        .with("subject_type", text(client.subject_type.as_str()))
        .with(
            "sector_identifier_uri",
            opt_text(client.sector_identifier_uri.as_deref()),
        )
        .with("contacts", texts(&client.contacts))
        .with("client_id_issued_at", time(client.client_id_issued_at))
        .with(
            "client_secret_expires_at",
            opt_time(client.client_secret_expires_at),
        )
        .with(
            "registration_iat",
            opt_uuid(client.registration_iat.as_ref().map(|i| i.as_uuid())),
        )
        .with(
            "registration_access_token_hash",
            client
                .registration_access_token_hash
                .as_ref()
                .map_or(Value::Null, |h| Value::Binary(h.clone())),
        )
        .with(
            "required_acr",
            opt_text(client.required_acr.map(|a| a.as_str())),
        )
        .with("required_amr", texts(&client.required_amr))
        .with("enforcement_mode", text(client.enforcement_mode.as_str()))
        .with(
            "min_device_assurance",
            opt_text(client.min_device_assurance.map(|d| d.as_str())),
        )
        .with(
            "require_verified_email",
            opt_bool(client.require_verified_email),
        )
        .with(
            "require_verified_phone",
            opt_bool(client.require_verified_phone),
        )
        .with(
            "backchannel_logout_uri",
            opt_text(client.backchannel_logout_uri.as_deref()),
        )
        .with(
            "backchannel_logout_session_required",
            Value::Bool(client.backchannel_logout_session_required),
        )
        .with(
            "post_logout_redirect_uris",
            texts(&client.post_logout_redirect_uris),
        )
        .with("claim_mappings", claim_mappings)
        .with("login_strategy", text(client.login_strategy.as_str()))
        .with(
            "show_federation_button",
            Value::Bool(client.show_federation_button),
        )
        .with(
            "federation_timeout_ms",
            Value::Int(i64::from(client.federation_timeout_ms)),
        )
        .with("unified_input", Value::Bool(client.unified_input))
        .with(
            "org_id",
            opt_uuid(client.org_id.as_ref().map(|o| o.as_uuid())),
        )
        .with("revision", revision(client.revision)?)
        .with("created_at", time(client.created_at)))
}

const CLIENT_SET: &str = "c.client_secret_hash = $client_secret_hash,
    c.redirect_uris = $redirect_uris, c.allowed_scopes = $allowed_scopes,
    c.grant_types = $grant_types, c.client_name = $client_name, c.active = $active,
    c.project_id = $project_id, c.application_type = $application_type,
    c.required_acr = $required_acr, c.required_amr = $required_amr,
    c.enforcement_mode = $enforcement_mode, c.min_device_assurance = $min_device_assurance,
    c.require_verified_email = $require_verified_email,
    c.require_verified_phone = $require_verified_phone,
    c.backchannel_logout_uri = $backchannel_logout_uri,
    c.backchannel_logout_session_required = $backchannel_logout_session_required,
    c.claim_mappings = $claim_mappings, c.logo_uri = $logo_uri,
    c.token_endpoint_auth_method = $token_endpoint_auth_method,
    c.response_types = $response_types, c.subject_type = $subject_type,
    c.sector_identifier_uri = $sector_identifier_uri, c.contacts = $contacts,
    c.client_secret_expires_at = $client_secret_expires_at,
    c.registration_access_token_hash = $registration_access_token_hash,
    c.login_strategy = $login_strategy, c.show_federation_button = $show_federation_button,
    c.federation_timeout_ms = $federation_timeout_ms, c.unified_input = $unified_input,
    c.org_id = $org_id, c.default_resource = $default_resource,
    c.post_logout_redirect_uris = $post_logout_redirect_uris, c.jwks = $jwks";

fn get_client(tx: &Statements<'_>, client_id: &str) -> SidResult<Option<OAuth2Client>> {
    let rows = tx.run(
        &format!("MATCH (c:SidClient) WHERE c.client_id = $id RETURN {CLIENT}"),
        Params::default().with("id", text(client_id)),
    )?;
    rows.first().map(client).transpose()
}

/// Hold what `client` references for the commit: its default resource,
/// claimed, since retiring a resource clears the clients it reads naming it,
/// and its organization, which is never deleted.
fn hold_client_references(
    tx: &Statements<'_>,
    client: &OAuth2Client,
    created: Created,
) -> SidResult<()> {
    if let Some(resource) = client.default_resource
        && created.resource != Some(resource)
    {
        let rows = tx.run(
            "MATCH (r:SidResource) WHERE r.id = $id RETURN id(r) AS node",
            Params::default().with("id", uuid(resource.as_uuid())),
        )?;
        if !claim_first(tx, &rows)? {
            return Err(SidError::NotFound(format!("protected resource {resource}")));
        }
    }
    if let Some(org) = client.org_id {
        hold_org(tx, org)?;
    }
    Ok(())
}

/// Add `client` as the client role of its held application in `tx`. An
/// existing `client_id`, or an application that already has a client role,
/// is `Conflict`.
pub(super) fn insert_client(
    tx: &Statements<'_>,
    client: &OAuth2Client,
    created: Created,
) -> SidResult<()> {
    if !claim_application(tx, client.application_id, client.project_id, created)? {
        return Err(SidError::NotFound(format!(
            "application {} in project {}",
            client.application_id, client.project_id
        )));
    }
    hold_client_references(tx, client, created)?;
    for (property, value) in [
        ("client_id", text(&client.client_id)),
        ("application_id", uuid(client.application_id.as_uuid())),
    ] {
        let taken = tx.run(
            &format!("MATCH (c:SidClient) WHERE c.{property} = $value RETURN c.client_id AS id"),
            Params::default().with("value", value),
        )?;
        if !taken.is_empty() {
            return Err(conflict(client));
        }
    }
    tx.run(
        "CREATE (c:SidClient {client_id: $client_id, project_id: $project_id,
            application_id: $application_id, default_resource: $default_resource,
            application_type: $application_type, client_secret_hash: $client_secret_hash,
            jwks: $jwks, redirect_uris: $redirect_uris, allowed_scopes: $allowed_scopes,
            grant_types: $grant_types, client_name: $client_name, logo_uri: $logo_uri,
            active: $active, token_endpoint_auth_method: $token_endpoint_auth_method,
            response_types: $response_types, subject_type: $subject_type,
            sector_identifier_uri: $sector_identifier_uri, contacts: $contacts,
            client_id_issued_at: $client_id_issued_at,
            client_secret_expires_at: $client_secret_expires_at,
            registration_iat: $registration_iat,
            registration_access_token_hash: $registration_access_token_hash,
            required_acr: $required_acr, required_amr: $required_amr,
            enforcement_mode: $enforcement_mode, min_device_assurance: $min_device_assurance,
            require_verified_email: $require_verified_email,
            require_verified_phone: $require_verified_phone,
            backchannel_logout_uri: $backchannel_logout_uri,
            backchannel_logout_session_required: $backchannel_logout_session_required,
            post_logout_redirect_uris: $post_logout_redirect_uris,
            claim_mappings: $claim_mappings, login_strategy: $login_strategy,
            show_federation_button: $show_federation_button,
            federation_timeout_ms: $federation_timeout_ms, unified_input: $unified_input,
            org_id: $org_id, revision: $revision, created_at: $created_at})",
        client_params(client)?,
    )?;
    Ok(())
}

fn conflict(client: &OAuth2Client) -> SidError {
    SidError::Conflict(format!(
        "oauth2 client {} exists, or application {} already has a client role",
        client.client_id, client.application_id
    ))
}

/// Delete client `client_id` with every access and role assignment it held,
/// in `tx`; returns its application.
fn delete_client(tx: &Statements<'_>, client_id: &str) -> SidResult<Option<ApplicationId>> {
    let Some(stored) = get_client(tx, client_id)? else {
        return Ok(None);
    };
    super::rbac::delete_client_records(tx, client_id)?;
    for query in [
        "MATCH (x:SidResourceAccess) WHERE x.client_id = $id DETACH DELETE x",
        "MATCH (c:SidClient) WHERE c.client_id = $id DETACH DELETE c",
    ] {
        tx.run(query, Params::default().with("id", text(client_id)))?;
    }
    Ok(Some(stored.application_id))
}

fn access(row: &Row) -> SidResult<ResourceAccess> {
    Ok(ResourceAccess {
        client_id: get_text(row, "client_id")?,
        resource_id: ResourceId::from_uuid(get_uuid(row, "resource_id")?)
            .map_err(stored("access resource"))?,
        scopes: get_texts(row, "scopes")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn access_key(client_id: &str, resource: ResourceId) -> SidResult<Value> {
    key(&[client_id.as_bytes(), resource.as_bytes()])
}

fn iat(row: &Row) -> SidResult<InitialAccessToken> {
    let count = |name: &str| -> SidResult<u32> {
        let value = get_int(row, name)?;
        u32::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
    };
    Ok(InitialAccessToken {
        id: get_id(row, "id")?,
        token_hash: get_bytes(row, "token_hash")?,
        project_id: ProjectId::from_uuid(get_uuid(row, "project_id")?)
            .map_err(stored("token project"))?,
        max_clients: count("max_clients")?,
        clients_registered: count("clients_registered")?,
        allowed_scopes: get_texts(row, "allowed_scopes")?,
        allowed_grant_types: get_texts(row, "allowed_grant_types")?,
        allowed_redirect_patterns: get_texts(row, "allowed_redirect_patterns")?,
        created_by: get_id(row, "created_by")?,
        revoked: get_bool(row, "revoked")?,
        expires_at: get_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn get_iat(
    tx: &Statements<'_>,
    property: &str,
    value: Value,
) -> SidResult<Option<InitialAccessToken>> {
    let rows = tx.run(
        &format!("MATCH (t:SidInitialAccessToken) WHERE t.{property} = $value RETURN {TOKEN}"),
        Params::default().with("value", value),
    )?;
    rows.first().map(iat).transpose()
}

impl CoordinodeBackend {
    // === Issuers ===

    pub(super) async fn oidc_issuer_for(
        &self,
        authority: IssuerAuthority,
        org: OrgId,
    ) -> SidResult<Option<OidcIssuer>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (i:SidIssuer) WHERE i.authority_key = $key RETURN {ISSUER}"),
                Params::default().with("key", authority_key(authority, org)?),
            )?;
            rows.first().map(issuer).transpose()
        })
        .await
    }

    pub(super) async fn oidc_issuer_by_handle(
        &self,
        handle: &IssuerHandle,
    ) -> SidResult<Option<OidcIssuer>> {
        let handle = handle.as_str().to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (i:SidIssuer) WHERE i.handle = $handle RETURN {ISSUER}"),
                Params::default().with("handle", text(&handle)),
            )?;
            rows.first().map(issuer).transpose()
        })
        .await
    }

    pub(super) async fn insert_oidc_issuer(
        &self,
        stored: &OidcIssuer,
        first_key: &IssuerSigningKey,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        stored.check_first_key(first_key)?;
        let (stored, first_key) = (stored.clone(), first_key.clone());
        self.transaction(move |tx| {
            hold_org(tx, stored.recipient_org)?;
            // Concurrent provisioners agree on the first issuer of the
            // authority and organization: its key is unique.
            let exists = tx.run(
                "MATCH (i:SidIssuer) WHERE i.authority_key = $key RETURN i.id AS id",
                Params::default().with(
                    "key",
                    authority_key(stored.authority, stored.recipient_org)?,
                ),
            )?;
            if !exists.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            create_issuer(tx, &stored)?;
            create_issuer_key(tx, &first_key)?;
            finalize(tx, &format!("oidc_issuer:{}", stored.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn oidc_issuer_signing_keys(
        &self,
        issuer_id: IssuerId,
    ) -> SidResult<Vec<IssuerSigningKey>> {
        self.read(move |tx| issuer_keys(tx, issuer_id)).await
    }

    pub(super) async fn list_oidc_issuers(&self) -> SidResult<Vec<OidcIssuer>> {
        self.read(|tx| {
            let rows = tx.run(
                &format!("MATCH (i:SidIssuer) RETURN {ISSUER} ORDER BY i.created_at, i.id"),
                Params::default(),
            )?;
            rows.iter().map(issuer).collect()
        })
        .await
    }

    pub(super) async fn import_oidc_issuer(
        &self,
        restored: &OidcIssuer,
        keys: &[IssuerSigningKey],
        ctx: MutationContext,
    ) -> SidResult<bool> {
        restored.check_keys(keys)?;
        let (restored, keys) = (restored.clone(), keys.to_vec());
        self.transaction(move |tx| {
            hold_org(tx, restored.recipient_org)?;
            let rows = tx.run(
                &format!("MATCH (i:SidIssuer) WHERE i.id = $id RETURN {ISSUER}, id(i) AS node"),
                Params::default().with("id", uuid(restored.id.as_uuid())),
            )?;
            if let Some(row) = rows.first() {
                // Its node is held: a concurrent change of it conflicts.
                super::hold_first(tx, &rows)?;
                return if issuer(row)? == restored && issuer_keys(tx, restored.id)? == keys {
                    Ok(Decision::Abandon(false))
                } else {
                    Err(SidError::Conflict(format!(
                        "issuer {} is stored differently",
                        restored.id
                    )))
                };
            }
            create_issuer(tx, &restored)?;
            for key in &keys {
                create_issuer_key(tx, key)?;
            }
            finalize(tx, &format!("oidc_issuer:{}", restored.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === The instance organization ===

    pub(super) async fn instance_organization(&self) -> SidResult<Option<Organization>> {
        self.read(|tx| {
            let rows = tx.run(
                "MATCH (o:SidOrganization) WHERE o.is_instance = true
                 RETURN o.id AS id, o.org_type AS org_type, o.status AS status,
                        o.canonical_domain AS canonical_domain, o.created_at AS created_at",
                Params::default(),
            )?;
            rows.first().map(organization).transpose()
        })
        .await
    }

    pub(super) async fn insert_instance_organization(
        &self,
        org: &Organization,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let org = org.clone();
        self.transaction(move |tx| {
            // One instance organization: concurrent first starts meet on
            // its unique flag and agree on the first one stored.
            let exists = tx.run(
                "MATCH (o:SidOrganization) WHERE o.is_instance = true RETURN o.id AS id",
                Params::default(),
            )?;
            if !exists.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "CREATE (o:SidOrganization {id: $id, org_type: $org_type, status: $status,
                    canonical_domain: $domain, is_instance: true, created_at: $created_at})",
                Params::default()
                    .with("id", uuid(org.id.as_uuid()))
                    .with("org_type", text(org.org_type.as_str()))
                    .with("status", text(org.status.as_str()))
                    .with("domain", text(&org.canonical_domain))
                    .with("created_at", time(org.created_at)),
            )?;
            finalize(tx, &format!("organization:{}", org.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn assign_unowned_clients(
        &self,
        org: OrgId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            hold_org(tx, org)?;
            let rows = tx.run(
                "MATCH (c:SidClient) WHERE c.org_id IS NULL
                 SET c.org_id = $org, c.revision = c.revision + 1
                 RETURN count(*) AS n",
                Params::default().with("org", uuid(org.as_uuid())),
            )?;
            let assigned = get_count(&rows)?;
            if assigned == 0 {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, &format!("organization:{org}"), ctx.clone())?;
            Ok(Decision::Commit(assigned))
        })
        .await
    }

    // === Applications ===

    pub(super) async fn create_application(
        &self,
        app: &Application,
        client: Option<&OAuth2Client>,
        resource: Option<&ProtectedResource>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if client.is_some_and(|c| c.application_id != app.id || c.project_id != app.project_id) {
            return Err(SidError::Validation(format!(
                "the client role of application {} names another application or project",
                app.id
            )));
        }
        if resource.is_some_and(|r| r.application_id != Some(app.id)) {
            return Err(SidError::Validation(format!(
                "the resource role of application {} names another application",
                app.id
            )));
        }
        let (app, client, resource) = (app.clone(), client.cloned(), resource.cloned());
        self.mutate(format!("application:{}", app.id), ctx, move |tx| {
            if let Some(kind) = app.system {
                let taken = tx.run(
                    "MATCH (a:SidApplication) WHERE a.system_integration = $kind RETURN a.id AS id",
                    Params::default().with("kind", text(kind.as_str())),
                )?;
                if !taken.is_empty() {
                    return Err(SidError::Conflict(format!(
                        "system integration {} already exists",
                        kind.as_str()
                    )));
                }
            }
            insert_application(tx, &app)?;
            let mut created = Created {
                application: Some(app.id),
                resource: None,
            };
            // The resource first: the client may name it as its default.
            if let Some(resource) = &resource {
                insert_resource(tx, resource, created)?;
                created.resource = Some(resource.id);
            }
            if let Some(client) = &client {
                insert_client(tx, client, created)?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn get_application(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<Application>> {
        self.read(move |tx| get_application(tx, id)).await
    }

    pub(super) async fn system_application(
        &self,
        kind: SystemIntegration,
    ) -> SidResult<Option<Application>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (a:SidApplication) WHERE a.system_integration = $kind RETURN {APPLICATION}"
                ),
                Params::default().with("kind", text(kind.as_str())),
            )?;
            rows.first().map(application).transpose()
        })
        .await
    }

    pub(super) async fn list_applications_by_project(
        &self,
        project: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Application>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (a:SidApplication) WHERE a.project_id = $project RETURN {APPLICATION}"
                ),
                Params::default().with("project", uuid(project.as_uuid())),
            )?;
            let all = rows
                .iter()
                .map(application)
                .collect::<SidResult<Vec<_>>>()?;
            Ok(sorted_page(
                all,
                |a| (a.created_at, *a.id.as_uuid()),
                offset,
                limit,
            ))
        })
        .await
    }

    pub(super) async fn update_application(
        &self,
        app: &Application,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let app = app.clone();
        self.transaction(move |tx| {
            let Some(stored) = get_application(tx, app.id)? else {
                return Ok(Decision::Abandon(false));
            };
            // Project and creation time never change; the time compares at the
            // precision it is stored at.
            if stored.revision != app.revision
                || stored.project_id != app.project_id
                || stored.created_at != super::stored_time(app.created_at)
            {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (a:SidApplication) WHERE a.id = $id
                 SET a.name = $name, a.updated_at = $updated_at, a.revision = $next",
                Params::default()
                    .with("id", uuid(app.id.as_uuid()))
                    .with("name", text(&app.name))
                    .with("updated_at", time(app.updated_at))
                    .with("next", next_revision(app.revision)?),
            )?;
            finalize(tx, &format!("application:{}", app.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_application(
        &self,
        id: ApplicationId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            if get_application(tx, id)?.is_none() {
                return Ok(Decision::Abandon(false));
            }
            // The client role goes; its access goes with it.
            let clients = tx.run(
                "MATCH (c:SidClient) WHERE c.application_id = $id RETURN c.client_id AS client_id",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            for row in &clients {
                delete_client(tx, &get_text(row, "client_id")?)?;
            }
            // The resource role is retired, never deleted: its indicator
            // stays reserved.
            let now = time(Utc::now());
            let retired = tx.run(
                "MATCH (r:SidResource) WHERE r.application_id = $id
                 SET r.state = 'retired', r.application_id = null,
                     r.revision = r.revision + 1, r.updated_at = $now
                 RETURN r.id AS id",
                Params::default()
                    .with("id", uuid(id.as_uuid()))
                    .with("now", now),
            )?;
            for row in &retired {
                let resource = Value::Binary(get_bytes(row, "id")?);
                tx.run(
                    "MATCH (x:SidResourceAccess) WHERE x.resource_id = $resource DETACH DELETE x",
                    Params::default().with("resource", resource.clone()),
                )?;
                tx.run(
                    "MATCH (c:SidClient) WHERE c.default_resource = $resource
                     SET c.default_resource = null, c.revision = c.revision + 1",
                    Params::default().with("resource", resource),
                )?;
            }
            tx.run(
                "MATCH (a:SidApplication) WHERE a.id = $id DETACH DELETE a",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            finalize(tx, &format!("application:{id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === OAuth clients ===

    pub(super) async fn get_oauth2_client(
        &self,
        client_id: &str,
    ) -> SidResult<Option<OAuth2Client>> {
        let client_id = client_id.to_owned();
        self.read(move |tx| get_client(tx, &client_id)).await
    }

    pub(super) async fn oauth2_client_of_application(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<OAuth2Client>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (c:SidClient) WHERE c.application_id = $id RETURN {CLIENT}"),
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            rows.first().map(client).transpose()
        })
        .await
    }

    pub(super) async fn create_oauth2_client(
        &self,
        stored: &OAuth2Client,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(
            format!("oauth2_client:{}", stored.client_id),
            ctx,
            move |tx| insert_client(tx, &stored, Created::default()),
        )
        .await
    }

    pub(super) async fn update_oauth2_client(
        &self,
        update: &OAuth2Client,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let update = update.clone();
        self.transaction(move |tx| {
            let Some(stored) = get_client(tx, &update.client_id)? else {
                return Ok(Decision::Abandon(false));
            };
            // The client's origin never changes: an update carrying another
            // origin writes nothing. Its times compare at the precision they
            // are stored at.
            if stored.revision != update.revision
                || stored.created_at != super::stored_time(update.created_at)
                || stored.client_id_issued_at != super::stored_time(update.client_id_issued_at)
                || stored.registration_iat != update.registration_iat
                || stored.application_id != update.application_id
            {
                return Ok(Decision::Abandon(false));
            }
            hold_client_references(tx, &update, Created::default())?;
            tx.run(
                &format!(
                    "MATCH (c:SidClient) WHERE c.client_id = $client_id
                     SET {CLIENT_SET}, c.revision = $next"
                ),
                client_params(&update)?.with("next", next_revision(update.revision)?),
            )?;
            finalize(
                tx,
                &format!("oauth2_client:{}", update.client_id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_oauth2_client(
        &self,
        client_id: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let client_id = client_id.to_owned();
        self.mutate(format!("oauth2_client:{client_id}"), ctx, move |tx| {
            if let Some(app) = delete_client(tx, &client_id)? {
                // An application left without any role goes too.
                let resource = tx.run(
                    "MATCH (r:SidResource) WHERE r.application_id = $id RETURN r.id AS id",
                    Params::default().with("id", uuid(app.as_uuid())),
                )?;
                if resource.is_empty() {
                    tx.run(
                        "MATCH (a:SidApplication) WHERE a.id = $id DETACH DELETE a",
                        Params::default().with("id", uuid(app.as_uuid())),
                    )?;
                }
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn list_oauth2_clients(
        &self,
        project: Option<ProjectId>,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<OAuth2Client>> {
        let (offset, limit) = (page(offset)?, page(limit)?);
        self.read(move |tx| {
            let (filter, params) = match project {
                Some(project) => (
                    "WHERE c.project_id = $project",
                    Params::default().with("project", uuid(project.as_uuid())),
                ),
                None => ("", Params::default()),
            };
            let rows = tx.run(
                &format!(
                    "MATCH (c:SidClient) {filter} RETURN {CLIENT}
                     ORDER BY c.created_at DESC, c.client_id SKIP $offset LIMIT $limit"
                ),
                params
                    .with("offset", offset.clone())
                    .with("limit", limit.clone()),
            )?;
            rows.iter().map(client).collect()
        })
        .await
    }

    // === Protected resources ===

    pub(super) async fn create_protected_resource(
        &self,
        stored: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let stored = stored.clone();
        self.mutate(
            format!("protected_resource:{}", stored.id),
            ctx,
            move |tx| insert_resource(tx, &stored, Created::default()),
        )
        .await
    }

    pub(super) async fn get_protected_resource(
        &self,
        id: ResourceId,
    ) -> SidResult<Option<ProtectedResource>> {
        self.read(move |tx| get_resource(tx, id)).await
    }

    pub(super) async fn protected_resource_of_application(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<ProtectedResource>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidResource) WHERE r.application_id = $id RETURN {RESOURCE}"),
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            rows.first().map(resource).transpose()
        })
        .await
    }

    pub(super) async fn protected_resource_by_indicator(
        &self,
        issuer_id: IssuerId,
        indicator: &ResourceIndicator,
    ) -> SidResult<Option<ProtectedResource>> {
        let indicator = indicator.clone();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidResource) WHERE r.indicator_key = $key RETURN {RESOURCE}"),
                Params::default().with("key", indicator_key(issuer_id, &indicator)?),
            )?;
            rows.first().map(resource).transpose()
        })
        .await
    }

    pub(super) async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<ProtectedResource>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidResource) RETURN {RESOURCE}"),
                Params::default(),
            )?;
            let all = rows.iter().map(resource).collect::<SidResult<Vec<_>>>()?;
            Ok(sorted_page(
                all,
                |r| (r.created_at, *r.id.as_uuid()),
                offset,
                limit,
            ))
        })
        .await
    }

    pub(super) async fn import_protected_resource(
        &self,
        stored: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let stored = stored.clone();
        self.transaction(move |tx| {
            // Only the id is a repeat of this import; any other key held by
            // another resource is a conflict.
            if get_resource(tx, stored.id)?.is_some() {
                return Ok(Decision::Abandon(false));
            }
            if let Some(app) = stored.application_id {
                let held = tx.run(
                    "MATCH (a:SidApplication) WHERE a.id = $id RETURN id(a) AS node",
                    Params::default().with("id", uuid(app.as_uuid())),
                )?;
                if !claim_first(tx, &held)? {
                    return Err(SidError::NotFound(format!("application {app}")));
                }
            }
            write_resource(tx, &stored)?;
            finalize(
                tx,
                &format!("protected_resource:{}", stored.id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn update_protected_resource(
        &self,
        update: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        // A resource is retired only with its application.
        if update.state == ResourceState::Retired {
            return Ok(false);
        }
        let update = update.clone();
        self.transaction(move |tx| {
            let Some(stored) = get_resource(tx, update.id)? else {
                return Ok(Decision::Abandon(false));
            };
            if stored.revision != update.revision
                || stored.state == ResourceState::Retired
                || stored.application_id != update.application_id
                || stored.issuer_id != update.issuer_id
                || stored.indicator != update.indicator
                || stored.created_at != super::stored_time(update.created_at)
            {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (r:SidResource) WHERE r.id = $id
                 SET r.scopes = $scopes, r.state = $state, r.updated_at = $updated_at,
                     r.revision = $next",
                Params::default()
                    .with("id", uuid(update.id.as_uuid()))
                    .with("scopes", texts(&update.scopes))
                    .with("state", text(update.state.as_str()))
                    .with("updated_at", time(update.updated_at))
                    .with("next", next_revision(update.revision)?),
            )?;
            finalize(
                tx,
                &format!("protected_resource:{}", update.id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    // === Resource access ===

    pub(super) async fn set_resource_access(
        &self,
        grant: &ResourceAccess,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let grant = grant.clone();
        self.transaction(move |tx| {
            // The resource and the client are claimed: a retirement or a
            // client deletion, which removes the accesses it reads, conflicts
            // with this grant and sees it.
            let resource = tx.run(
                "MATCH (r:SidResource) WHERE r.id = $id RETURN id(r) AS node, r.state AS state",
                Params::default().with("id", uuid(grant.resource_id.as_uuid())),
            )?;
            let Some(row) = resource.first() else {
                return Err(SidError::NotFound(format!(
                    "protected resource {}",
                    grant.resource_id
                )));
            };
            if get_text(row, "state")? == ResourceState::Retired.as_str() {
                return Err(SidError::InvalidState(format!(
                    "protected resource {} is retired",
                    grant.resource_id
                )));
            }
            tx.claim(get_int(row, "node")?)?;
            // The client is an OAuth client or, failing that, a live machine
            // user, the order in which the token endpoint resolves a client id.
            let oauth = tx.run(
                "MATCH (c:SidClient) WHERE c.client_id = $id RETURN id(c) AS node",
                Params::default().with("id", text(&grant.client_id)),
            )?;
            let target = if claim_first(tx, &oauth)? {
                "oauth2_client"
            } else {
                let machine = tx.run(
                    "MATCH (m:SidMachineUser) WHERE m.client_id = $id AND m.status <> 'deleted'
                     RETURN id(m) AS node",
                    Params::default().with("id", text(&grant.client_id)),
                )?;
                if !claim_first(tx, &machine)? {
                    return Err(SidError::NotFound(format!("client {}", grant.client_id)));
                }
                "machine_user"
            };
            let pair = access_key(&grant.client_id, grant.resource_id)?;
            let updated = tx.run(
                "MATCH (x:SidResourceAccess) WHERE x.pair = $pair SET x.scopes = $scopes
                 RETURN x.pair AS pair",
                Params::default()
                    .with("pair", pair.clone())
                    .with("scopes", texts(&grant.scopes)),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (x:SidResourceAccess {pair: $pair, client_id: $client_id,
                        client_kind: $kind, resource_id: $resource_id, scopes: $scopes,
                        created_at: $created_at})",
                    Params::default()
                        .with("pair", pair)
                        .with("client_id", text(&grant.client_id))
                        .with("kind", text(target))
                        .with("resource_id", uuid(grant.resource_id.as_uuid()))
                        .with("scopes", texts(&grant.scopes))
                        .with("created_at", time(grant.created_at)),
                )?;
            }
            finalize(tx, &format!("{target}:{}", grant.client_id), ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    pub(super) async fn remove_resource_access(
        &self,
        client_id: &str,
        resource_id: ResourceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let client_id = client_id.to_owned();
        self.transaction(move |tx| {
            let removed = get_count(&tx.run(
                "MATCH (x:SidResourceAccess) WHERE x.pair = $pair DETACH DELETE x
                 RETURN count(*) AS n",
                Params::default().with("pair", access_key(&client_id, resource_id)?),
            )?)?;
            if removed == 0 {
                // A keyed removal of access the client no longer has still
                // records its completion: a retry after a later grant must
                // not remove that.
                let Some(completion) = &ctx.operation else {
                    return Ok(Decision::Abandon(false));
                };
                super::operation::record(tx, completion)?;
                return Ok(Decision::Commit(false));
            }
            finalize(tx, &format!("oauth2_client:{client_id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn resource_access(
        &self,
        client_id: &str,
        resource_id: ResourceId,
    ) -> SidResult<Option<ResourceAccess>> {
        let client_id = client_id.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (x:SidResourceAccess) WHERE x.pair = $pair RETURN {ACCESS}"),
                Params::default().with("pair", access_key(&client_id, resource_id)?),
            )?;
            rows.first().map(access).transpose()
        })
        .await
    }

    pub(super) async fn list_resource_access(
        &self,
        property: &'static str,
        value: Value,
        order: &'static str,
    ) -> SidResult<Vec<ResourceAccess>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (x:SidResourceAccess) WHERE x.{property} = $value RETURN {ACCESS}"),
                Params::default().with("value", value.clone()),
            )?;
            let all = rows.iter().map(access).collect::<SidResult<Vec<_>>>()?;
            // Oldest first, then by the other side of the access.
            Ok(if order == "client_id" {
                sorted_page(all, |x| (x.created_at, x.client_id.clone()), 0, u64::MAX)
            } else {
                sorted_page(
                    all,
                    |x| (x.created_at, x.resource_id.as_uuid().to_string()),
                    0,
                    u64::MAX,
                )
            })
        })
        .await
    }

    // === Initial access tokens ===

    pub(super) async fn create_initial_access_token(
        &self,
        token: &InitialAccessToken,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let token = token.clone();
        self.mutate(format!("iat:{}", token.id), ctx, move |tx| {
            if get_iat(tx, "id", uuid(token.id.as_uuid()))?.is_some() {
                return Err(SidError::Conflict(
                    "initial access token already exists".into(),
                ));
            }
            tx.run(
                "CREATE (t:SidInitialAccessToken {id: $id, token_hash: $token_hash,
                    project_id: $project_id, max_clients: $max_clients,
                    clients_registered: $clients_registered, allowed_scopes: $allowed_scopes,
                    allowed_grant_types: $allowed_grant_types,
                    allowed_redirect_patterns: $allowed_redirect_patterns,
                    created_by: $created_by, revoked: $revoked, expires_at: $expires_at,
                    created_at: $created_at})",
                Params::default()
                    .with("id", uuid(token.id.as_uuid()))
                    .with("token_hash", Value::Binary(token.token_hash.clone()))
                    .with("project_id", uuid(token.project_id.as_uuid()))
                    .with("max_clients", Value::Int(i64::from(token.max_clients)))
                    .with(
                        "clients_registered",
                        Value::Int(i64::from(token.clients_registered)),
                    )
                    .with("allowed_scopes", texts(&token.allowed_scopes))
                    .with("allowed_grant_types", texts(&token.allowed_grant_types))
                    .with(
                        "allowed_redirect_patterns",
                        texts(&token.allowed_redirect_patterns),
                    )
                    .with("created_by", uuid(token.created_by.as_uuid()))
                    .with("revoked", Value::Bool(token.revoked))
                    .with("expires_at", time(token.expires_at))
                    .with("created_at", time(token.created_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_initial_access_token(
        &self,
        id: InitialAccessTokenId,
    ) -> SidResult<Option<InitialAccessToken>> {
        self.read(move |tx| get_iat(tx, "id", uuid(id.as_uuid())))
            .await
    }

    pub(super) async fn get_initial_access_token_by_hash(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<InitialAccessToken>> {
        let hash = hash.to_vec();
        self.read(move |tx| get_iat(tx, "token_hash", Value::Binary(hash.clone())))
            .await
    }

    pub(super) async fn list_initial_access_tokens_by_project(
        &self,
        project: ProjectId,
    ) -> SidResult<Vec<InitialAccessToken>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (t:SidInitialAccessToken) WHERE t.project_id = $project RETURN {TOKEN}"
                ),
                Params::default().with("project", uuid(project.as_uuid())),
            )?;
            let all = rows.iter().map(iat).collect::<SidResult<Vec<_>>>()?;
            Ok(sorted_page(
                all,
                |t| (t.created_at, *t.id.as_uuid()),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn revoke_initial_access_token(
        &self,
        id: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("iat:{id}"), ctx, move |tx| {
            let revoked = tx.run(
                "MATCH (t:SidInitialAccessToken) WHERE t.id = $id SET t.revoked = true
                 RETURN t.id AS id",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            if revoked.is_empty() {
                return Err(SidError::NotFound(format!("initial access token {id}")));
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn register_dynamic_client(
        &self,
        app: &Application,
        client: &OAuth2Client,
        iat_id: InitialAccessTokenId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if client.application_id != app.id || client.project_id != app.project_id {
            return Err(SidError::Validation(format!(
                "registered client {} names another application or project",
                client.client_id
            )));
        }
        let (app, client) = (app.clone(), client.clone());
        self.mutate(
            format!("oauth2_client:{}", client.client_id),
            ctx,
            move |tx| {
                let token = get_iat(tx, "id", uuid(iat_id.as_uuid()))?
                    .ok_or_else(|| SidError::NotFound(format!("initial access token {iat_id}")))?;
                if token.revoked {
                    return Err(SidError::Revoked(format!("initial access token {iat_id}")));
                }
                if token.expires_at <= Utc::now() {
                    return Err(SidError::Expired(format!("initial access token {iat_id}")));
                }
                if token.max_clients > 0 && token.clients_registered >= token.max_clients {
                    return Err(SidError::InvalidState(format!(
                        "initial access token {iat_id} reached its client limit"
                    )));
                }
                // Every registration under the token writes its count:
                // concurrent ones conflict, so the limit holds.
                tx.run(
                    "MATCH (t:SidInitialAccessToken) WHERE t.id = $id
                 SET t.clients_registered = t.clients_registered + 1",
                    Params::default().with("id", uuid(iat_id.as_uuid())),
                )?;
                insert_application(tx, &app)?;
                insert_client(
                    tx,
                    &client,
                    Created {
                        application: Some(app.id),
                        resource: None,
                    },
                )
            },
        )
        .await
    }
}
