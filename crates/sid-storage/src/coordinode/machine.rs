// SPDX-License-Identifier: AGPL-3.0-only
//! Non-human actors in CoordiNode: machine users with their credentials and
//! impersonation grants, provisioning connectors with theirs.
//!
//! A credential added, rotated or revoked writes its owner's node, so the
//! count of usable credentials a new one is checked against conflicts with
//! a concurrent addition. A connector's state, grants and credentials
//! advance or write it, and a write fenced by a connector holds the
//! connector and the credential it acted with.

use chrono::{DateTime, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::machine_user::{
    CredentialStatus, ImpersonationGrant, MachineOwner, MachineRestrictions, MachineUser,
    MachineUserCredential, MachineUserStatus,
};
use sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS;
use sid_core::models::{
    ConnectorState, MachineUserId, MutationContext, OrgId, ProjectId, ProvisioningConnector,
    ProvisioningConnectorId, ProvisioningCredential, ProvisioningCredentialId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, finalize, get_bytes,
    get_int, get_opt_int, get_opt_text, get_opt_time, get_opt_uuid, get_parsed, get_text,
    get_texts, get_time, hold_first, key, opt_text, opt_time, opt_uuid, sorted_page, texts, time,
};

const MACHINE: &str = "m.id AS id, m.project_id AS project_id, m.machine_type AS machine_type,
    m.owner_type AS owner_type, m.owner_id AS owner_id, m.client_id AS client_id,
    m.display_name AS display_name, m.description AS description, m.status AS status,
    m.scopes AS scopes, m.ip_allowlist AS ip_allowlist, m.rate_limit_rpm AS rate_limit_rpm,
    m.max_token_lifetime AS max_token_lifetime, m.expires_at AS expires_at,
    m.created_at AS created_at, m.updated_at AS updated_at";

const MACHINE_CREDENTIAL: &str = "k.kid AS kid, k.machine_user_id AS machine_user_id,
    k.credential_type AS credential_type, k.status AS status,
    k.credential_data AS credential_data, k.algorithm AS algorithm,
    k.expires_at AS expires_at, k.created_at AS created_at";

const GRANT: &str = "g.machine_user_id AS machine_user_id, g.target_type AS target_type,
    g.target AS target, g.allowed_scopes AS allowed_scopes, g.created_at AS created_at";

const CONNECTOR: &str = "c.id AS id, c.org_id AS org_id, c.direction AS direction,
    c.client_id AS client_id, c.display_name AS display_name, c.state AS state,
    c.revision AS revision, c.created_at AS created_at, c.updated_at AS updated_at";

const CONNECTOR_CREDENTIAL: &str = "k.id AS id, k.connector_id AS connector_id, k.kind AS kind,
    k.status AS status, k.verifier AS verifier, k.expires_at AS expires_at,
    k.created_at AS created_at";

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn id<T>(row: &Row, name: &str, from: fn(&[u8]) -> Result<T, sid_ids::IdError>) -> SidResult<T> {
    from(&get_bytes(row, name)?).map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

fn small(value: i64, name: &str) -> SidResult<u32> {
    u32::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
}

/// Write the `turn` of the node of `label` with id `value`: a concurrent
/// change of what it owns conflicts. False when there is no such node.
fn take_turn(tx: &Statements<'_>, label: &str, value: Value) -> SidResult<bool> {
    let rows = tx.run(
        &format!(
            "MATCH (n:{label}) WHERE n.id = $id SET n.turn = coalesce(n.turn, 0) + 1
             RETURN n.id AS id"
        ),
        Params::default().with("id", value),
    )?;
    Ok(!rows.is_empty())
}

// === Machine users ===

// Unknown stored values are errors, never an active service owned by a Profile.
fn machine_user(row: &Row) -> SidResult<MachineUser> {
    Ok(MachineUser {
        id: id(row, "id", MachineUserId::from_slice)?,
        project_id: id(row, "project_id", ProjectId::from_slice)?,
        machine_type: get_parsed(row, "machine_type")?,
        owner: MachineOwner::from_stored(
            get_parsed(row, "owner_type")?,
            get_opt_uuid(row, "owner_id")?,
        )
        .map_err(SidError::Storage)?,
        client_id: get_text(row, "client_id")?,
        display_name: get_text(row, "display_name")?,
        description: get_opt_text(row, "description")?,
        status: get_parsed(row, "status")?,
        scopes: get_texts(row, "scopes")?,
        restrictions: MachineRestrictions {
            ip_allowlist: get_texts(row, "ip_allowlist")?,
            rate_limit_rpm: small(get_int(row, "rate_limit_rpm")?, "rate_limit_rpm")?,
        },
        max_token_lifetime: get_opt_int(row, "max_token_lifetime")?
            .map(|v| small(v, "max_token_lifetime"))
            .transpose()?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn machine_where(tx: &Statements<'_>, filter: &str, value: Value) -> SidResult<Vec<MachineUser>> {
    let rows = tx.run(
        &format!("MATCH (m:SidMachineUser) WHERE {filter} RETURN {MACHINE}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(machine_user).collect()
}

// Unknown stored values are errors, never a usable client secret.
fn machine_credential(row: &Row) -> SidResult<MachineUserCredential> {
    Ok(MachineUserCredential {
        kid: get_text(row, "kid")?,
        machine_user_id: id(row, "machine_user_id", MachineUserId::from_slice)?,
        credential_type: get_parsed(row, "credential_type")?,
        status: get_parsed(row, "status")?,
        credential_data: get_text(row, "credential_data")?,
        algorithm: get_opt_text(row, "algorithm")?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn machine_credentials_where(
    tx: &Statements<'_>,
    filter: &str,
    value: Value,
) -> SidResult<Vec<MachineUserCredential>> {
    let rows = tx.run(
        &format!("MATCH (k:SidMachineCredential) WHERE {filter} RETURN {MACHINE_CREDENTIAL}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(machine_credential).collect()
}

/// Store a new credential in `tx`; an existing kid is `Conflict`.
fn insert_machine_credential(tx: &Statements<'_>, k: &MachineUserCredential) -> SidResult<()> {
    if !machine_credentials_where(tx, "k.kid = $value", Value::String(k.kid.clone()))?.is_empty() {
        return Err(SidError::Conflict(
            "machine credential already exists".into(),
        ));
    }
    tx.run(
        "CREATE (k:SidMachineCredential {kid: $kid, machine_user_id: $machine_user_id,
            credential_type: $credential_type, status: $status,
            credential_data: $credential_data, algorithm: $algorithm,
            expires_at: $expires_at, created_at: $created_at})",
        Params::default()
            .with("kid", Value::String(k.kid.clone()))
            .with("machine_user_id", bin(k.machine_user_id.as_bytes()))
            .with(
                "credential_type",
                Value::String(k.credential_type.as_str().into()),
            )
            .with("status", Value::String(k.status.as_str().into()))
            .with("credential_data", Value::String(k.credential_data.clone()))
            .with("algorithm", opt_text(k.algorithm.as_deref()))
            .with("expires_at", opt_time(k.expires_at))
            .with("created_at", time(k.created_at)),
    )?;
    Ok(())
}

fn grant(row: &Row) -> SidResult<ImpersonationGrant> {
    Ok(ImpersonationGrant {
        machine_user_id: id(row, "machine_user_id", MachineUserId::from_slice)?,
        target_type: get_parsed(row, "target_type")?,
        target: get_text(row, "target")?,
        allowed_scopes: get_texts(row, "allowed_scopes")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn grant_key(machine: MachineUserId, target_type: &str, target: &str) -> SidResult<Value> {
    key(&[
        machine.as_bytes(),
        target_type.as_bytes(),
        target.as_bytes(),
    ])
}

/// Delete in `tx` the machine users of `project` with everything they own.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    for m in machine_where(tx, "m.project_id = $value", bin(project.as_bytes()))? {
        for query in [
            "MATCH (k:SidMachineCredential) WHERE k.machine_user_id = $id DETACH DELETE k",
            "MATCH (g:SidImpersonationGrant) WHERE g.machine_user_id = $id DETACH DELETE g",
            "MATCH (m:SidMachineUser) WHERE m.id = $id DETACH DELETE m",
        ] {
            tx.run(query, Params::default().with("id", bin(m.id.as_bytes())))?;
        }
        tx.run(
            "MATCH (x:SidResourceAccess) WHERE x.client_id = $client DETACH DELETE x",
            Params::default().with("client", Value::String(m.client_id)),
        )?;
    }
    Ok(())
}

// === Provisioning connectors ===

// Unknown stored values are errors, never an active connector.
fn connector(row: &Row) -> SidResult<ProvisioningConnector> {
    Ok(ProvisioningConnector {
        id: id(row, "id", ProvisioningConnectorId::from_slice)?,
        org_id: id(row, "org_id", OrgId::from_slice)?,
        direction: get_parsed(row, "direction")?,
        client_id: get_text(row, "client_id")?,
        display_name: get_text(row, "display_name")?,
        state: get_parsed(row, "state")?,
        revision: get_int(row, "revision")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn get_connector(
    tx: &Statements<'_>,
    connector_id: ProvisioningConnectorId,
) -> SidResult<Option<ProvisioningConnector>> {
    let rows = tx.run(
        &format!("MATCH (c:SidProvisioningConnector) WHERE c.id = $id RETURN {CONNECTOR}"),
        Params::default().with("id", bin(connector_id.as_bytes())),
    )?;
    rows.first().map(connector).transpose()
}

// Unknown stored values are errors, never a usable credential.
fn connector_credential(row: &Row) -> SidResult<ProvisioningCredential> {
    Ok(ProvisioningCredential {
        id: id(row, "id", ProvisioningCredentialId::from_slice)?,
        connector_id: id(row, "connector_id", ProvisioningConnectorId::from_slice)?,
        kind: get_parsed(row, "kind")?,
        status: get_parsed(row, "status")?,
        verifier: get_text(row, "verifier")?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
    })
}

fn insert_connector_credential(tx: &Statements<'_>, k: &ProvisioningCredential) -> SidResult<()> {
    let found = tx.run(
        "MATCH (k:SidProvisioningCredential) WHERE k.id = $id RETURN k.id AS id",
        Params::default().with("id", bin(k.id.as_bytes())),
    )?;
    if !found.is_empty() {
        return Err(SidError::Conflict(
            "provisioning credential already exists".into(),
        ));
    }
    tx.run(
        "CREATE (k:SidProvisioningCredential {id: $id, connector_id: $connector_id,
            kind: $kind, status: $status, verifier: $verifier, expires_at: $expires_at,
            created_at: $created_at})",
        Params::default()
            .with("id", bin(k.id.as_bytes()))
            .with("connector_id", bin(k.connector_id.as_bytes()))
            .with("kind", Value::String(k.kind.as_str().into()))
            .with("status", Value::String(k.status.as_str().into()))
            .with("verifier", Value::String(k.verifier.clone()))
            .with("expires_at", opt_time(k.expires_at))
            .with("created_at", time(k.created_at)),
    )?;
    Ok(())
}

/// Take `connector_id`'s turn while it is active; false when it is not.
fn active_turn(tx: &Statements<'_>, connector_id: ProvisioningConnectorId) -> SidResult<bool> {
    let rows = tx.run(
        "MATCH (c:SidProvisioningConnector) WHERE c.id = $id AND c.state = 'active'
         SET c.turn = coalesce(c.turn, 0) + 1 RETURN c.id AS id",
        Params::default().with("id", bin(connector_id.as_bytes())),
    )?;
    Ok(!rows.is_empty())
}

/// Fail with `Fenced` unless `connector_id` is still active at `revision`
/// with `credential` usable; both are held for the commit.
pub(super) fn check_connector_fence(
    tx: &Statements<'_>,
    connector_id: ProvisioningConnectorId,
    revision: i64,
    credential: ProvisioningCredentialId,
) -> SidResult<()> {
    let fenced = || {
        SidError::Fenced(format!(
            "connector {connector_id} changed since it was authorized"
        ))
    };
    let rows = tx.run(
        "MATCH (c:SidProvisioningConnector) WHERE c.id = $id AND c.revision = $revision
           AND c.state = 'active'
         RETURN id(c) AS node",
        Params::default()
            .with("id", bin(connector_id.as_bytes()))
            .with("revision", Value::Int(revision)),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(fenced());
    }
    let rows = tx.run(
        &format!(
            "MATCH (k:SidProvisioningCredential) WHERE k.id = $id AND k.connector_id = $connector
             RETURN id(k) AS node, {CONNECTOR_CREDENTIAL}"
        ),
        Params::default()
            .with("id", bin(credential.as_bytes()))
            .with("connector", bin(connector_id.as_bytes())),
    )?;
    let usable = match rows.first() {
        Some(row) => connector_credential(row)?.is_usable_at(Utc::now()),
        None => false,
    };
    if !usable || !hold_first(tx, &rows)? {
        return Err(fenced());
    }
    Ok(())
}

impl CoordinodeBackend {
    // === Machine users ===

    pub(super) async fn get_machine_user(
        &self,
        machine: MachineUserId,
    ) -> SidResult<Option<MachineUser>> {
        self.read(move |tx| Ok(machine_where(tx, "m.id = $value", bin(machine.as_bytes()))?.pop()))
            .await
    }

    pub(super) async fn get_machine_user_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<MachineUser>> {
        let client_id = client_id.to_owned();
        self.read(move |tx| {
            Ok(machine_where(tx, "m.client_id = $value", Value::String(client_id.clone()))?.pop())
        })
        .await
    }

    pub(super) async fn create_machine_user(
        &self,
        m: &MachineUser,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let m = m.clone();
        self.mutate(format!("machine_user:{}", m.id), ctx, move |tx| {
            let project = tx.run(
                "MATCH (j:SidProject) WHERE j.id = $id RETURN id(j) AS node",
                Params::default().with("id", bin(m.project_id.as_bytes())),
            )?;
            if !claim_first(tx, &project)? {
                return Err(SidError::NotFound(format!("project {}", m.project_id)));
            }
            if !machine_where(tx, "m.id = $value", bin(m.id.as_bytes()))?.is_empty() {
                return Err(SidError::Conflict("machine user already exists".into()));
            }
            tx.run(
                "CREATE (m:SidMachineUser {id: $id, project_id: $project_id,
                    machine_type: $machine_type, owner_type: $owner_type, owner_id: $owner_id,
                    client_id: $client_id, display_name: $display_name,
                    description: $description, status: $status, scopes: $scopes,
                    ip_allowlist: $ip_allowlist, rate_limit_rpm: $rate_limit_rpm,
                    max_token_lifetime: $max_token_lifetime, expires_at: $expires_at,
                    created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", bin(m.id.as_bytes()))
                    .with("project_id", bin(m.project_id.as_bytes()))
                    .with(
                        "machine_type",
                        Value::String(m.machine_type.as_str().into()),
                    )
                    .with("owner_type", Value::String(m.owner.kind().as_str().into()))
                    .with("owner_id", opt_uuid(m.owner.id().as_ref()))
                    .with("client_id", Value::String(m.client_id.clone()))
                    .with("display_name", Value::String(m.display_name.clone()))
                    .with("description", opt_text(m.description.as_deref()))
                    .with("status", Value::String(m.status.as_str().into()))
                    .with("scopes", texts(&m.scopes))
                    .with("ip_allowlist", texts(&m.restrictions.ip_allowlist))
                    .with(
                        "rate_limit_rpm",
                        Value::Int(i64::from(m.restrictions.rate_limit_rpm)),
                    )
                    .with(
                        "max_token_lifetime",
                        m.max_token_lifetime
                            .map_or(Value::Null, |v| Value::Int(i64::from(v))),
                    )
                    .with("expires_at", opt_time(m.expires_at))
                    .with("created_at", time(m.created_at))
                    .with("updated_at", time(m.updated_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn update_machine_user(
        &self,
        m: &MachineUser,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let m = m.clone();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (m:SidMachineUser) WHERE m.id = $id AND m.status <> 'deleted'
                 SET m.display_name = $display_name, m.description = $description,
                     m.scopes = $scopes, m.ip_allowlist = $ip_allowlist,
                     m.rate_limit_rpm = $rate_limit_rpm,
                     m.max_token_lifetime = $max_token_lifetime, m.expires_at = $expires_at,
                     m.updated_at = $now
                 RETURN m.id AS id",
                Params::default()
                    .with("id", bin(m.id.as_bytes()))
                    .with("display_name", Value::String(m.display_name.clone()))
                    .with("description", opt_text(m.description.as_deref()))
                    .with("scopes", texts(&m.scopes))
                    .with("ip_allowlist", texts(&m.restrictions.ip_allowlist))
                    .with(
                        "rate_limit_rpm",
                        Value::Int(i64::from(m.restrictions.rate_limit_rpm)),
                    )
                    .with(
                        "max_token_lifetime",
                        m.max_token_lifetime
                            .map_or(Value::Null, |v| Value::Int(i64::from(v))),
                    )
                    .with("expires_at", opt_time(m.expires_at))
                    .with("now", time(Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("machine_user:{}", m.id), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn transition_machine_user(
        &self,
        machine: MachineUserId,
        from: MachineUserStatus,
        to: MachineUserStatus,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (m:SidMachineUser) WHERE m.id = $id AND m.status = $from
                 SET m.status = $to, m.updated_at = $now RETURN m.id AS id",
                Params::default()
                    .with("id", bin(machine.as_bytes()))
                    .with("from", Value::String(from.as_str().into()))
                    .with("to", Value::String(to.as_str().into()))
                    .with("now", time(Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("machine_user:{machine}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn delete_machine_user(
        &self,
        machine: MachineUserId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("machine_user:{machine}"), ctx, move |tx| {
            // A deleted machine user keeps its record but no access to any
            // resource.
            let rows = tx.run(
                "MATCH (m:SidMachineUser) WHERE m.id = $id SET m.status = 'deleted'
                 RETURN m.client_id AS client_id",
                Params::default().with("id", bin(machine.as_bytes())),
            )?;
            if let Some(row) = rows.first() {
                tx.run(
                    "MATCH (x:SidResourceAccess) WHERE x.client_id = $client DETACH DELETE x",
                    Params::default().with("client", Value::String(get_text(row, "client_id")?)),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn list_machine_users_by_project(
        &self,
        project: ProjectId,
    ) -> SidResult<Vec<MachineUser>> {
        self.read(move |tx| machine_where(tx, "m.project_id = $value", bin(project.as_bytes())))
            .await
    }

    // === Machine credentials ===

    pub(super) async fn get_machine_credential_by_kid(
        &self,
        kid: &str,
    ) -> SidResult<Option<MachineUserCredential>> {
        let kid = kid.to_owned();
        self.read(move |tx| {
            Ok(machine_credentials_where(tx, "k.kid = $value", Value::String(kid.clone()))?.pop())
        })
        .await
    }

    pub(super) async fn add_machine_credential(
        &self,
        k: &MachineUserCredential,
        active_limit: Option<u64>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let k = k.clone();
        self.mutate(format!("machine_cred:{}", k.kid), ctx, move |tx| {
            // The owner's turn makes the count and the insert one step.
            if !take_turn(tx, "SidMachineUser", bin(k.machine_user_id.as_bytes()))? {
                return Err(SidError::NotFound(format!(
                    "machine user {}",
                    k.machine_user_id
                )));
            }
            if let Some(limit) = active_limit {
                let usable = machine_credentials_where(
                    tx,
                    "k.machine_user_id = $value",
                    bin(k.machine_user_id.as_bytes()),
                )?
                .iter()
                .filter(|c| c.status.is_usable())
                .count();
                if u64::try_from(usable).is_ok_and(|n| n >= limit) {
                    return Err(SidError::ResourceExhausted(format!(
                        "machine user already holds {limit} usable credentials"
                    )));
                }
            }
            insert_machine_credential(tx, &k)
        })
        .await
    }

    pub(super) async fn rotate_machine_credential(
        &self,
        machine: MachineUserId,
        old_kid: &str,
        new: &MachineUserCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (old_kid, new) = (old_kid.to_owned(), new.clone());
        self.transaction(move |tx| {
            let Some(current) =
                machine_credentials_where(tx, "k.kid = $value", Value::String(old_kid.clone()))?
                    .pop()
                    .filter(|c| {
                        c.machine_user_id == machine && c.status == CredentialStatus::Active
                    })
            else {
                return Ok(Decision::Abandon(false));
            };
            take_turn(tx, "SidMachineUser", bin(machine.as_bytes()))?;
            // The grace ends at the credential's own expiry when that comes
            // first.
            let ends = match current.expires_at {
                Some(own) if own < grace_until => own,
                _ => grace_until,
            };
            tx.run(
                "MATCH (k:SidMachineCredential) WHERE k.kid = $kid
                 SET k.status = 'grace_period', k.expires_at = $ends",
                Params::default()
                    .with("kid", Value::String(old_kid.clone()))
                    .with("ends", time(ends)),
            )?;
            insert_machine_credential(tx, &new)?;
            finalize(tx, &format!("machine_cred:{old_kid}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn revoke_machine_credential(
        &self,
        machine: MachineUserId,
        kid: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let kid = kid.to_owned();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (k:SidMachineCredential) WHERE k.kid = $kid AND k.machine_user_id = $machine
                   AND k.status IN ['active', 'grace_period']
                 SET k.status = 'revoked' RETURN k.kid AS kid",
                Params::default()
                    .with("kid", Value::String(kid.clone()))
                    .with("machine", bin(machine.as_bytes())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            take_turn(tx, "SidMachineUser", bin(machine.as_bytes()))?;
            finalize(tx, &format!("machine_cred:{kid}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn revoke_active_machine_credentials_by_user(
        &self,
        machine: MachineUserId,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            take_turn(tx, "SidMachineUser", bin(machine.as_bytes()))?;
            let rows = tx.run(
                "MATCH (k:SidMachineCredential) WHERE k.machine_user_id = $machine
                   AND k.status IN ['active', 'grace_period']
                 SET k.status = 'revoked' RETURN k.kid AS kid",
                Params::default().with("machine", bin(machine.as_bytes())),
            )?;
            finalize(
                tx,
                &format!("machine_cred:cascade_revoke:user:{machine}"),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(
                u64::try_from(rows.len()).map_err(|_| SidError::Storage("revoked count".into()))?,
            ))
        })
        .await
    }

    pub(super) async fn list_machine_credentials_by_user(
        &self,
        machine: MachineUserId,
    ) -> SidResult<Vec<MachineUserCredential>> {
        self.read(move |tx| {
            machine_credentials_where(tx, "k.machine_user_id = $value", bin(machine.as_bytes()))
        })
        .await
    }

    pub(super) async fn list_expiring_machine_credentials(
        &self,
        within_days: u32,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let cutoff = Utc::now() + chrono::Duration::days(i64::from(within_days));
        self.read(move |tx| {
            machine_credentials_where(
                tx,
                "k.status = 'active' AND k.expires_at IS NOT NULL AND k.expires_at <= $value",
                time(cutoff),
            )
        })
        .await
    }

    // === Impersonation grants ===

    pub(super) async fn save_impersonation_grant(
        &self,
        g: &ImpersonationGrant,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let g = g.clone();
        self.mutate(
            format!("impersonation_grant:{}", g.machine_user_id),
            ctx,
            move |tx| {
                let machine = tx.run(
                    "MATCH (m:SidMachineUser) WHERE m.id = $id RETURN id(m) AS node",
                    Params::default().with("id", bin(g.machine_user_id.as_bytes())),
                )?;
                if !claim_first(tx, &machine)? {
                    return Err(SidError::NotFound(format!(
                        "machine user {}",
                        g.machine_user_id
                    )));
                }
                let triple = grant_key(g.machine_user_id, g.target_type.as_str(), &g.target)?;
                let updated = tx.run(
                    "MATCH (g:SidImpersonationGrant) WHERE g.triple = $triple
                     SET g.allowed_scopes = $scopes RETURN g.triple AS triple",
                    Params::default()
                        .with("triple", triple.clone())
                        .with("scopes", texts(&g.allowed_scopes)),
                )?;
                if updated.is_empty() {
                    tx.run(
                        "CREATE (g:SidImpersonationGrant {triple: $triple,
                            machine_user_id: $machine, target_type: $target_type,
                            target: $target, allowed_scopes: $scopes, created_at: $created_at})",
                        Params::default()
                            .with("triple", triple)
                            .with("machine", bin(g.machine_user_id.as_bytes()))
                            .with("target_type", Value::String(g.target_type.as_str().into()))
                            .with("target", Value::String(g.target.clone()))
                            .with("scopes", texts(&g.allowed_scopes))
                            .with("created_at", time(g.created_at)),
                    )?;
                }
                Ok(())
            },
        )
        .await
    }

    pub(super) async fn delete_impersonation_grant(
        &self,
        machine: MachineUserId,
        target_type: &str,
        target: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let triple = grant_key(machine, target_type, target)?;
        self.mutate(format!("impersonation_grant:{machine}"), ctx, move |tx| {
            tx.run(
                "MATCH (g:SidImpersonationGrant) WHERE g.triple = $triple DETACH DELETE g",
                Params::default().with("triple", triple.clone()),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list_impersonation_grants(
        &self,
        machine: MachineUserId,
    ) -> SidResult<Vec<ImpersonationGrant>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (g:SidImpersonationGrant) WHERE g.machine_user_id = $id RETURN {GRANT}"
                ),
                Params::default().with("id", bin(machine.as_bytes())),
            )?;
            rows.iter().map(grant).collect()
        })
        .await
    }

    // === Provisioning connectors ===

    pub(super) async fn get_provisioning_connector(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> SidResult<Option<ProvisioningConnector>> {
        self.read(move |tx| get_connector(tx, connector_id)).await
    }

    pub(super) async fn get_provisioning_connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<ProvisioningConnector>> {
        let client_id = client_id.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (c:SidProvisioningConnector) WHERE c.client_id = $id RETURN {CONNECTOR}"
                ),
                Params::default().with("id", Value::String(client_id.clone())),
            )?;
            rows.first().map(connector).transpose()
        })
        .await
    }

    pub(super) async fn list_provisioning_connectors(
        &self,
        org: OrgId,
    ) -> SidResult<Vec<ProvisioningConnector>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (c:SidProvisioningConnector) WHERE c.org_id = $id RETURN {CONNECTOR}"
                ),
                Params::default().with("id", bin(org.as_bytes())),
            )?;
            let all = rows.iter().map(connector).collect::<SidResult<Vec<_>>>()?;
            // Newest first, then by id descending.
            Ok(sorted_page(
                all,
                |c| (std::cmp::Reverse(c.created_at), std::cmp::Reverse(c.id)),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn create_provisioning_connector(
        &self,
        c: &ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let c = c.clone();
        self.mutate(format!("provisioning_connector:{}", c.id), ctx, move |tx| {
            if get_connector(tx, c.id)?.is_some() {
                return Err(SidError::Conflict(
                    "provisioning connector already exists".into(),
                ));
            }
            tx.run(
                "CREATE (c:SidProvisioningConnector {id: $id, org_id: $org_id,
                    direction: $direction, client_id: $client_id, display_name: $display_name,
                    state: $state, revision: $revision, created_at: $created_at,
                    updated_at: $updated_at})",
                Params::default()
                    .with("id", bin(c.id.as_bytes()))
                    .with("org_id", bin(c.org_id.as_bytes()))
                    .with("direction", Value::String(c.direction.as_str().into()))
                    .with("client_id", Value::String(c.client_id.clone()))
                    .with("display_name", Value::String(c.display_name.clone()))
                    .with("state", Value::String(c.state.as_str().into()))
                    .with("revision", Value::Int(c.revision))
                    .with("created_at", time(c.created_at))
                    .with("updated_at", time(c.updated_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn rename_provisioning_connector(
        &self,
        connector_id: ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let display_name = display_name.to_owned();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidProvisioningConnector) WHERE c.id = $id AND c.revision = $revision
                   AND c.state <> 'retired'
                 SET c.display_name = $name, c.revision = c.revision + 1, c.updated_at = $now
                 RETURN c.id AS id",
                Params::default()
                    .with("id", bin(connector_id.as_bytes()))
                    .with("revision", Value::Int(revision))
                    .with("name", Value::String(display_name.clone()))
                    .with("now", time(Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(
                tx,
                &format!("provisioning_connector:{connector_id}"),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn transition_provisioning_connector(
        &self,
        connector_id: ProvisioningConnectorId,
        from: ConnectorState,
        to: ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if !from.may_become(to) {
            return Ok(false);
        }
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidProvisioningConnector) WHERE c.id = $id AND c.state = $from
                 SET c.state = $to, c.revision = c.revision + 1, c.updated_at = $now
                 RETURN c.id AS id",
                Params::default()
                    .with("id", bin(connector_id.as_bytes()))
                    .with("from", Value::String(from.as_str().into()))
                    .with("to", Value::String(to.as_str().into()))
                    .with("now", time(Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            if to == ConnectorState::Retired {
                tx.run(
                    "MATCH (k:SidProvisioningCredential) WHERE k.connector_id = $id
                       AND k.status IN ['active', 'grace_period']
                     SET k.status = 'revoked'",
                    Params::default().with("id", bin(connector_id.as_bytes())),
                )?;
            }
            finalize(
                tx,
                &format!("provisioning_connector:{connector_id}"),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn add_provisioning_credential(
        &self,
        k: &ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let k = k.clone();
        self.transaction(move |tx| {
            // The connector's turn makes its state, the count and the insert
            // one step.
            if !active_turn(tx, k.connector_id)? {
                return Ok(Decision::Abandon(false));
            }
            let rows = tx.run(
                &format!(
                    "MATCH (k:SidProvisioningCredential) WHERE k.connector_id = $id
                     RETURN {CONNECTOR_CREDENTIAL}"
                ),
                Params::default().with("id", bin(k.connector_id.as_bytes())),
            )?;
            let usable = rows
                .iter()
                .map(connector_credential)
                .collect::<SidResult<Vec<_>>>()?
                .iter()
                .filter(|c| c.status.is_usable())
                .count();
            if usable >= MAX_USABLE_CONNECTOR_CREDENTIALS {
                return Err(SidError::ResourceExhausted(format!(
                    "connector already holds {MAX_USABLE_CONNECTOR_CREDENTIALS} usable credentials"
                )));
            }
            insert_connector_credential(tx, &k)?;
            finalize(
                tx,
                &format!("provisioning_credential:{}", k.id),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn rotate_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        old: ProvisioningCredentialId,
        new: &ProvisioningCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let new = new.clone();
        self.transaction(move |tx| {
            if !active_turn(tx, connector_id)? {
                return Ok(Decision::Abandon(false));
            }
            let moved = tx.run(
                "MATCH (k:SidProvisioningCredential) WHERE k.id = $id AND k.connector_id = $connector
                   AND k.status = 'active'
                 SET k.status = 'grace_period', k.expires_at = $grace RETURN k.id AS id",
                Params::default()
                    .with("id", bin(old.as_bytes()))
                    .with("connector", bin(connector_id.as_bytes()))
                    .with("grace", time(grace_until)),
            )?;
            if moved.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            insert_connector_credential(tx, &new)?;
            finalize(tx, &format!("provisioning_credential:{old}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn revoke_provisioning_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        credential: ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (k:SidProvisioningCredential) WHERE k.id = $id AND k.connector_id = $connector
                   AND k.status IN ['active', 'grace_period']
                 SET k.status = 'revoked' RETURN k.id AS id",
                Params::default()
                    .with("id", bin(credential.as_bytes()))
                    .with("connector", bin(connector_id.as_bytes())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            take_turn(tx, "SidProvisioningConnector", bin(connector_id.as_bytes()))?;
            finalize(
                tx,
                &format!("provisioning_credential:{credential}"),
                ctx.clone(),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn list_provisioning_credentials(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> SidResult<Vec<ProvisioningCredential>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (k:SidProvisioningCredential) WHERE k.connector_id = $id
                     RETURN {CONNECTOR_CREDENTIAL}"
                ),
                Params::default().with("id", bin(connector_id.as_bytes())),
            )?;
            let all = rows
                .iter()
                .map(connector_credential)
                .collect::<SidResult<Vec<_>>>()?;
            // Newest first, then by id descending.
            Ok(sorted_page(
                all,
                |k| (std::cmp::Reverse(k.created_at), std::cmp::Reverse(k.id)),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn find_provisioning_credential(
        &self,
        verifier: &str,
    ) -> SidResult<Option<(ProvisioningCredential, ProvisioningConnector)>> {
        let verifier = verifier.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (k:SidProvisioningCredential) WHERE k.verifier = $verifier
                     RETURN {CONNECTOR_CREDENTIAL}"
                ),
                Params::default().with("verifier", Value::String(verifier.clone())),
            )?;
            let Some(k) = rows.first().map(connector_credential).transpose()? else {
                return Ok(None);
            };
            let c = get_connector(tx, k.connector_id)?.ok_or_else(|| {
                SidError::Storage(format!("credential {} names no connector", k.id))
            })?;
            Ok(Some((k, c)))
        })
        .await
    }
}
