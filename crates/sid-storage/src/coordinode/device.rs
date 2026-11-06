// SPDX-License-Identifier: AGPL-3.0-only
//! Devices, their hardware attestations and device authorization requests
//! (RFC 8628) in CoordiNode.
//!
//! Trusting a device takes its owner's turn, so the count of trusted
//! devices a trust is checked against conflicts with a concurrent trust. A
//! device authorization is decided, polled and redeemed by writing its own
//! node: of concurrent writers one commits.

use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    Device, DeviceAttestation, DeviceAttestationId, DeviceAuthCodeId, DeviceAuthDecision,
    DeviceAuthStatus, DeviceAuthorizationCode, DeviceCodeRedemption, DeviceId, DevicePoll,
    DeviceTrustChange, MutationContext, ProfileId, ProjectId, RefreshToken, ResourceId, Session,
    SessionId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, finalize, get_bool, get_bytes, get_int,
    get_opt_bytes, get_opt_text, get_opt_time, get_parsed, get_text, get_time, get_uuid,
    hold_first, opt_text, opt_time, time, uuid,
};

const DEVICE: &str = "d.id AS id, d.profile_id AS profile_id, d.display_name AS display_name,
    d.device_type AS device_type, d.os_info AS os_info, d.assurance AS assurance,
    d.trusted AS trusted, d.hardware_attested AS hardware_attested,
    d.fingerprint_hash AS fingerprint_hash, d.last_ip_geo AS last_ip_geo,
    d.first_seen_at AS first_seen_at, d.last_seen_at AS last_seen_at";

const ATTESTATION: &str = "a.id AS id, a.device_id AS device_id, a.profile_id AS profile_id,
    a.format AS format, a.key_storage AS key_storage, a.status AS status,
    a.device_public_key AS device_public_key, a.attestation_object AS attestation_object,
    a.attestation_certificate AS attestation_certificate, a.aaguid AS aaguid,
    a.credential_id AS credential_id, a.created_at AS created_at,
    a.updated_at AS updated_at, a.revoked_at AS revoked_at";

const AUTH: &str = "c.id AS id, c.client_id AS client_id,
    c.device_code_hash AS device_code_hash, c.user_code AS user_code, c.scope AS scope,
    c.resource_id AS resource_id, c.status AS status, c.authorized_by AS authorized_by,
    c.project_id AS project_id, c.interval_secs AS interval_secs, c.created_at AS created_at,
    c.expires_at AS expires_at, c.authorized_at AS authorized_at,
    c.last_polled_at AS last_polled_at, c.redeemed_session_id AS redeemed_session_id";

/// RFC 8628 §3.5: each slow_down adds 5 seconds to the polling interval.
const SLOW_DOWN_STEP_SECS: i32 = 5;

fn bin(bytes: &[u8; 16]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn id<T>(row: &Row, name: &str, from: fn(&[u8]) -> Result<T, sid_ids::IdError>) -> SidResult<T> {
    from(&get_bytes(row, name)?).map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

fn opt_id<T>(
    row: &Row,
    name: &str,
    from: fn(&[u8]) -> Result<T, sid_ids::IdError>,
) -> SidResult<Option<T>> {
    get_opt_bytes(row, name)?
        .map(|b| from(&b).map_err(|e| SidError::Storage(format!("{name}: {e}"))))
        .transpose()
}

/// Commit only the keyed command's completion of a write that changed
/// nothing; without one there is nothing to record.
fn unchanged<T>(tx: &Statements<'_>, ctx: &MutationContext, answer: T) -> SidResult<Decision<T>> {
    match &ctx.operation {
        Some(completion) => {
            super::operation::record(tx, completion)?;
            Ok(Decision::Commit(answer))
        }
        None => Ok(Decision::Abandon(answer)),
    }
}

// === Devices ===

fn device(row: &Row) -> SidResult<Device> {
    Ok(Device {
        id: id(row, "id", DeviceId::from_slice)?,
        profile_id: id(row, "profile_id", ProfileId::from_slice)?,
        display_name: get_opt_text(row, "display_name")?,
        device_type: get_parsed(row, "device_type")?,
        os_info: get_opt_text(row, "os_info")?,
        assurance: get_parsed(row, "assurance")?,
        trusted: get_bool(row, "trusted")?,
        hardware_attested: get_bool(row, "hardware_attested")?,
        fingerprint_hash: get_opt_text(row, "fingerprint_hash")?,
        last_ip_geo: get_opt_text(row, "last_ip_geo")?,
        first_seen_at: get_time(row, "first_seen_at")?,
        last_seen_at: get_time(row, "last_seen_at")?,
    })
}

fn get_device(tx: &Statements<'_>, device_id: DeviceId) -> SidResult<Option<Device>> {
    let rows = tx.run(
        &format!("MATCH (d:SidDevice) WHERE d.id = $id RETURN {DEVICE}"),
        Params::default().with("id", bin(device_id.as_bytes())),
    )?;
    rows.first().map(device).transpose()
}

// === Attestations ===

fn attestation(row: &Row) -> SidResult<DeviceAttestation> {
    Ok(DeviceAttestation {
        id: DeviceAttestationId(get_uuid(row, "id")?),
        device_id: id(row, "device_id", DeviceId::from_slice)?,
        profile_id: id(row, "profile_id", ProfileId::from_slice)?,
        format: get_parsed(row, "format")?,
        key_storage: get_parsed(row, "key_storage")?,
        status: get_parsed(row, "status")?,
        device_public_key: get_bytes(row, "device_public_key")?,
        attestation_object: get_opt_bytes(row, "attestation_object")?,
        attestation_certificate: get_opt_bytes(row, "attestation_certificate")?,
        aaguid: get_opt_text(row, "aaguid")?,
        credential_id: get_opt_text(row, "credential_id")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
        revoked_at: get_opt_time(row, "revoked_at")?,
    })
}

fn attestations_where(
    tx: &Statements<'_>,
    filter: &str,
    value: Value,
) -> SidResult<Vec<DeviceAttestation>> {
    let rows = tx.run(
        &format!("MATCH (a:SidDeviceAttestation) WHERE {filter} RETURN {ATTESTATION}"),
        Params::default().with("value", value),
    )?;
    rows.iter().map(attestation).collect()
}

// === Device authorization ===

fn auth(tx: &Statements<'_>, row: &Row) -> SidResult<DeviceAuthorizationCode> {
    // A session ended since names nothing.
    let redeemed_session_id = match opt_id(row, "redeemed_session_id", SessionId::from_slice)? {
        Some(session) => {
            let live = tx.run(
                "MATCH (s:SidSession) WHERE s.id = $id RETURN s.id AS id",
                Params::default().with("id", bin(session.as_bytes())),
            )?;
            (!live.is_empty()).then_some(session)
        }
        None => None,
    };
    let interval = get_int(row, "interval_secs")?;
    Ok(DeviceAuthorizationCode {
        id: DeviceAuthCodeId(get_uuid(row, "id")?),
        client_id: get_text(row, "client_id")?,
        device_code_hash: get_bytes(row, "device_code_hash")?,
        user_code: get_text(row, "user_code")?,
        scope: get_opt_text(row, "scope")?,
        resource: id(row, "resource_id", ResourceId::from_slice)?,
        status: get_parsed(row, "status")?,
        authorized_by: opt_id(row, "authorized_by", ProfileId::from_slice)?,
        project_id: id(row, "project_id", ProjectId::from_slice)?,
        interval: i32::try_from(interval)
            .map_err(|_| SidError::Storage(format!("interval_secs: {interval}")))?,
        created_at: get_time(row, "created_at")?,
        expires_at: get_time(row, "expires_at")?,
        authorized_at: get_opt_time(row, "authorized_at")?,
        last_polled_at: get_opt_time(row, "last_polled_at")?,
        redeemed_session_id,
    })
}

fn auth_where(
    tx: &Statements<'_>,
    filter: &str,
    value: Value,
) -> SidResult<Option<DeviceAuthorizationCode>> {
    let rows = tx.run(
        &format!("MATCH (c:SidDeviceAuth) WHERE {filter} RETURN {AUTH}"),
        Params::default().with("value", value),
    )?;
    rows.first().map(|row| auth(tx, row)).transpose()
}

/// Delete in `tx` the devices of `profile`, and clear it from the device
/// authorizations it decided.
pub(super) fn delete_profile_records(tx: &Statements<'_>, profile: ProfileId) -> SidResult<()> {
    for query in [
        "MATCH (d:SidDevice) WHERE d.profile_id = $id DETACH DELETE d",
        "MATCH (c:SidDeviceAuth) WHERE c.authorized_by = $id SET c.authorized_by = null",
    ] {
        tx.run(query, Params::default().with("id", bin(profile.as_bytes())))?;
    }
    Ok(())
}

/// Delete in `tx` the device authorizations of `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    tx.run(
        "MATCH (c:SidDeviceAuth) WHERE c.project_id = $id DETACH DELETE c",
        Params::default().with("id", bin(project.as_bytes())),
    )?;
    Ok(())
}

impl CoordinodeBackend {
    // === Devices ===

    pub(super) async fn create_device(&self, d: &Device, ctx: MutationContext) -> SidResult<()> {
        let d = d.clone();
        self.mutate(format!("device:{}", d.id), ctx, move |tx| {
            let owner = tx.run(
                "MATCH (p:SidProfile) WHERE p.id = $id RETURN id(p) AS node",
                Params::default().with("id", bin(d.profile_id.as_bytes())),
            )?;
            if !hold_first(tx, &owner)? {
                return Err(SidError::NotFound(format!("profile {}", d.profile_id)));
            }
            if get_device(tx, d.id)?.is_some() {
                return Err(SidError::Conflict("device already exists".into()));
            }
            tx.run(
                "CREATE (d:SidDevice {id: $id, profile_id: $profile_id,
                    display_name: $display_name, device_type: $device_type, os_info: $os_info,
                    assurance: $assurance, trusted: $trusted,
                    hardware_attested: $hardware_attested, fingerprint_hash: $fingerprint_hash,
                    last_ip_geo: $last_ip_geo, first_seen_at: $first_seen_at,
                    last_seen_at: $last_seen_at})",
                Params::default()
                    .with("id", bin(d.id.as_bytes()))
                    .with("profile_id", bin(d.profile_id.as_bytes()))
                    .with("display_name", opt_text(d.display_name.as_deref()))
                    .with("device_type", Value::String(d.device_type.as_str().into()))
                    .with("os_info", opt_text(d.os_info.as_deref()))
                    .with("assurance", Value::String(d.assurance.as_str().into()))
                    .with("trusted", Value::Bool(d.trusted))
                    .with("hardware_attested", Value::Bool(d.hardware_attested))
                    .with("fingerprint_hash", opt_text(d.fingerprint_hash.as_deref()))
                    .with("last_ip_geo", opt_text(d.last_ip_geo.as_deref()))
                    .with("first_seen_at", time(d.first_seen_at))
                    .with("last_seen_at", time(d.last_seen_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn rename_device(
        &self,
        device_id: DeviceId,
        display_name: Option<&str>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let display_name = display_name.map(str::to_owned);
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (d:SidDevice) WHERE d.id = $id SET d.display_name = $name RETURN {DEVICE}"
                ),
                Params::default()
                    .with("id", bin(device_id.as_bytes()))
                    .with("name", opt_text(display_name.as_deref())),
            )?;
            let Some(row) = rows.first() else {
                return Ok(Decision::Abandon(false));
            };
            let mut ctx = ctx.clone();
            ctx.record_effect(&device(row)?)?;
            finalize(tx, &format!("device:{device_id}"), ctx)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn set_device_trust(
        &self,
        device_id: DeviceId,
        trusted: bool,
        max_trusted: usize,
        ctx: MutationContext,
    ) -> SidResult<DeviceTrustChange> {
        self.transaction(move |tx| {
            let Some(current) = get_device(tx, device_id)? else {
                return Ok(Decision::Abandon(DeviceTrustChange::NotFound));
            };
            let mut ctx = ctx.clone();
            if current.trusted == trusted {
                ctx.record_effect(&current)?;
                return unchanged(tx, &ctx, DeviceTrustChange::Unchanged);
            }
            if trusted {
                // The owner's turn makes the count and the trust one step.
                tx.run(
                    "MATCH (p:SidProfile) WHERE p.id = $id
                     SET p.device_turn = coalesce(p.device_turn, 0) + 1",
                    Params::default().with("id", bin(current.profile_id.as_bytes())),
                )?;
                let rows = tx.run(
                    "MATCH (d:SidDevice) WHERE d.profile_id = $id AND d.trusted = true
                     RETURN count(d) AS n",
                    Params::default().with("id", bin(current.profile_id.as_bytes())),
                )?;
                let count = super::get_count(&rows)?;
                if usize::try_from(count).is_ok_and(|n| n >= max_trusted) {
                    return Ok(Decision::Abandon(DeviceTrustChange::LimitReached));
                }
            }
            let assurance = match (trusted, current.assurance.as_str()) {
                (true, "unknown" | "recognized") => "trusted",
                (false, "trusted") => "recognized",
                (_, kept) => kept,
            };
            let rows = tx.run(
                &format!(
                    "MATCH (d:SidDevice) WHERE d.id = $id
                     SET d.trusted = $trusted, d.assurance = $assurance, d.last_seen_at = $now
                     RETURN {DEVICE}"
                ),
                Params::default()
                    .with("id", bin(device_id.as_bytes()))
                    .with("trusted", Value::Bool(trusted))
                    .with("assurance", Value::String(assurance.into()))
                    .with("now", time(Utc::now())),
            )?;
            let changed = rows
                .first()
                .map(device)
                .transpose()?
                .ok_or_else(|| SidError::Storage("device vanished".into()))?;
            ctx.record_effect(&changed)?;
            finalize(tx, &format!("device:{device_id}"), ctx)?;
            Ok(Decision::Commit(DeviceTrustChange::Changed))
        })
        .await
    }

    pub(super) async fn get_device(&self, device_id: DeviceId) -> SidResult<Option<Device>> {
        self.read(move |tx| get_device(tx, device_id)).await
    }

    pub(super) async fn list_devices_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<Device>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (d:SidDevice) WHERE d.profile_id = $id RETURN {DEVICE}"),
                Params::default().with("id", bin(profile.as_bytes())),
            )?;
            rows.iter().map(device).collect()
        })
        .await
    }

    pub(super) async fn delete_device(
        &self,
        device_id: DeviceId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("device:{device_id}"), ctx, move |tx| {
            tx.run(
                "MATCH (d:SidDevice) WHERE d.id = $id DETACH DELETE d",
                Params::default().with("id", bin(device_id.as_bytes())),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_device_by_fingerprint(
        &self,
        profile: ProfileId,
        fingerprint_hash: &str,
    ) -> SidResult<Option<Device>> {
        let fingerprint_hash = fingerprint_hash.to_owned();
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (d:SidDevice) WHERE d.profile_id = $id AND d.fingerprint_hash = $hash
                     RETURN {DEVICE}"
                ),
                Params::default()
                    .with("id", bin(profile.as_bytes()))
                    .with("hash", Value::String(fingerprint_hash.clone())),
            )?;
            rows.first().map(device).transpose()
        })
        .await
    }

    // === Attestations ===

    pub(super) async fn create_device_attestation(
        &self,
        a: &DeviceAttestation,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let a = a.clone();
        self.mutate(
            format!("device_attestation:{}", a.device_id),
            ctx,
            move |tx| {
                // One attestation per device: a revoked one is replaced by the
                // new enrollment, a live one refuses it.
                if let Some(stored) =
                    attestations_where(tx, "a.device_id = $value", bin(a.device_id.as_bytes()))?
                        .pop()
                {
                    if stored.status.as_str() != "revoked" {
                        return Err(SidError::Conflict(
                            "device already has a live attestation".into(),
                        ));
                    }
                    tx.run(
                        "MATCH (a:SidDeviceAttestation) WHERE a.device_id = $id DETACH DELETE a",
                        Params::default().with("id", bin(a.device_id.as_bytes())),
                    )?;
                }
                tx.run(
                    "CREATE (a:SidDeviceAttestation {id: $id, device_id: $device_id,
                    profile_id: $profile_id, format: $format, key_storage: $key_storage,
                    status: $status, device_public_key: $device_public_key,
                    attestation_object: $attestation_object,
                    attestation_certificate: $attestation_certificate, aaguid: $aaguid,
                    credential_id: $credential_id, created_at: $created_at,
                    updated_at: $updated_at, revoked_at: $revoked_at})",
                    Params::default()
                        .with("id", uuid(&a.id.0))
                        .with("device_id", bin(a.device_id.as_bytes()))
                        .with("profile_id", bin(a.profile_id.as_bytes()))
                        .with("format", Value::String(a.format.as_str().into()))
                        .with("key_storage", Value::String(a.key_storage.as_str().into()))
                        .with("status", Value::String(a.status.as_str().into()))
                        .with(
                            "device_public_key",
                            Value::Binary(a.device_public_key.clone()),
                        )
                        .with(
                            "attestation_object",
                            a.attestation_object
                                .clone()
                                .map_or(Value::Null, Value::Binary),
                        )
                        .with(
                            "attestation_certificate",
                            a.attestation_certificate
                                .clone()
                                .map_or(Value::Null, Value::Binary),
                        )
                        .with("aaguid", opt_text(a.aaguid.as_deref()))
                        .with("credential_id", opt_text(a.credential_id.as_deref()))
                        .with("created_at", time(a.created_at))
                        .with("updated_at", time(a.updated_at))
                        .with("revoked_at", opt_time(a.revoked_at)),
                )?;
                Ok(())
            },
        )
        .await
    }

    pub(super) async fn rotate_device_attestation(
        &self,
        device_id: DeviceId,
        device_public_key: &[u8],
        attestation_object: Option<&[u8]>,
        attestation_certificate: Option<&[u8]>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (key, object, certificate) = (
            device_public_key.to_vec(),
            attestation_object.map(<[u8]>::to_vec),
            attestation_certificate.map(<[u8]>::to_vec),
        );
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (a:SidDeviceAttestation) WHERE a.device_id = $id AND a.status <> 'revoked'
                 SET a.device_public_key = $key, a.attestation_object = $object,
                     a.attestation_certificate = $certificate, a.status = 'unverified',
                     a.updated_at = $now
                 RETURN a.id AS id",
                Params::default()
                    .with("id", bin(device_id.as_bytes()))
                    .with("key", Value::Binary(key.clone()))
                    .with("object", object.clone().map_or(Value::Null, Value::Binary))
                    .with(
                        "certificate",
                        certificate.clone().map_or(Value::Null, Value::Binary),
                    )
                    .with("now", time(Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &format!("device_attestation:{device_id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn revoke_device_attestation(
        &self,
        device_id: DeviceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let now = time(Utc::now());
            let rows = tx.run(
                "MATCH (a:SidDeviceAttestation) WHERE a.device_id = $id AND a.status <> 'revoked'
                 SET a.status = 'revoked', a.revoked_at = $now, a.updated_at = $now
                 RETURN a.id AS id",
                Params::default()
                    .with("id", bin(device_id.as_bytes()))
                    .with("now", now),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            // A revoked key no longer attests anything about the device.
            tx.run(
                "MATCH (d:SidDevice) WHERE d.id = $id SET d.hardware_attested = false",
                Params::default().with("id", bin(device_id.as_bytes())),
            )?;
            finalize(tx, &format!("device_attestation:{device_id}"), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn get_device_attestation(
        &self,
        id: DeviceAttestationId,
    ) -> SidResult<Option<DeviceAttestation>> {
        self.read(move |tx| Ok(attestations_where(tx, "a.id = $value", uuid(&id.0))?.pop()))
            .await
    }

    pub(super) async fn get_device_attestation_by_device_id(
        &self,
        device_id: DeviceId,
    ) -> SidResult<Option<DeviceAttestation>> {
        self.read(move |tx| {
            Ok(
                attestations_where(tx, "a.device_id = $value", bin(device_id.as_bytes()))?
                    .into_iter()
                    .find(|a| a.status.as_str() != "revoked"),
            )
        })
        .await
    }

    pub(super) async fn list_device_attestations_by_profile(
        &self,
        profile: ProfileId,
    ) -> SidResult<Vec<DeviceAttestation>> {
        self.read(move |tx| {
            let all = attestations_where(tx, "a.profile_id = $value", bin(profile.as_bytes()))?;
            // Newest first.
            Ok(super::sorted_page(
                all,
                |a| (std::cmp::Reverse(a.created_at), std::cmp::Reverse(a.id.0)),
                0,
                u64::MAX,
            ))
        })
        .await
    }

    pub(super) async fn delete_device_attestation(
        &self,
        device_id: DeviceId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("device_attestation:{device_id}"), ctx, move |tx| {
            tx.run(
                "MATCH (a:SidDeviceAttestation) WHERE a.device_id = $id DETACH DELETE a",
                Params::default().with("id", bin(device_id.as_bytes())),
            )?;
            Ok(())
        })
        .await
    }

    // === Device authorization ===

    pub(super) async fn create_device_auth_code(
        &self,
        c: &DeviceAuthorizationCode,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let c = c.clone();
        self.mutate(format!("device_auth:{}", c.id.0), ctx, move |tx| {
            for (label, value, what) in [
                ("SidProject", bin(c.project_id.as_bytes()), "project"),
                (
                    "SidResource",
                    bin(c.resource.as_bytes()),
                    "protected resource",
                ),
            ] {
                let held = tx.run(
                    &format!("MATCH (n:{label}) WHERE n.id = $id RETURN id(n) AS node"),
                    Params::default().with("id", value),
                )?;
                if !hold_first(tx, &held)? {
                    return Err(SidError::NotFound(format!("the device request's {what}")));
                }
            }
            if auth_where(tx, "c.id = $value", uuid(&c.id.0))?.is_some() {
                return Err(SidError::Conflict(
                    "device authorization already exists".into(),
                ));
            }
            tx.run(
                "CREATE (c:SidDeviceAuth {id: $id, client_id: $client_id,
                    device_code_hash: $device_code_hash, user_code: $user_code, scope: $scope,
                    resource_id: $resource_id, status: $status, authorized_by: $authorized_by,
                    project_id: $project_id, interval_secs: $interval, created_at: $created_at,
                    expires_at: $expires_at, authorized_at: $authorized_at,
                    last_polled_at: $last_polled_at, redeemed_session_id: $redeemed})",
                Params::default()
                    .with("id", uuid(&c.id.0))
                    .with("client_id", Value::String(c.client_id.clone()))
                    .with(
                        "device_code_hash",
                        Value::Binary(c.device_code_hash.clone()),
                    )
                    .with("user_code", Value::String(c.user_code.clone()))
                    .with("scope", opt_text(c.scope.as_deref()))
                    .with("resource_id", bin(c.resource.as_bytes()))
                    .with("status", Value::String(c.status.as_str().into()))
                    .with(
                        "authorized_by",
                        c.authorized_by.map_or(Value::Null, |p| bin(p.as_bytes())),
                    )
                    .with("project_id", bin(c.project_id.as_bytes()))
                    .with("interval", Value::Int(i64::from(c.interval)))
                    .with("created_at", time(c.created_at))
                    .with("expires_at", time(c.expires_at))
                    .with("authorized_at", opt_time(c.authorized_at))
                    .with("last_polled_at", opt_time(c.last_polled_at))
                    .with(
                        "redeemed",
                        c.redeemed_session_id
                            .map_or(Value::Null, |s| bin(s.as_bytes())),
                    ),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_device_auth_by_device_code_hash(
        &self,
        device_code_hash: &[u8],
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let hash = device_code_hash.to_vec();
        self.read(move |tx| {
            auth_where(
                tx,
                "c.device_code_hash = $value",
                Value::Binary(hash.clone()),
            )
        })
        .await
    }

    pub(super) async fn get_device_auth_by_user_code(
        &self,
        user_code: &str,
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let user_code = user_code.to_owned();
        self.read(move |tx| {
            auth_where(tx, "c.user_code = $value", Value::String(user_code.clone()))
        })
        .await
    }

    pub(super) async fn decide_device_auth(
        &self,
        id: DeviceAuthCodeId,
        decision: DeviceAuthDecision,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let now = Utc::now();
            let pending = auth_where(tx, "c.id = $value", uuid(&id.0))?
                .is_some_and(|c| c.status == DeviceAuthStatus::Pending && c.expires_at > now);
            if !pending {
                return Ok(Decision::Abandon(false));
            }
            let (status, by, at) = match decision {
                DeviceAuthDecision::Authorize(profile) => {
                    ("authorized", bin(profile.as_bytes()), time(now))
                }
                DeviceAuthDecision::Deny => ("denied", Value::Null, Value::Null),
            };
            tx.run(
                "MATCH (c:SidDeviceAuth) WHERE c.id = $id AND c.status = 'pending'
                 SET c.status = $status, c.authorized_by = $by, c.authorized_at = $at",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("status", Value::String(status.into()))
                    .with("by", by)
                    .with("at", at),
            )?;
            finalize(tx, &format!("device_auth:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn record_device_poll(
        &self,
        id: DeviceAuthCodeId,
        ctx: MutationContext,
    ) -> SidResult<DevicePoll> {
        self.transaction(move |tx| {
            // Concurrent polls write this node: each sees the previous one's
            // time.
            let c = auth_where(tx, "c.id = $value", uuid(&id.0))?
                .ok_or_else(|| SidError::NotFound(format!("device authorization {}", id.0)))?;
            let now = Utc::now();
            let too_soon = c
                .last_polled_at
                .is_some_and(|t| now - t < chrono::Duration::seconds(c.interval.into()));
            let (poll, interval) = if too_soon {
                let grown = c
                    .interval
                    .checked_add(SLOW_DOWN_STEP_SECS)
                    .ok_or_else(|| SidError::Storage("device poll interval overflow".into()))?;
                (DevicePoll::SlowDown, grown)
            } else {
                (DevicePoll::Allowed, c.interval)
            };
            tx.run(
                "MATCH (c:SidDeviceAuth) WHERE c.id = $id
                 SET c.last_polled_at = $now, c.interval_secs = $interval",
                Params::default()
                    .with("id", uuid(&id.0))
                    .with("now", time(now))
                    .with("interval", Value::Int(i64::from(interval))),
            )?;
            finalize(tx, &format!("device_auth:{}", id.0), ctx.clone())?;
            Ok(Decision::Commit(poll))
        })
        .await
    }

    pub(super) async fn redeem_device_code(
        &self,
        device_code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> SidResult<DeviceCodeRedemption> {
        let (hash, session, refresh_token) = (
            device_code_hash.to_vec(),
            session.clone(),
            refresh_token.clone(),
        );
        self.transaction(move |tx| {
            let Some(c) = auth_where(
                tx,
                "c.device_code_hash = $value",
                Value::Binary(hash.clone()),
            )?
            else {
                return Ok(Decision::Abandon(DeviceCodeRedemption::NotAuthorized));
            };
            if c.status == DeviceAuthStatus::Redeemed {
                return Ok(Decision::Abandon(DeviceCodeRedemption::AlreadyRedeemed {
                    session_id: c.redeemed_session_id,
                }));
            }
            if c.status != DeviceAuthStatus::Authorized || c.expires_at <= Utc::now() {
                return Ok(Decision::Abandon(DeviceCodeRedemption::NotAuthorized));
            }
            super::session::insert(tx, &session)?;
            // Written at the authorized status: of concurrent redemptions one
            // commits, the others run again and find it redeemed.
            tx.run(
                "MATCH (c:SidDeviceAuth) WHERE c.id = $id AND c.status = 'authorized'
                 SET c.status = 'redeemed', c.redeemed_session_id = $session",
                Params::default()
                    .with("id", uuid(&c.id.0))
                    .with("session", bin(session.id.as_bytes())),
            )?;
            super::session::insert_token(tx, &refresh_token)?;
            finalize(tx, &format!("session:{}", session.id), ctx.clone())?;
            Ok(Decision::Commit(DeviceCodeRedemption::Redeemed))
        })
        .await
    }

    pub(super) async fn cleanup_expired_device_auth_codes(
        &self,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidDeviceAuth) WHERE c.expires_at < $now AND c.status = 'pending'
                 DETACH DELETE c RETURN count(*) AS n",
                Params::default().with("now", time(Utc::now())),
            )?;
            let removed = super::get_count(&rows)?;
            // Nothing expired and nothing owed: no action to record.
            if removed == 0 && ctx.work.is_empty() {
                return Ok(Decision::Abandon(0));
            }
            finalize(tx, "device_auth:cleanup", ctx.clone())?;
            Ok(Decision::Commit(removed))
        })
        .await
    }
}
