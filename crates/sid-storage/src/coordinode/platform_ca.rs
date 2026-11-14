// SPDX-License-Identifier: AGPL-3.0-only
//! The admitted platform CA set in CoordiNode: one node for the set's
//! revision and freshness, one per published generation, one per
//! generation's status and one for the configured publication. Every apply
//! holds and rewrites the set's node, so two applies are decided one after
//! the other: the later one reads what the earlier one committed.

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::platform_ca::{
    AnchorStatus, Applied, GenerationStatus, HeldAnchors, HeldGeneration, HeldSet, IssuerStatus,
    PlatformCaArchive, PlatformCaError, PlatformCaSet, PlatformCaState, PlatformCaStore,
};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, field, finalize, get_bytes, get_int,
    get_opt_int, hold_first,
};

/// The audit chain the store's writes are recorded on.
const CHAIN: &str = "installation:platform_ca";

/// What an apply decided, besides a store failure.
enum Outcome {
    Applied(Applied),
    /// The generation arrived with another certificate than the one held.
    Conflict(u32),
}

fn stored(value: u64, field: &str) -> SidResult<i64> {
    i64::try_from(value).map_err(|_| SidError::Validation(format!("{field} {value} out of range")))
}

/// The serials `row` holds under `name`, as written by [`serials`].
fn get_serials(row: &Row, name: &str) -> SidResult<Vec<Vec<u8>>> {
    match field(row, name)? {
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::Binary(serial) => Ok(serial.clone()),
                other => Err(SidError::Storage(format!(
                    "{name} holds no serial: {other:?}"
                ))),
            })
            .collect(),
        other => Err(SidError::Storage(format!(
            "{name} is no list of serials: {other:?}"
        ))),
    }
}

fn serials(revoked: &[Vec<u8>]) -> Value {
    Value::Array(revoked.iter().cloned().map(Value::Binary).collect())
}

fn generation(number: u32) -> Params {
    Params::default().with("generation", Value::Int(i64::from(number)))
}

/// A stored non-negative number as the unsigned value it holds.
fn unsigned<T: TryFrom<i64>>(value: i64, field: &str) -> SidResult<T> {
    T::try_from(value)
        .map_err(|_| SidError::Storage(format!("stored {field} {value} out of range")))
}

/// Everything the store holds, as the transaction sees it.
fn archive(tx: &Statements<'_>) -> SidResult<PlatformCaArchive> {
    let publication = tx
        .run(
            "MATCH (p:SidPlatformCaSource) WHERE p.id = 1 RETURN p.publication AS publication",
            Params::default(),
        )?
        .first()
        .map(|row| super::get_text(row, "publication"))
        .transpose()?;
    let set = tx
        .run(
            "MATCH (s:SidPlatformCaSet) WHERE s.id = 1
             RETURN s.revision AS revision, s.issued_at AS issued_at,
                    s.next_update AS next_update",
            Params::default(),
        )?
        .first()
        .map(|row| {
            Ok::<_, SidError>(HeldSet {
                revision: unsigned(get_int(row, "revision")?, "revision")?,
                issued_at: get_int(row, "issued_at")?,
                next_update: get_int(row, "next_update")?,
            })
        })
        .transpose()?;
    let mut generations = Vec::new();
    for row in tx.run(
        "MATCH (g:SidPlatformCaGeneration)
         RETURN g.generation AS generation, g.certificate AS certificate, g.state AS state,
                g.overlap_end AS overlap_end, g.listed_in AS listed_in",
        Params::default(),
    )? {
        let state = get_int(&row, "state")?;
        generations.push(HeldGeneration {
            generation: unsigned(get_int(&row, "generation")?, "generation")?,
            certificate: get_bytes(&row, "certificate")?,
            state: PlatformCaState::from_rank(state)
                .ok_or_else(|| SidError::Storage(format!("stored platform CA state {state}")))?,
            overlap_end: get_opt_int(&row, "overlap_end")?,
            listed_in: unsigned(get_int(&row, "listed_in")?, "revision")?,
        });
    }
    generations.sort_unstable_by_key(|g| g.generation);
    let mut status = Vec::new();
    for row in tx.run(
        "MATCH (c:SidPlatformCaStatus)
         RETURN c.generation AS generation, c.number AS number,
                c.next_update AS next_update, c.revoked AS revoked",
        Params::default(),
    )? {
        status.push(GenerationStatus {
            generation: unsigned(get_int(&row, "generation")?, "generation")?,
            number: unsigned(get_int(&row, "number")?, "CRL number")?,
            next_update: get_int(&row, "next_update")?,
            // Written in byte order by every writer.
            revoked: get_serials(&row, "revoked")?,
        });
    }
    status.sort_unstable_by_key(|c| c.generation);
    let mut issuers = Vec::new();
    for row in tx.run(
        "MATCH (c:SidCaIssuerStatus)
         RETURN c.issuer AS issuer, c.number AS number, c.next_update AS next_update,
                c.revoked AS revoked",
        Params::default(),
    )? {
        issuers.push(IssuerStatus {
            issuer: get_bytes(&row, "issuer")?
                .try_into()
                .map_err(|_| SidError::Storage("a stored issuer name".into()))?,
            number: unsigned(get_int(&row, "number")?, "CRL number")?,
            next_update: get_int(&row, "next_update")?,
            revoked: get_serials(&row, "revoked")?,
        });
    }
    issuers.sort_unstable_by_key(|c| c.issuer);
    Ok(PlatformCaArchive {
        publication,
        set,
        generations,
        status,
        issuers,
    })
}

/// What a move decided, besides a store failure.
enum Moved {
    Written,
    /// The store holds exactly the archive already.
    Held,
    /// The store holds other platform CA state.
    Occupied,
}

/// Hold `moved` as its source did; see
/// [`PlatformCaStore::import_platform_cas`]. Every node is unique by its
/// key, so a concurrent move collides, runs again and finds it held.
fn import(
    tx: &Statements<'_>,
    moved: &PlatformCaArchive,
    ctx: &MutationContext,
) -> SidResult<Decision<Moved>> {
    let held = archive(tx)?;
    if held == *moved {
        return Ok(Decision::Abandon(Moved::Held));
    }
    if !held.is_empty() {
        return Ok(Decision::Abandon(Moved::Occupied));
    }
    if let Some(publication) = &moved.publication {
        tx.create_absent(
            "CREATE (p:SidPlatformCaSource {id: 1, publication: $publication})",
            Params::default().with("publication", Value::String(publication.clone())),
        )?;
    }
    if let Some(set) = &moved.set {
        tx.create_absent(
            "CREATE (s:SidPlatformCaSet {id: 1, revision: $revision, issued_at: $issued_at,
                 next_update: $next_update})",
            Params::default()
                .with("revision", Value::Int(stored(set.revision, "revision")?))
                .with("issued_at", Value::Int(set.issued_at))
                .with("next_update", Value::Int(set.next_update)),
        )?;
    }
    for held in &moved.generations {
        tx.create_absent(
            "CREATE (g:SidPlatformCaGeneration {generation: $generation,
                 certificate: $certificate, state: $state, overlap_end: $overlap_end,
                 listed_in: $listed_in})",
            generation(held.generation)
                .with("certificate", Value::Binary(held.certificate.clone()))
                .with("state", Value::Int(held.state.rank()))
                .with(
                    "overlap_end",
                    held.overlap_end.map_or(Value::Null, Value::Int),
                )
                .with("listed_in", Value::Int(stored(held.listed_in, "revision")?)),
        )?;
    }
    for crl in &moved.status {
        let mut revoked = crl.revoked.clone();
        revoked.sort_unstable();
        revoked.dedup();
        tx.create_absent(
            "CREATE (c:SidPlatformCaStatus {generation: $generation, number: $number,
                 next_update: $next_update, revoked: $revoked})",
            generation(crl.generation)
                .with("number", Value::Int(stored(crl.number, "CRL number")?))
                .with("next_update", Value::Int(crl.next_update))
                .with("revoked", serials(&revoked)),
        )?;
    }
    // The target held none: the same write that records one holds it.
    for crl in &moved.issuers {
        record_issuer(tx, crl)?;
    }
    finalize(tx, CHAIN, ctx.clone())?;
    Ok(Decision::Commit(Moved::Written))
}

fn issuer(name: &[u8; 32]) -> Params {
    Params::default().with("issuer", Value::Binary(name.to_vec()))
}

/// Hold one issuer's authenticated CRL: its number and time when not older
/// than the held one, and every serial it revokes beside those held.
fn record_issuer(tx: &Statements<'_>, crl: &IssuerStatus) -> SidResult<()> {
    let number = stored(crl.number, "CRL number")?;
    let rows = tx.run(
        "MATCH (c:SidCaIssuerStatus) WHERE c.issuer = $issuer
         RETURN id(c) AS node, c.number AS number, c.next_update AS next_update,
                c.revoked AS revoked",
        issuer(&crl.issuer),
    )?;
    let Some(row) = rows.first() else {
        let mut revoked = crl.revoked.clone();
        revoked.sort_unstable();
        revoked.dedup();
        // Concurrent first recorders meet on the unique node: the one that
        // lost runs again and merges into it.
        tx.create_absent(
            "CREATE (c:SidCaIssuerStatus {issuer: $issuer, number: $number,
                 next_update: $next_update, revoked: $revoked})",
            issuer(&crl.issuer)
                .with("number", Value::Int(number))
                .with("next_update", Value::Int(crl.next_update))
                .with("revoked", serials(&revoked)),
        )?;
        return Ok(());
    };
    if !hold_first(tx, &rows)? {
        return Err(SidError::Storage("an issuer's status vanished".into()));
    }
    // A lower number changes neither the number nor its time; its
    // revocations are kept all the same.
    let (number, next_update) = if get_int(row, "number")? <= number {
        (number, crl.next_update)
    } else {
        (get_int(row, "number")?, get_int(row, "next_update")?)
    };
    let mut revoked = get_serials(row, "revoked")?;
    revoked.extend(crl.revoked.iter().cloned());
    revoked.sort_unstable();
    revoked.dedup();
    tx.run(
        "MATCH (c:SidCaIssuerStatus) WHERE c.issuer = $issuer
         SET c.number = $number, c.next_update = $next_update, c.revoked = $revoked",
        issuer(&crl.issuer)
            .with("number", Value::Int(number))
            .with("next_update", Value::Int(next_update))
            .with("revoked", serials(&revoked)),
    )?;
    Ok(())
}

/// Hold `set` unless a newer one is held; see [`PlatformCaStore`].
fn apply(
    tx: &Statements<'_>,
    set: &PlatformCaSet,
    ctx: &MutationContext,
) -> SidResult<Decision<Outcome>> {
    let revision = stored(set.revision, "revision")?;
    let held = tx.run(
        "MATCH (s:SidPlatformCaSet) WHERE s.id = 1 RETURN id(s) AS node, s.revision AS revision",
        Params::default(),
    )?;
    if let Some(row) = held.first() {
        if get_int(row, "revision")? > revision {
            return Ok(Decision::Abandon(Outcome::Applied(Applied::Stale)));
        }
        // Held for the commit and rewritten below: an apply committed
        // meanwhile makes this one run again on what it left.
        if !hold_first(tx, &held)? {
            return Err(SidError::Storage("the platform CA set vanished".into()));
        }
    }
    // Every generation is read before anything is written: a set naming a
    // held generation with another certificate holds nothing.
    let mut known = Vec::with_capacity(set.generations.len());
    for listed in &set.generations {
        let rows = tx.run(
            "MATCH (g:SidPlatformCaGeneration) WHERE g.generation = $generation
             RETURN g.certificate AS certificate, g.state AS state,
                    g.overlap_end AS overlap_end",
            generation(listed.generation),
        )?;
        let state = match rows.first() {
            Some(row) => {
                if get_bytes(row, "certificate")? != listed.certificate {
                    return Ok(Decision::Abandon(Outcome::Conflict(listed.generation)));
                }
                Some((get_int(row, "state")?, get_opt_int(row, "overlap_end")?))
            }
            None => None,
        };
        known.push(state);
    }
    for (listed, known) in set.generations.iter().zip(known) {
        // The state moves only to a narrower one, and a wider state keeps
        // the narrower one already held, with its overlap end.
        let rank = listed.state.rank();
        let (state, overlap_end) = match known {
            Some((held, overlap_end)) if held > rank => (held, overlap_end),
            _ => (rank, listed.overlap_end),
        };
        let values = generation(listed.generation)
            .with("certificate", Value::Binary(listed.certificate.clone()))
            .with("state", Value::Int(state))
            .with("overlap_end", overlap_end.map_or(Value::Null, Value::Int))
            .with("listed_in", Value::Int(revision));
        if known.is_some() {
            tx.run(
                "MATCH (g:SidPlatformCaGeneration) WHERE g.generation = $generation
                 SET g.state = $state, g.overlap_end = $overlap_end, g.listed_in = $listed_in",
                values,
            )?;
        } else {
            tx.create_absent(
                "CREATE (g:SidPlatformCaGeneration {generation: $generation,
                     certificate: $certificate, state: $state, overlap_end: $overlap_end,
                     listed_in: $listed_in})",
                values,
            )?;
        }
    }
    let values = Params::default()
        .with("revision", Value::Int(revision))
        .with("issued_at", Value::Int(set.issued_at))
        .with("next_update", Value::Int(set.next_update));
    if held.is_empty() {
        tx.create_absent(
            "CREATE (s:SidPlatformCaSet {id: 1, revision: $revision, issued_at: $issued_at,
                 next_update: $next_update})",
            values,
        )?;
    } else {
        tx.run(
            "MATCH (s:SidPlatformCaSet) WHERE s.id = 1
             SET s.revision = $revision, s.issued_at = $issued_at,
                 s.next_update = $next_update",
            values,
        )?;
    }
    finalize(tx, CHAIN, ctx.clone())?;
    Ok(Decision::Commit(Outcome::Applied(Applied::Current)))
}

/// Hold one generation's authenticated CRL: its number and time when not
/// older than the held one, and every serial it revokes beside those held.
fn record(tx: &Statements<'_>, crl: &GenerationStatus) -> SidResult<()> {
    let number = stored(crl.number, "CRL number")?;
    let rows = tx.run(
        "MATCH (c:SidPlatformCaStatus) WHERE c.generation = $generation
         RETURN id(c) AS node, c.number AS number, c.next_update AS next_update,
                c.revoked AS revoked",
        generation(crl.generation),
    )?;
    let Some(row) = rows.first() else {
        let mut revoked = crl.revoked.clone();
        revoked.sort_unstable();
        revoked.dedup();
        tx.create_absent(
            "CREATE (c:SidPlatformCaStatus {generation: $generation, number: $number,
                 next_update: $next_update, revoked: $revoked})",
            generation(crl.generation)
                .with("number", Value::Int(number))
                .with("next_update", Value::Int(crl.next_update))
                .with("revoked", serials(&revoked)),
        )?;
        return Ok(());
    };
    if !hold_first(tx, &rows)? {
        return Err(SidError::Storage("a platform CA status vanished".into()));
    }
    // A lower number changes neither the number nor its time; its
    // revocations are kept all the same.
    let (number, next_update) = if get_int(row, "number")? <= number {
        (number, crl.next_update)
    } else {
        (get_int(row, "number")?, get_int(row, "next_update")?)
    };
    let mut revoked = get_serials(row, "revoked")?;
    revoked.extend(crl.revoked.iter().cloned());
    revoked.sort_unstable();
    revoked.dedup();
    tx.run(
        "MATCH (c:SidPlatformCaStatus) WHERE c.generation = $generation
         SET c.number = $number, c.next_update = $next_update, c.revoked = $revoked",
        generation(crl.generation)
            .with("number", Value::Int(number))
            .with("next_update", Value::Int(next_update))
            .with("revoked", serials(&revoked)),
    )?;
    Ok(())
}

/// The anchors of the held revision at `now`; `Ok(Err(..))` when no set is
/// held or the held one is past its refresh time.
fn held(tx: &Statements<'_>, now: i64) -> SidResult<Result<HeldAnchors, PlatformCaError>> {
    let set = tx.run(
        "MATCH (s:SidPlatformCaSet) WHERE s.id = 1
         RETURN s.revision AS revision, s.issued_at AS issued_at,
                s.next_update AS next_update",
        Params::default(),
    )?;
    let Some(row) = set.first() else {
        return Ok(Err(PlatformCaError::NotProvisioned));
    };
    let revision = get_int(row, "revision")?;
    let (issued_at, next_update) = (get_int(row, "issued_at")?, get_int(row, "next_update")?);
    if now > next_update {
        return Ok(Err(PlatformCaError::Stale));
    }
    let rows = tx.run(
        "MATCH (g:SidPlatformCaGeneration) WHERE g.listed_in = $revision
         RETURN g.generation AS generation, g.certificate AS certificate,
                g.state AS state, g.overlap_end AS overlap_end",
        Params::default().with("revision", Value::Int(revision)),
    )?;
    let mut generations = Vec::with_capacity(rows.len());
    for row in &rows {
        let overlap_end = get_opt_int(row, "overlap_end")?;
        let anchors = match get_int(row, "state")? {
            0 => true,
            1 => overlap_end.is_some_and(|end| end > now),
            _ => false,
        };
        if anchors {
            generations.push((
                get_int(row, "generation")?,
                get_bytes(row, "certificate")?,
                overlap_end,
            ));
        }
    }
    // Newest generation first.
    generations.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    let mut until = next_update;
    let mut anchors = Vec::with_capacity(generations.len());
    let mut status = Vec::with_capacity(generations.len());
    for (number, certificate, overlap_end) in generations {
        if let Some(overlap_end) = overlap_end {
            until = until.min(overlap_end);
        }
        let crl = tx.run(
            "MATCH (c:SidPlatformCaStatus) WHERE c.generation = $generation
             RETURN c.next_update AS next_update, c.revoked AS revoked",
            Params::default().with("generation", Value::Int(number)),
        )?;
        anchors.push(certificate);
        status.push(match crl.first() {
            Some(row) => AnchorStatus {
                until: Some(get_int(row, "next_update")?),
                revoked: get_serials(row, "revoked")?,
            },
            None => AnchorStatus::default(),
        });
    }
    Ok(Ok(HeldAnchors {
        revision: u64::try_from(revision)
            .map_err(|_| SidError::Storage("negative held revision".into()))?,
        anchors,
        status,
        until,
        // Both are seconds since the epoch, so the halfway point cannot
        // overflow; a set issued after its own refresh time renews at once.
        renew_at: issued_at + (next_update - issued_at).max(0) / 2,
    }))
}

#[async_trait]
impl PlatformCaStore for CoordinodeBackend {
    async fn record_issuer_status(
        &self,
        status: &IssuerStatus,
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let status = status.clone();
        self.transaction(move |tx| {
            record_issuer(tx, &status)?;
            finalize(tx, CHAIN, ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await?;
        Ok(())
    }

    async fn held_issuer_status(&self, name: &[u8; 32]) -> Result<AnchorStatus, PlatformCaError> {
        let name = *name;
        Ok(self
            .read(move |tx| {
                let rows = tx.run(
                    "MATCH (c:SidCaIssuerStatus) WHERE c.issuer = $issuer
                     RETURN c.next_update AS next_update, c.revoked AS revoked",
                    issuer(&name),
                )?;
                rows.first().map_or(Ok(AnchorStatus::default()), |row| {
                    Ok(AnchorStatus {
                        until: Some(get_int(row, "next_update")?),
                        revoked: get_serials(row, "revoked")?,
                    })
                })
            })
            .await?)
    }

    async fn export_platform_cas(&self) -> Result<PlatformCaArchive, PlatformCaError> {
        Ok(self.read(archive).await?)
    }

    async fn import_platform_cas(
        &self,
        moved: &PlatformCaArchive,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError> {
        let moved = moved.clone();
        match self.transaction(move |tx| import(tx, &moved, &ctx)).await? {
            Moved::Written => Ok(true),
            Moved::Held => Ok(false),
            Moved::Occupied => Err(PlatformCaError::Occupied),
        }
    }

    async fn apply_platform_cas(
        &self,
        set: &PlatformCaSet,
        ctx: MutationContext,
    ) -> Result<Applied, PlatformCaError> {
        let set = set.clone();
        match self.transaction(move |tx| apply(tx, &set, &ctx)).await? {
            Outcome::Applied(applied) => Ok(applied),
            Outcome::Conflict(generation) => Err(PlatformCaError::Conflict(generation)),
        }
    }

    async fn record_platform_ca_status(
        &self,
        status: &[GenerationStatus],
        ctx: MutationContext,
    ) -> Result<(), PlatformCaError> {
        let status = status.to_vec();
        self.transaction(move |tx| {
            for crl in &status {
                record(tx, crl)?;
            }
            finalize(tx, CHAIN, ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await?;
        Ok(())
    }

    async fn held_platform_cas(&self, now: i64) -> Result<HeldAnchors, PlatformCaError> {
        self.read(move |tx| held(tx, now)).await?
    }

    async fn platform_ca_publication(&self) -> Result<Option<String>, PlatformCaError> {
        Ok(self
            .read(|tx| {
                let rows = tx.run(
                    "MATCH (p:SidPlatformCaSource) WHERE p.id = 1
                     RETURN p.publication AS publication",
                    Params::default(),
                )?;
                rows.first()
                    .map(|row| super::get_text(row, "publication"))
                    .transpose()
            })
            .await?)
    }

    async fn configure_platform_ca_publication(
        &self,
        publication: &str,
        ctx: MutationContext,
    ) -> Result<bool, PlatformCaError> {
        let publication = publication.to_owned();
        Ok(self
            .transaction(move |tx| {
                let rows = tx.run(
                    "MATCH (p:SidPlatformCaSource) WHERE p.id = 1 RETURN p.id AS id",
                    Params::default(),
                )?;
                if !rows.is_empty() {
                    return Ok(Decision::Abandon(false));
                }
                // Concurrent first provisionings meet on the unique node:
                // the one that lost runs again and finds it configured.
                tx.create_absent(
                    "CREATE (p:SidPlatformCaSource {id: 1, publication: $publication})",
                    Params::default().with("publication", Value::String(publication.clone())),
                )?;
                finalize(tx, CHAIN, ctx.clone())?;
                Ok(Decision::Commit(true))
            })
            .await?)
    }
}
