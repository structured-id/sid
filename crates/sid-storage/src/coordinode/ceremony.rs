// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state, single-use admissions and windowed counts in CoordiNode:
//! one node per namespaced key. Every decision writes that node (creates,
//! changes or deletes it), so concurrent takers, admitters and counters of
//! one key conflict and run again on what the winner left. Deadlines are
//! microseconds of the host clock, read inside the transaction: a run again
//! judges expiry when it applies.

use std::time::Duration;

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::{
    CeremonyCount, CeremonyEntry, CeremonyRecords, CeremonyStateStore, OwedWork,
    SingleUseAdmissions,
};

use super::{CoordinodeBackend, Decision, Params, Statements, get_bytes, get_int, slot};

fn now() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

/// The deadline `ttl` from `now`; a lifetime past the range is a caller
/// error, never a deadline in the past.
fn deadline(now: i64, ttl: Duration) -> SidResult<i64> {
    i64::try_from(ttl.as_micros())
        .ok()
        .and_then(|ttl| now.checked_add(ttl))
        .ok_or_else(|| {
            SidError::Storage(format!("ceremony state lifetime {ttl:?} is out of range"))
        })
}

/// The value and deadline stored for `slot`, expired or not.
fn stored(tx: &Statements<'_>, slot: &[u8]) -> SidResult<Option<(Vec<u8>, i64)>> {
    let rows = tx.run(
        "MATCH (c:SidCeremonyState) WHERE c.slot = $slot
         RETURN c.value AS value, c.expires AS expires",
        Params::default().with("slot", Value::Binary(slot.to_vec())),
    )?;
    rows.first()
        .map(|row| Ok((get_bytes(row, "value")?, get_int(row, "expires")?)))
        .transpose()
}

/// Store `value` until `expires` for `slot`, over whatever it held.
fn write(
    tx: &Statements<'_>,
    slot: &[u8],
    present: bool,
    value: &[u8],
    expires: i64,
) -> SidResult<()> {
    let query = if present {
        "MATCH (c:SidCeremonyState) WHERE c.slot = $slot
         SET c.value = $value, c.expires = $expires"
    } else {
        "CREATE (c:SidCeremonyState {slot: $slot, value: $value, expires: $expires})"
    };
    tx.run(
        query,
        Params::default()
            .with("slot", Value::Binary(slot.to_vec()))
            .with("value", Value::Binary(value.to_vec()))
            .with("expires", Value::Int(expires)),
    )?;
    Ok(())
}

fn delete(tx: &Statements<'_>, slot: &[u8]) -> SidResult<()> {
    tx.run(
        "MATCH (c:SidCeremonyState) WHERE c.slot = $slot DETACH DELETE c",
        Params::default().with("slot", Value::Binary(slot.to_vec())),
    )?;
    Ok(())
}

/// Remove `ceremony` inside a mutation's transaction, while it is live and
/// exactly as read; otherwise `Error::Expired`, and the mutation commits
/// nothing. The removal writes the node, so a concurrent consumer of the
/// same ceremony conflicts and runs again on what this one left.
pub(super) fn consume(
    tx: &Statements<'_>,
    ceremony: &sid_core::models::CeremonyConsumption,
) -> SidResult<()> {
    let slot = slot(ceremony.namespace, &ceremony.key)?;
    match stored(tx, &slot)? {
        Some((held, expires)) if expires > now() && held == ceremony.stored => delete(tx, &slot),
        _ => Err(SidError::Expired(format!(
            "ceremony {}:{} is no longer pending",
            ceremony.namespace, ceremony.key
        ))),
    }
}

/// The count and window end stored for `slot`.
fn counted(tx: &Statements<'_>, slot: &[u8]) -> SidResult<Option<(i64, i64)>> {
    let rows = tx.run(
        "MATCH (c:SidCeremonyCount) WHERE c.slot = $slot
         RETURN c.count AS count, c.window_end AS window_end",
        Params::default().with("slot", Value::Binary(slot.to_vec())),
    )?;
    rows.first()
        .map(|row| Ok((get_int(row, "count")?, get_int(row, "window_end")?)))
        .transpose()
}

fn count_of(key: &str, count: i64) -> SidResult<u64> {
    u64::try_from(count).map_err(|_| SidError::Storage(format!("count of {key} is {count}")))
}

/// Delete every node of `label` whose `deadline` property passed.
fn purge(tx: &Statements<'_>, label: &str, deadline: &str) -> SidResult<u64> {
    let rows = tx.run(
        &format!(
            "MATCH (c:{label}) WHERE c.{deadline} <= $now DETACH DELETE c RETURN count(*) AS n"
        ),
        Params::default().with("now", Value::Int(now())),
    )?;
    let n = rows
        .first()
        .map(|row| get_int(row, "n"))
        .transpose()?
        .unwrap_or(0);
    count_of(label, n)
}

#[async_trait]
impl SingleUseAdmissions for CoordinodeBackend {
    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> SidResult<bool> {
        let slot = slot(namespace, key)?;
        self.transaction(move |tx| {
            let now = now();
            let held = stored(tx, &slot)?;
            if held.as_ref().is_some_and(|(_, expires)| *expires > now) {
                return Ok(Decision::Abandon(false));
            }
            write(tx, &slot, held.is_some(), &[], deadline(now, ttl)?)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    async fn admit_for(
        &self,
        namespace: &str,
        key: &str,
        holder: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        let (slot, holder) = (slot(namespace, key)?, holder.to_vec());
        self.transaction(move |tx| {
            let now = now();
            let held = stored(tx, &slot)?;
            match &held {
                // A live admission is confirmed to its holder, not extended.
                Some((value, expires)) if *expires > now => Ok(Decision::Abandon(*value == holder)),
                _ => {
                    write(tx, &slot, held.is_some(), &holder, deadline(now, ttl)?)?;
                    Ok(Decision::Commit(true))
                }
            }
        })
        .await
    }
}

#[async_trait]
impl CeremonyStateStore for CoordinodeBackend {
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<()> {
        let (slot, value) = (slot(namespace, key)?, value.to_vec());
        self.transaction(move |tx| {
            let present = stored(tx, &slot)?.is_some();
            write(tx, &slot, present, &value, deadline(now(), ttl)?)?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    async fn put_ceremony_state_owing(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
        owed: OwedWork<'_>,
    ) -> SidResult<()> {
        let (slot, value) = (slot(namespace, key)?, value.to_vec());
        let (work, capacity) = (owed.work.clone(), owed.capacity);
        self.transaction(move |tx| {
            let present = stored(tx, &slot)?.is_some();
            write(tx, &slot, present, &value, deadline(now(), ttl)?)?;
            super::work::insert(tx, &work, capacity)?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    async fn replace_ceremony_state_owing(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
        owed: OwedWork<'_>,
    ) -> SidResult<bool> {
        let (slot, expected, value) = (slot(namespace, key)?, expected.to_vec(), value.to_vec());
        let (work, capacity) = (owed.work.clone(), owed.capacity);
        self.transaction(move |tx| {
            let now = now();
            match stored(tx, &slot)? {
                Some((held, expires)) if expires > now && held == expected => {
                    write(tx, &slot, true, &value, deadline(now, ttl)?)?;
                    super::work::insert(tx, &work, capacity)?;
                    Ok(Decision::Commit(true))
                }
                _ => Ok(Decision::Abandon(false)),
            }
        })
        .await
    }

    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        let slot = slot(namespace, key)?;
        self.transaction(move |tx| match stored(tx, &slot)? {
            Some((value, expires)) if expires > now() => {
                delete(tx, &slot)?;
                Ok(Decision::Commit(Some(value)))
            }
            _ => Ok(Decision::Abandon(None)),
        })
        .await
    }

    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        let slot = slot(namespace, key)?;
        self.transaction(move |tx| {
            let now = now();
            Ok(Decision::Abandon(
                stored(tx, &slot)?
                    .filter(|(_, expires)| *expires > now)
                    .map(|(value, _)| value),
            ))
        })
        .await
    }

    async fn replace_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        let (slot, expected, value) = (slot(namespace, key)?, expected.to_vec(), value.to_vec());
        self.transaction(move |tx| {
            let now = now();
            match stored(tx, &slot)? {
                Some((held, expires)) if expires > now && held == expected => {
                    write(tx, &slot, true, &value, deadline(now, ttl)?)?;
                    Ok(Decision::Commit(true))
                }
                _ => Ok(Decision::Abandon(false)),
            }
        })
        .await
    }

    async fn count_in_window(
        &self,
        namespace: &str,
        key: &str,
        window: Duration,
    ) -> SidResult<u64> {
        let (slot, key) = (slot(namespace, key)?, key.to_owned());
        self.transaction(move |tx| {
            let now = now();
            let held = counted(tx, &slot)?;
            let (count, ends) = match held {
                Some((count, ends)) if ends > now => (
                    count
                        .checked_add(1)
                        .ok_or_else(|| SidError::Storage(format!("count of {key} overflows")))?,
                    ends,
                ),
                _ => (1, deadline(now, window)?),
            };
            let query = if held.is_some() {
                "MATCH (c:SidCeremonyCount) WHERE c.slot = $slot
                 SET c.count = $count, c.window_end = $window_end"
            } else {
                "CREATE (c:SidCeremonyCount {slot: $slot, count: $count, window_end: $window_end})"
            };
            tx.run(
                query,
                Params::default()
                    .with("slot", Value::Binary(slot.clone()))
                    .with("count", Value::Int(count))
                    .with("window_end", Value::Int(ends)),
            )?;
            Ok(Decision::Commit(count_of(&key, count)?))
        })
        .await
    }

    async fn read_count(&self, namespace: &str, key: &str) -> SidResult<u64> {
        let (slot, key) = (slot(namespace, key)?, key.to_owned());
        self.transaction(move |tx| {
            let now = now();
            let count = counted(tx, &slot)?
                .filter(|(_, ends)| *ends > now)
                .map_or(0, |(count, _)| count);
            Ok(Decision::Abandon(count_of(&key, count)?))
        })
        .await
    }

    async fn clear_count(&self, namespace: &str, key: &str) -> SidResult<()> {
        let slot = slot(namespace, key)?;
        self.transaction(move |tx| {
            if counted(tx, &slot)?.is_none() {
                return Ok(Decision::Abandon(()));
            }
            tx.run(
                "MATCH (c:SidCeremonyCount) WHERE c.slot = $slot DETACH DELETE c",
                Params::default().with("slot", Value::Binary(slot.clone())),
            )?;
            Ok(Decision::Commit(()))
        })
        .await
    }

    async fn purge_expired_ceremony_state(&self) -> SidResult<u64> {
        self.transaction(|tx| {
            // Two counts of stored nodes: their sum stays far inside u64.
            let dropped = purge(tx, "SidCeremonyState", "expires")?
                + purge(tx, "SidCeremonyCount", "window_end")?;
            Ok(if dropped == 0 {
                Decision::Abandon(0)
            } else {
                Decision::Commit(dropped)
            })
        })
        .await
    }

    async fn export_ceremony_state(&self) -> SidResult<CeremonyRecords> {
        self.read(|tx| {
            let now = now();
            let rows = tx.run(
                "MATCH (c:SidCeremonyState) WHERE c.expires > $now
                 RETURN c.slot AS slot, c.value AS value, c.expires AS expires",
                Params::default().with("now", Value::Int(now)),
            )?;
            let mut states = rows
                .iter()
                .map(|row| {
                    let (namespace, key) = unslot(&get_bytes(row, "slot")?)?;
                    Ok(CeremonyEntry {
                        namespace,
                        key,
                        value: get_bytes(row, "value")?,
                        expires_at: instant(get_int(row, "expires")?)?,
                    })
                })
                .collect::<SidResult<Vec<_>>>()?;
            states.sort_by(|a, b| (&a.namespace, &a.key).cmp(&(&b.namespace, &b.key)));
            let rows = tx.run(
                "MATCH (c:SidCeremonyCount) WHERE c.window_end > $now
                 RETURN c.slot AS slot, c.count AS count, c.window_end AS window_end",
                Params::default().with("now", Value::Int(now)),
            )?;
            let mut counts = rows
                .iter()
                .map(|row| {
                    let (namespace, key) = unslot(&get_bytes(row, "slot")?)?;
                    Ok(CeremonyCount {
                        count: count_of(&key, get_int(row, "count")?)?,
                        namespace,
                        key,
                        window_ends: instant(get_int(row, "window_end")?)?,
                    })
                })
                .collect::<SidResult<Vec<_>>>()?;
            counts.sort_by(|a, b| (&a.namespace, &a.key).cmp(&(&b.namespace, &b.key)));
            Ok(CeremonyRecords { states, counts })
        })
        .await
    }

    async fn import_ceremony_state(&self, records: &CeremonyRecords) -> SidResult<u64> {
        let records = records.clone();
        self.transaction(move |tx| {
            let now = now();
            let mut stored_count = 0u64;
            for entry in &records.states {
                let slot = slot(&entry.namespace, &entry.key)?;
                let wanted = (entry.value.clone(), entry.expires_at.timestamp_micros());
                let held = stored(tx, &slot)?;
                match &held {
                    Some(live) if live.1 > now => {
                        let held = (live.0.clone(), whole_ms(live.1));
                        crate::transfer_repeat(&held, &wanted, "ceremony state")?;
                    }
                    _ => {
                        write(tx, &slot, held.is_some(), &wanted.0, wanted.1)?;
                        stored_count += 1;
                    }
                }
            }
            for count in &records.counts {
                let slot = slot(&count.namespace, &count.key)?;
                let value = i64::try_from(count.count).map_err(|_| {
                    SidError::Validation(format!("count of {} is too large", count.key))
                })?;
                let wanted = (value, count.window_ends.timestamp_micros());
                let held = counted(tx, &slot)?;
                match &held {
                    Some(live) if live.1 > now => {
                        crate::transfer_repeat(
                            &(live.0, whole_ms(live.1)),
                            &wanted,
                            "ceremony count",
                        )?;
                    }
                    _ => {
                        let query = if held.is_some() {
                            "MATCH (c:SidCeremonyCount) WHERE c.slot = $slot
                             SET c.count = $count, c.window_end = $window_end"
                        } else {
                            "CREATE (c:SidCeremonyCount {slot: $slot, count: $count,
                                window_end: $window_end})"
                        };
                        tx.run(
                            query,
                            Params::default()
                                .with("slot", Value::Binary(slot.clone()))
                                .with("count", Value::Int(wanted.0))
                                .with("window_end", Value::Int(wanted.1)),
                        )?;
                        stored_count += 1;
                    }
                }
            }
            Ok(if stored_count == 0 {
                Decision::Abandon(0)
            } else {
                Decision::Commit(stored_count)
            })
        })
        .await
    }
}

/// The namespace and key a slot was made of.
fn unslot(slot: &[u8]) -> SidResult<(String, String)> {
    let malformed = || SidError::Storage("malformed ceremony slot".into());
    let (length, rest) = slot.split_first_chunk::<4>().ok_or_else(malformed)?;
    let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| malformed())?;
    let (namespace, key) = rest.split_at_checked(length).ok_or_else(malformed)?;
    Ok((
        String::from_utf8(namespace.to_vec()).map_err(|_| malformed())?,
        String::from_utf8(key.to_vec()).map_err(|_| malformed())?,
    ))
}

/// A stored microsecond deadline at millisecond precision, the precision
/// every store keeps a deadline at; truncated, so it never lasts longer.
fn whole_ms(micros: i64) -> i64 {
    micros - micros.rem_euclid(1000)
}

/// The instant of a stored microsecond deadline, at millisecond precision.
fn instant(micros: i64) -> SidResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_micros(whole_ms(micros))
        .ok_or_else(|| SidError::Storage(format!("ceremony deadline {micros} is out of range")))
}
