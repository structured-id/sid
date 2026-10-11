// SPDX-License-Identifier: AGPL-3.0-only
//! JetStream topology of the identity family: a retained history of facts
//! and the addressed work of required receivers, on disjoint subjects.
//!
//! - History (`<root>.events.identity.>`): `Limits` retention bounded by age,
//!   read by observers and replay. It is never the last copy of an obligation.
//! - Work (`<root>.work.identity.<recipient>.>`): file-backed `WorkQueue`
//!   with no age limit and bounded bytes and messages; a full queue refuses
//!   the publication (`DiscardNew`), so the producer keeps its obligation.
//!   A message stays until its receiver's consumer settles it, whether or
//!   not that consumer exists yet; nobody purges or deletes it.
//!
//! One owner per deployment creates these streams; every process, the owner
//! included, verifies existing ones and is not ready while they differ.
//! Nothing here changes a stream that exists.

use std::collections::HashMap;
use std::time::Duration;

use async_nats::jetstream::{self, stream};
use sid_core::models::event::WorkRecipient;

/// Version of the stream definitions below. An owner refuses to touch a
/// stream that a newer version defined.
pub const TOPOLOGY_VERSION: u32 = 1;

/// Stream metadata key carrying [`TOPOLOGY_VERSION`].
const VERSION_KEY: &str = "sid.topology.version";

/// The prefix every catalogued event type carries; transport subjects
/// replace it with the family's subject prefix.
const TYPE_PREFIX: &str = "sid.";

/// Who may create and change the streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyRole {
    /// The deployment's topology owner: creates missing streams. An
    /// existing stream must already be as defined; it is never changed.
    Own,
    /// Any other producer or consumer: the streams must already be as
    /// defined here.
    Verify,
}

/// Bounds and placement of the identity streams.
#[derive(Debug, Clone)]
pub struct Topology {
    /// First subject token and stream-name prefix: `sid`. Isolated
    /// topologies sharing one server (the test suite) use another.
    root: String,
    /// How long a fact stays in history.
    pub history_max_age: Duration,
    /// Messages the work stream holds before refusing new work.
    pub work_max_messages: i64,
    /// Bytes the work stream holds before refusing new work.
    pub work_max_bytes: i64,
    /// Copies of each stream in a clustered server.
    pub replicas: usize,
}

impl Default for Topology {
    fn default() -> Self {
        Self {
            root: "sid".into(),
            history_max_age: Duration::from_secs(7 * 24 * 60 * 60),
            work_max_messages: 1_000_000,
            work_max_bytes: 1 << 30,
            replicas: 1,
        }
    }
}

/// Why the topology is not usable.
#[derive(Debug, thiserror::Error)]
pub enum TopologyError {
    /// Another stream already holds these subjects, such as a broad stream
    /// of an earlier installation. Nothing was changed.
    #[error("stream {held_by} already holds {subjects}; it must be drained into this topology")]
    Conflict { subjects: String, held_by: String },
    /// A newer topology version defined the stream; this process is stale.
    #[error(
        "stream {stream} is defined by topology version {found}, newer than {TOPOLOGY_VERSION}"
    )]
    Newer { stream: String, found: String },
    /// The stream is missing or differs and this process does not own it.
    #[error("stream {stream} is not as this topology defines it: {reason}")]
    NotReady { stream: String, reason: String },
    #[error("NATS: {0}")]
    Nats(String),
    /// The deployment's topology settings are invalid.
    #[error("event topology configuration: {0}")]
    Config(String),
}

impl TopologyRole {
    /// `SID_NATS_TOPOLOGY`: `own` or `verify`; `default` when unset. Every
    /// deployment names one owner; the others verify.
    pub fn from_env(default: Self) -> Result<Self, TopologyError> {
        match std::env::var("SID_NATS_TOPOLOGY").ok().as_deref() {
            None | Some("") => Ok(default),
            Some("own") => Ok(Self::Own),
            Some("verify") => Ok(Self::Verify),
            Some(other) => Err(TopologyError::Config(format!(
                "SID_NATS_TOPOLOGY must be `own` or `verify`, got `{other}`"
            ))),
        }
    }
}

/// `name` as a positive number, or `default` when unset.
fn env_number<T: std::str::FromStr + PartialOrd + Default>(
    name: &str,
    default: T,
) -> Result<T, TopologyError> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(value) => value
            .parse::<T>()
            .ok()
            .filter(|n| *n > T::default())
            .ok_or_else(|| TopologyError::Config(format!("{name} must be a positive number"))),
    }
}

impl Topology {
    /// The deployment's topology: `SID_NATS_HISTORY_MAX_AGE_SECS`,
    /// `SID_NATS_WORK_MAX_MESSAGES`, `SID_NATS_WORK_MAX_BYTES` and
    /// `SID_NATS_REPLICAS` over the defaults. Every process of a deployment
    /// reads the same values: one that differs is not ready.
    pub fn from_env() -> Result<Self, TopologyError> {
        let default = Self::default();
        Ok(Self {
            history_max_age: Duration::from_secs(env_number(
                "SID_NATS_HISTORY_MAX_AGE_SECS",
                default.history_max_age.as_secs(),
            )?),
            work_max_messages: env_number("SID_NATS_WORK_MAX_MESSAGES", default.work_max_messages)?,
            work_max_bytes: env_number("SID_NATS_WORK_MAX_BYTES", default.work_max_bytes)?,
            replicas: env_number("SID_NATS_REPLICAS", default.replicas)?,
            ..default
        })
    }

    /// A topology under subject root `root` (one token: letters, digits,
    /// `-`, `_`).
    pub fn with_root(root: impl Into<String>) -> Result<Self, TopologyError> {
        let root = root.into();
        let valid = !root.is_empty()
            && root
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(TopologyError::Config(format!(
                "invalid subject root {root:?}"
            )));
        }
        Ok(Self {
            root,
            ..Self::default()
        })
    }

    fn stream_prefix(&self) -> String {
        self.root.to_ascii_uppercase().replace('-', "_")
    }

    /// The retained history stream.
    pub fn history_stream(&self) -> String {
        format!("{}_IDENTITY_EVENTS", self.stream_prefix())
    }

    /// The addressed work stream.
    pub fn work_stream(&self) -> String {
        format!("{}_IDENTITY_WORK", self.stream_prefix())
    }

    fn history_prefix(&self) -> String {
        format!("{}.events.identity", self.root)
    }

    fn work_prefix(&self, recipient: &WorkRecipient) -> String {
        format!("{}.work.identity.{recipient}", self.root)
    }

    /// The history subject of `event_type`; `None` for a type outside the
    /// catalogue's naming.
    pub fn history_subject(&self, event_type: &str) -> Option<String> {
        concrete(event_type).map(|rest| format!("{}.{rest}", self.history_prefix()))
    }

    /// The subject of `event_type` addressed to `recipient`.
    pub fn work_subject(&self, recipient: &WorkRecipient, event_type: &str) -> Option<String> {
        concrete(event_type).map(|rest| format!("{}.{rest}", self.work_prefix(recipient)))
    }

    /// History subjects matching type patterns (`prefix.*` and `prefix.>`
    /// take any suffix); empty is all history.
    pub fn history_filters(&self, patterns: &[String]) -> Result<Vec<String>, String> {
        filters(&self.history_prefix(), patterns)
    }

    /// Work subjects of `recipient` matching type patterns; empty is
    /// everything addressed to it.
    pub fn work_filters(
        &self,
        recipient: &WorkRecipient,
        patterns: &[String],
    ) -> Result<Vec<String>, String> {
        filters(&self.work_prefix(recipient), patterns)
    }

    fn metadata() -> HashMap<String, String> {
        HashMap::from([(VERSION_KEY.to_string(), TOPOLOGY_VERSION.to_string())])
    }

    /// The history stream's definition.
    pub fn history_config(&self) -> stream::Config {
        stream::Config {
            name: self.history_stream(),
            subjects: vec![format!("{}.>", self.history_prefix())],
            retention: stream::RetentionPolicy::Limits,
            storage: stream::StorageType::File,
            max_age: self.history_max_age,
            // Unlimited, written as the server reports it.
            max_messages: -1,
            max_bytes: -1,
            num_replicas: self.replicas,
            metadata: Self::metadata(),
            ..Default::default()
        }
    }

    /// The work stream's definition.
    pub fn work_config(&self) -> stream::Config {
        stream::Config {
            name: self.work_stream(),
            subjects: vec![format!("{}.work.identity.>", self.root)],
            retention: stream::RetentionPolicy::WorkQueue,
            storage: stream::StorageType::File,
            // Age never removes work; only its receiver's settlement does.
            max_age: Duration::ZERO,
            // The duplicate window stays the server's: it only spares a quick
            // republication. A handoff repeated after it (a crash between the
            // broker's acknowledgement and the producer recording it) arrives
            // again with the same delivery id, and every receiver keys what it
            // stores by that id (a routing job, a dispatch job, a settlement),
            // so it takes effect once however late it comes.
            max_messages: self.work_max_messages,
            max_bytes: self.work_max_bytes,
            discard: stream::DiscardPolicy::New,
            deny_delete: true,
            deny_purge: true,
            allow_rollup: false,
            allow_message_ttl: false,
            num_replicas: self.replicas,
            metadata: Self::metadata(),
            ..Default::default()
        }
    }

    /// Bring the streams to this definition (`Own`) or check that they are
    /// (`Verify`). A stream of another name holding the subjects, or one a
    /// newer version defined, is left untouched and refused.
    pub async fn prepare(
        &self,
        js: &jetstream::Context,
        role: TopologyRole,
    ) -> Result<(), TopologyError> {
        for config in [self.history_config(), self.work_config()] {
            prepare_stream(js, config, role).await?;
        }
        Ok(())
    }
}

/// `event_type` without the catalogue prefix, when it is a concrete type.
fn concrete(event_type: &str) -> Option<&str> {
    event_type
        .strip_prefix(TYPE_PREFIX)
        .filter(|rest| !rest.is_empty() && !rest.contains(['*', '>', ' ']))
}

fn filters(prefix: &str, patterns: &[String]) -> Result<Vec<String>, String> {
    if patterns.is_empty() {
        return Ok(vec![format!("{prefix}.>")]);
    }
    patterns
        .iter()
        .map(|pattern| {
            if pattern == "sid.>" || pattern == "sid.*" {
                return Ok(format!("{prefix}.>"));
            }
            let rest = pattern
                .strip_prefix(TYPE_PREFIX)
                .ok_or_else(|| format!("type pattern {pattern:?} is outside the catalogue"))?;
            // A trailing `*` takes any suffix, as the bus's own type
            // filters do, so it becomes the multi-token wildcard.
            Ok(match rest.strip_suffix(".*") {
                Some(head) => format!("{prefix}.{head}.>"),
                None => format!("{prefix}.{rest}"),
            })
        })
        .collect()
}

/// The definition's fields that decide retention and placement, as the
/// server reports them, compared with what the topology requires.
fn differs(found: &stream::Config, wanted: &stream::Config) -> Option<String> {
    let checks: [(&str, bool); 12] = [
        ("subjects", found.subjects != wanted.subjects),
        ("retention", found.retention != wanted.retention),
        ("storage", found.storage != wanted.storage),
        ("max_age", found.max_age != wanted.max_age),
        ("max_messages", found.max_messages != wanted.max_messages),
        ("max_bytes", found.max_bytes != wanted.max_bytes),
        ("discard", found.discard != wanted.discard),
        ("deny_delete", found.deny_delete != wanted.deny_delete),
        ("deny_purge", found.deny_purge != wanted.deny_purge),
        // Either would remove a message nobody settled.
        (
            "allow_message_ttl",
            found.allow_message_ttl != wanted.allow_message_ttl,
        ),
        ("allow_rollup", found.allow_rollup != wanted.allow_rollup),
        ("replicas", found.num_replicas != wanted.num_replicas),
    ];
    let differing: Vec<&str> = checks
        .iter()
        .filter(|(_, differ)| *differ)
        .map(|(name, _)| *name)
        .collect();
    (!differing.is_empty()).then(|| differing.join(", "))
}

async fn prepare_stream(
    js: &jetstream::Context,
    wanted: stream::Config,
    role: TopologyRole,
) -> Result<(), TopologyError> {
    use async_nats::jetstream::context::GetStreamByNameErrorKind;

    let probe = wanted.subjects[0].clone();
    let holder = |js: &jetstream::Context| {
        let probe = probe.clone();
        let js = js.clone();
        async move {
            match js.stream_by_subject(probe.clone()).await {
                Ok(name) => Ok(Some(name)),
                Err(e) if e.kind() == GetStreamByNameErrorKind::NotFound => Ok(None),
                Err(e) => Err(TopologyError::Nats(format!("look up {probe}: {e}"))),
            }
        }
    };
    let held_by = match (holder(js).await?, role) {
        (Some(name), _) => name,
        (None, TopologyRole::Verify) => {
            return Err(TopologyError::NotReady {
                stream: wanted.name,
                reason: "missing".into(),
            });
        }
        (None, TopologyRole::Own) => match js.create_stream(wanted.clone()).await {
            Ok(_) => return Ok(()),
            // Another replica of the owner may have created it meanwhile:
            // what holds the subjects now decides.
            Err(e) => holder(js)
                .await?
                .ok_or_else(|| TopologyError::Nats(format!("create {}: {e}", wanted.name)))?,
        },
    };
    if held_by != wanted.name {
        return Err(TopologyError::Conflict {
            subjects: probe,
            held_by,
        });
    }
    let mut stream = js
        .get_stream(&wanted.name)
        .await
        .map_err(|e| TopologyError::Nats(format!("get {}: {e}", wanted.name)))?;
    let found = stream
        .info()
        .await
        .map_err(|e| TopologyError::Nats(format!("info {}: {e}", wanted.name)))?
        .config
        .clone();
    let version = found.metadata.get(VERSION_KEY).cloned().unwrap_or_default();
    if version
        .parse::<u32>()
        .is_ok_and(|found| found > TOPOLOGY_VERSION)
    {
        return Err(TopologyError::Newer {
            stream: wanted.name,
            found: version,
        });
    }
    // An existing stream is never changed here, by the owner either: a
    // stream definition cannot be compared and swapped atomically, so a
    // stale owner reading before a newer one wrote could roll it back.
    // Moving to another definition is a transition of its own.
    let current = version == TOPOLOGY_VERSION.to_string();
    match differs(&found, &wanted) {
        None if current => Ok(()),
        reason => Err(TopologyError::NotReady {
            stream: wanted.name,
            reason: reason.unwrap_or_else(|| format!("topology version {version:?}")),
        }),
    }
}

#[cfg(test)]
mod tests;
