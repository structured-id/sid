// SPDX-License-Identifier: AGPL-3.0-only
//! Versioned upgrades of a SQLite database file.
//!
//! A file records its schema version in `PRAGMA user_version`. Opening one
//! applies, in one `BEGIN IMMEDIATE` transaction, the baseline (an empty file
//! only) and every migration above its version, then records the new
//! version: an interrupted upgrade leaves the file as it was and the next
//! open starts again, and a second process opening the same file waits for
//! the first and finds it current. A file this build cannot serve (from a
//! newer build, or a pre-versioning file whose schema is not the baseline)
//! is refused unchanged, never recreated.

use sid_core::{Error as SidError, Result as SidResult};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{SqliteConnection, SqlitePool};
use std::str::FromStr;

/// The version a file has once the baseline schema is applied.
pub(crate) const BASELINE_VERSION: i64 = 1;

/// One schema change, applied to files below `version`.
pub(crate) struct Migration {
    pub version: i64,
    pub sql: &'static str,
}

/// Every migration above the baseline, in ascending version order.
pub(crate) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 2,
        sql: EMAIL_POLICY_REVISION,
    },
    Migration {
        version: 3,
        sql: WEBAUTHN_USER_HANDLES,
    },
    Migration {
        version: 4,
        sql: CREDENTIAL_POLICY_ARTIFACT,
    },
    Migration {
        version: 5,
        sql: HISTORY_EVALUATOR_SPLIT,
    },
];

/// The history evaluator's keys and lifecycle move to its own tables, keyed by
/// the owner's history input domain; the PostgreSQL migration 058 and the
/// evaluator's own migration set state the contract. An embedded file keeps
/// both in one database. Only an empty history layout is converted: the guard
/// row's check fails, aborting the whole upgrade unchanged, when any history
/// data exists. The upgrade transaction holds the write lock, so nothing is
/// written between the check and the change.
const HISTORY_EVALUATOR_SPLIT: &str = "
CREATE TEMP TABLE history_split_guard (rows INTEGER NOT NULL CHECK (rows = 0));
INSERT INTO history_split_guard (rows) SELECT
    (SELECT count(*) FROM password_histories)
  + (SELECT count(*) FROM password_history_epochs)
  + (SELECT count(*) FROM password_history_entries)
  + (SELECT count(*) FROM password_history_lifecycle)
  + (SELECT count(*) FROM password_history_replaced)
  + (SELECT count(*) FROM password_history_uses);
DROP TABLE history_split_guard;

DROP TABLE password_history_uses;
DROP TABLE password_history_replaced;
DROP TABLE password_history_lifecycle;
ALTER TABLE password_history_epochs DROP COLUMN wrapped_key;

CREATE TABLE password_history_write_cutoff (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    not_before TEXT
);
INSERT INTO password_history_write_cutoff (singleton) VALUES (1);

CREATE TABLE history_key_write_cutoff (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    not_before TEXT
);
INSERT INTO history_key_write_cutoff (singleton) VALUES (1);

CREATE TABLE history_key_epochs (
    id              TEXT PRIMARY KEY,
    owner_domain    BLOB NOT NULL CHECK (length(owner_domain) = 32),
    suite           TEXT NOT NULL CHECK (suite IN ('pallas-poseidon-v1')),
    public_key      BLOB NOT NULL CHECK (length(public_key) = 32),
    wrapped_key     BLOB NOT NULL,
    ksf_memory_kib  INTEGER NOT NULL CHECK (ksf_memory_kib > 0),
    ksf_passes      INTEGER NOT NULL CHECK (ksf_passes > 0),
    ksf_lanes       INTEGER NOT NULL CHECK (ksf_lanes > 0),
    ksf_salt        BLOB NOT NULL CHECK (length(ksf_salt) = 32),
    status          TEXT NOT NULL CHECK (status IN ('active', 'compare_only', 'retired')),
    created_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX history_key_one_active_epoch
    ON history_key_epochs (owner_domain) WHERE status = 'active';

CREATE INDEX history_key_epochs_owner ON history_key_epochs (owner_domain);

CREATE TABLE history_key_lifecycle (
    owner_domain BLOB PRIMARY KEY CHECK (length(owner_domain) = 32),
    revision     INTEGER NOT NULL CHECK (revision >= 0),
    live_epochs  TEXT NOT NULL
);

CREATE TABLE history_key_replaced (
    epoch_id             TEXT PRIMARY KEY REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain         BLOB NOT NULL CHECK (length(owner_domain) = 32),
    replaced_at_revision INTEGER NOT NULL CHECK (replaced_at_revision > 0)
);

CREATE TABLE history_key_uses (
    operation_id TEXT NOT NULL,
    epoch_id     TEXT NOT NULL REFERENCES history_key_epochs(id) ON DELETE CASCADE,
    owner_domain BLOB NOT NULL CHECK (length(owner_domain) = 32),
    expires_at   TEXT NOT NULL,
    PRIMARY KEY (operation_id, epoch_id)
);

CREATE INDEX history_key_uses_owner ON history_key_uses (owner_domain, epoch_id);

CREATE TABLE history_key_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor_id    TEXT NOT NULL,
    actor_type  TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    metadata    TEXT NOT NULL
);
";

/// Policy verdicts name their verifying artifact; the PostgreSQL migration
/// 056 states the contract. SQLite cannot add a table constraint, so
/// triggers refuse a row whose evidence columns disagree.
const CREDENTIAL_POLICY_ARTIFACT: &str = "
ALTER TABLE credentials ADD COLUMN zkpp_artifact BLOB CHECK (length(zkpp_artifact) = 32);

CREATE TABLE credential_policy_evidence_legacy (
    credential_id   TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    zkpp_verified   INTEGER NOT NULL,
    policy_version  INTEGER,
    reason          TEXT NOT NULL CHECK (reason IN ('artifact_not_recorded')),
    demoted_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO credential_policy_evidence_legacy (credential_id, profile_id, zkpp_verified, policy_version, reason)
SELECT id, profile_id, zkpp_verified, policy_version, 'artifact_not_recorded'
FROM credentials
WHERE zkpp_artifact IS NULL AND (zkpp_verified <> 0 OR policy_version IS NOT NULL);

UPDATE credentials SET zkpp_verified = 0, policy_version = NULL
WHERE zkpp_artifact IS NULL AND (zkpp_verified <> 0 OR policy_version IS NOT NULL);

CREATE TRIGGER credentials_policy_evidence_insert
BEFORE INSERT ON credentials
WHEN NOT ((NEW.zkpp_verified <> 0 AND NEW.policy_version IS NOT NULL AND NEW.zkpp_artifact IS NOT NULL)
       OR (NEW.zkpp_verified = 0 AND NEW.policy_version IS NULL AND NEW.zkpp_artifact IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'credential policy evidence');
END;

CREATE TRIGGER credentials_policy_evidence_update
BEFORE UPDATE OF zkpp_verified, policy_version, zkpp_artifact ON credentials
WHEN NOT ((NEW.zkpp_verified <> 0 AND NEW.policy_version IS NOT NULL AND NEW.zkpp_artifact IS NOT NULL)
       OR (NEW.zkpp_verified = 0 AND NEW.policy_version IS NULL AND NEW.zkpp_artifact IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'credential policy evidence');
END;
";

/// WebAuthn user handles; the PostgreSQL migration 054 states the contract.
const WEBAUTHN_USER_HANDLES: &str = "
CREATE TABLE webauthn_user_handles (
    profile_id  TEXT NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    rp_id       TEXT NOT NULL,
    user_handle BLOB NOT NULL CHECK (length(user_handle) = 16),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile_id, rp_id),
    UNIQUE (rp_id, user_handle)
);
";

/// Email policy revisions; the PostgreSQL migration 053 states the contract.
/// Keys written before revisions are revision 0 and quarantined: reserved,
/// never routed. The fence lets an email key be written only under the
/// active revision; a build that does not know revisions writes none.
const EMAIL_POLICY_REVISION: &str = "
CREATE TABLE email_policy_activations (
    scope        TEXT PRIMARY KEY,
    revision     INTEGER NOT NULL CHECK (revision > 0),
    activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

ALTER TABLE principals ADD COLUMN email_policy_revision INTEGER;

UPDATE principals SET email_policy_revision = 0 WHERE principal_type = 'email';

CREATE TABLE email_policy_dispositions (
    principal_id  TEXT PRIMARY KEY REFERENCES principals (id) ON DELETE CASCADE,
    from_revision INTEGER NOT NULL,
    to_revision   INTEGER NOT NULL,
    disposition   TEXT NOT NULL CHECK (disposition IN ('migrated', 'quarantined')),
    reason        TEXT NOT NULL,
    recorded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO email_policy_dispositions (principal_id, from_revision, to_revision, disposition, reason)
SELECT id, 0, 1, 'quarantined', 'no_source_evidence'
FROM principals WHERE principal_type = 'email';

INSERT INTO email_policy_activations (scope, revision) VALUES ('installation', 1);

CREATE TRIGGER principals_email_policy_insert
BEFORE INSERT ON principals
WHEN (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
  OR (NEW.principal_type = 'email'
      AND NEW.email_policy_revision IS NOT
          (SELECT revision FROM email_policy_activations WHERE scope = 'installation'))
BEGIN
    SELECT RAISE(ABORT, 'email policy fence');
END;

CREATE TRIGGER principals_email_policy_update
BEFORE UPDATE OF value, email_policy_revision, principal_type ON principals
WHEN (NEW.principal_type = 'email') <> (NEW.email_policy_revision IS NOT NULL)
  OR (NEW.principal_type = 'email'
      AND (NEW.value IS NOT OLD.value
           OR NEW.email_policy_revision IS NOT OLD.email_policy_revision)
      AND NEW.email_policy_revision IS NOT
          (SELECT revision FROM email_policy_activations WHERE scope = 'installation'))
BEGIN
    SELECT RAISE(ABORT, 'email policy fence');
END;
";

/// Bring the file behind `pool` to the latest version of `baseline` plus
/// `migrations`.
pub(crate) async fn upgrade(
    pool: &SqlitePool,
    baseline: &'static str,
    migrations: &[Migration],
) -> SidResult<()> {
    let latest = migrations.last().map_or(BASELINE_VERSION, |m| m.version);
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage("begin schema upgrade"))?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("read schema version"))?;
    let from = match version {
        0 if objects(&mut tx).await?.is_empty() => {
            sqlx::raw_sql(baseline)
                .execute(&mut *tx)
                .await
                .map_err(storage("create baseline schema"))?;
            BASELINE_VERSION
        }
        // A file from before versioning is served only if it is exactly the
        // baseline; anything else has an unknown shape.
        0 if objects(&mut tx).await? == baseline_objects(baseline).await? => BASELINE_VERSION,
        0 => {
            return Err(SidError::InvalidState(
                "the SQLite file has an unversioned schema that is not the baseline; \
                 it is left unchanged"
                    .into(),
            ));
        }
        v if v > latest => {
            return Err(SidError::InvalidState(format!(
                "the SQLite file has schema version {v}, newer than {latest} this build \
                 serves; it is left unchanged"
            )));
        }
        v => v,
    };
    for migration in migrations.iter().filter(|m| m.version > from) {
        sqlx::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                SidError::Storage(format!("schema migration {}: {e}", migration.version))
            })?;
    }
    if version != latest {
        // A PRAGMA takes no bound parameter; `latest` is an integer.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "PRAGMA user_version = {latest}"
        )))
        .execute(&mut *tx)
        .await
        .map_err(storage("record schema version"))?;
    }
    tx.commit().await.map_err(storage("commit schema upgrade"))
}

/// The schema objects of a database (tables, indexes, triggers, views) as
/// SQLite records them, in a stable order.
async fn objects(conn: &mut SqliteConnection) -> SidResult<Vec<(String, String, Option<String>)>> {
    sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )
    .fetch_all(conn)
    .await
    .map_err(storage("read schema objects"))
}

/// The schema objects `baseline` creates, from a scratch in-memory database.
async fn baseline_objects(
    baseline: &'static str,
) -> SidResult<Vec<(String, String, Option<String>)>> {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .map_err(storage("open reference database"))?;
    let reference = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(storage("open reference database"))?;
    let mut conn = reference
        .acquire()
        .await
        .map_err(storage("open reference database"))?;
    sqlx::raw_sql(baseline)
        .execute(&mut *conn)
        .await
        .map_err(storage("create reference schema"))?;
    objects(&mut conn).await
}

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests;
