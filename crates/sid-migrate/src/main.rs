// SPDX-License-Identifier: AGPL-3.0-only
//! sid-migrate: offline transfer of an installation's database between
//! SQLite and PostgreSQL through the portable snapshot of `sid-storage`.
//!
//! ```bash
//! # Export into an encrypted archive
//! sid-migrate export --source "sqlite:///var/lib/sid/auth.db" --output backup.sidsnap --key-file archive.key
//!
//! # Import an archive into an uninitialized installation
//! sid-migrate import --target "postgres://user:pass@db:5432/sid" --input backup.sidsnap --key-file archive.key
//!
//! # Direct migration
//! sid-migrate migrate --source "sqlite:///path" --target "postgres://..."
//!
//! # Verify a migration
//! sid-migrate verify --source "sqlite:///path" --target "postgres://..."
//! ```

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sid_authn::snapshot_rules::AuthnSnapshotRules;
use sid_plugin::audit::AuditLog;
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use sid_storage::snapshot::{self, archive};
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "sid-migrate",
    version,
    about = "StructuredID data migration tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Export all data of a stopped SID installation into an encrypted archive.
    Export {
        /// Source database URL (e.g., "sqlite:///var/lib/sid/auth.db" or "postgres://...")
        #[arg(long)]
        source: String,

        /// Output archive path; an existing file is refused
        #[arg(long, short)]
        output: PathBuf,

        /// The archive key: a file of exactly 32 random bytes
        #[arg(long)]
        key_file: PathBuf,

        /// PostgreSQL schema name (for shared-database deployments)
        #[arg(long)]
        schema: Option<String>,

        /// The password-history evaluator's database, when it is not the
        /// source database (PostgreSQL URL)
        #[arg(long)]
        history_keys: Option<String>,
    },

    /// Import an archive into an uninitialized SID installation, or resume
    /// the interrupted import of the same archive into it.
    Import {
        /// Target database URL
        #[arg(long)]
        target: String,

        /// Input archive path
        #[arg(long, short)]
        input: PathBuf,

        /// The archive key the archive was exported under
        #[arg(long)]
        key_file: PathBuf,

        /// PostgreSQL schema name (for shared-database deployments)
        #[arg(long)]
        schema: Option<String>,

        /// The password-history evaluator's database, when it is not the
        /// target database (PostgreSQL URL)
        #[arg(long)]
        history_keys: Option<String>,
    },

    /// Migrate data directly from one backend to another (no intermediate file).
    Migrate {
        /// Source database URL
        #[arg(long)]
        source: String,

        /// Target database URL
        #[arg(long)]
        target: String,

        /// Source PostgreSQL schema name
        #[arg(long)]
        source_schema: Option<String>,

        /// Target PostgreSQL schema name
        #[arg(long)]
        target_schema: Option<String>,

        /// The source's password-history evaluator database, when separate
        #[arg(long)]
        source_history_keys: Option<String>,

        /// The target's password-history evaluator database, when separate
        #[arg(long)]
        target_history_keys: Option<String>,
    },

    /// Verify data consistency between two backends.
    Verify {
        /// Source database URL
        #[arg(long)]
        source: String,

        /// Target database URL
        #[arg(long)]
        target: String,

        /// Source PostgreSQL schema name
        #[arg(long)]
        source_schema: Option<String>,

        /// Target PostgreSQL schema name
        #[arg(long)]
        target_schema: Option<String>,

        /// The source's password-history evaluator database, when separate
        #[arg(long)]
        source_history_keys: Option<String>,

        /// The target's password-history evaluator database, when separate
        #[arg(long)]
        target_history_keys: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("another TLS crypto provider is already installed"))?;
    sid_crypto::jwt::install_jwt_provider()?;
    let crypto = sid_crypto::AwsLcPrimitives::new();
    let rules = AuthnSnapshotRules;

    match cli.command {
        Commands::Export {
            source,
            output,
            key_file,
            schema,
            history_keys,
        } => {
            check_backend(&source, schema.as_deref(), history_keys.as_deref())?;
            let key = archive_key(&key_file).await?;
            info!(output = %output.display(), "starting export");
            let store =
                connect_backend(&source, schema.as_deref(), history_keys.as_deref()).await?;
            let snapshot = snapshot::export(store.store(), &rules).await?;
            let sealed = archive::seal(&snapshot, &key, &crypto)?;
            write_new(&output, &sealed).await?;
            println!(
                "Exported {} entities to {}",
                snapshot.metadata.total_entities,
                output.display()
            );
        }

        Commands::Import {
            target,
            input,
            key_file,
            schema,
            history_keys,
        } => {
            check_backend(&target, schema.as_deref(), history_keys.as_deref())?;
            let key = archive_key(&key_file).await?;
            info!(input = %input.display(), "starting import");
            let sealed = tokio::fs::read(&input)
                .await
                .context("failed to read the archive")?;
            let snapshot = archive::open(&sealed, &key, &crypto)?;
            info!(
                snapshot = %snapshot.metadata.snapshot_id,
                source_backend = %snapshot.metadata.source_backend,
                entities = snapshot.metadata.total_entities,
                "archive opened"
            );
            let store =
                connect_backend(&target, schema.as_deref(), history_keys.as_deref()).await?;
            let result = snapshot::import(store.store(), &rules, &crypto, &snapshot).await?;
            println!("{result}");
        }

        Commands::Migrate {
            source,
            target,
            source_schema,
            target_schema,
            source_history_keys,
            target_history_keys,
        } => {
            check_backend(
                &source,
                source_schema.as_deref(),
                source_history_keys.as_deref(),
            )?;
            check_backend(
                &target,
                target_schema.as_deref(),
                target_history_keys.as_deref(),
            )?;
            info!("starting direct migration");
            let source_store = connect_backend(
                &source,
                source_schema.as_deref(),
                source_history_keys.as_deref(),
            )
            .await?;
            let target_store = connect_backend(
                &target,
                target_schema.as_deref(),
                target_history_keys.as_deref(),
            )
            .await?;
            let snapshot = snapshot::export(source_store.store(), &rules).await?;
            let result = snapshot::import(target_store.store(), &rules, &crypto, &snapshot).await?;
            println!("{result}");

            info!("running post-migration verification...");
            let verified =
                snapshot::verify(source_store.store(), target_store.store(), &rules).await?;
            println!("{verified}");
            if !verified.passed {
                bail!("post-migration verification failed");
            }
        }

        Commands::Verify {
            source,
            target,
            source_schema,
            target_schema,
            source_history_keys,
            target_history_keys,
        } => {
            check_backend(
                &source,
                source_schema.as_deref(),
                source_history_keys.as_deref(),
            )?;
            check_backend(
                &target,
                target_schema.as_deref(),
                target_history_keys.as_deref(),
            )?;
            let source_store = connect_backend(
                &source,
                source_schema.as_deref(),
                source_history_keys.as_deref(),
            )
            .await?;
            let target_store = connect_backend(
                &target,
                target_schema.as_deref(),
                target_history_keys.as_deref(),
            )
            .await?;
            let result =
                snapshot::verify(source_store.store(), target_store.store(), &rules).await?;
            println!("{result}");
            if !result.passed {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// The archive key the operator keeps in `path`.
async fn archive_key(path: &Path) -> Result<archive::ArchiveKey> {
    let bytes = tokio::fs::read(path)
        .await
        .context("failed to read the archive key file")?;
    Ok(archive::ArchiveKey::from_bytes(&bytes)?)
}

/// Write `bytes` to a new owner-readable file at `path`, never following or
/// truncating an existing one: an archive carries sealed credentials.
async fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .await
        .context("failed to create the output file")?;
    use tokio::io::AsyncWriteExt;
    file.write_all(bytes)
        .await
        .context("failed to write the output file")?;
    file.sync_all()
        .await
        .context("failed to synchronize the output file")
}

/// One installation's data: its storage backend, the audit log over it and
/// the password-history evaluator's key store, which a standalone
/// installation keeps in the same database under its own tables and a split
/// one in the evaluator's own.
struct Connected {
    storage: Box<dyn StorageBackend>,
    audit: Box<dyn AuditLog>,
    keys: Box<dyn HistoryKeyStore>,
}

impl Connected {
    fn store(&self) -> snapshot::Store<'_> {
        snapshot::Store {
            storage: self.storage.as_ref(),
            audit: self.audit.as_ref(),
            history_keys: self.keys.as_ref(),
        }
    }
}

/// Connect to a storage backend and its history key store based on URL
/// scheme: the evaluator's own PostgreSQL database `history_keys`, or the
/// storage database itself. The key store's tables are created if missing.
async fn connect_backend(
    url: &str,
    schema: Option<&str>,
    history_keys: Option<&str>,
) -> Result<Connected> {
    check_backend(url, schema, history_keys)?;
    if url.starts_with("sqlite:") {
        #[cfg(feature = "storage-sqlite")]
        {
            let path = url.strip_prefix("sqlite://").unwrap_or(url);
            let backend = sid_storage::sqlite::SqliteBackend::new(path)
                .await
                .context("failed to connect to SQLite")?;
            Ok(Connected {
                keys: Box::new(backend.history_keys()),
                audit: Box::new(sid_storage::sqlite::SqliteAuditLog::new(
                    backend.writer().clone(),
                )),
                storage: Box::new(backend),
            })
        }
        #[cfg(not(feature = "storage-sqlite"))]
        unreachable!("refused by check_backend")
    } else {
        #[cfg(feature = "storage-pg")]
        {
            let backend = sid_storage::PostgresBackend::new(url, schema.map(String::from))
                .await
                .context("failed to connect to PostgreSQL")?;
            let keys = match history_keys {
                Some(keys_url) => sid_storage::PgHistoryKeyStore::connect(keys_url)
                    .await
                    .context("failed to connect to the history key store")?,
                None => sid_storage::PgHistoryKeyStore::new(backend.pool().clone()),
            };
            keys.migrate()
                .await
                .context("history key store migrations")?;
            Ok(Connected {
                keys: Box::new(keys),
                audit: Box::new(sid_storage::audit_log::PostgresAuditLog::new(
                    backend.pool().clone(),
                )),
                storage: Box::new(backend),
            })
        }
        #[cfg(not(feature = "storage-pg"))]
        unreachable!("refused by check_backend")
    }
}

/// Whether `url` with these options names a backend this build can open,
/// decided before any input is read or any database reached, so a wrong
/// target never waits on its input or lets the source be connected and
/// migrated first.
fn check_backend(url: &str, schema: Option<&str>, history_keys: Option<&str>) -> Result<()> {
    if url.starts_with("sqlite:") {
        // A PostgreSQL schema means nothing to a SQLite file: refused, never
        // silently ignored.
        if schema.is_some() {
            bail!("a SQLite installation has no PostgreSQL schema; drop the schema option");
        }
        if history_keys.is_some() {
            bail!("a SQLite installation keeps its history keys in its own file");
        }
        if !cfg!(feature = "storage-sqlite") {
            bail!("SQLite support not compiled in. Enable the `storage-sqlite` feature.");
        }
    } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        if !cfg!(feature = "storage-pg") {
            bail!("PostgreSQL support not compiled in. Enable the `storage-pg` feature.");
        }
        if let Some(keys) = history_keys
            && !(keys.starts_with("postgres://") || keys.starts_with("postgresql://"))
        {
            bail!("the history key store is a PostgreSQL database; give it a postgres:// URL");
        }
        // The rules the backend applies when it connects: its URL parser and
        // its schema-name check. A URL that parses but names no reachable
        // host is only known by connecting.
        #[cfg(feature = "storage-pg")]
        {
            use sid_storage::migrator::{validate_database_url, validate_schema_name};
            validate_database_url(url)?;
            if let Some(schema) = schema {
                validate_schema_name(schema)?;
            }
            if let Some(keys) = history_keys {
                validate_database_url(keys)?;
            }
        }
    } else {
        bail!("Unsupported database URL scheme. Use 'sqlite://' or 'postgres://'.");
    }
    Ok(())
}
