// SPDX-License-Identifier: AGPL-3.0-only
//! sid-migrate — Data migration CLI for StructuredID.
//!
//! Supports exporting, importing, migrating, and verifying data
//! between SQLite and PostgreSQL storage backends.
//!
//! ```bash
//! # Export to JSON
//! sid-migrate export --source "sqlite:///var/lib/sid/auth.db" --output backup.json
//!
//! # Import from JSON
//! sid-migrate import --target "postgres://user:pass@db:5432/sid" --input backup.json
//!
//! # Direct migration
//! sid-migrate migrate --source "sqlite:///path" --target "postgres://..."
//!
//! # Verify migration
//! sid-migrate verify --source "sqlite:///path" --target "postgres://..."
//! ```

mod export;
mod import;
mod snapshot;
mod verify;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use std::path::PathBuf;
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
    /// Export all data from a SID instance to a JSON file.
    Export {
        /// Source database URL (e.g., "sqlite:///var/lib/sid/auth.db" or "postgres://...")
        #[arg(long)]
        source: String,

        /// Output file path
        #[arg(long, short)]
        output: PathBuf,

        /// PostgreSQL schema name (for shared-database deployments)
        #[arg(long)]
        schema: Option<String>,

        /// Include audit log in export (can be very large)
        #[arg(long, default_value = "false")]
        include_audit: bool,

        /// The password-history evaluator's database, when it is not the
        /// source database (PostgreSQL URL)
        #[arg(long)]
        history_keys: Option<String>,
    },

    /// Import data from a JSON file into a SID instance.
    Import {
        /// Target database URL
        #[arg(long)]
        target: String,

        /// Input file path
        #[arg(long, short)]
        input: PathBuf,

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

        /// Include audit log in migration
        #[arg(long, default_value = "false")]
        include_audit: bool,

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

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Commands::Export {
            source,
            output,
            schema,
            include_audit,
            history_keys,
        } => {
            info!(output = %output.display(), "starting export");
            let store =
                connect_backend(&source, schema.as_deref(), history_keys.as_deref()).await?;
            let snapshot = export::export_snapshot(
                store.storage.as_ref(),
                store.keys.as_ref(),
                &source,
                include_audit,
            )
            .await?;

            let json =
                serde_json::to_string_pretty(&snapshot).context("failed to serialize snapshot")?;
            // Snapshots contain sealed credentials and history keys: create a
            // new owner-readable file rather than following or truncating a path.
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options
                .open(&output)
                .await
                .context("failed to create output file")?;
            use tokio::io::AsyncWriteExt;
            file.write_all(json.as_bytes())
                .await
                .context("failed to write output file")?;
            file.sync_all()
                .await
                .context("failed to synchronize output file")?;

            info!(
                entities = snapshot.metadata.total_entities,
                path = %output.display(),
                "export complete"
            );
            println!(
                "Exported {} entities to {}",
                snapshot.metadata.total_entities,
                output.display()
            );
        }

        Commands::Import {
            target,
            input,
            schema,
            history_keys,
        } => {
            info!(input = %input.display(), "starting import");
            let json = tokio::fs::read_to_string(&input)
                .await
                .context("failed to read input file")?;
            let snapshot: snapshot::Snapshot =
                serde_json::from_str(&json).context("failed to parse snapshot JSON")?;

            info!(
                version = snapshot.metadata.version,
                source_backend = %snapshot.metadata.source_backend,
                entities = snapshot.metadata.total_entities,
                "snapshot loaded"
            );

            let store =
                connect_backend(&target, schema.as_deref(), history_keys.as_deref()).await?;
            let result =
                import::import_snapshot(store.storage.as_ref(), store.keys.as_ref(), &snapshot)
                    .await?;

            println!("{result}");
        }

        Commands::Migrate {
            source,
            target,
            source_schema,
            target_schema,
            include_audit,
            source_history_keys,
            target_history_keys,
        } => {
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

            // Export from source
            let snapshot = export::export_snapshot(
                source_store.storage.as_ref(),
                source_store.keys.as_ref(),
                &source,
                include_audit,
            )
            .await?;
            info!(
                entities = snapshot.metadata.total_entities,
                "source data exported, importing to target..."
            );

            // Import to target
            let result = import::import_snapshot(
                target_store.storage.as_ref(),
                target_store.keys.as_ref(),
                &snapshot,
            )
            .await?;
            println!("{result}");

            // Auto-verify
            info!("running post-migration verification...");
            let verify_result = verify::verify_backends(
                source_store.storage.as_ref(),
                source_store.keys.as_ref(),
                target_store.storage.as_ref(),
                target_store.keys.as_ref(),
            )
            .await?;
            println!("{verify_result}");

            if !verify_result.passed {
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
            info!("starting verification");
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

            let result = verify::verify_backends(
                source_store.storage.as_ref(),
                source_store.keys.as_ref(),
                target_store.storage.as_ref(),
                target_store.keys.as_ref(),
            )
            .await?;
            println!("{result}");

            if !result.passed {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// One installation's data: its storage backend and the password-history
/// evaluator's key store, which a standalone installation keeps in the same
/// database under its own tables and a split one in the evaluator's own.
struct Store {
    storage: Box<dyn StorageBackend>,
    keys: Box<dyn HistoryKeyStore>,
}

/// Connect to a storage backend and its history key store based on URL
/// scheme: the evaluator's own PostgreSQL database `history_keys`, or the
/// storage database itself. The key store's tables are created if missing.
async fn connect_backend(
    url: &str,
    schema: Option<&str>,
    history_keys: Option<&str>,
) -> Result<Store> {
    if url.starts_with("sqlite:") {
        #[cfg(feature = "storage-sqlite")]
        {
            if history_keys.is_some() {
                bail!("a SQLite installation keeps its history keys in its own file");
            }
            let path = url.strip_prefix("sqlite://").unwrap_or(url);
            let backend = sid_storage::sqlite::SqliteBackend::new(path)
                .await
                .context("failed to connect to SQLite")?;
            Ok(Store {
                keys: Box::new(backend.history_keys()),
                storage: Box::new(backend),
            })
        }
        #[cfg(not(feature = "storage-sqlite"))]
        {
            bail!("SQLite support not compiled in. Enable the `storage-sqlite` feature.");
        }
    } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
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
            Ok(Store {
                keys: Box::new(keys),
                storage: Box::new(backend),
            })
        }
        #[cfg(not(feature = "storage-pg"))]
        {
            bail!("PostgreSQL support not compiled in. Enable the `storage-pg` feature.");
        }
    } else {
        bail!("Unsupported database URL scheme. Use 'sqlite://' or 'postgres://'.");
    }
}
