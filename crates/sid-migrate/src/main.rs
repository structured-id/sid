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
        } => {
            info!(output = %output.display(), "starting export");
            let backend = connect_backend(&source, schema.as_deref()).await?;
            let snapshot =
                export::export_snapshot(backend.as_ref(), &source, include_audit).await?;

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

            let backend = connect_backend(&target, schema.as_deref()).await?;
            let result = import::import_snapshot(backend.as_ref(), &snapshot).await?;

            println!("{result}");
        }

        Commands::Migrate {
            source,
            target,
            source_schema,
            target_schema,
            include_audit,
        } => {
            info!("starting direct migration");
            let source_backend = connect_backend(&source, source_schema.as_deref()).await?;
            let target_backend = connect_backend(&target, target_schema.as_deref()).await?;

            // Export from source
            let snapshot =
                export::export_snapshot(source_backend.as_ref(), &source, include_audit).await?;
            info!(
                entities = snapshot.metadata.total_entities,
                "source data exported, importing to target..."
            );

            // Import to target
            let result = import::import_snapshot(target_backend.as_ref(), &snapshot).await?;
            println!("{result}");

            // Auto-verify
            info!("running post-migration verification...");
            let verify_result =
                verify::verify_backends(source_backend.as_ref(), target_backend.as_ref()).await?;
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
        } => {
            info!("starting verification");
            let source_backend = connect_backend(&source, source_schema.as_deref()).await?;
            let target_backend = connect_backend(&target, target_schema.as_deref()).await?;

            let result =
                verify::verify_backends(source_backend.as_ref(), target_backend.as_ref()).await?;
            println!("{result}");

            if !result.passed {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Connect to a storage backend based on URL scheme.
async fn connect_backend(url: &str, schema: Option<&str>) -> Result<Box<dyn StorageBackend>> {
    if url.starts_with("sqlite:") {
        #[cfg(feature = "storage-sqlite")]
        {
            let path = url.strip_prefix("sqlite://").unwrap_or(url);
            let backend = sid_storage::sqlite::SqliteBackend::new(path)
                .await
                .context("failed to connect to SQLite")?;
            Ok(Box::new(backend))
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
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "storage-pg"))]
        {
            bail!("PostgreSQL support not compiled in. Enable the `storage-pg` feature.");
        }
    } else {
        bail!("Unsupported database URL scheme. Use 'sqlite://' or 'postgres://'.");
    }
}
