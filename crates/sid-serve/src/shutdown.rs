// SPDX-License-Identifier: Apache-2.0
//! Stopping a service: the signal that begins it and the interval calls in
//! flight get to finish, shared by every listener of the process.

use std::time::Duration;

use tracing::info;

/// Resolves on SIGINT or SIGTERM.
pub async fn signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("SIGINT handler: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!("SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received SIGINT, initiating graceful shutdown..."),
        _ = terminate => info!("Received SIGTERM, initiating graceful shutdown..."),
    }
}

/// A `SID_SHUTDOWN_DRAIN_SECONDS` value outside 1 to 3600 seconds.
#[derive(Debug)]
pub struct InvalidDrainInterval(String);

impl std::fmt::Display for InvalidDrainInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SID_SHUTDOWN_DRAIN_SECONDS must be 1 to {MAX_DRAIN_SECONDS} seconds, got {:?}",
            self.0
        )
    }
}

impl std::error::Error for InvalidDrainInterval {}

/// How long calls in flight may finish after shutdown begins, from
/// `SID_SHUTDOWN_DRAIN_SECONDS` (default 25 s, inside the usual 30 s pod
/// termination grace period).
pub fn drain_interval(value: Option<&str>) -> Result<Duration, InvalidDrainInterval> {
    let seconds = match value {
        None => DEFAULT_DRAIN_SECONDS,
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=MAX_DRAIN_SECONDS).contains(s))
            .ok_or_else(|| InvalidDrainInterval(v.to_owned()))?,
    };
    Ok(Duration::from_secs(seconds))
}

/// [`drain_interval`] of the process's `SID_SHUTDOWN_DRAIN_SECONDS`.
pub fn drain_interval_from_env() -> Result<Duration, InvalidDrainInterval> {
    drain_interval(std::env::var("SID_SHUTDOWN_DRAIN_SECONDS").ok().as_deref())
}

const DEFAULT_DRAIN_SECONDS: u64 = 25;
const MAX_DRAIN_SECONDS: u64 = 3600;

#[cfg(test)]
mod tests;
