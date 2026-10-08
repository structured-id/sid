// SPDX-License-Identifier: AGPL-3.0-only
//! The event bus of a `sid-server` deployment: bundled or external NATS.
//!
//! `SID_NATS_URL` unset or `embedded` spawns `nats-server` as a child process
//! with JetStream stored under the data directory; `nats://…` / `tls://…`
//! connects to an external cluster. There is no in-process fallback: a
//! configured bus that cannot start stops the server, and committed work stays
//! pending in the database until a bus is available.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use sid_plugin::event_bus::EventBus;
use tracing::{info, warn};

/// Which bus `SID_NATS_URL` selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBusMode {
    /// `nats-server` bundled as a child process (the default).
    Embedded,
    /// An external NATS cluster at this URL.
    External(String),
}

impl EventBusMode {
    /// Parse the `SID_NATS_URL` value; unset or empty means embedded.
    pub fn from_setting(value: Option<&str>) -> Result<Self, EventBusStartError> {
        match value.map(str::trim) {
            None | Some("") | Some("embedded") => Ok(Self::Embedded),
            Some(url) if url.starts_with("nats://") || url.starts_with("tls://") => {
                Ok(Self::External(url.to_string()))
            }
            Some(other) => Err(EventBusStartError::InvalidSetting(other.to_string())),
        }
    }
}

/// A connected bus, and the bundled server that must outlive it.
pub struct ConnectedBus {
    pub bus: Arc<dyn EventBus>,
    pub embedded: Option<EmbeddedNats>,
}

/// Start (if embedded) and connect the event bus, or fail.
pub async fn connect_event_bus(
    mode: &EventBusMode,
    data_dir: &Path,
) -> Result<ConnectedBus, EventBusStartError> {
    match mode {
        EventBusMode::Embedded => {
            let (embedded, url) = EmbeddedNats::spawn(&data_dir.join("nats"))?;
            let bus = sid_infra::NatsEventBus::connect(&url)
                .await
                .map_err(|e| EventBusStartError::Connect(e.to_string()))?;
            info!(port = embedded.port(), "Event bus: embedded NATS");
            Ok(ConnectedBus {
                bus: Arc::new(bus),
                embedded: Some(embedded),
            })
        }
        EventBusMode::External(url) => {
            let bus = sid_infra::NatsEventBus::connect(url)
                .await
                .map_err(|e| EventBusStartError::Connect(e.to_string()))?;
            info!("Event bus: external NATS at {url}");
            Ok(ConnectedBus {
                bus: Arc::new(bus),
                embedded: None,
            })
        }
    }
}

/// Embedded NATS server process manager.
///
/// Spawns `nats-server` with JetStream and manages its lifecycle.
/// On Drop, the child process is killed.
pub struct EmbeddedNats {
    child: Mutex<Option<Child>>,
    port: u16,
}

impl EmbeddedNats {
    /// Spawn `nats-server` with JetStream stored in `store_dir` (created if
    /// missing), so retained events survive a restart. Returns the handle and
    /// the URL to connect to; dropping the handle stops the server.
    pub fn spawn(store_dir: &Path) -> Result<(Self, String), EventBusStartError> {
        std::fs::create_dir_all(store_dir)
            .map_err(|e| EventBusStartError::Io(format!("create {}: {e}", store_dir.display())))?;
        let port = find_available_port()?;
        let store_path: PathBuf = store_dir.to_path_buf();

        let child = Command::new("nats-server")
            .args([
                "--addr",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--jetstream",
                "--store_dir",
                &store_path.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    EventBusStartError::NotInstalled
                } else {
                    EventBusStartError::Io(e.to_string())
                }
            })?;

        let nats_url = format!("nats://127.0.0.1:{port}");
        info!(port, store = %store_path.display(), "Embedded NATS server starting");

        let embedded = Self {
            child: Mutex::new(Some(child)),
            port,
        };
        embedded.wait_ready()?;
        info!(port, "Embedded NATS server ready");
        Ok((embedded, nats_url))
    }

    /// NATS server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wait for NATS to accept TCP connections (up to 5 seconds).
    fn wait_ready(&self) -> Result<(), EventBusStartError> {
        let addr = format!("127.0.0.1:{}", self.port);
        for attempt in 0..50 {
            if std::net::TcpStream::connect(&addr).is_ok() {
                return Ok(());
            }
            if let Ok(mut guard) = self.child.lock()
                && let Some(ref mut child) = *guard
                && let Ok(Some(status)) = child.try_wait()
            {
                return Err(EventBusStartError::Crashed(format!(
                    "nats-server exited with {status}"
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            if attempt == 10 {
                warn!("Embedded NATS still starting after 1s...");
            }
        }
        Err(EventBusStartError::Timeout)
    }

    /// Stop the embedded NATS server and wait for it to exit.
    pub fn stop(&self) {
        let Ok(mut guard) = self.child.lock() else {
            return;
        };
        let Some(mut child) = guard.take() else {
            return;
        };
        info!(port = self.port, "Stopping embedded NATS server");
        if let Err(e) = child.kill() {
            warn!(error = %e, "failed to stop embedded NATS server");
        }
        if let Err(e) = child.wait() {
            warn!(error = %e, "failed to reap embedded NATS server");
        }
    }
}

impl Drop for EmbeddedNats {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Find an available TCP port by binding to port 0.
fn find_available_port() -> Result<u16, EventBusStartError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| EventBusStartError::Io(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| EventBusStartError::Io(e.to_string()))?
        .port();
    drop(listener); // Release the port for nats-server.
    Ok(port)
}

/// Why the event bus could not start.
#[derive(Debug, thiserror::Error)]
pub enum EventBusStartError {
    #[error("SID_NATS_URL must be unset, `embedded`, or a nats:// or tls:// URL, got `{0}`")]
    InvalidSetting(String),
    #[error(
        "nats-server not found in PATH. Install: https://github.com/nats-io/nats-server/releases"
    )]
    NotInstalled,
    #[error("embedded NATS server did not start within 5 seconds")]
    Timeout,
    #[error("embedded NATS server crashed: {0}")]
    Crashed(String),
    #[error("cannot connect to NATS: {0}")]
    Connect(String),
    #[error("I/O error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests;
