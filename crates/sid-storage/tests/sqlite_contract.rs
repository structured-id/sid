// SPDX-License-Identifier: Apache-2.0
//! The complete storage contract on SQLite through its one entry point: what a
//! backend outside this crate writes to run it.

#![cfg(feature = "storage-sqlite")]

use sid_storage::sqlite::SqliteBackend;

async fn setup() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("an in-memory backend")
}

sid_plugin::storage_conformance!(setup);
