// SPDX-License-Identifier: AGPL-3.0-only
//! A test run's setup script: prepares the test store named on its command
//! line once, then marks the run so the tests using it only connect or copy
//! it. nextest passes the file the marker goes to in `NEXTEST_ENV`.
//!
//! - `engine`, `storage`: migrate that shared PostgreSQL database;
//! - `template`: make the migrated database isolated installations copy;
//! - `coordinode` (with storage-coordinode): make the CoordiNode store with
//!   SID's schema each CoordiNode test copies.

use std::io::Write;

use sid_storage::testing::TestDatabase;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let name = std::env::args()
        .nth(1)
        .expect("name the store to prepare: engine, storage, template or coordinode");
    let marker = if name == "coordinode" {
        coordinode().await
    } else {
        let database = TestDatabase::parse(&name)
            .expect("name the store to prepare: engine, storage, template or coordinode");
        database
            .prepare()
            .await
            .expect("migrate the test database (docker-compose.test.yml up?)");
        format!("{}=1", database.marker())
    };
    let env_file = std::env::var("NEXTEST_ENV").expect("run as a nextest setup script");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(env_file)
        .expect("open the setup script's environment file");
    writeln!(file, "{marker}").expect("mark the store prepared");
}

#[cfg(feature = "storage-coordinode")]
async fn coordinode() -> String {
    let run = std::env::var("NEXTEST_RUN_ID").expect("run as a nextest setup script");
    let root = std::env::temp_dir().join("sid-coordinode-template");
    let dir = sid_storage::testing::prepare_coordinode_template(&root, &run)
        .await
        .expect("SID's schema in a CoordiNode template");
    format!(
        "{}={}",
        sid_storage::testing::COORDINODE_TEMPLATE,
        dir.display()
    )
}

#[cfg(not(feature = "storage-coordinode"))]
async fn coordinode() -> String {
    panic!("the CoordiNode template needs the storage-coordinode feature");
}
