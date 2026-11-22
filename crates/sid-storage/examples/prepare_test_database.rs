// SPDX-License-Identifier: AGPL-3.0-only
//! The test run's setup script: migrates the shared PostgreSQL test database
//! once, then marks the run so its tests connect without migrating it.
//! nextest passes the file the marker goes to in `NEXTEST_ENV`.

use std::io::Write;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    sid_storage::testing::prepare()
        .await
        .expect("migrate the shared test database (docker-compose.test.yml up?)");
    let env_file = std::env::var("NEXTEST_ENV").expect("run as a nextest setup script");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(env_file)
        .expect("open the setup script's environment file");
    writeln!(file, "{}=1", sid_storage::testing::PREPARED).expect("mark the database prepared");
}
