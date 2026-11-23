// SPDX-License-Identifier: AGPL-3.0-only
//! A test run's setup script: migrates the shared PostgreSQL test database
//! named on its command line (`engine` or `storage`) once, then marks the
//! run so the tests using it connect without migrating it. nextest passes
//! the file the marker goes to in `NEXTEST_ENV`.

use std::io::Write;

use sid_storage::testing::TestDatabase;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let database = std::env::args()
        .nth(1)
        .as_deref()
        .and_then(TestDatabase::parse)
        .expect("name the database to prepare: engine or storage");
    database
        .prepare()
        .await
        .expect("migrate the shared test database (docker-compose.test.yml up?)");
    let env_file = std::env::var("NEXTEST_ENV").expect("run as a nextest setup script");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(env_file)
        .expect("open the setup script's environment file");
    writeln!(file, "{}=1", database.marker()).expect("mark the database prepared");
}
