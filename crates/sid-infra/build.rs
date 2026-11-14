// SPDX-License-Identifier: AGPL-3.0-only
//! Compiles in the platform CA set of the platform this build is made for.
//!
//! The build that makes a delivery fetches that platform's published set
//! and names the file in `SID_BUILD_PLATFORM_CAS`; it is carried in the
//! binary as the set the installation verifies under from its first start,
//! with no network. A build that names a platform (`SID_BUILD_PLATFORM`)
//! and no set is refused: a delivery for a platform never goes out without
//! that platform's certificates. A build that names neither carries none.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=SID_BUILD_PLATFORM");
    println!("cargo:rerun-if-env-changed=SID_BUILD_PLATFORM_CAS");
    let given = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let set = match (given("SID_BUILD_PLATFORM"), given("SID_BUILD_PLATFORM_CAS")) {
        (_, Some(path)) => {
            println!("cargo:rerun-if-changed={path}");
            std::fs::read(&path)
                .unwrap_or_else(|e| panic!("SID_BUILD_PLATFORM_CAS {path:?} cannot be read: {e}"))
        }
        (Some(platform), None) => panic!(
            "this build is made for the platform {platform} and carries no platform CA set: \
             fetch {platform}/.well-known/sid-ca/index.json and name the file in \
             SID_BUILD_PLATFORM_CAS"
        ),
        (None, None) => Vec::new(),
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(out.join("platform_cas.json"), set).expect("write the carried platform CA set");
}
