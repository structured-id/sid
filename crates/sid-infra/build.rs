// SPDX-License-Identifier: AGPL-3.0-only
//! Fixes the platform this build is made for and compiles in its CA set.
//!
//! The platform is named by its origin (`SID_BUILD_PLATFORM`, as the build
//! of an official delivery gives it) or selected by the one flag of a local
//! publication (`SID_BUILD_PLATFORM_DEV`: `false` for production, `true` for
//! the development platform). A build given neither is made for no platform
//! and carries no set.
//!
//! The set is the platform's publication as this build obtained it: the file
//! named in `SID_BUILD_PLATFORM_CAS` when the builder fetched it already,
//! otherwise fetched here from the platform. It is carried in the binary as
//! the set the installation verifies under from its first start, with no
//! network. A delivery for a platform never goes out without asking that
//! platform: one that cannot be reached stops the build. A platform that
//! publishes no set yet gives a build that carries none and fetches the set
//! itself once the platform publishes.

use std::path::PathBuf;
use std::process::Command;

#[path = "build_platform.rs"]
mod build_platform;

fn main() {
    for name in [
        "SID_BUILD_PLATFORM",
        "SID_BUILD_PLATFORM_DEV",
        "SID_BUILD_PLATFORM_CAS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let given = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let platform = build_platform::selected(
        given("SID_BUILD_PLATFORM").as_deref(),
        given("SID_BUILD_PLATFORM_DEV").as_deref(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // The crate reads the platform with `option_env!`: set here, the flag
    // and the origin reach it alike, and so do its consumers' builds.
    if let Some(platform) = &platform {
        println!("cargo:rustc-env=SID_BUILD_PLATFORM={platform}");
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let carried = out.join("platform_cas.json");
    let set = match (platform, given("SID_BUILD_PLATFORM_CAS")) {
        (_, Some(path)) => {
            println!("cargo:rerun-if-changed={path}");
            std::fs::read(&path)
                .unwrap_or_else(|e| panic!("SID_BUILD_PLATFORM_CAS {path:?} cannot be read: {e}"))
        }
        // Only a build that reads the platform's publication carries its
        // set: without the feature nothing here asks the platform.
        (Some(platform), None) if std::env::var_os("CARGO_FEATURE_PLATFORM_CA").is_some() => {
            fetched(&platform, &carried)
        }
        (Some(_), None) => Vec::new(),
        (None, None) => Vec::new(),
    };
    std::fs::write(carried, set).expect("write the carried platform CA set");
}

/// The CA set `platform` publishes now, fetched into `file`: no redirect is
/// followed and only the publication's JSON is taken. Empty when the
/// platform answers and publishes no set yet.
fn fetched(platform: &str, file: &std::path::Path) -> Vec<u8> {
    let publication = build_platform::publication_of(platform);
    let fetch = Command::new("curl")
        // First, so the builder's curl configuration is not read: it could
        // follow a redirect or skip certificate verification for the set
        // this build will trust.
        .arg("--disable")
        .args(["--fail", "--silent", "--show-error", "--max-time", "30"])
        .arg("--output")
        .arg(file)
        .args(["--write-out", "%{http_code} %{content_type}"])
        .arg(&publication)
        .output()
        .unwrap_or_else(|e| {
            panic!("this build is made for {platform}: curl cannot run to fetch its CA set: {e}")
        });
    if !fetch.status.success() {
        panic!(
            "this build is made for {platform} and its CA set cannot be fetched from \
             {publication}: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        );
    }
    let written = String::from_utf8_lossy(&fetch.stdout);
    let (status, content_type) = written.split_once(' ').unwrap_or((&written, ""));
    match build_platform::answer(status, content_type) {
        Ok(build_platform::Answer::Set) => {
            std::fs::read(file).unwrap_or_else(|e| panic!("the fetched platform CA set: {e}"))
        }
        Ok(build_platform::Answer::NoSetYet) => {
            println!(
                "cargo:warning={platform} publishes no platform CA set yet (answered \
                 {content_type:?}): this build carries none"
            );
            Vec::new()
        }
        Err(why) => panic!(
            "this build is made for {platform} and {publication} is no publication to build \
             on: {why}"
        ),
    }
}
