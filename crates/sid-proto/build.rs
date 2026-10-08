// SPDX-License-Identifier: AGPL-3.0-only
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto sources live in the standalone `proto/` repo. By default we
    // consume them via the `sid/proto` git submodule (../../proto relative
    // to this crate). For local development across the standalone proto
    // repo and the sid workspace, set SID_PROTO_DIR to an absolute path to
    // override — build.rs re-runs on the override too.
    println!("cargo:rerun-if-env-changed=SID_PROTO_DIR");
    let proto_dir_owned = std::env::var("SID_PROTO_DIR")
        .ok()
        .map(std::path::PathBuf::from);
    let proto_dir: &std::path::Path = proto_dir_owned
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("../../proto"));

    // Auto-discover all .proto files under sid/v1/.
    // No more manual list — adding a new .proto file just works.
    let pattern = proto_dir.join("sid/v1/**/*.proto");
    let pattern_str = pattern.to_str().expect("invalid proto_dir path");

    let mut protos: Vec<std::path::PathBuf> = glob::glob(pattern_str)?
        .filter_map(|entry| entry.ok())
        .collect();

    if protos.is_empty() {
        panic!(
            "No .proto files found matching {}. Ensure proto/ submodule is initialized.",
            pattern_str
        );
    }

    // Sort for deterministic builds.
    protos.sort();

    let mut include_paths = vec![proto_dir.to_path_buf()];
    // System well-known types (Fedora: protobuf-devel, Debian: libprotobuf-dev)
    let sys_include = std::path::Path::new("/usr/include");
    if sys_include.join("google/protobuf").exists() {
        include_paths.push(sys_include.to_path_buf());
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let descriptor_path = out_dir.join("proto_descriptor.bin");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // The identifier messages are owned by `sid-ids-proto` (with their
        // validated conversions); one Rust type per identifier kind.
        .extern_path(".sid.v1.ids", "::sid_ids_proto::sid::v1::ids")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&protos, &include_paths)?;

    // Rerun if any proto file changes.
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    // Also rerun if proto directory structure changes (new files added).
    println!(
        "cargo:rerun-if-changed={}",
        proto_dir.join("sid/v1").display()
    );

    Ok(())
}
