// SPDX-License-Identifier: AGPL-3.0-only
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto sources live in the standalone `proto/` repo, consumed through
    // the `sid/proto` submodule. The crate's `proto` entry links to it, so a
    // packaged crate carries the sources it compiles. For local development
    // across the standalone proto repo and the sid workspace, set
    // SID_PROTO_DIR to an absolute path to override; build.rs re-runs on it.
    println!("cargo:rerun-if-env-changed=SID_PROTO_DIR");
    let proto_dir_owned = std::env::var("SID_PROTO_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("proto")
        });
    let proto_dir: &std::path::Path = &proto_dir_owned;

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
        // The client and server stubs need the transport; the messages do not.
        .server_mod_attribute(".", "#[cfg(feature = \"grpc\")]")
        .client_mod_attribute(".", "#[cfg(feature = \"grpc\")]")
        // Map entries encode in key order, so equal messages encode equally
        // and a retried keyed command keeps its fingerprint.
        .btree_map(".")
        // The identifier messages are owned by `sid-ids-proto` (with their
        // validated conversions); one Rust type per identifier kind.
        .extern_path(".sid.v1.ids", "::sid_ids_proto::sid::v1::ids")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&protos, &include_paths)?;
    // The descriptor set names each file relative to its include root.
    let files: Vec<&str> = protos
        .iter()
        .map(|proto| {
            proto
                .strip_prefix(proto_dir)
                .ok()
                .and_then(|name| name.to_str())
                .expect("a proto below the proto directory")
        })
        .collect();
    sid_proto_build::KeyedBindings::new("crate::KeyedMethod", "sid.v1")
        .types("google.protobuf", "::prost_types")
        .types("sid.v1.ids", "::sid_ids_proto::sid::v1::ids")
        .types("sid", "crate::sid")
        .write(&descriptor_path, &files, &out_dir.join("keyed.rs"))?;

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
