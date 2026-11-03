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
        // Map entries encode in key order, so equal messages encode equally
        // and a retried keyed command keeps its fingerprint.
        .btree_map(".")
        // The identifier messages are owned by `sid-ids-proto` (with their
        // validated conversions); one Rust type per identifier kind.
        .extern_path(".sid.v1.ids", "::sid_ids_proto::sid::v1::ids")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&protos, &include_paths)?;
    keyed_requests(&descriptor_path, &out_dir.join("keyed.rs"))?;

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

/// `google.protobuf.MethodOptions.IdempotencyLevel.NO_SIDE_EFFECTS`.
const NO_SIDE_EFFECTS: i32 = 1;
/// `google.protobuf.MethodOptions.IdempotencyLevel.IDEMPOTENT`.
const IDEMPOTENT: i32 = 2;

/// Checks the retry rule every method declares in `(sid.v1.common.retry)`
/// and writes to `out` the identity of every keyed method: a type per method
/// implementing `KeyedMethod`, in a module per package and service, and the
/// sorted list of those methods.
///
/// A method that changes state (any idempotency_level but NO_SIDE_EFFECTS)
/// declares exactly one rule: `keyed: true`, a ceremony or a natural rule
/// with its reason; keyed and natural methods are IDEMPOTENT, and a method
/// without effects declares none. The proto is the only place this is
/// declared, so anything else fails the build.
fn keyed_requests(
    descriptors: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use prost_reflect::{DescriptorPool, Value};
    use std::collections::BTreeMap;

    let pool = DescriptorPool::decode(std::fs::read(descriptors)?.as_slice())?;
    let retry = pool
        .get_extension_by_name("sid.v1.common.retry")
        .ok_or("sid/v1/common/operation.proto defines the retry option")?;
    // Module path (package below `sid.v1`, then service) → its keyed methods.
    let mut keyed: BTreeMap<Vec<String>, Vec<KeyedMethod>> = BTreeMap::new();
    let mut wrong = Vec::new();
    for service in pool.services() {
        for method in service.methods() {
            let rpc = format!("{}/{}", service.full_name(), method.name());
            let options = method.options();
            let level = options
                .get_field_by_name("idempotency_level")
                .and_then(|level| level.as_enum_number());
            let rule = options
                .has_extension(&retry)
                .then(|| options.get_extension(&retry));
            let rule = rule.as_ref().and_then(|rule| {
                let rule = rule.as_message()?;
                rule.fields().next().map(|(field, value)| match value {
                    Value::Bool(true) if field.name() == "keyed" => Ok("keyed"),
                    Value::String(text) if !text.trim().is_empty() => Ok(match field.name() {
                        "ceremony" => "ceremony",
                        _ => "natural",
                    }),
                    _ => Err(field.name().to_owned()),
                })
            });
            match (level, rule) {
                (Some(NO_SIDE_EFFECTS), None) => {}
                (Some(NO_SIDE_EFFECTS), Some(_)) => {
                    wrong.push(format!("{rpc}: a method without effects has no retry rule"))
                }
                (_, None) => wrong.push(format!(
                    "{rpc}: a method that changes state declares its (sid.v1.common.retry) rule"
                )),
                (_, Some(Err(field))) => wrong.push(format!(
                    "{rpc}: the retry rule `{field}` is `keyed: true` or a stated reason"
                )),
                (level, Some(Ok(rule @ ("keyed" | "natural")))) if level != Some(IDEMPOTENT) => {
                    wrong.push(format!(
                        "{rpc}: a {rule} retry rule is idempotency_level = IDEMPOTENT"
                    ))
                }
                (_, Some(Ok("keyed"))) => {
                    if method.is_client_streaming() || method.is_server_streaming() {
                        wrong.push(format!("{rpc}: a keyed method is unary"));
                    }
                    let Some(package) = service.package_name().strip_prefix("sid.v1.") else {
                        wrong.push(format!("{rpc}: a keyed method of another package"));
                        continue;
                    };
                    let mut module: Vec<String> = package.split('.').map(str::to_owned).collect();
                    module.push(snake_case(service.name()));
                    match rust_message(&method.input()) {
                        Some(request) => keyed.entry(module).or_default().push(KeyedMethod {
                            name: method.name().to_owned(),
                            rpc,
                            request,
                        }),
                        None => {
                            wrong.push(format!("{rpc}: a keyed request is a top-level message"))
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if !wrong.is_empty() {
        return Err(wrong.join("\n").into());
    }
    let mut code = String::new();
    let mut methods = Vec::new();
    let mut open: Vec<String> = Vec::new();
    for (module, entries) in &keyed {
        let common = open.iter().zip(module).take_while(|(a, b)| a == b).count();
        for _ in common..open.len() {
            code.push_str("}\n");
        }
        open.truncate(common);
        for segment in &module[common..] {
            code.push_str(&format!("pub mod {segment} {{\n"));
            open.push(segment.clone());
        }
        for entry in entries {
            code.push_str(&format!(
                "/// `{rpc}`.\npub struct {name};\n\
                 impl crate::KeyedMethod for {name} {{\n    \
                 const METHOD: &'static str = \"{rpc}\";\n    \
                 type Request = {request};\n\
                 }}\n",
                rpc = entry.rpc,
                name = entry.name,
                request = entry.request,
            ));
            methods.push(entry.rpc.clone());
        }
    }
    for _ in &open {
        code.push_str("}\n");
    }
    methods.sort_unstable();
    code.push_str("/// Every keyed method, as `package.Service/Method`, sorted.\n");
    code.push_str("pub const METHODS: &[&str] = &[\n");
    for rpc in methods {
        code.push_str(&format!("    \"{rpc}\",\n"));
    }
    code.push_str("];\n");
    std::fs::write(out, code)?;
    Ok(())
}

/// One keyed method: its name, `package.Service/Method` and the Rust type of
/// its request.
struct KeyedMethod {
    name: String,
    rpc: String,
    request: String,
}

/// The Rust type prost generates for a top-level `message`; none for a
/// nested one.
fn rust_message(message: &prost_reflect::MessageDescriptor) -> Option<String> {
    let package = message.package_name();
    let local = message.full_name().get(package.len() + 1..)?;
    if local.contains('.') {
        return None;
    }
    Some(match package {
        "google.protobuf" if local == "Empty" => "()".to_owned(),
        "google.protobuf" => format!("::prost_types::{local}"),
        "sid.v1.ids" => format!("::sid_ids_proto::sid::v1::ids::{local}"),
        _ => format!("crate::{}::{local}", package.replace('.', "::")),
    })
}

/// `AccountService` as `account_service`.
fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (i, c) in name.char_indices() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                snake.push('_');
            }
            snake.push(c.to_ascii_lowercase());
        } else {
            snake.push(c);
        }
    }
    snake
}
