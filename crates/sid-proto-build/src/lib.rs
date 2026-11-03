// SPDX-License-Identifier: AGPL-3.0-only
//! What a crate's build reads from the methods of the protos it compiles:
//! each method's `(sid.v1.common.retry)` rule checked, and a typed binding
//! per keyed method written for the crate to include.
//!
//! A method that changes state (any `idempotency_level` but
//! `NO_SIDE_EFFECTS`) declares exactly one rule: `keyed: true`, a ceremony
//! or a natural rule with its reason; keyed and natural methods are
//! `IDEMPOTENT`, keyed ones unary, and a method without effects declares
//! none. The proto is the only place this is declared, so anything else
//! fails the build. Only the services of the crate's own compile inputs are
//! checked and bound; the files they import are another crate's.

use std::collections::BTreeMap;

use prost_reflect::{DescriptorPool, MessageDescriptor, MethodDescriptor, Value};

/// `google.protobuf.MethodOptions.IdempotencyLevel.NO_SIDE_EFFECTS`.
const NO_SIDE_EFFECTS: i32 = 1;
/// `google.protobuf.MethodOptions.IdempotencyLevel.IDEMPOTENT`.
const IDEMPOTENT: i32 = 2;

/// The method option holding a method's retry rule.
const RETRY: &str = "sid.v1.common.retry";

/// Why a crate's protos cannot be bound: every method that declares its
/// rule wrongly, one line each.
#[derive(Debug)]
pub struct Error(Vec<String>);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("\n"))
    }
}

impl std::error::Error for Error {}

/// How a crate's keyed bindings are named and typed.
#[derive(Debug, Clone)]
pub struct KeyedBindings {
    /// Path of the `KeyedMethod` trait the bindings implement.
    keyed_trait: String,
    /// The package the binding modules are named below: `sid.v1` names
    /// `sid.v1.projects.ProjectService` `projects::project_service`.
    module_root: String,
    /// The Rust module of each proto package's messages, by package; a
    /// package below one listed is the listed module's submodule.
    types: Vec<(String, String)>,
}

impl KeyedBindings {
    /// Bindings implementing `keyed_trait`, in modules named below the
    /// package `module_root`.
    pub fn new(keyed_trait: impl Into<String>, module_root: impl Into<String>) -> Self {
        Self {
            keyed_trait: keyed_trait.into(),
            module_root: module_root.into(),
            types: Vec::new(),
        }
    }

    /// The messages of `package`, and of the packages below it, are in the
    /// Rust module `module` (`::prost_types` for `google.protobuf`).
    pub fn types(mut self, package: impl Into<String>, module: impl Into<String>) -> Self {
        self.types.push((package.into(), module.into()));
        self
    }

    /// Check the retry rule of every method the services of `files` declare
    /// (proto file names as `descriptor_set` names them) and return the
    /// bindings of their keyed methods: a type per method implementing the
    /// keyed trait, in a module per package and service, and `METHODS`, every
    /// keyed method as `package.Service/Method`, sorted.
    pub fn generate(&self, descriptor_set: &[u8], files: &[&str]) -> Result<String, Error> {
        let pool = DescriptorPool::decode(descriptor_set)
            .map_err(|e| Error(vec![format!("the descriptor set: {e}")]))?;
        let retry = pool.get_extension_by_name(RETRY).ok_or_else(|| {
            Error(vec![format!(
                "the descriptors define no {RETRY}: compile sid/v1/common/operation.proto with them"
            )])
        })?;
        let mut keyed: BTreeMap<Vec<String>, Vec<Keyed>> = BTreeMap::new();
        let mut wrong = Vec::new();
        for file in pool.files().filter(|f| files.contains(&f.name())) {
            for service in file.services() {
                for method in service.methods() {
                    let rpc = format!("{}/{}", service.full_name(), method.name());
                    match self.rule(&method, &retry) {
                        Ok(Some(Rule::Keyed)) => match self.keyed(&method) {
                            Ok((module, entry)) => keyed.entry(module).or_default().push(entry),
                            Err(why) => wrong.push(format!("{rpc}: {why}")),
                        },
                        Ok(_) => {}
                        Err(why) => wrong.push(format!("{rpc}: {why}")),
                    }
                }
            }
        }
        if !wrong.is_empty() {
            return Err(Error(wrong));
        }
        Ok(self.code(&keyed))
    }

    /// [`Self::generate`] from the descriptor set at `descriptors`, written
    /// to `out`.
    pub fn write(
        &self,
        descriptors: &std::path::Path,
        files: &[&str],
        out: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let code = self.generate(&std::fs::read(descriptors)?, files)?;
        std::fs::write(out, code)?;
        Ok(())
    }

    /// The rule `method` declares, checked against its idempotency level.
    fn rule(
        &self,
        method: &MethodDescriptor,
        retry: &prost_reflect::ExtensionDescriptor,
    ) -> Result<Option<Rule>, String> {
        let options = method.options();
        let level = options
            .get_field_by_name("idempotency_level")
            .and_then(|level| level.as_enum_number());
        let declared = options
            .has_extension(retry)
            .then(|| options.get_extension(retry));
        let rule = match declared.as_deref().and_then(Value::as_message) {
            None => None,
            Some(rule) => Some(match rule.fields().next() {
                Some((field, Value::Bool(true))) if field.name() == "keyed" => Rule::Keyed,
                Some((field, Value::String(text))) if !text.trim().is_empty() => {
                    match field.name() {
                        "ceremony" => Rule::Ceremony,
                        _ => Rule::Natural,
                    }
                }
                Some((field, _)) => {
                    return Err(format!(
                        "the retry rule `{}` is `keyed: true` or a stated reason",
                        field.name()
                    ));
                }
                None => return Err("the retry rule names none of its rules".into()),
            }),
        };
        match (level, rule) {
            (Some(NO_SIDE_EFFECTS), None) => Ok(None),
            (Some(NO_SIDE_EFFECTS), Some(_)) => {
                Err("a method without effects has no retry rule".into())
            }
            (_, None) => Err(format!(
                "a method that changes state declares its ({RETRY}) rule"
            )),
            (level, Some(rule @ (Rule::Keyed | Rule::Natural))) if level != Some(IDEMPOTENT) => {
                Err(format!(
                    "a {} retry rule is idempotency_level = IDEMPOTENT",
                    rule.name()
                ))
            }
            (_, Some(Rule::Keyed))
                if method.is_client_streaming() || method.is_server_streaming() =>
            {
                Err("a keyed method is unary".into())
            }
            (_, rule) => Ok(rule),
        }
    }

    /// The module path and binding of keyed `method`.
    fn keyed(&self, method: &MethodDescriptor) -> Result<(Vec<String>, Keyed), String> {
        let service = method.parent_service();
        let package = service.package_name();
        let below = if package == self.module_root {
            ""
        } else {
            package
                .strip_prefix(&self.module_root)
                .and_then(|rest| rest.strip_prefix('.'))
                .ok_or_else(|| {
                    format!(
                        "a keyed method of package {package}, outside {}",
                        self.module_root
                    )
                })?
        };
        let mut module: Vec<String> = below
            .split('.')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        module.push(snake_case(service.name()));
        let request = self.rust_message(&method.input())?;
        Ok((
            module,
            Keyed {
                name: method.name().to_owned(),
                rpc: format!("{}/{}", service.full_name(), method.name()),
                request,
            },
        ))
    }

    /// The Rust type of the top-level message `message`.
    fn rust_message(&self, message: &MessageDescriptor) -> Result<String, String> {
        let package = message.package_name();
        let local = message
            .full_name()
            .get(package.len() + 1..)
            .filter(|local| !local.contains('.'))
            .ok_or_else(|| "a keyed request is a top-level message".to_owned())?;
        if package == "google.protobuf" && local == "Empty" {
            return Ok("()".to_owned());
        }
        let (listed, module) = self
            .types
            .iter()
            .filter(|(listed, _)| {
                package == listed
                    || package
                        .strip_prefix(listed.as_str())
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .max_by_key(|(listed, _)| listed.len())
            .ok_or_else(|| format!("no Rust module is given for the messages of {package}"))?;
        let mut path = module.clone();
        for segment in package[listed.len()..].split('.').filter(|s| !s.is_empty()) {
            path.push_str("::");
            path.push_str(segment);
        }
        Ok(format!("{path}::{local}"))
    }

    /// The bindings of `keyed`, by module.
    fn code(&self, keyed: &BTreeMap<Vec<String>, Vec<Keyed>>) -> String {
        let mut code = String::new();
        let mut methods = Vec::new();
        let mut open: Vec<String> = Vec::new();
        for (module, entries) in keyed {
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
                     impl {keyed_trait} for {name} {{\n    \
                     const METHOD: &'static str = \"{rpc}\";\n    \
                     type Request = {request};\n\
                     }}\n",
                    rpc = entry.rpc,
                    name = entry.name,
                    keyed_trait = self.keyed_trait,
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
        code
    }
}

/// A method's declared retry rule.
#[derive(Debug, Clone, Copy)]
enum Rule {
    Keyed,
    Ceremony,
    Natural,
}

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Self::Keyed => "keyed",
            Self::Ceremony => "ceremony",
            Self::Natural => "natural",
        }
    }
}

/// One keyed method: its name, `package.Service/Method` and the Rust type of
/// its request.
#[derive(Debug)]
struct Keyed {
    name: String,
    rpc: String,
    request: String,
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

#[cfg(test)]
mod tests;
