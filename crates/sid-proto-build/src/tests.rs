// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

use protox::file::{
    ChainFileResolver, File, FileResolver, GoogleFileResolver, IncludeFileResolver,
};

/// Methods declaring every retry rule correctly, keyed ones in two services,
/// with requests of this package, of another crate's package and Empty.
const THINGS: &str = r#"
syntax = "proto3";
package acme.v1.things;
import "google/protobuf/empty.proto";
import "sid/v1/common/operation.proto";
import "acme/shared/v1/shared.proto";
import "acme/v1/other/other.proto";

service ThingService {
  rpc GetThing(GetThingRequest) returns (Thing) {
    option idempotency_level = NO_SIDE_EFFECTS;
  }
  rpc CreateThing(CreateThingRequest) returns (Thing) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc TouchThing(acme.shared.v1.Ref) returns (google.protobuf.Empty) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc ResetAll(google.protobuf.Empty) returns (google.protobuf.Empty) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc SetThingName(CreateThingRequest) returns (Thing) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { natural: "sets the name to the value given" };
  }
  rpc ExchangeCode(CreateThingRequest) returns (Thing) {
    option (sid.v1.common.retry) = { ceremony: "the code is consumed once" };
  }
  rpc WatchThings(GetThingRequest) returns (stream Thing) {
    option idempotency_level = NO_SIDE_EFFECTS;
  }
}

service AuditTrail {
  rpc Seal(GetThingRequest) returns (google.protobuf.Empty) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
}

message GetThingRequest { string id = 1; }
message CreateThingRequest { string name = 1; }
message Thing { string id = 1; string name = 2; }
"#;

/// Messages another crate owns.
const SHARED: &str = r#"
syntax = "proto3";
package acme.shared.v1;
message Ref { string id = 1; }
"#;

/// An imported file another crate binds: a keyed method and one without a
/// rule, neither of which the importer checks or binds.
const OTHER: &str = r#"
syntax = "proto3";
package acme.v1.other;
import "sid/v1/common/operation.proto";

service OtherService {
  rpc Change(ChangeRequest) returns (ChangeRequest) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc Undeclared(ChangeRequest) returns (ChangeRequest);
}

message ChangeRequest { string id = 1; }
"#;

/// One method per way of declaring a retry rule wrongly.
const WRONG: &str = r#"
syntax = "proto3";
package acme.v1.wrong;
import "sid/v1/common/operation.proto";
import "acmeish/v1/unmapped.proto";

service WrongService {
  rpc Undeclared(Request) returns (Request);
  rpc ReadWithRule(Request) returns (Request) {
    option idempotency_level = NO_SIDE_EFFECTS;
    option (sid.v1.common.retry) = { natural: "reads" };
  }
  rpc KeyedUnknown(Request) returns (Request) {
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc NaturalUnknown(Request) returns (Request) {
    option (sid.v1.common.retry) = { natural: "sets a value" };
  }
  rpc KeyedFalse(Request) returns (Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: false };
  }
  rpc BlankReason(Request) returns (Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { natural: "  " };
  }
  rpc EmptyRule(Request) returns (Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = {};
  }
  rpc KeyedStream(Request) returns (stream Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc KeyedNested(Request.Inner) returns (Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
  rpc KeyedUnmapped(acmeish.v1.Loose) returns (Request) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
}

message Request {
  message Inner { string id = 1; }
  string id = 1;
}
"#;

/// Messages of a package no Rust module is given for: `acme` maps whole
/// package segments, not a name prefix.
const UNMAPPED: &str = r#"
syntax = "proto3";
package acmeish.v1;
message Loose { string id = 1; }
"#;

/// A keyed method of a package outside the bindings' module root.
const OUTSIDE: &str = r#"
syntax = "proto3";
package beta.v1;
import "sid/v1/common/operation.proto";

service OutsideService {
  rpc Change(ChangeRequest) returns (ChangeRequest) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
}

message ChangeRequest { string id = 1; }
"#;

/// A keyed request whose proto name is not prost's Rust name.
const ACRONYM: &str = r#"
syntax = "proto3";
package acme.v1.ca;
import "sid/v1/common/operation.proto";

service CaService {
  rpc RotateCA(RotateCARequest) returns (RotateCARequest) {
    option idempotency_level = IDEMPOTENT;
    option (sid.v1.common.retry) = { keyed: true };
  }
}

message RotateCARequest { string id = 1; }
"#;

/// A file without the retry option among its imports.
const NO_OPTION: &str = r#"
syntax = "proto3";
package acme.v1.plain;
service PlainService {
  rpc Get(Plain) returns (Plain) { option idempotency_level = NO_SIDE_EFFECTS; }
}
message Plain { string id = 1; }
"#;

/// The fixture sources by file name.
struct Fixtures;

impl FileResolver for Fixtures {
    fn open_file(&self, name: &str) -> Result<File, protox::Error> {
        let source = match name {
            "acme/v1/things/things.proto" => THINGS,
            "acme/shared/v1/shared.proto" => SHARED,
            "acme/v1/other/other.proto" => OTHER,
            "acme/v1/wrong/wrong.proto" => WRONG,
            "acmeish/v1/unmapped.proto" => UNMAPPED,
            "beta/v1/outside.proto" => OUTSIDE,
            "acme/v1/plain/plain.proto" => NO_OPTION,
            "acme/v1/ca/ca.proto" => ACRONYM,
            _ => return Err(protox::Error::file_not_found(name)),
        };
        File::from_source(name, source)
    }
}

/// The descriptor set of `files` with every import, as a build compiles it:
/// the fixtures, then SID's own protos for the retry option.
fn descriptors(files: &[&str]) -> Vec<u8> {
    let mut resolver = ChainFileResolver::new();
    resolver.add(Fixtures);
    resolver.add(IncludeFileResolver::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto"),
    ));
    resolver.add(GoogleFileResolver::new());
    protox::Compiler::with_file_resolver(resolver)
        .include_imports(true)
        .open_files(files)
        .expect("the fixtures compile")
        .encode_file_descriptor_set()
}

/// Bindings as a crate below `acme.v1` with a shared-message crate declares
/// them.
fn bindings() -> KeyedBindings {
    KeyedBindings::new("crate::KeyedMethod", "acme.v1")
        .types("google.protobuf", "::prost_types")
        .types("acme", "crate::acme")
        .types("acme.shared", "::acme_shared")
}

/// The errors `generate` reports for `file`, one per line.
fn errors(file: &str) -> Vec<String> {
    match bindings().generate(&descriptors(&[file]), &[file]) {
        Ok(code) => panic!("{file} is bound:\n{code}"),
        Err(Error(lines)) => lines,
    }
}

/// A correctly declared file binds every keyed method, in a module per
/// package below the root and per service, with each request's Rust type
/// resolved through the most specific package mapping (`acme.shared` over
/// `acme`, Empty as `()`), and lists them sorted. Reads, natural and
/// ceremony methods and streams without effects bind nothing.
#[test]
fn test_keyed_methods_are_bound_by_package_and_service() {
    let file = "acme/v1/things/things.proto";
    let code = bindings()
        .generate(&descriptors(&[file]), &[file])
        .expect("a correct file binds");
    let expected = "\
pub mod things {
pub mod audit_trail {
/// `acme.v1.things.AuditTrail/Seal`.
pub struct Seal;
impl crate::KeyedMethod for Seal {
    const METHOD: &'static str = \"acme.v1.things.AuditTrail/Seal\";
    type Request = crate::acme::v1::things::GetThingRequest;
}
}
pub mod thing_service {
/// `acme.v1.things.ThingService/CreateThing`.
pub struct CreateThing;
impl crate::KeyedMethod for CreateThing {
    const METHOD: &'static str = \"acme.v1.things.ThingService/CreateThing\";
    type Request = crate::acme::v1::things::CreateThingRequest;
}
/// `acme.v1.things.ThingService/TouchThing`.
pub struct TouchThing;
impl crate::KeyedMethod for TouchThing {
    const METHOD: &'static str = \"acme.v1.things.ThingService/TouchThing\";
    type Request = ::acme_shared::v1::Ref;
}
/// `acme.v1.things.ThingService/ResetAll`.
pub struct ResetAll;
impl crate::KeyedMethod for ResetAll {
    const METHOD: &'static str = \"acme.v1.things.ThingService/ResetAll\";
    type Request = ();
}
}
}
/// Every keyed method, as `package.Service/Method`, sorted.
pub const METHODS: &[&str] = &[
    \"acme.v1.things.AuditTrail/Seal\",
    \"acme.v1.things.ThingService/CreateThing\",
    \"acme.v1.things.ThingService/ResetAll\",
    \"acme.v1.things.ThingService/TouchThing\",
];
";
    assert_eq!(code, expected);
}

/// The services of imported files belong to the crate that compiles them:
/// an import's keyed method is not bound here and its undeclared method is
/// not this crate's error, while the same file given as an input is checked.
#[test]
fn test_only_the_crates_own_files_are_checked_and_bound() {
    let things = "acme/v1/things/things.proto";
    let code = bindings()
        .generate(&descriptors(&[things]), &[things])
        .expect("the import's own errors are not the importer's");
    assert!(!code.contains("OtherService"), "{code}");

    let other = "acme/v1/other/other.proto";
    let Err(Error(lines)) = bindings().generate(&descriptors(&[things]), &[things, other]) else {
        panic!("the undeclared method of an own file is an error");
    };
    assert_eq!(
        lines,
        [
            "acme.v1.other.OtherService/Undeclared: a method that changes state declares its (sid.v1.common.retry) rule"
        ]
    );
}

/// Every wrong declaration fails the build, each named by its method in one
/// report, so a crate learns all of them at once.
#[test]
fn test_every_wrong_declaration_is_reported() {
    let rpc = |method: &str| format!("acme.v1.wrong.WrongService/{method}");
    assert_eq!(
        errors("acme/v1/wrong/wrong.proto"),
        [
            format!(
                "{}: a method that changes state declares its (sid.v1.common.retry) rule",
                rpc("Undeclared")
            ),
            format!(
                "{}: a method without effects has no retry rule",
                rpc("ReadWithRule")
            ),
            format!(
                "{}: a keyed retry rule is idempotency_level = IDEMPOTENT",
                rpc("KeyedUnknown")
            ),
            format!(
                "{}: a natural retry rule is idempotency_level = IDEMPOTENT",
                rpc("NaturalUnknown")
            ),
            format!(
                "{}: the retry rule `keyed` is `keyed: true` or a stated reason",
                rpc("KeyedFalse")
            ),
            format!(
                "{}: the retry rule `natural` is `keyed: true` or a stated reason",
                rpc("BlankReason")
            ),
            format!(
                "{}: the retry rule names none of its rules",
                rpc("EmptyRule")
            ),
            format!("{}: a keyed method is unary", rpc("KeyedStream")),
            format!(
                "{}: a keyed request is a top-level message",
                rpc("KeyedNested")
            ),
            format!(
                "{}: no Rust module is given for the messages of acmeish.v1",
                rpc("KeyedUnmapped")
            ),
        ]
    );
}

/// A keyed method outside the module root has no module to be bound in.
#[test]
fn test_a_keyed_method_outside_the_root_is_refused() {
    assert_eq!(
        errors("beta/v1/outside.proto"),
        ["beta.v1.OutsideService/Change: a keyed method of package beta.v1, outside acme.v1"]
    );
}

/// Without the retry option in the descriptors nothing can be checked, so
/// the build fails rather than binding nothing.
#[test]
fn test_descriptors_without_the_retry_option_are_refused() {
    let file = "acme/v1/plain/plain.proto";
    let Err(Error(lines)) = bindings().generate(&descriptors(&[file]), &[file]) else {
        panic!("descriptors without the option are refused");
    };
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("define no sid.v1.common.retry"),
        "{lines:?}"
    );
}

/// Regression guard: a request is named by the type prost generates for it
/// (`RotateCARequest` is `RotateCaRequest` in Rust), so the binding compiles.
#[test]
fn test_a_request_is_named_as_prost_names_it() {
    let file = "acme/v1/ca/ca.proto";
    let code = bindings()
        .generate(&descriptors(&[file]), &[file])
        .expect("binds");
    assert!(
        code.contains("type Request = crate::acme::v1::ca::RotateCaRequest;"),
        "{code}"
    );
}

/// `snake_case` puts an underscore before every capital but the first.
#[test]
fn test_snake_case() {
    assert_eq!(snake_case("AccountService"), "account_service");
    assert_eq!(snake_case("ReBAcService"), "re_b_ac_service");
    assert_eq!(snake_case("Plain"), "plain");
}
