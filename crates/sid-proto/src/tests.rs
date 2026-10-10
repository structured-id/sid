// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use prost::Message;

fn names(encoded: &[u8]) -> Vec<String> {
    prost_types::FileDescriptorSet::decode(encoded)
        .unwrap()
        .file
        .into_iter()
        .map(|file| file.name().to_owned())
        .collect()
}

/// The identifier messages are the ones `sid-ids-proto` owns, not a second
/// generated copy, and the embedded descriptor set still describes them.
#[test]
fn identifier_messages_are_the_shared_types() {
    let id: sid_ids_proto::BindingId = sid::v1::ids::BindingId::default();
    let _: sid_ids_proto::MachineUserId = sid::v1::ids::MachineUserId::default();
    assert!(id.value.is_empty());
    assert!(
        names(FILE_DESCRIPTOR_SET)
            .iter()
            .any(|f| f == sid_ids_proto::PROTO_PATH)
    );
}

/// The decision service's set carries its file and what it imports, and no
/// other service's file: its transcoder mounts no foreign route.
#[test]
fn forward_auth_set_has_only_its_file_and_imports() {
    let files = names(&descriptor_set_of(|name| name == FORWARD_AUTH_PROTO));
    assert!(files.iter().any(|f| f == FORWARD_AUTH_PROTO));
    assert!(files.iter().any(|f| f == "google/api/httpbody.proto"));
    assert!(files.iter().any(|f| f == "google/api/annotations.proto"));
    assert!(!files.iter().any(|f| f == "sid/v1/authn/issuer.proto"));
    assert!(!files.iter().any(|f| f == "sid/v1/authz/authz.proto"));
}

/// The identity service's set is everything but the decision service.
#[test]
fn the_rest_excludes_forward_auth() {
    let files = names(&descriptor_set_of(|name| name != FORWARD_AUTH_PROTO));
    assert!(!files.iter().any(|f| f == FORWARD_AUTH_PROTO));
    assert!(files.iter().any(|f| f == "sid/v1/authn/issuer.proto"));
}

/// Selected files are carried byte for byte: re-encoding them through
/// `prost_types` would drop what it does not model, such as the
/// `google.api.http` method options the transcoder mounts routes from.
#[test]
fn files_keep_their_options() {
    fn raw_files(set: &[u8]) -> Vec<Vec<u8>> {
        let mut buf = set;
        let mut files = Vec::new();
        while !buf.is_empty() {
            let (tag, wire) = prost::encoding::decode_key(&mut buf).unwrap();
            assert_eq!((tag, wire), (1, prost::encoding::WireType::LengthDelimited));
            let len = prost::encoding::decode_varint(&mut buf).unwrap() as usize;
            files.push(buf[..len].to_vec());
            buf = &buf[len..];
        }
        files
    }
    let all = raw_files(FILE_DESCRIPTOR_SET);
    let selected = raw_files(&descriptor_set_of(|name| name == FORWARD_AUTH_PROTO));
    assert!(!selected.is_empty());
    for file in &selected {
        assert!(all.contains(file), "a selected file changed on the way");
    }
}

/// RPCs served over gRPC only, by decision: an RPC without a
/// `google.api.http` rule is unreachable through the transcoder, so each
/// one here is a choice, not an oversight.
const INTERNAL_RPCS: &[&str] = &[
    // The RFC 6749 / 8628 / 7009 / 7662 HTTP forms are OidcProviderService's
    // issuer endpoints over the same logic; these are the typed gRPC form.
    "sid.v1.authn.AuthService/OAuth2Authorize",
    "sid.v1.authn.AuthService/OAuth2Introspect",
    "sid.v1.authn.AuthService/OAuth2Revoke",
    "sid.v1.authn.AuthService/OAuth2Token",
    "sid.v1.authn.AuthService/StartDeviceAuthorization",
    // The issuer registry the forward-auth decision reads; relying parties
    // use OidcProviderService.
    "sid.v1.authn.OidcIssuerService/GetOidcIssuer",
    "sid.v1.authn.OidcIssuerService/GetProtectedResource",
    // Called only by the credential service, under its own service
    // identity, to have the history evaluator select an operation's domains.
    "sid.v1.authn.PasswordHistoryEvaluatorService/PreparePasswordHistory",
    // The account BFF reaches it over the deployment's gRPC channel; a
    // browser or relying party has no business with it.
    "sid.v1.authn.SystemIntegrationService/GetAccountConnection",
    // The event stream is a gRPC channel for native and gRPC-Web consumers
    // (event-system.md, Channel 1).
    "sid.v1.events.EventStreamService/Replay",
    "sid.v1.events.EventStreamService/Subscribe",
    // RFC 7591 / 7592 registration is OidcProviderService's issuer endpoints.
    "sid.v1.projects.ProjectService/DeleteRegisteredClient",
    "sid.v1.projects.ProjectService/GetRegisteredClient",
    "sid.v1.projects.ProjectService/RegisterClient",
    "sid.v1.projects.ProjectService/UpdateRegisteredClient",
    // The RFC 7644 HTTP form is ScimProtocolService over the same operations;
    // ProtoJSON of these messages is not the SCIM wire format.
    "sid.v1.scim.ScimService/CreateGroup",
    "sid.v1.scim.ScimService/CreateUser",
    "sid.v1.scim.ScimService/DeleteGroup",
    "sid.v1.scim.ScimService/DeleteUser",
    "sid.v1.scim.ScimService/GetGroup",
    "sid.v1.scim.ScimService/GetResourceTypes",
    "sid.v1.scim.ScimService/GetSchemas",
    "sid.v1.scim.ScimService/GetServiceProviderConfig",
    "sid.v1.scim.ScimService/GetUser",
    "sid.v1.scim.ScimService/ListGroups",
    "sid.v1.scim.ScimService/ListUsers",
    "sid.v1.scim.ScimService/PatchGroup",
    "sid.v1.scim.ScimService/PatchUser",
    "sid.v1.scim.ScimService/ReplaceUser",
];

/// Every CE RPC has a `google.api.http` rule or is listed as deliberately
/// internal; a listed RPC that gains a rule or disappears is removed from
/// the list.
#[test]
fn every_rpc_is_annotated_or_deliberately_internal() {
    let pool = prost_reflect::DescriptorPool::decode(FILE_DESCRIPTOR_SET).unwrap();
    let http = pool
        .get_extension_by_name("google.api.http")
        .expect("google/api/annotations.proto is in the set");
    let mut unannotated = Vec::new();
    for service in pool.services() {
        if !service.package_name().starts_with("sid.v1") {
            continue;
        }
        for method in service.methods() {
            if !method.options().has_extension(&http) {
                unannotated.push(format!("{}/{}", service.full_name(), method.name()));
            }
        }
    }
    unannotated.sort();
    let mut internal: Vec<String> = INTERNAL_RPCS.iter().map(|s| (*s).to_owned()).collect();
    internal.sort();
    assert_eq!(unannotated, internal);
}

/// Every file comes after the files it imports, so the set loads in order.
#[test]
fn files_follow_their_imports() {
    let set = prost_types::FileDescriptorSet::decode(
        descriptor_set_of(|name| name == FORWARD_AUTH_PROTO).as_slice(),
    )
    .unwrap();
    let mut seen = std::collections::HashSet::new();
    for file in &set.file {
        for dependency in &file.dependency {
            assert!(
                seen.contains(dependency.as_str()),
                "{} before {dependency}",
                file.name()
            );
        }
        seen.insert(file.name());
    }
}
