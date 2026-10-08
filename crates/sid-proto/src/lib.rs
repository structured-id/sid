// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Protocol Buffer Definitions
//!
//! Generated code from proto/ repository via `tonic-build`.
//! Do not edit generated files manually.
//!
//! Proto packages are organized by domain (sid.v1.identity, sid.v1.authn, etc.)
//! but re-exported flat at `sid::v1::*` for ergonomic use.

#![allow(clippy::all)]
#![allow(warnings)]

pub mod sid {
    pub mod v1 {
        pub mod common {
            tonic::include_proto!("sid.v1.common");
        }

        /// Identifier messages, owned by `sid-ids-proto` with their validated
        /// conversions to `sid-ids` types.
        pub use sid_ids_proto::sid::v1::ids;

        pub mod identity {
            tonic::include_proto!("sid.v1.identity");
        }

        pub mod authn {
            tonic::include_proto!("sid.v1.authn");
        }

        pub mod authz {
            tonic::include_proto!("sid.v1.authz");
        }

        pub mod account {
            tonic::include_proto!("sid.v1.account");
        }

        pub mod admin {
            tonic::include_proto!("sid.v1.admin");
        }

        pub mod projects {
            tonic::include_proto!("sid.v1.projects");
        }

        pub mod machine {
            tonic::include_proto!("sid.v1.machine");
        }

        pub mod federation {
            tonic::include_proto!("sid.v1.federation");
        }

        pub mod events {
            tonic::include_proto!("sid.v1.events");
        }

        pub mod scim {
            tonic::include_proto!("sid.v1.scim");
        }

        pub mod attestation {
            tonic::include_proto!("sid.v1.attestation");
        }

        pub mod test {
            tonic::include_proto!("sid.v1.test");
        }

        // Re-export all domain types at sid::v1::* for ergonomic access.
        // This is the deliberate public API surface — consumers use `sid::v1::Profile`,
        // not `sid::v1::identity::Profile`.
        pub use account::*;
        pub use admin::*;
        pub use attestation::*;
        pub use authn::*;
        pub use authz::*;
        pub use common::*;
        pub use federation::*;
        pub use identity::*;
        pub use machine::*;
        pub use projects::*;
        pub use scim::*;
        pub use test::*;
    }
}

/// The Google API types the SID protos use, such as `google.api.HttpBody`.
pub mod google {
    pub mod api {
        tonic::include_proto!("google.api");
    }
}

/// Encoded `FileDescriptorSet` for proto3 JSON transcoding via `prost-reflect`.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/proto_descriptor.bin"));

/// The proto file of the forward-auth decision service, which only the
/// decision service serves.
pub const FORWARD_AUTH_PROTO: &str = "sid/v1/authz/forward_auth.proto";

/// The encoded `FileDescriptorSet` of the files `keep` selects together with
/// every file they import, in dependency order. A service that transcodes its
/// own RPCs hands its transcoder only these, so no route of another service
/// is mounted on it.
pub fn descriptor_set_of(keep: impl Fn(&str) -> bool) -> Vec<u8> {
    use prost::Message;
    use prost::encoding::{WireType, decode_key, decode_varint, encode_key, encode_varint};
    use std::collections::{HashMap, HashSet};

    // Each file is kept as its original bytes: decoding and re-encoding it
    // through `prost_types` would drop the extensions it does not model, the
    // `google.api.http` options among them. `prost_types` only reads names
    // and imports.
    let mut raw: Vec<(prost_types::FileDescriptorProto, &[u8])> = Vec::new();
    let mut buf = FILE_DESCRIPTOR_SET;
    while !buf.is_empty() {
        let (tag, wire) = decode_key(&mut buf).expect("descriptor set field key");
        assert!(
            tag == 1 && wire == WireType::LengthDelimited,
            "a FileDescriptorSet holds only `file`"
        );
        let len = usize::try_from(decode_varint(&mut buf).expect("file length"))
            .expect("file length fits in memory");
        let (bytes, rest) = buf.split_at(len);
        let file = prost_types::FileDescriptorProto::decode(bytes).expect("file descriptor");
        raw.push((file, bytes));
        buf = rest;
    }
    let by_name: HashMap<&str, &prost_types::FileDescriptorProto> =
        raw.iter().map(|(file, _)| (file.name(), file)).collect();
    let mut needed: HashSet<&str> = HashSet::new();
    let mut pending: Vec<&str> = raw
        .iter()
        .map(|(file, _)| file.name())
        .filter(|name| keep(name))
        .collect();
    while let Some(name) = pending.pop() {
        if needed.insert(name)
            && let Some(file) = by_name.get(name)
        {
            pending.extend(file.dependency.iter().map(String::as_str));
        }
    }
    // The embedded set lists every file after its imports; keeping that
    // order keeps the result loadable file by file.
    let mut out = Vec::new();
    for (file, bytes) in &raw {
        if needed.contains(file.name()) {
            encode_key(1, WireType::LengthDelimited, &mut out);
            encode_varint(bytes.len() as u64, &mut out);
            out.extend_from_slice(bytes);
        }
    }
    out
}

#[cfg(test)]
mod tests;
