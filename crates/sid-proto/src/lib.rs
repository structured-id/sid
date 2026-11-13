// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Protocol Buffer Definitions
//!
//! Generated code from proto/ repository via `tonic-build`: the messages
//! always, the gRPC client and server stubs with the `grpc` feature.
//! Do not edit generated files manually.
//!
//! Proto packages are organized by domain (sid.v1.identity, sid.v1.authn, etc.)
//! but re-exported flat at `sid::v1::*` for ergonomic use.

#![allow(clippy::all)]
#![allow(warnings)]

/// The generated code of proto package `$package`, without the transport
/// `tonic::include_proto!` would require.
macro_rules! include_proto {
    ($package:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $package, ".rs"));
    };
}

pub mod sid {
    pub mod v1 {
        pub mod common {
            include_proto!("sid.v1.common");
        }

        /// Identifier messages, owned by `sid-ids-proto` with their validated
        /// conversions to `sid-ids` types.
        pub use sid_ids_proto::sid::v1::ids;

        pub mod identity {
            include_proto!("sid.v1.identity");
        }

        pub mod authn {
            include_proto!("sid.v1.authn");
        }

        pub mod authz {
            include_proto!("sid.v1.authz");
        }

        pub mod account {
            include_proto!("sid.v1.account");
        }

        pub mod admin {
            include_proto!("sid.v1.admin");
        }

        pub mod projects {
            include_proto!("sid.v1.projects");
        }

        pub mod machine {
            include_proto!("sid.v1.machine");
        }

        pub mod federation {
            include_proto!("sid.v1.federation");
        }

        pub mod events {
            include_proto!("sid.v1.events");
        }

        pub mod scim {
            include_proto!("sid.v1.scim");
        }

        pub mod attestation {
            include_proto!("sid.v1.attestation");
        }

        pub mod test {
            include_proto!("sid.v1.test");
        }

        /// Public UI settings a UI host serves with its configuration; kept
        /// out of the flat re-export below.
        pub mod ui {
            include_proto!("sid.v1.ui");
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

/// A `sid.v1.common.IpAddress` whose value is not 4 or 16 bytes. Carries the
/// length, nothing of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddressError {
    length: usize,
}

impl IpAddressError {
    /// The length the message carried.
    pub const fn length(&self) -> usize {
        self.length
    }
}

impl core::fmt::Display for IpAddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "an IP address is 4 or 16 bytes, not {}", self.length)
    }
}

impl core::error::Error for IpAddressError {}

impl From<core::net::IpAddr> for sid::v1::common::IpAddress {
    /// The address's octets in network order: 4 for IPv4, 16 for IPv6. An
    /// IPv4-mapped IPv6 address stays 16 bytes.
    fn from(address: core::net::IpAddr) -> Self {
        let value = match address {
            core::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            core::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        Self { value }
    }
}

impl TryFrom<&sid::v1::common::IpAddress> for core::net::IpAddr {
    type Error = IpAddressError;

    /// The address the message carries; the length is the family. An
    /// IPv4-mapped IPv6 address is read as IPv6, never folded into IPv4.
    fn try_from(message: &sid::v1::common::IpAddress) -> Result<Self, IpAddressError> {
        let length = message.value.len();
        if let Ok(v4) = <[u8; 4]>::try_from(message.value.as_slice()) {
            Ok(Self::V4(v4.into()))
        } else if let Ok(v6) = <[u8; 16]>::try_from(message.value.as_slice()) {
            Ok(Self::V6(v6.into()))
        } else {
            Err(IpAddressError { length })
        }
    }
}

/// The Google API types the SID protos use, such as `google.api.HttpBody`.
pub mod google {
    pub mod api {
        include_proto!("google.api");
    }
}

/// A method the proto declares `(sid.v1.common.retry) = { keyed: true }`:
/// its command is named by an operation context. The build generates one
/// type per such method, in [`keyed`], and no other.
pub trait KeyedMethod {
    /// The method, as `package.Service/Method`.
    const METHOD: &'static str;
    /// Its request message.
    type Request: prost::Message;
}

/// The keyed methods, by package below `sid.v1` and service:
/// `keyed::account::account_service::AddEmail`.
pub mod keyed {
    include!(concat!(env!("OUT_DIR"), "/keyed.rs"));

    /// Whether the gRPC request `path` (`/package.Service/Method`) calls a
    /// keyed method.
    pub fn is_keyed_path(path: &str) -> bool {
        path.strip_prefix('/')
            .is_some_and(|method| METHODS.binary_search(&method).is_ok())
    }
}

/// Encoded `FileDescriptorSet` for proto3 JSON transcoding via `prost-reflect`.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/proto_descriptor.bin"));

/// The proto file of the forward-auth decision service, which only the
/// decision service serves.
pub const FORWARD_AUTH_PROTO: &str = "sid/v1/authz/forward_auth.proto";

/// The proto file of the platform CA publication, which only the platform
/// serves.
pub const PLATFORM_CA_PROTO: &str = "sid/v1/federation/platform_ca.proto";

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
