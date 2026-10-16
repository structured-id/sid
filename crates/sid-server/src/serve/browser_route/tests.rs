// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// The handle and the gRPC path are split off `/i/{handle}/grpc/...`.
#[test]
fn addressed_path_names_handle_and_method() {
    assert_eq!(
        addressed("/i/0123abcd/grpc/sid.v1.authn.AuthService/OpaqueLoginStart"),
        Some(("0123abcd", "/sid.v1.authn.AuthService/OpaqueLoginStart"))
    );
}

/// Anything else is no addressed call: no handle, no `grpc` segment, a
/// longer segment that only starts with it, another issuer endpoint, a root
/// gRPC path.
#[test]
fn other_paths_are_not_addressed() {
    for path in [
        "/i/",
        "/i/0123abcd",
        "/i/0123abcd/grpc",
        "/i/0123abcd/grpcx/sid.v1.authn.AuthService/OpaqueLoginStart",
        "/i/0123abcd/oauth2/token",
        "/sid.v1.authn.AuthService/OpaqueLoginStart",
    ] {
        assert_eq!(addressed(path), None, "{path}");
    }
}

/// Every published path is a gRPC path (`/package.Service/Method`), listed
/// once.
#[test]
fn browser_methods_are_distinct_grpc_paths() {
    let mut seen = std::collections::HashSet::new();
    for method in BROWSER_METHODS {
        let (service, name) = method
            .strip_prefix('/')
            .and_then(|m| m.split_once('/'))
            .unwrap_or_else(|| panic!("{method}"));
        assert!(
            service.contains('.') && !name.is_empty() && !name.contains('/'),
            "{method}"
        );
        assert!(seen.insert(method), "{method} listed twice");
    }
}
