// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_infra::client_credential::ClientAuthentication;

#[test]
fn minimal_config_takes_defaults() {
    let config: AuthConfig = serde_saphyr::from_str("upstream: http://sid:50051\n").unwrap();
    assert_eq!(config.grpc_listen, "0.0.0.0:50061");
    assert!(config.login_url.is_empty());
    assert!(config.route_policy_path.is_none());
    assert!(config.cache_url.is_none());
    #[cfg(feature = "http")]
    assert!(config.http.is_none());
}

/// A misspelled key is refused instead of leaving the default in force; so
/// is the removed installation URL, which nothing reads any more.
#[test]
fn unknown_keys_are_refused() {
    for extra in ["route_policies: /x", "issuer_url: https://sid.example.com"] {
        let result: Result<AuthConfig, _> =
            serde_saphyr::from_str(&format!("upstream: http://sid:50051\n{extra}\n"));
        assert!(result.is_err(), "{extra}");
    }
}

/// The upstream has no default: a deployment names it.
#[test]
fn upstream_is_required() {
    let result: Result<AuthConfig, _> = serde_saphyr::from_str("login_url: https://x.example\n");
    assert!(result.is_err());
}

/// The checker credential names its issuer, client and one authentication
/// method; a method's fields belong to it alone.
#[test]
fn the_checker_credential_names_one_method() {
    let config: AuthConfig = serde_saphyr::from_str(
        "upstream: http://sid:50051\nauthz_checker:\n  \
         issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef\n  \
         client_id: route-checker\n  \
         authentication: { method: private_key_jwt, key_file: /etc/sid/checker.pem, algorithm: EdDSA }\n",
    )
    .unwrap();
    let checker = config.authz_checker.unwrap();
    assert_eq!(checker.client_id, "route-checker");
    assert!(matches!(
        checker.authentication,
        ClientAuthentication::PrivateKeyJwt { key_id: None, .. }
    ));

    let mixed: Result<AuthConfig, _> = serde_saphyr::from_str(
        "upstream: http://sid:50051\nauthz_checker:\n  \
         issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef\n  \
         client_id: route-checker\n  \
         authentication: { method: client_secret_basic, secret_file: /s, algorithm: EdDSA }\n",
    );
    assert!(mixed.is_err());
}

/// The reference file shipped with the crate parses.
#[test]
fn reference_file_parses() {
    let config: AuthConfig = serde_saphyr::from_str(include_str!("../../sid-auth.yaml")).unwrap();
    assert_eq!(config.upstream, "http://sid-server:50051");
    #[cfg(feature = "http")]
    assert!(config.http.is_some());
}

/// A receiver reads its upstream, resource, origin and own credential from
/// the environment; every one of them is required, the cache is not.
#[test]
fn a_receiver_needs_its_resource_origin_and_credential() {
    let complete = [
        ("SID_GRPC_UPSTREAM", "http://sid:50051"),
        ("SID_RECEIVER_RESOURCE", "https://orders.example.com/"),
        ("SID_RECEIVER_ORIGIN", "https://orders.example.com"),
        ("SID_AUTHZ_CHECKER_CLIENT_ID", "orders-receiver"),
        (
            "SID_AUTHZ_CHECKER_ISSUER",
            "https://sid.example.com/i/platform",
        ),
        ("SID_AUTHZ_CHECKER_METHOD", "client_secret_basic"),
        ("SID_AUTHZ_CHECKER_SECRET_FILE", "/run/secrets/orders"),
    ];
    let without = |missing: &str| {
        ReceiverConfig::from_vars(|name| {
            complete
                .iter()
                .find(|(key, _)| *key == name && *key != missing)
                .map(|(_, value)| (*value).to_owned())
        })
    };
    let config = without("").unwrap();
    assert_eq!(config.resource, "https://orders.example.com/");
    assert_eq!(config.origin, "https://orders.example.com");
    assert_eq!(config.checker.issuer, "https://sid.example.com/i/platform");
    for (name, _) in complete {
        assert!(without(name).is_err(), "{name} is required");
    }
}
