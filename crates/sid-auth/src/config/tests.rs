// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn minimal_config_takes_defaults() {
    let config: AuthConfig =
        serde_yaml::from_str("upstream: http://sid:50051\nissuer_url: https://sid.example.com\n")
            .unwrap();
    assert_eq!(config.grpc_listen, "0.0.0.0:50061");
    assert!(config.login_url.is_empty());
    assert!(config.route_policy_path.is_none());
    assert!(config.cache_url.is_none());
    #[cfg(feature = "http")]
    assert!(config.http.is_none());
}

/// A misspelled key is refused instead of leaving the default in force.
#[test]
fn unknown_keys_are_refused() {
    let result: Result<AuthConfig, _> = serde_yaml::from_str(
        "upstream: http://sid:50051\nissuer_url: https://sid.example.com\nroute_policies: /x\n",
    );
    assert!(result.is_err());
}

/// Upstream and issuer have no default: a deployment names them.
#[test]
fn upstream_and_issuer_are_required() {
    let result: Result<AuthConfig, _> = serde_yaml::from_str("issuer_url: https://x.example\n");
    assert!(result.is_err());
    let result: Result<AuthConfig, _> = serde_yaml::from_str("upstream: http://sid:50051\n");
    assert!(result.is_err());
}

/// The checker credential names its issuer, client and one authentication
/// method; a method's fields belong to it alone.
#[test]
fn the_checker_credential_names_one_method() {
    let config: AuthConfig = serde_yaml::from_str(
        "upstream: http://sid:50051\nissuer_url: https://sid.example.com\nauthz_checker:\n  \
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

    let mixed: Result<AuthConfig, _> = serde_yaml::from_str(
        "upstream: http://sid:50051\nissuer_url: https://sid.example.com\nauthz_checker:\n  \
         issuer: https://sid.example.com/i/0123456789abcdef0123456789abcdef\n  \
         client_id: route-checker\n  \
         authentication: { method: client_secret_basic, secret_file: /s, algorithm: EdDSA }\n",
    );
    assert!(mixed.is_err());
}

/// The reference file shipped with the crate parses.
#[test]
fn reference_file_parses() {
    let config: AuthConfig = serde_yaml::from_str(include_str!("../../sid-auth.yaml")).unwrap();
    assert_eq!(config.issuer_url, "https://auth.example.com");
    #[cfg(feature = "http")]
    assert!(config.http.is_some());
}

/// A receiver reads its issuer, resource, origin and own credential from the
/// environment; every one of them is required, the cache is not.
#[test]
fn a_receiver_needs_its_resource_origin_and_credential() {
    let complete = [
        ("SID_GRPC_UPSTREAM", "http://sid:50051"),
        ("SID_ISSUER_URL", "https://sid.example.com"),
        ("SID_RECEIVER_RESOURCE", "https://ops.example.com/"),
        ("SID_RECEIVER_ORIGIN", "https://ops.example.com"),
        ("SID_AUTHZ_CHECKER_CLIENT_ID", "ops-receiver"),
        (
            "SID_AUTHZ_CHECKER_ISSUER",
            "https://sid.example.com/i/platform",
        ),
        ("SID_AUTHZ_CHECKER_METHOD", "client_secret_basic"),
        ("SID_AUTHZ_CHECKER_SECRET_FILE", "/run/secrets/ops"),
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
    assert_eq!(config.resource, "https://ops.example.com/");
    assert_eq!(config.origin, "https://ops.example.com");
    assert_eq!(config.checker.issuer, "https://sid.example.com/i/platform");
    assert!(config.cache_url.is_none());
    for (name, _) in complete {
        assert!(without(name).is_err(), "{name} is required");
    }
}
