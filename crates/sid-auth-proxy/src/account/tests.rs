// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const INSTALLATION: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";

fn bundle() -> ClientConnection {
    ClientConnection {
        issuer: format!("{INSTALLATION}/i/{HANDLE}"),
        client_id: "account-web".into(),
        resource: format!("{INSTALLATION}/account"),
        scopes: vec!["openid".into(), "account".into()],
        redirect_uri: "https://account.sid.example.com/auth/callback".into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
    }
}

/// A provisioned connection becomes the BFF's, with the handle the token
/// endpoint needs taken from the issuer.
#[test]
fn a_provisioned_connection_is_accepted() {
    let connection = Connection::accept(bundle(), INSTALLATION).unwrap();
    assert_eq!(connection.issuer_handle, HANDLE);
    assert_eq!(
        connection.token_endpoint(),
        format!("{INSTALLATION}/i/{HANDLE}/oauth2/token")
    );
}

/// The account API's answer is the same representation: converted, it is
/// accepted as the same connection.
#[test]
fn the_account_api_answer_is_the_same_connection() {
    let b = bundle();
    let answer = AccountConnection {
        issuer: b.issuer.clone(),
        client_id: b.client_id.clone(),
        resource: b.resource.clone(),
        scopes: b.scopes.clone(),
        redirect_uri: b.redirect_uri.clone(),
        token_endpoint_auth_method: b.token_endpoint_auth_method.clone(),
    };
    assert_eq!(
        Connection::accept(answered(answer), INSTALLATION).unwrap(),
        Connection::accept(b, INSTALLATION).unwrap()
    );
}

/// A connection that would have the BFF sign in at another installation,
/// under a handle that is not one, as a client it cannot authenticate, or
/// without its target, is refused, wherever it came from.
#[test]
fn an_unusable_connection_is_refused() {
    let cases: [fn(&mut ClientConnection); 7] = [
        |c| c.issuer = format!("https://other.example.com/i/{HANDLE}"),
        |c| c.issuer = format!("{INSTALLATION}/i/not-a-handle"),
        |c| c.token_endpoint_auth_method = "client_secret_basic".into(),
        |c| c.client_id = String::new(),
        |c| c.resource = String::new(),
        |c| c.scopes.clear(),
        |c| c.redirect_uri = "not a url".into(),
    ];
    for spoil in cases {
        let mut bad = bundle();
        spoil(&mut bad);
        assert!(
            Connection::accept(bad.clone(), INSTALLATION).is_err(),
            "{bad:?}"
        );
    }
}

/// A delivered bundle is read as JSON and validated like any other
/// connection; malformed JSON, an unknown field or an unusable connection
/// is refused.
#[test]
fn a_delivered_bundle_is_parsed_and_validated() {
    let json = serde_json::to_string(&bundle()).unwrap();
    assert_eq!(
        Connection::parse(&json, INSTALLATION).unwrap(),
        Connection::accept(bundle(), INSTALLATION).unwrap()
    );

    assert!(Connection::parse("{", INSTALLATION).is_err());
    let mut extended = serde_json::to_value(bundle()).unwrap();
    extended["client_secret"] = "s3cret".into();
    assert!(Connection::parse(&extended.to_string(), INSTALLATION).is_err());
    let mut foreign = bundle();
    foreign.issuer = format!("https://other.example.com/i/{HANDLE}");
    assert!(Connection::parse(&serde_json::to_string(&foreign).unwrap(), INSTALLATION).is_err());
}

/// A bundle file that cannot be read is an error, never a fallback.
#[test]
fn a_missing_bundle_file_is_an_error() {
    let missing = std::env::temp_dir().join("sid-bff-connection-that-does-not-exist.json");
    assert!(Connection::load(&missing, INSTALLATION).is_err());
}

/// The authorization request is the code flow with S256 PKCE, for the
/// connection's API, returning to the registered callback; every value is
/// encoded, none is taken from the browser's request.
#[test]
fn the_authorization_request_asks_for_the_connection_resource() {
    let connection = Connection::accept(bundle(), INSTALLATION).unwrap();
    let url = connection.authorize_url("challenge", "state-1", "nonce-1");
    assert_eq!(
        url.as_str().split('?').next().unwrap(),
        format!("{INSTALLATION}/i/{HANDLE}/oauth2/authorize")
    );
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "account-web");
    assert_eq!(
        query["redirect_uri"],
        "https://account.sid.example.com/auth/callback"
    );
    assert_eq!(query["scope"], "openid account");
    assert_eq!(query["resource"], format!("{INSTALLATION}/account"));
    assert_eq!(query["code_challenge"], "challenge");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["state"], "state-1");
    assert_eq!(query["nonce"], "nonce-1");
}

/// Without SID the connection is not learned, and the next call asks again
/// instead of keeping the failure.
#[tokio::test]
async fn an_unreachable_sid_is_asked_again() {
    let (key, _) = ClientKey::generate().unwrap();
    let link = AccountLink::new(key, INSTALLATION.into(), crate::test_channel());
    assert!(link.connection().await.is_err());
    assert!(link.connection.get().is_none());
    assert!(link.connection().await.is_err());
}

/// A link given its connection by the deployment never asks SID for one: the
/// unreachable test channel is not called.
#[tokio::test]
async fn a_delivered_connection_needs_no_discovery() {
    let (key, _) = ClientKey::generate().unwrap();
    let connection = Connection::accept(bundle(), INSTALLATION).unwrap();
    let link = AccountLink::delivered(
        key,
        INSTALLATION.into(),
        crate::test_channel(),
        connection.clone(),
    );
    assert_eq!(link.connection().await.unwrap(), &connection);
}
