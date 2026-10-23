// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const INSTALLATION: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";
/// The `kid` of the BFF's key, registered for the client.
const KID: &str = "bff-key";

fn bundle() -> ClientConnection {
    ClientConnection {
        issuer: format!("{INSTALLATION}/i/{HANDLE}"),
        client_id: "account-web".into(),
        resource: format!("{INSTALLATION}/account"),
        scopes: vec!["openid".into(), "account".into()],
        redirect_uri: "https://account.sid.example.com/auth/callback".into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
        key_ids: vec!["previous-key".into(), KID.into()],
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
        Connection::accept(answered(answer, KID), INSTALLATION).unwrap(),
        Connection::accept(b, INSTALLATION).unwrap()
    );
}

/// A connection that would have the BFF sign in at another installation,
/// under a handle that is not one, as a client it cannot authenticate, or
/// without its target, is refused, wherever it came from.
#[test]
fn an_unusable_connection_is_refused() {
    let cases: [fn(&mut ClientConnection); 12] = [
        // Two scopes in one entry would be split by the issuer and match
        // neither registered scope (RFC 6749 §3.3).
        |c| c.scopes.push("orders.read orders.write".into()),
        |c| c.scopes.push(String::new()),
        |c| c.issuer = format!("https://other.example.com/i/{HANDLE}"),
        |c| c.issuer = format!("{INSTALLATION}/i/not-a-handle"),
        |c| c.token_endpoint_auth_method = "client_secret_basic".into(),
        |c| c.client_id = String::new(),
        |c| c.resource = String::new(),
        // RFC 8707 §2: an absolute URI without a fragment.
        |c| c.resource = "not-a-uri".into(),
        |c| c.resource = format!("{INSTALLATION}/account#part"),
        |c| c.scopes.clear(),
        // The callback needs an ID token, issued only for `openid`
        // (OIDC Core 1.0 §3.1.2.1).
        |c| c.scopes = vec!["account".into()],
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
        Connection::parse(&json, INSTALLATION, KID).unwrap(),
        Connection::accept(bundle(), INSTALLATION).unwrap()
    );

    assert!(Connection::parse("{", INSTALLATION, KID).is_err());
    let mut extended = serde_json::to_value(bundle()).unwrap();
    extended["client_secret"] = "s3cret".into();
    assert!(Connection::parse(&extended.to_string(), INSTALLATION, KID).is_err());
    let mut foreign = bundle();
    foreign.issuer = format!("https://other.example.com/i/{HANDLE}");
    assert!(
        Connection::parse(&serde_json::to_string(&foreign).unwrap(), INSTALLATION, KID).is_err()
    );
}

/// A bundle of a client that did not register the BFF's key (another
/// client's bundle beside this key) is refused at start: every code
/// redemption would fail with `invalid_client`.
#[test]
fn a_bundle_of_a_client_without_the_bffs_key_is_refused() {
    let json = serde_json::to_string(&bundle()).unwrap();
    assert!(Connection::parse(&json, INSTALLATION, "another-key").is_err());
    let mut keyless = bundle();
    keyless.key_ids.clear();
    assert!(
        Connection::parse(&serde_json::to_string(&keyless).unwrap(), INSTALLATION, KID).is_err()
    );
}

/// The callback goes into protocol requests exactly as registered: SID
/// compares redirect URIs as strings, so a normalized spelling (lowercased
/// host) would be an unregistered callback.
#[test]
fn the_callback_is_sent_as_registered() {
    let mut b = bundle();
    b.redirect_uri = "https://Account.SID.example.com/auth/callback".into();
    let connection = Connection::accept(b, INSTALLATION).unwrap();
    assert_eq!(
        connection.redirect_uri,
        "https://Account.SID.example.com/auth/callback"
    );
    let url = connection.authorize_url("challenge", "state-1", "nonce-1");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query["redirect_uri"],
        "https://Account.SID.example.com/auth/callback"
    );
}

/// Scopes are part of what a session's tokens were issued for: a bundle that
/// narrows them is another connection, while their order is not.
#[test]
fn the_binding_covers_the_scopes_but_not_their_order() {
    let base = Connection::accept(bundle(), INSTALLATION).unwrap();
    let mut narrowed = bundle();
    narrowed.scopes = vec!["openid".into()];
    assert_ne!(
        Connection::accept(narrowed, INSTALLATION)
            .unwrap()
            .binding(),
        base.binding()
    );
    let mut reordered = bundle();
    reordered.scopes.reverse();
    assert_eq!(
        Connection::accept(reordered, INSTALLATION)
            .unwrap()
            .binding(),
        base.binding()
    );
}

/// A pending sign-in is bound to the callback as well: a bundle that changes
/// only the callback keeps sessions but not sign-ins started before it.
#[test]
fn the_sign_in_binding_covers_the_callback() {
    let base = Connection::accept(bundle(), INSTALLATION).unwrap();
    let mut moved = bundle();
    moved.redirect_uri = "https://new.sid.example.com/auth/callback".into();
    let moved = Connection::accept(moved, INSTALLATION).unwrap();
    assert_eq!(moved.binding(), base.binding());
    assert_ne!(moved.sign_in_binding(), base.sign_in_binding());
}

/// A bundle file that cannot be read is an error, never a fallback.
#[test]
fn a_missing_bundle_file_is_an_error() {
    let missing = std::env::temp_dir().join("sid-bff-connection-that-does-not-exist.json");
    assert!(Connection::load(&missing, INSTALLATION, KID).is_err());
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

/// A lazy channel to nowhere.
fn unreachable() -> tonic::transport::Channel {
    tonic::transport::Channel::from_static("http://127.0.0.1:1")
        .connect_timeout(std::time::Duration::from_millis(100))
        .connect_lazy()
}

fn key() -> ClientKey {
    ClientKey::generate_ed25519().unwrap().0
}

/// Without the issuer the connection is not learned, and the next call asks
/// again instead of keeping the failure.
#[tokio::test]
async fn an_unreachable_issuer_is_asked_again() {
    let client = RpClient::new(key(), INSTALLATION.into(), unreachable()).unwrap();
    assert!(matches!(
        client.connection().await,
        Err(RpClientError::Rpc(_))
    ));
    assert!(client.connection.get().is_none());
    assert!(client.connection().await.is_err());
}

/// A client given its connection by the deployment never asks the issuer for
/// one: the unreachable channel is not called.
#[tokio::test]
async fn a_delivered_connection_needs_no_discovery() {
    let connection = Connection::accept(bundle(), INSTALLATION).unwrap();
    let client = RpClient::delivered(
        key(),
        INSTALLATION.into(),
        unreachable(),
        connection.clone(),
    )
    .unwrap();
    assert_eq!(client.connection().await.unwrap(), &connection);
}

/// A key that names no key id cannot be this client's: the registration
/// lists the client's keys by id, and connection proofs are issued by it.
#[tokio::test]
async fn a_key_without_an_id_is_refused() {
    let (_, pem) = ClientKey::generate_ed25519().unwrap();
    let unnamed = ClientKey::from_pem(&pem, "EdDSA", None).unwrap();
    assert!(matches!(
        RpClient::new(unnamed, INSTALLATION.into(), unreachable()),
        Err(RpClientError::Invalid(_))
    ));
}
