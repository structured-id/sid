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
    let connection = Connection::accept(bundle()).unwrap();
    assert_eq!(connection.issuer_handle, HANDLE);
    assert_eq!(
        connection.token_endpoint(),
        format!("{INSTALLATION}/i/{HANDLE}/oauth2/token")
    );
}

/// A connection to the installation's root-addressed base issuer is
/// accepted with the empty handle that names it, and its endpoints are at
/// the root.
#[test]
fn a_connection_to_the_root_issuer_is_accepted() {
    let mut root = bundle();
    root.issuer = INSTALLATION.into();
    let connection = Connection::accept(root).unwrap();
    assert_eq!(connection.issuer_handle, "");
    assert_eq!(
        connection.token_endpoint(),
        format!("{INSTALLATION}/oauth2/token")
    );
}

/// The issuer's host is not the adapter's to compare: an issuer whose
/// canonical URL lives at another host than the one the adapter reaches the
/// installation at is selected by its organization segment, and its
/// endpoints are under that issuer.
#[test]
fn an_issuer_at_another_host_is_selected_by_its_segment() {
    let mut elsewhere = bundle();
    elsewhere.issuer = format!("https://login.acme.example/i/{HANDLE}");
    let connection = Connection::accept(elsewhere).unwrap();
    assert_eq!(connection.issuer_handle, HANDLE);
    assert_eq!(
        connection.token_endpoint(),
        format!("https://login.acme.example/i/{HANDLE}/oauth2/token")
    );
}

/// A connection the BFF could not address (an issuer that is not an issuer
/// URL, a handle that is not one), as a client it cannot authenticate, or
/// without its target, is refused, wherever it came from.
#[test]
fn an_unusable_connection_is_refused() {
    let cases: [fn(&mut ClientConnection); 13] = [
        // Two scopes in one entry would be split by the issuer and match
        // neither registered scope (RFC 6749 §3.3).
        |c| c.scopes.push("orders.read orders.write".into()),
        |c| c.scopes.push(String::new()),
        |c| c.issuer = format!("{INSTALLATION}/i/not-a-handle"),
        |c| c.issuer = format!("{INSTALLATION}/i/{HANDLE}?tenant=x"),
        |c| c.issuer = "not a url".into(),
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
        assert!(Connection::accept(bad.clone()).is_err(), "{bad:?}");
    }
}

/// A delivered bundle is read as JSON and validated like any other
/// connection; malformed JSON, an unknown field or an unusable connection
/// is refused.
#[test]
fn a_delivered_bundle_is_parsed_and_validated() {
    let json = serde_json::to_string(&bundle()).unwrap();
    assert_eq!(
        Connection::parse(&json, KID).unwrap(),
        Connection::accept(bundle()).unwrap()
    );

    assert!(Connection::parse("{", KID).is_err());
    let mut extended = serde_json::to_value(bundle()).unwrap();
    extended["client_secret"] = "s3cret".into();
    assert!(Connection::parse(&extended.to_string(), KID).is_err());
    let mut malformed = bundle();
    malformed.issuer = format!("{INSTALLATION}/i/not-a-handle");
    assert!(Connection::parse(&serde_json::to_string(&malformed).unwrap(), KID).is_err());
}

/// A bundle of a client that did not register the BFF's key (another
/// client's bundle beside this key) is refused at start: every code
/// redemption would fail with `invalid_client`.
#[test]
fn a_bundle_of_a_client_without_the_bffs_key_is_refused() {
    let json = serde_json::to_string(&bundle()).unwrap();
    assert!(Connection::parse(&json, "another-key").is_err());
    let mut keyless = bundle();
    keyless.key_ids.clear();
    assert!(Connection::parse(&serde_json::to_string(&keyless).unwrap(), KID).is_err());
}

/// The callback goes into protocol requests exactly as registered: SID
/// compares redirect URIs as strings, so a normalized spelling (lowercased
/// host) would be an unregistered callback.
#[test]
fn the_callback_is_sent_as_registered() {
    let mut b = bundle();
    b.redirect_uri = "https://Account.SID.example.com/auth/callback".into();
    let connection = Connection::accept(b).unwrap();
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
    let base = Connection::accept(bundle()).unwrap();
    let mut narrowed = bundle();
    narrowed.scopes = vec!["openid".into()];
    assert_ne!(
        Connection::accept(narrowed).unwrap().binding(),
        base.binding()
    );
    let mut reordered = bundle();
    reordered.scopes.reverse();
    assert_eq!(
        Connection::accept(reordered).unwrap().binding(),
        base.binding()
    );
}

/// A pending sign-in is bound to the callback as well: a bundle that changes
/// only the callback keeps sessions but not sign-ins started before it.
#[test]
fn the_sign_in_binding_covers_the_callback() {
    let base = Connection::accept(bundle()).unwrap();
    let mut moved = bundle();
    moved.redirect_uri = "https://new.sid.example.com/auth/callback".into();
    let moved = Connection::accept(moved).unwrap();
    assert_eq!(moved.binding(), base.binding());
    assert_ne!(moved.sign_in_binding(), base.sign_in_binding());
}

/// The authorization request is the code flow with S256 PKCE, for the
/// connection's API, returning to the registered callback; every value is
/// encoded, none is taken from the browser's request.
#[test]
fn the_authorization_request_asks_for_the_connection_resource() {
    let connection = Connection::accept(bundle()).unwrap();
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
