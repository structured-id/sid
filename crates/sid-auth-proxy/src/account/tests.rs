// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const INSTALLATION: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";

fn answer() -> AccountConnection {
    AccountConnection {
        issuer: format!("{INSTALLATION}/i/{HANDLE}"),
        client_id: "account-web".into(),
        resource: format!("{INSTALLATION}/account"),
        scopes: vec!["openid".into(), "account".into()],
        redirect_uri: "https://account.sid.example.com/auth/callback".into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
    }
}

/// SID's answer becomes the connection, with the handle the token endpoint
/// needs taken from the issuer.
#[test]
fn a_provisioned_answer_is_the_connection() {
    let connection = Connection::from_answer(answer(), INSTALLATION).unwrap();
    assert_eq!(connection.issuer_handle, HANDLE);
    assert_eq!(
        connection.token_endpoint(),
        format!("{INSTALLATION}/i/{HANDLE}/oauth2/token")
    );
}

/// An answer that would have the BFF sign in at another installation, under
/// a handle that is not one, as a client it cannot authenticate, or without
/// its target, is refused.
#[test]
fn an_unusable_answer_is_refused() {
    let cases: [fn(&mut AccountConnection); 6] = [
        |a| a.issuer = format!("https://other.example.com/i/{HANDLE}"),
        |a| a.issuer = format!("{INSTALLATION}/i/not-a-handle"),
        |a| a.token_endpoint_auth_method = "client_secret_basic".into(),
        |a| a.resource = String::new(),
        |a| a.scopes.clear(),
        |a| a.redirect_uri = "not a url".into(),
    ];
    for spoil in cases {
        let mut bad = answer();
        spoil(&mut bad);
        assert!(
            Connection::from_answer(bad.clone(), INSTALLATION).is_err(),
            "{bad:?}"
        );
    }
}

/// The authorization request is the code flow with S256 PKCE, for the
/// account API, returning to the registered callback; every value is
/// encoded, none is taken from the browser's request.
#[test]
fn the_authorization_request_asks_for_the_account_api() {
    let connection = Connection::from_answer(answer(), INSTALLATION).unwrap();
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
