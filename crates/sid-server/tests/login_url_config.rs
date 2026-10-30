// SPDX-License-Identifier: AGPL-3.0-only
//! The sign-in page the authorization endpoint sends users to, derived from
//! the account UI the deployment serves.

use sid_authn::system_integration::AccountSettings;
use sid_core::models::ClientKeySet;
use sid_server::init::sign_in_page;

const ISSUER: &str = "https://sid.example.com";

fn account(url: &str) -> AccountSettings {
    let keys = ClientKeySet::try_from(serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k",
    }]}))
    .unwrap();
    AccountSettings::new(url, keys).unwrap()
}

/// Without an account UI there is no sign-in page: the client then gets
/// `login_required` rather than a page invented for it.
#[test]
fn no_account_ui_no_sign_in_page() {
    assert!(sign_in_page(None, ISSUER).unwrap().is_none());
}

/// The account UI's sign-in route on the issuer's site is the page; another
/// sub-domain of the same site is that site.
#[test]
fn the_account_ui_route_is_the_sign_in_page() {
    let page = sign_in_page(Some(&account("https://sid.example.com/account/")), ISSUER)
        .unwrap()
        .unwrap();
    assert_eq!(page.as_str(), "https://sid.example.com/account/login");
    let page = sign_in_page(Some(&account("https://account.sid.example.com")), ISSUER)
        .unwrap()
        .unwrap();
    assert_eq!(page.as_str(), "https://account.sid.example.com/login");
    assert!(
        sign_in_page(
            Some(&account("http://localhost:9000/")),
            "http://localhost:8085"
        )
        .is_ok()
    );
}

/// An account UI on another site than the issuer host stops startup: its
/// ceremony responses could not set the IdP session cookie on the issuer
/// host.
#[test]
fn an_account_ui_on_another_site_is_refused() {
    for value in [
        "https://login.example.net/",
        "https://sid.example.com.evil.test/",
    ] {
        let error = sign_in_page(Some(&account(value)), ISSUER).unwrap_err();
        assert!(
            error.to_string().contains("same site"),
            "{value:?}: {error}"
        );
    }
}
