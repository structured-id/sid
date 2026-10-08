// SPDX-License-Identifier: AGPL-3.0-only
//! The sign-in page the authorization endpoint sends users to
//! (`SID_LOGIN_URL`).

use sid_server::init::login_url;

const ISSUER: &str = "https://sid.example.com";

/// Unset or empty means no sign-in page.
#[test]
fn login_url_absent() {
    assert!(login_url(None, ISSUER).unwrap().is_none());
    assert!(login_url(Some(""), ISSUER).unwrap().is_none());
}

/// An http(s) URL with a host on the issuer's site is taken as given, its
/// query kept; another sub-domain or port of the same site is that site.
#[test]
fn login_url_parsed() {
    let url = login_url(
        Some("https://login.sid.example.com/sign-in?tenant=a"),
        ISSUER,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        url.as_str(),
        "https://login.sid.example.com/sign-in?tenant=a"
    );
    assert!(login_url(Some("http://localhost:9000/"), "http://localhost:8085").is_ok());
}

/// Anything else stops startup rather than sending users nowhere.
#[test]
fn login_url_rejects_non_urls() {
    for value in [
        "sign-in",
        "/sign-in",
        "javascript:alert(1)",
        "ftp://sid.example.com/",
    ] {
        assert!(login_url(Some(value), ISSUER).is_err(), "{value:?}");
    }
}

/// A page on another site than the issuer host stops startup: its ceremony
/// responses could not set the IdP session cookie on the issuer host.
#[test]
fn login_url_rejects_another_site() {
    for value in [
        "https://login.example.net/",
        "http://login.sid.example.com/",
        "https://sid.example.com.evil.test/",
    ] {
        let error = login_url(Some(value), ISSUER).unwrap_err();
        assert!(
            error.to_string().contains("same site"),
            "{value:?}: {error}"
        );
    }
}
