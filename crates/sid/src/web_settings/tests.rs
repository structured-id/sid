// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn own() -> Url {
    url("https://sid.example.com/")
}

fn field(e: WebSettingsError) -> &'static str {
    match e {
        WebSettingsError::InvalidField { field, .. } => field,
        other => panic!("not a field refusal: {other}"),
    }
}

/// A public URL override is an https origin (http only on loopback) with no
/// path, credentials, query or fragment: anything else would put the cookie
/// and every built address on a URL browsers do not reach the same way.
#[test]
fn public_url_is_an_origin() {
    for ok in [
        "https://login.example.com",
        "https://login.example.com/",
        "http://localhost:8080",
    ] {
        assert!(public_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "login.example.com",
        "http://login.example.com",
        "https://login.example.com/sid",
        "https://u:p@login.example.com",
        "https://login.example.com/?a=1",
        "https://login.example.com/#x",
        "ftp://login.example.com",
    ] {
        assert_eq!(field(public_url(bad).unwrap_err()), "public_url", "{bad}");
    }
}

/// The console lives on the public URL's site: another prefix on its origin,
/// or a sibling host including its root. Its root, the paths the
/// installation serves and another site are refused; a missing trailing
/// slash is added.
#[test]
fn console_url_is_same_site_and_away_from_served_paths() {
    let public = own();
    for (given, kept) in [
        (
            "https://sid.example.com/admin/",
            "https://sid.example.com/admin/",
        ),
        (
            "https://sid.example.com/console",
            "https://sid.example.com/console/",
        ),
        ("https://admin.example.com/", "https://admin.example.com/"),
        (
            "https://admin.example.com/ops/",
            "https://admin.example.com/ops/",
        ),
    ] {
        assert_eq!(
            console_url(given, &public).unwrap().as_str(),
            kept,
            "{given}"
        );
    }
    for bad in [
        "https://sid.example.com/",
        "https://sid.example.com/account/",
        "https://sid.example.com/api/x/",
        "https://sid.example.com/v1/",
        "https://sid.example.com/.well-known/",
        "https://admin.example.net/",
        "http://admin.example.com/",
    ] {
        assert_eq!(
            field(console_url(bad, &public).unwrap_err()),
            "console_url",
            "{bad}"
        );
    }
}

/// Unset settings resolve to the own URL and the default console; a stored
/// override and console are served; a stored console that no longer fits
/// the public URL falls back to the default instead of another site.
#[test]
fn resolution_defaults_and_fallbacks() {
    let none = resolve(&own(), None);
    assert_eq!(none.public_url, own());
    assert!(!none.public_url_overridden);
    assert_eq!(none.console_url.as_str(), "https://sid.example.com/admin/");
    assert_eq!(none.cookie_scope, CookieScope::ThisHost);

    let stored = WebSettings {
        public_url: Some("https://login.example.org/".into()),
        console_url: Some("https://admin.example.com/".into()),
        ..WebSettings::default()
    };
    let resolved = resolve(&own(), Some(&stored));
    assert!(resolved.public_url_overridden);
    assert_eq!(resolved.public_url.as_str(), "https://login.example.org/");
    assert_eq!(
        resolved.console_url.as_str(),
        "https://login.example.org/admin/"
    );
}

fn in_force(scope: CookieScope) -> InForce {
    resolve(
        &own(),
        Some(&WebSettings {
            cookie_scope: scope,
            ..WebSettings::default()
        }),
    )
}

/// The base host is always admitted. Every subdomain admits descendants
/// only, never a look-alike suffix; a selection admits exactly its listed
/// hosts and the names its pattern matches whole.
#[test]
fn scope_admits_its_hosts_only() {
    let this = in_force(CookieScope::ThisHost);
    assert!(this.admits("SID.example.com."));
    assert!(!this.admits("app.sid.example.com"));

    let all = in_force(CookieScope::AllSubdomains);
    assert!(all.admits("deep.app.sid.example.com"));
    assert!(!all.admits("evilsid.example.com"));
    assert!(!all.admits("example.com"));

    let selected = in_force(CookieScope::SelectedSubdomains {
        hosts: vec!["app.sid.example.com".into()],
        pattern: Some(r"[a-z]+\.apps\.sid\.example\.com".into()),
    });
    assert!(selected.admits("APP.sid.example.com"));
    assert!(selected.admits("crm.apps.sid.example.com"));
    assert!(!selected.admits("crm.apps.sid.example.com.evil.com"));
    assert!(!selected.admits("x1.apps.sid.example.com"));
    assert!(!selected.admits("other.sid.example.com"));
}

fn scope_req(
    domain: wire::SessionCookieDomain,
    subdomains: &[&str],
    pattern: &str,
) -> wire::UpdateSessionCookieScopeRequest {
    wire::UpdateSessionCookieScopeRequest {
        domain: domain as i32,
        subdomains: subdomains.iter().map(|s| (*s).to_owned()).collect(),
        subdomain_pattern: pattern.to_owned(),
    }
}

/// A requested scope is validated whole: a scope must be named; subdomains
/// only come with a selection, must be under the base and are normalized;
/// a pattern must compile; a widened scope needs a host that can carry a
/// cookie for its subdomains.
#[test]
fn requested_scope_validation() {
    use wire::SessionCookieDomain as D;
    let public = own();
    assert_eq!(
        requested_scope(
            &scope_req(
                D::SelectedSubdomains,
                &["App.Sid.Example.com.", "app.sid.example.com"],
                ""
            ),
            &public
        )
        .unwrap(),
        CookieScope::SelectedSubdomains {
            hosts: vec!["app.sid.example.com".into()],
            pattern: None
        }
    );
    assert_eq!(
        requested_scope(&scope_req(D::AllSubdomains, &[], ""), &public).unwrap(),
        CookieScope::AllSubdomains
    );
    for (req, expected) in [
        (scope_req(D::Unspecified, &[], ""), "domain"),
        (
            scope_req(D::ThisHost, &["a.sid.example.com"], ""),
            "subdomains",
        ),
        (scope_req(D::SelectedSubdomains, &[], ""), "subdomains"),
        (
            scope_req(D::SelectedSubdomains, &["a.example.net"], ""),
            "subdomains",
        ),
        (
            scope_req(D::SelectedSubdomains, &["sid.example.com"], ""),
            "subdomains",
        ),
        (
            scope_req(D::SelectedSubdomains, &["bad_label.sid.example.com"], ""),
            "subdomains",
        ),
        (
            scope_req(D::SelectedSubdomains, &[], "("),
            "subdomain_pattern",
        ),
    ] {
        assert_eq!(
            field(requested_scope(&req, &public).unwrap_err()),
            expected,
            "{req:?}"
        );
    }
    // A host that is itself a public suffix, or an address, cannot share a
    // cookie with subdomains.
    for host in [
        "https://github.io/",
        "http://127.0.0.1:8080/",
        "http://localhost:8080/",
    ] {
        assert_eq!(
            field(requested_scope(&scope_req(D::AllSubdomains, &[], ""), &url(host)).unwrap_err()),
            "domain",
            "{host}"
        );
    }
}
