// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn selected(hosts: &[&str]) -> CookieScope {
    CookieScope::SelectedSubdomains {
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        pattern: None,
    }
}

/// Narrowing is what must end the secrets shared under the former scope:
/// leaving every subdomain, dropping a selected host, or leaving the
/// selection for this host alone. Widening and keeping the scope narrow
/// nothing.
#[test]
fn narrowing_is_any_loss_of_hosts() {
    use CookieScope::*;
    assert!(ThisHost.narrows(&AllSubdomains));
    assert!(selected(&["a.example.com"]).narrows(&AllSubdomains));
    assert!(ThisHost.narrows(&selected(&["a.example.com"])));
    assert!(selected(&["a.example.com"]).narrows(&selected(&["a.example.com", "b.example.com"])));

    assert!(!AllSubdomains.narrows(&AllSubdomains));
    assert!(!AllSubdomains.narrows(&ThisHost));
    assert!(!selected(&["a.example.com"]).narrows(&ThisHost));
    assert!(!ThisHost.narrows(&ThisHost));
    assert!(!selected(&["a.example.com"]).narrows(&selected(&["a.example.com"])));
}

// Within a selection only a lost host narrows: adding a host or listing the
// same hosts in another order keeps every session. A pattern added keeps
// them; a pattern changed or removed may admit fewer hosts, so it narrows.
// Bug prevented: every user signed out because an administrator added a
// subdomain to the list.
#[test]
fn a_selection_narrows_only_when_it_loses_hosts() {
    let with = |hosts: &[&str], pattern: Option<&str>| CookieScope::SelectedSubdomains {
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        pattern: pattern.map(str::to_owned),
    };
    let ab = with(&["a.example.com", "b.example.com"], None);
    assert!(!with(&["b.example.com", "a.example.com"], None).narrows(&ab));
    assert!(!with(&["a.example.com", "b.example.com", "c.example.com"], None).narrows(&ab));
    assert!(with(&["a.example.com"], None).narrows(&ab));
    assert!(!with(&["a.example.com", "b.example.com"], Some("x")).narrows(&ab));
    let patterned = with(&["a.example.com"], Some("x"));
    assert!(with(&["a.example.com"], Some("y")).narrows(&patterned));
    assert!(with(&["a.example.com"], None).narrows(&patterned));
    assert!(!with(&["a.example.com"], Some("x")).narrows(&patterned));
}

// A UI mount is a literal absolute path ending with `/`: anything a browser
// would rewrite (escapes, dot segments, doubled slashes) or a missing slash
// is refused, so a saved console address is always one the bundle serves.
#[test]
fn a_ui_mount_is_a_literal_path() {
    for ok in ["/", "/admin/", "/my-console/v1/", "/a.b_c~d/"] {
        assert!(is_ui_mount(ok), "{ok}");
    }
    for bad in [
        "admin/",
        "/admin",
        "/my%20console/",
        "/a//b/",
        "/a/./b/",
        "/a/../",
        "/ä/",
        "/a b/",
    ] {
        assert!(!is_ui_mount(bad), "{bad}");
    }
}

/// The stored form round-trips through JSON, tagged by the scope.
#[test]
fn settings_round_trip() {
    let settings = WebSettings {
        public_url: Some("https://sid.example.com".into()),
        console_url: Some("https://admin.example.com/".into()),
        cookie_scope: CookieScope::SelectedSubdomains {
            hosts: vec!["app.example.com".into()],
            pattern: Some(r"^[a-z]+\.apps\.example\.com$".into()),
        },
        revision: 3,
    };
    let json = serde_json::to_vec(&settings).unwrap();
    assert_eq!(
        serde_json::from_slice::<WebSettings>(&json).unwrap(),
        settings
    );
}
