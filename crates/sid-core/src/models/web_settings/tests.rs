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
