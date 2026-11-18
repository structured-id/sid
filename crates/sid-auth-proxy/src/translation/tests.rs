// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn identity() -> UpstreamIdentity {
    UpstreamIdentity {
        subject: "up_01HY000000000000000000".into(),
        email: Some("user@sid.example.com".into()),
        display_name: Some("Test User".into()),
        preferred_username: Some("testuser".into()),
        groups: vec!["admin".into(), "editor".into(), "viewer".into()],
    }
}

#[test]
fn test_render_email() {
    assert_eq!(
        render_template("{{ .Email }}", &identity()),
        "user@sid.example.com"
    );
}

#[test]
fn test_render_subject() {
    assert_eq!(
        render_template("{{ .Subject }}", &identity()),
        "up_01HY000000000000000000"
    );
}

/// `{{ .User }}` is the forward-auth user template: the same opaque subject.
#[test]
fn test_render_user_is_the_subject() {
    assert_eq!(
        render_template("{{ .User }}", &identity()),
        "up_01HY000000000000000000"
    );
}

#[test]
fn test_render_groups_semicolon() {
    assert_eq!(
        render_template("{{ .Groups | join ';' }}", &identity()),
        "admin;editor;viewer"
    );
}

/// A value the request did not prove renders empty: nothing is invented for
/// an absent email, name, username or group set.
#[test]
fn test_an_undisclosed_value_renders_empty() {
    let bare = UpstreamIdentity {
        subject: "up_01".into(),
        ..UpstreamIdentity::default()
    };
    assert_eq!(
        render_template(
            "[{{ .Email }}][{{ .DisplayName }}][{{ .PreferredUsername }}][{{ .Groups }}]",
            &bare
        ),
        "[][][][]"
    );
}

#[test]
fn test_header_translation() {
    let mut templates = std::collections::HashMap::new();
    templates.insert("X-WEBAUTH-USER".into(), "{{ .Email }}".into());
    templates.insert("X-WEBAUTH-ROLE".into(), "{{ .Groups | join ',' }}".into());

    let config = AuthTranslation {
        mode: TranslationMode::Header,
        headers: templates,
        cookie: None,
    };

    let headers = translate(&identity(), &config, None);
    assert_eq!(
        headers.get("x-webauth-user").unwrap().to_str().unwrap(),
        "user@sid.example.com"
    );
    assert_eq!(
        headers.get("x-webauth-role").unwrap().to_str().unwrap(),
        "admin,editor,viewer"
    );
}

#[test]
fn test_cookie_translation() {
    let config = AuthTranslation {
        mode: TranslationMode::Cookie,
        headers: Default::default(),
        cookie: Some(CookieTranslation {
            name: "_sid_session".into(),
            domain: Some(".example.com".into()),
            secure: true,
            http_only: true,
            same_site: "lax".into(),
            content: "jwt".into(),
        }),
    };

    let headers = translate(&identity(), &config, Some("test_jwt_token"));
    let cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.starts_with("_sid_session=test_jwt_token"));
    assert!(cookie.contains("Domain=.example.com"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=lax"));
}
