// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn test_claims() -> ForwardAuthClaims {
    ForwardAuthClaims {
        sub: "up_01HY000000000000000000".into(),
        iss: "https://sid.example.com".into(),
        exp: 9999999999,
        iat: 1000000000,
        auth_time: 1000000000,
        acr: "standard".into(),
        scope: "openid profile email".into(),
        roles: "admin editor viewer".into(),
        sid: "sess_01".into(),
        jti: "tok_01".into(),
        email: Some("user@sid.example.com".into()),
        name: Some("Test User".into()),
        preferred_username: Some("testuser".into()),
        groups: None,
        cnf: None,
    }
}

#[test]
fn test_render_email() {
    let claims = test_claims();
    assert_eq!(
        render_template("{{ .Email }}", &claims),
        "user@sid.example.com"
    );
}

#[test]
fn test_render_subject() {
    let claims = test_claims();
    assert_eq!(
        render_template("{{ .Subject }}", &claims),
        "up_01HY000000000000000000"
    );
}

#[test]
fn test_render_user_backwards_compat() {
    let claims = test_claims();
    // {{ .User }} is deprecated alias, still works
    assert_eq!(
        render_template("{{ .User }}", &claims),
        "up_01HY000000000000000000"
    );
}

#[test]
fn test_render_groups_semicolon() {
    let claims = test_claims();
    assert_eq!(
        render_template("{{ .Groups | join ';' }}", &claims),
        "admin;editor;viewer"
    );
}

#[test]
fn test_header_translation() {
    let claims = test_claims();
    let mut templates = std::collections::HashMap::new();
    templates.insert("X-WEBAUTH-USER".into(), "{{ .Email }}".into());
    templates.insert("X-WEBAUTH-ROLE".into(), "{{ .Groups | join ',' }}".into());

    let config = AuthTranslation {
        mode: TranslationMode::Header,
        headers: templates,
        cookie: None,
    };

    let headers = translate(&claims, &config, None);
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

    let claims = test_claims();
    let headers = translate(&claims, &config, Some("test_jwt_token"));
    let cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.starts_with("_sid_session=test_jwt_token"));
    assert!(cookie.contains("Domain=.example.com"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=lax"));
}
