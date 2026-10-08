// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use serde_json::json;

fn body(value: Value) -> HttpBody {
    HttpBody {
        content_type: "application/json".into(),
        data: value.to_string().into_bytes(),
        extensions: vec![],
    }
}

/// RFC 7591 §2 metadata is read with its registered names: `scope` as one
/// space-separated string, methods and types by their names; a field this
/// server does not know is ignored.
#[test]
fn reads_registered_metadata() {
    let metadata = Metadata::parse(Some(&body(json!({
        "client_name": "CI",
        "redirect_uris": ["https://ci.sid.example.com/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "application_type": "native",
        "subject_type": "public",
        "contacts": ["ops@sid.example.com"],
        "scope": "openid  profile",
        "software_id": "ignored",
    }))))
    .unwrap();
    assert_eq!(metadata.client_name.as_deref(), Some("CI"));
    assert_eq!(
        metadata.token_endpoint_auth_method,
        Some(TokenEndpointAuthMethod::ClientSecretPost)
    );
    assert_eq!(metadata.application_type, ApplicationType::Native);
    assert_eq!(metadata.subject_type, SubjectType::Public);
    assert_eq!(metadata.scope, ["openid", "profile"]);
}

/// Left out, a field takes the value the registration then defaults: `web`,
/// the documented subject type, the RFC 7591 §2 authentication method; `null`
/// counts as left out.
#[test]
fn absent_fields_are_left_to_their_defaults() {
    let metadata = Metadata::parse(Some(&body(json!({
        "client_name": "App",
        "contacts": null,
    }))))
    .unwrap();
    assert_eq!(metadata.application_type, ApplicationType::Web);
    assert_eq!(metadata.subject_type, SubjectType::Unspecified);
    assert_eq!(metadata.token_endpoint_auth_method, None);
    assert!(metadata.contacts.is_empty());
    let registration = metadata.into_registration("h".into());
    assert_eq!(
        registration.token_endpoint_auth_method,
        i32::from(TokenEndpointAuthMethod::Unspecified)
    );
}

/// A known field with a value of the wrong type or outside its values is
/// refused naming the field, never coerced (authentication-flow.md,
/// registration metadata A); a body that is not a JSON object is refused.
#[test]
fn refuses_invalid_values() {
    for (value, field) in [
        (
            json!({"redirect_uris": "https://x.sid.example.com"}),
            "redirect_uris",
        ),
        (json!({"redirect_uris": [1]}), "redirect_uris"),
        (json!({"client_name": 5}), "client_name"),
        (
            json!({"token_endpoint_auth_method": "tls_client_auth"}),
            "token_endpoint_auth_method",
        ),
        (json!({"application_type": "spa"}), "application_type"),
        (json!({"subject_type": "opaque"}), "subject_type"),
        (json!({"scope": ["openid"]}), "scope"),
    ] {
        assert_eq!(
            Metadata::parse(Some(&body(value.clone())))
                .unwrap_err()
                .field,
            Some(field),
            "{value}"
        );
    }
    let text = HttpBody {
        content_type: "text/plain".into(),
        data: b"{}".to_vec(),
        extensions: vec![],
    };
    for refused in [None, Some(&text), Some(&body(json!([])))] {
        assert_eq!(Metadata::parse(refused).unwrap_err().field, None);
    }
}

/// An update names the client it updates (RFC 7592 §2.2); another or no
/// `client_id` is refused. The returned secret travels to the check.
#[test]
fn an_update_names_its_client() {
    let parse = |value| Metadata::parse(Some(&body(value))).unwrap();
    let update = parse(json!({"client_id": "dyn_1", "client_secret": "s"}))
        .into_update("dyn_1".into(), "h".into())
        .unwrap();
    assert_eq!(update.client_secret.as_deref(), Some("s"));
    assert_eq!(update.subject_type, None);
    for value in [json!({"client_id": "dyn_2"}), json!({})] {
        assert_eq!(
            parse(value)
                .into_update("dyn_1".into(), "h".into())
                .unwrap_err()
                .field,
            Some("client_id")
        );
    }
}

fn application() -> OAuthClient {
    OAuthClient {
        client_id: "dyn_1".into(),
        name: "CI".into(),
        r#type: ApplicationType::Spa.into(),
        redirect_uris: vec!["https://ci.sid.example.com/cb".into()],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic.into(),
        client_id_issued_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        issuer: "https://sid.example.com/i/abc".into(),
        ..Default::default()
    }
}

/// The registration answer carries every registered value, the credentials,
/// the secret's expiry as a number (0 = never) and the management location
/// under the client's issuer (RFC 7591 §3.2.1, RFC 7592 §3).
#[test]
fn the_registration_answer_carries_the_credentials() {
    let answer = client_information(
        &application(),
        Some(Credentials {
            client_secret: Some("secret"),
            registration_access_token: "rat",
        }),
    );
    assert_eq!(answer["client_id"], json!("dyn_1"));
    assert_eq!(answer["client_secret"], json!("secret"));
    assert_eq!(answer["client_secret_expires_at"], json!(0));
    assert_eq!(answer["client_id_issued_at"], json!(1_700_000_000));
    assert_eq!(answer["registration_access_token"], json!("rat"));
    assert_eq!(
        answer["registration_client_uri"],
        json!("https://sid.example.com/i/abc/oauth2/register/dyn_1")
    );
    assert_eq!(
        answer["token_endpoint_auth_method"],
        json!("client_secret_basic")
    );
    assert_eq!(answer["application_type"], json!("web"));
    assert_eq!(answer["subject_type"], json!("public"));
    assert_eq!(answer["scope"], json!("openid profile"));
    assert!(answer.get("contacts").is_none(), "{answer}");
}

/// A read or update answer has no credentials: the secret is stored only as a
/// hash and the registration access token is not re-issued.
#[test]
fn a_read_answer_has_no_credentials() {
    let answer = client_information(&application(), None);
    for field in [
        "client_secret",
        "client_secret_expires_at",
        "registration_access_token",
    ] {
        assert!(answer.get(field).is_none(), "{field}: {answer}");
    }
    assert_eq!(answer["client_name"], json!("CI"));
}
