// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use sid_core::grpc_error::{ApiError, ErrorReason};

use super::*;

fn body(content_type: &str, value: &Value) -> HttpBody {
    HttpBody {
        content_type: content_type.into(),
        data: value.to_string().into_bytes(),
        extensions: Vec::new(),
    }
}

fn scim(value: &Value) -> HttpBody {
    body("application/scim+json", value)
}

/// The status and JSON body of an answer.
fn answer(response: &Response<HttpBody>) -> (u16, Value) {
    let status = response
        .metadata()
        .get("x-http-code")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let data = &response.get_ref().data;
    let value = if data.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(data).unwrap()
    };
    (status, value)
}

fn refused(response: Response<HttpBody>) -> (u16, Option<String>) {
    let (status, value) = answer(&response);
    assert_eq!(value["schemas"], json!([ERROR_SCHEMA]));
    assert_eq!(value["status"], json!(status.to_string()));
    (status, value["scimType"].as_str().map(str::to_owned))
}

/// RFC 7643 §3: a resource without its schema in `schemas` is no SCIM
/// resource; other media types and non-objects are refused as syntax.
#[test]
fn a_resource_must_name_its_schema() {
    let user = json!({ "schemas": [USER_SCHEMA], "userName": "ada" });
    assert!(read_resource(Some(&scim(&user)), USER_SCHEMA).is_ok());
    // Plain JSON is accepted too (RFC 7644 §8.1).
    assert!(
        read_resource(
            Some(&body("application/json; charset=utf-8", &user)),
            USER_SCHEMA
        )
        .is_ok()
    );

    for (case, request) in [
        ("no schemas", Some(scim(&json!({ "userName": "ada" })))),
        (
            "another schema",
            Some(scim(&json!({ "schemas": [GROUP_SCHEMA] }))),
        ),
        ("not an object", Some(scim(&json!(["ada"])))),
        (
            "form body",
            Some(body("application/x-www-form-urlencoded", &user)),
        ),
        ("no body", None),
    ] {
        let err = read_resource(request.as_ref(), USER_SCHEMA).unwrap_err();
        assert_eq!(
            refused(err.answer()),
            (400, Some("invalidSyntax".into())),
            "{case}"
        );
    }
}

/// A User's attributes reach the typed request; the enterprise extension's
/// department is read from the extension, and an omitted `active` does not
/// deactivate.
#[test]
fn a_user_is_read_with_its_extension() {
    let user = json!({
        "schemas": [USER_SCHEMA, ENTERPRISE_SCHEMA],
        "userName": "ada",
        "externalId": "E-1",
        "name": { "givenName": "Ada", "familyName": "Lovelace" },
        "emails": [{ "value": "ada@corp.example.com", "type": "work", "primary": true }],
        "phoneNumbers": [{ "value": "+15551234567", "type": "work" }],
        "title": "Engineer",
        ENTERPRISE_SCHEMA: { "department": "R&D" },
    });
    let read = UserJson::read(user.as_object().unwrap()).unwrap();
    assert_eq!(read.user_name, "ada");
    assert_eq!(read.external_id, "E-1");
    assert_eq!(read.name.unwrap().family_name, "Lovelace");
    assert_eq!(read.emails[0].value, "ada@corp.example.com");
    assert!(read.emails[0].primary);
    assert!(!read.phone_numbers[0].primary);
    assert_eq!(read.department, "R&D");
    assert_eq!(read.title, "Engineer");
    assert!(read.active);

    let inactive = json!({ "userName": "ada", "active": false });
    assert!(
        !UserJson::read(inactive.as_object().unwrap())
            .unwrap()
            .active
    );
}

/// An attribute of the wrong JSON type is `invalidValue`, without echoing
/// the value.
#[test]
fn a_wrongly_typed_attribute_is_an_invalid_value() {
    for user in [
        json!({ "userName": 7 }),
        json!({ "userName": "ada", "active": "yes" }),
        json!({ "userName": "ada", "emails": { "value": "x" } }),
        json!({ "userName": "ada", "name": "Ada" }),
    ] {
        let err = UserJson::read(user.as_object().unwrap()).err().unwrap();
        let (status, value) = answer(&err.answer());
        assert_eq!(
            (status, value["scimType"].clone()),
            (400, json!("invalidValue"))
        );
        assert!(!value["detail"].as_str().unwrap().contains("yes"));
    }
}

fn patch(operations: Value) -> HttpBody {
    scim(&json!({ "schemas": [PATCH_SCHEMA], "Operations": operations }))
}

fn op(op: &str, path: &str, value: &str) -> proto::ScimPatchOp {
    proto::ScimPatchOp {
        op: op.into(),
        path: path.into(),
        value: value.into(),
    }
}

/// RFC 7644 §3.5.2: operations with a path pass through, a non-string value
/// as its JSON text; an add or replace without a path becomes one operation
/// per attribute of its value, `name` and extension attributes by their
/// paths; the op name is case-insensitive.
#[test]
fn patch_operations_reach_the_typed_form() {
    let operations = read_patch(Some(&patch(json!([
        { "op": "Replace", "path": "active", "value": false },
        { "op": "add", "path": "members", "value": [{ "value": "u1" }] },
        { "op": "remove", "path": "members[value eq \"u2\"]" },
        { "op": "replace", "value": {
            "title": "Lead",
            "name": { "givenName": "Ada" },
            ENTERPRISE_SCHEMA: { "department": "R&D" },
        } },
    ]))))
    .unwrap();
    assert_eq!(
        operations,
        vec![
            op("replace", "active", "false"),
            op("add", "members", r#"[{"value":"u1"}]"#),
            op("remove", "members[value eq \"u2\"]", ""),
            op("replace", "title", "Lead"),
            op("replace", "name.givenName", "Ada"),
            op("replace", &format!("{ENTERPRISE_SCHEMA}:department"), "R&D"),
        ]
    );
}

/// A PATCH without its message schema or operations is `invalidSyntax`; a
/// removal without a path is `noTarget` (RFC 7644 §3.5.2.2); a pathless
/// operation whose value is not an object is `invalidValue`.
#[test]
fn malformed_patches_are_refused() {
    for (request, expected) in [
        (
            scim(&json!({ "Operations": [{ "op": "add", "path": "title", "value": "x" }] })),
            "invalidSyntax",
        ),
        (patch(json!([])), "invalidSyntax"),
        (patch(json!({ "op": "add" })), "invalidSyntax"),
        (patch(json!([{ "op": "remove" }])), "noTarget"),
        (
            patch(json!([{ "op": "replace", "value": "x" }])),
            "invalidValue",
        ),
    ] {
        let err = read_patch(Some(&request)).unwrap_err();
        assert_eq!(refused(err.answer()), (400, Some(expected.into())));
    }
}

/// RFC 7644 §3.4.2.4: `count=0` (or less) asks for `totalResults` alone; an
/// absent count is the default.
#[test]
fn paging_honours_a_zero_count() {
    let request = |count| proto::ScimHttpRequest {
        count,
        ..Default::default()
    };
    let resources = vec![json!({ "id": "a" })];

    let none = Page::of(&request(Some(0)));
    assert_eq!(none.typed_count(), 1);
    let listed = none.response(7, 1, resources.clone());
    assert_eq!(listed["totalResults"], json!(7));
    assert_eq!(listed["itemsPerPage"], json!(0));
    assert_eq!(listed["Resources"], json!([]));
    assert_eq!(listed["schemas"], json!([LIST_SCHEMA]));

    let default = Page::of(&request(None));
    assert_eq!(default.typed_count(), 0);
    assert_eq!(
        default.response(7, 1, resources.clone())["Resources"],
        json!(resources)
    );
    assert_eq!(Page::of(&request(Some(5))).typed_count(), 5);
}

/// A User renders with its schemas (the extension only when it carries a
/// value), leaves unassigned attributes out and writes dateTimes as
/// RFC 3339.
#[test]
fn a_user_renders_as_rfc_7643() {
    let mut user = proto::ScimUser {
        id: "u1".into(),
        user_name: "ada".into(),
        active: true,
        meta: Some(proto::ScimMeta {
            resource_type: "User".into(),
            created: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            location: "https://sid.example.com/scim/v2/Users/u1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let rendered = user_json(&user);
    assert_eq!(rendered["schemas"], json!([USER_SCHEMA]));
    assert!(rendered.get("externalId").is_none());
    assert!(rendered.get("emails").is_none());
    assert_eq!(
        rendered["meta"]["created"],
        json!("2023-11-14T22:13:20.000Z")
    );
    assert!(rendered["meta"].get("lastModified").is_none());

    user.department = "R&D".into();
    let rendered = user_json(&user);
    assert_eq!(rendered["schemas"], json!([USER_SCHEMA, ENTERPRISE_SCHEMA]));
    assert_eq!(rendered[ENTERPRISE_SCHEMA]["department"], json!("R&D"));
    assert!(rendered.get("department").is_none());
}

/// A created resource is 201 with its location (RFC 7644 §3.3).
#[test]
fn a_created_resource_names_its_location() {
    let group = proto::ScimGroup {
        id: "g1".into(),
        display_name: "Engineering".into(),
        meta: Some(proto::ScimMeta {
            location: "https://sid.example.com/scim/v2/Groups/g1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let response = created(group_json(&group));
    assert_eq!(answer(&response).0, 201);
    assert_eq!(
        response.metadata().get("location").unwrap(),
        "https://sid.example.com/scim/v2/Groups/g1"
    );
    assert_eq!(answer(&no_content()), (204, Value::Null));
}

/// Refusals render as RFC 7644 §3.12 errors with the status their code
/// stands for and the `scimType` their ErrorInfo names; an authentication
/// failure challenges for a bearer token (RFC 6750 §3); a server-side
/// failure says when to retry and nothing about itself.
#[test]
fn refusals_render_as_scim_errors() {
    let unauthenticated: Status =
        ApiError::new(ErrorReason::TokenInvalid, "authentication required").into();
    let response = refusal(&unauthenticated, true);
    assert_eq!(
        response.metadata().get("www-authenticate").unwrap(),
        r#"Bearer error="invalid_token""#
    );
    assert_eq!(refused(response), (401, None));
    let response = refusal(&unauthenticated, false);
    assert_eq!(
        response.metadata().get("www-authenticate").unwrap(),
        "Bearer"
    );

    let taken: Status = ApiError::new(
        ErrorReason::UsernameAlreadyTaken,
        "the userName is held by another user",
    )
    .with_metadata(SCIM_TYPE, "uniqueness")
    .into();
    assert_eq!(
        refused(refusal(&taken, true)),
        (409, Some("uniqueness".into()))
    );

    let denied = Status::permission_denied("no");
    assert_eq!(refused(refusal(&denied, true)), (403, None));
    let missing = Status::not_found("no such user");
    assert_eq!(refused(refusal(&missing, true)), (404, None));

    let unavailable: Status =
        ApiError::new(ErrorReason::DependencyUnavailable, "store down at 10.0.0.7")
            .with_retry_after(Duration::from_millis(1500))
            .into();
    let response = refusal(&unavailable, true);
    assert_eq!(response.metadata().get("retry-after").unwrap(), "2");
    let (status, value) = answer(&response);
    assert_eq!(status, 503);
    assert!(value.get("detail").is_none(), "{value}");

    let internal = Status::internal("secret path /var/lib");
    let (status, value) = answer(&refusal(&internal, true));
    assert_eq!(status, 500);
    assert!(value.get("detail").is_none(), "{value}");
}
