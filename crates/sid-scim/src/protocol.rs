// SPDX-License-Identifier: AGPL-3.0-only
//! The SCIM 2.0 HTTP endpoint (RFC 7644): the RFC 7643/7644 JSON of a SCIM
//! client in, the typed operations of [`ScimServiceImpl`] called with the
//! same request metadata (so the same authentication and authorization), the
//! RFC's JSON, status and headers out. The body travels as
//! `google.api.HttpBody`, the status as `x-http-code` response metadata and
//! the headers as response metadata, which the transcoder turns into the HTTP
//! answer.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use sid_core::grpc_error::{extract_error_info, extract_retry_delay};
use sid_proto::google::api::HttpBody;
use sid_proto::sid::v1 as proto;
use sid_proto::sid::v1::scim_protocol_service_server::ScimProtocolService;
use sid_proto::sid::v1::scim_service_server::ScimService;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Request, Response, Status};

use crate::grpc::ScimServiceImpl;
use crate::refusal::SCIM_TYPE;

/// RFC 7643 §8.7.1: the core User schema.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// RFC 7643 §8.7.1: the core Group schema.
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// RFC 7643 §4.3: the enterprise User extension.
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// RFC 7644 §3.4.2: a query response.
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// RFC 7644 §3.5.2: a PATCH request.
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/// RFC 7644 §3.12: an error response.
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// RFC 7644 §3.1, §8.1: the SCIM media type.
const SCIM_JSON: &str = "application/scim+json";

/// The SCIM HTTP endpoint over the typed SCIM service.
pub struct ScimProtocolServiceImpl {
    scim: Arc<ScimServiceImpl>,
}

impl ScimProtocolServiceImpl {
    pub fn new(scim: Arc<ScimServiceImpl>) -> Self {
        Self { scim }
    }
}

type Answer = Result<Response<HttpBody>, Status>;

#[tonic::async_trait]
impl ScimProtocolService for ScimProtocolServiceImpl {
    async fn create_user(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let typed = match read_resource(http.body.as_ref(), USER_SCHEMA).and_then(|user| {
            let user = UserJson::read(&user)?;
            Ok(proto::ScimCreateUserRequest {
                external_id: user.external_id,
                user_name: user.user_name,
                name: user.name,
                display_name: user.display_name,
                emails: user.emails,
                phone_numbers: user.phone_numbers,
                department: user.department,
                title: user.title,
                active: user.active,
            })
        }) {
            Ok(typed) => typed,
            Err(refused) => return Ok(refused.answer()),
        };
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .create_user(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(user) => created(user_json(&user.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn get_user(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimGetUserRequest { id: http.id };
        Ok(
            match self
                .scim
                .get_user(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(user) => scim_json(200, &user_json(&user.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn list_users(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let page = Page::of(&http);
        let typed = proto::ScimListUsersRequest {
            filter: http.filter,
            start_index: http.start_index,
            count: page.typed_count(),
        };
        Ok(
            match self
                .scim
                .list_users(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(listed) => {
                    let listed = listed.into_inner();
                    let resources = listed.resources.iter().map(user_json).collect();
                    scim_json(
                        200,
                        &page.response(listed.total_results, listed.start_index, resources),
                    )
                }
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn replace_user(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let id = http.id;
        let typed = match read_resource(http.body.as_ref(), USER_SCHEMA).and_then(|user| {
            let user = UserJson::read(&user)?;
            Ok(proto::ScimReplaceUserRequest {
                id,
                external_id: user.external_id,
                user_name: user.user_name,
                name: user.name,
                display_name: user.display_name,
                emails: user.emails,
                phone_numbers: user.phone_numbers,
                department: user.department,
                title: user.title,
                active: user.active,
            })
        }) {
            Ok(typed) => typed,
            Err(refused) => return Ok(refused.answer()),
        };
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .replace_user(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(user) => scim_json(200, &user_json(&user.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn patch_user(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let operations = match read_patch(http.body.as_ref()) {
            Ok(operations) => operations,
            Err(refused) => return Ok(refused.answer()),
        };
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimPatchUserRequest {
            id: http.id,
            operations,
        };
        Ok(
            match self
                .scim
                .patch_user(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(user) => scim_json(200, &user_json(&user.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn delete_user(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimDeleteUserRequest { id: http.id };
        Ok(
            match self
                .scim
                .delete_user(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(_) => no_content(),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn create_group(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let typed = match read_resource(http.body.as_ref(), GROUP_SCHEMA).and_then(|group| {
            Ok(proto::ScimCreateGroupRequest {
                display_name: string(&group, "displayName")?,
                members: members(group.get("members"))?,
            })
        }) {
            Ok(typed) => typed,
            Err(refused) => return Ok(refused.answer()),
        };
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .create_group(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(group) => created(group_json(&group.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn get_group(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimGetGroupRequest { id: http.id };
        Ok(
            match self
                .scim
                .get_group(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(group) => scim_json(200, &group_json(&group.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn list_groups(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let page = Page::of(&http);
        let typed = proto::ScimListGroupsRequest {
            filter: http.filter,
            start_index: http.start_index,
            count: page.typed_count(),
        };
        Ok(
            match self
                .scim
                .list_groups(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(listed) => {
                    let listed = listed.into_inner();
                    let resources = listed.resources.iter().map(group_json).collect();
                    scim_json(
                        200,
                        &page.response(listed.total_results, listed.start_index, resources),
                    )
                }
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn patch_group(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let operations = match read_patch(http.body.as_ref()) {
            Ok(operations) => operations,
            Err(refused) => return Ok(refused.answer()),
        };
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimPatchGroupRequest {
            id: http.id,
            operations,
        };
        Ok(
            match self
                .scim
                .patch_group(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(group) => scim_json(200, &group_json(&group.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn delete_group(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, http) = request.into_parts();
        let presented = bearer_presented(&metadata);
        let typed = proto::ScimDeleteGroupRequest { id: http.id };
        Ok(
            match self
                .scim
                .delete_group(Request::from_parts(metadata, extensions, typed))
                .await
            {
                Ok(_) => no_content(),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn get_service_provider_config(
        &self,
        request: Request<proto::ScimHttpRequest>,
    ) -> Answer {
        let (metadata, extensions, _) = request.into_parts();
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .get_service_provider_config(Request::from_parts(
                    metadata,
                    extensions,
                    proto::ScimGetServiceProviderConfigRequest {},
                ))
                .await
            {
                Ok(config) => scim_json(200, &service_provider_config_json(&config.into_inner())),
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn get_resource_types(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, _) = request.into_parts();
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .get_resource_types(Request::from_parts(
                    metadata,
                    extensions,
                    proto::ScimGetResourceTypesRequest {},
                ))
                .await
            {
                Ok(types) => {
                    let resources: Vec<Value> = types
                        .into_inner()
                        .resources
                        .iter()
                        .map(resource_type_json)
                        .collect();
                    scim_json(200, &list_response(resources))
                }
                Err(status) => refusal(&status, presented),
            },
        )
    }

    async fn get_schemas(&self, request: Request<proto::ScimHttpRequest>) -> Answer {
        let (metadata, extensions, _) = request.into_parts();
        let presented = bearer_presented(&metadata);
        Ok(
            match self
                .scim
                .get_schemas(Request::from_parts(
                    metadata,
                    extensions,
                    proto::ScimGetSchemasRequest {},
                ))
                .await
            {
                Ok(schemas) => {
                    let resources: Vec<Value> = schemas
                        .into_inner()
                        .resources
                        .iter()
                        .map(schema_json)
                        .collect();
                    scim_json(200, &list_response(resources))
                }
                Err(status) => refusal(&status, presented),
            },
        )
    }
}

// ── Requests ──

/// A request refused before any operation ran: 400 with its RFC 7644 §3.12
/// `scimType`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refused {
    scim_type: &'static str,
    detail: String,
}

impl Refused {
    fn answer(&self) -> Response<HttpBody> {
        scim_error(400, Some(self.scim_type), &self.detail)
    }
}

/// The JSON object of a request body naming `schema` among its `schemas`
/// (RFC 7643 §3: `schemas` is REQUIRED and names the resource's schema).
fn read_resource(body: Option<&HttpBody>, schema: &str) -> Result<Map<String, Value>, Refused> {
    let object = read_json(body)?;
    let named = object
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|schemas| schemas.iter().any(|s| s.as_str() == Some(schema)));
    if !named {
        return Err(invalid_syntax("schemas must name the resource's schema"));
    }
    Ok(object)
}

/// The body as a JSON object, of the SCIM media type or plain JSON
/// (RFC 7644 §3.1, §8.1).
fn read_json(body: Option<&HttpBody>) -> Result<Map<String, Value>, Refused> {
    let body = body
        .filter(|b| !b.data.is_empty())
        .ok_or_else(|| invalid_syntax("the request has no body"))?;
    let media_type = body.content_type.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case(SCIM_JSON)
        && !media_type.eq_ignore_ascii_case("application/json")
    {
        return Err(invalid_syntax(
            "the request body must be application/scim+json",
        ));
    }
    match serde_json::from_slice(&body.data) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(invalid_syntax("the request body is not a JSON object")),
    }
}

/// The string attribute `name` of `object`; absent is empty.
fn string(object: &Map<String, Value>, name: &str) -> Result<String, Refused> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(invalid_value(name)),
    }
}

/// The boolean attribute `name` of `object`.
fn boolean(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, Refused> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid_value(name)),
    }
}

/// The complex attribute `name` of `object`; absent is empty.
fn complex<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a Map<String, Value>>, Refused> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(inner)) => Ok(Some(inner)),
        Some(_) => Err(invalid_value(name)),
    }
}

/// The multi-valued complex attribute `name` of `object`.
fn multi<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<Vec<&'a Map<String, Value>>, Refused> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_object().ok_or_else(|| invalid_value(name)))
            .collect(),
        Some(_) => Err(invalid_value(name)),
    }
}

/// A User resource's attributes (RFC 7643 §4.1, §4.3).
struct UserJson {
    external_id: String,
    user_name: String,
    name: Option<proto::ScimName>,
    display_name: String,
    emails: Vec<proto::ScimEmail>,
    phone_numbers: Vec<proto::ScimPhoneNumber>,
    department: String,
    title: String,
    active: bool,
}

impl UserJson {
    fn read(user: &Map<String, Value>) -> Result<Self, Refused> {
        let name = complex(user, "name")?
            .map(|name| {
                Ok::<_, Refused>(proto::ScimName {
                    formatted: string(name, "formatted")?,
                    family_name: string(name, "familyName")?,
                    given_name: string(name, "givenName")?,
                    middle_name: string(name, "middleName")?,
                    honorific_prefix: string(name, "honorificPrefix")?,
                    honorific_suffix: string(name, "honorificSuffix")?,
                })
            })
            .transpose()?;
        let emails = multi(user, "emails")?
            .into_iter()
            .map(|email| {
                Ok(proto::ScimEmail {
                    value: string(email, "value")?,
                    r#type: string(email, "type")?,
                    primary: boolean(email, "primary")?.unwrap_or(false),
                })
            })
            .collect::<Result<_, Refused>>()?;
        let phone_numbers = multi(user, "phoneNumbers")?
            .into_iter()
            .map(|phone| {
                Ok(proto::ScimPhoneNumber {
                    value: string(phone, "value")?,
                    r#type: string(phone, "type")?,
                    primary: boolean(phone, "primary")?.unwrap_or(false),
                })
            })
            .collect::<Result<_, Refused>>()?;
        let department = match complex(user, ENTERPRISE_SCHEMA)? {
            Some(enterprise) => string(enterprise, "department")?,
            None => String::new(),
        };
        Ok(Self {
            external_id: string(user, "externalId")?,
            user_name: string(user, "userName")?,
            name,
            display_name: string(user, "displayName")?,
            emails,
            phone_numbers,
            department,
            title: string(user, "title")?,
            // RFC 7643 §4.1.1 gives `active` no default: only an explicit
            // `false` deactivates, an omitted one never does.
            active: boolean(user, "active")?.unwrap_or(true),
        })
    }
}

/// A Group's `members` (RFC 7643 §4.2): the users' ids.
fn members(value: Option<&Value>) -> Result<Vec<proto::ScimMemberRef>, Refused> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let members = value.as_array().ok_or_else(|| invalid_value("members"))?;
    members
        .iter()
        .map(|member| {
            let member = member.as_object().ok_or_else(|| invalid_value("members"))?;
            Ok(proto::ScimMemberRef {
                value: string(member, "value")?,
                display: string(member, "display")?,
            })
        })
        .collect()
}

/// The operations of a PATCH request (RFC 7644 §3.5.2), each with a path: an
/// `add` or `replace` without one names its attributes in its value object
/// and becomes one operation per attribute (§3.5.2.1, §3.5.2.3). A value
/// that is not a string travels as its JSON text, as the typed operation
/// takes it.
fn read_patch(body: Option<&HttpBody>) -> Result<Vec<proto::ScimPatchOp>, Refused> {
    let request = read_json(body)?;
    let named = request
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|schemas| schemas.iter().any(|s| s.as_str() == Some(PATCH_SCHEMA)));
    if !named {
        return Err(invalid_syntax("schemas must name the PatchOp message"));
    }
    let operations = request
        .get("Operations")
        .and_then(Value::as_array)
        .filter(|operations| !operations.is_empty())
        .ok_or_else(|| invalid_syntax("Operations must hold at least one operation"))?;
    let mut typed = Vec::with_capacity(operations.len());
    for operation in operations {
        let operation = operation
            .as_object()
            .ok_or_else(|| invalid_syntax("an operation is not an object"))?;
        let op = string(operation, "op")?.to_ascii_lowercase();
        let path = string(operation, "path")?;
        let value = operation.get("value");
        if !path.is_empty() {
            typed.push(proto::ScimPatchOp {
                op,
                path,
                value: value.map(operation_value).unwrap_or_default(),
            });
            continue;
        }
        // RFC 7644 §3.5.2.2: a removal names its target.
        if op == "remove" {
            return Err(Refused {
                scim_type: "noTarget",
                detail: "a removal needs a path".into(),
            });
        }
        let Some(Value::Object(attributes)) = value else {
            return Err(invalid_value("value"));
        };
        for (attribute, value) in attributes {
            match value {
                // An extension's or `name`'s attributes, each by its path
                // (RFC 7644 §3.10: `urn:...:User:department`, `name.givenName`).
                Value::Object(inner) if attribute.starts_with("urn:") || attribute == "name" => {
                    let separator = if attribute == "name" { '.' } else { ':' };
                    for (sub, value) in inner {
                        typed.push(proto::ScimPatchOp {
                            op: op.clone(),
                            path: format!("{attribute}{separator}{sub}"),
                            value: operation_value(value),
                        });
                    }
                }
                value => typed.push(proto::ScimPatchOp {
                    op: op.clone(),
                    path: attribute.clone(),
                    value: operation_value(value),
                }),
            }
        }
    }
    Ok(typed)
}

/// An operation's value as the typed operation takes it: a string as it is,
/// anything else as its JSON text.
fn operation_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The paging a query asked for (RFC 7644 §3.4.2.4).
struct Page {
    /// `count` when the client gave one.
    count: Option<i32>,
}

impl Page {
    fn of(request: &proto::ScimHttpRequest) -> Self {
        Self {
            count: request.count,
        }
    }

    /// The count the typed query takes: none for the default; `count=0`
    /// still asks for the total, so one result is read and dropped.
    fn typed_count(&self) -> i32 {
        match self.count {
            Some(count) if count > 0 => count,
            Some(_) => 1,
            None => 0,
        }
    }

    /// The ListResponse of `resources`; none for `count=0` or a negative
    /// count, which RFC 7644 §3.4.2.4 reads as 0.
    fn response(&self, total: i32, start_index: i32, resources: Vec<Value>) -> Value {
        let resources = if self.count.is_some_and(|count| count <= 0) {
            Vec::new()
        } else {
            resources
        };
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        })
    }
}

// ── Responses ──

/// A ListResponse holding every one of `resources` (RFC 7644 §3.4.2, §4).
fn list_response(resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// `object[name] = value` unless `value` is empty: SCIM leaves unassigned
/// attributes out rather than empty (RFC 7643 §2.5).
fn put(object: &mut Map<String, Value>, name: &str, value: &str) {
    if !value.is_empty() {
        object.insert(name.into(), value.into());
    }
}

/// A Timestamp as an RFC 7643 §2.3.5 dateTime.
fn date_time(at: &prost_types::Timestamp) -> Option<String> {
    let nanos = u32::try_from(at.nanos).ok()?;
    chrono::DateTime::from_timestamp(at.seconds, nanos)
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// A resource's `meta` (RFC 7643 §3.1).
fn meta_json(meta: &proto::ScimMeta) -> Value {
    let mut object = Map::new();
    put(&mut object, "resourceType", &meta.resource_type);
    if let Some(created) = meta.created.as_ref().and_then(date_time) {
        object.insert("created".into(), created.into());
    }
    if let Some(modified) = meta.last_modified.as_ref().and_then(date_time) {
        object.insert("lastModified".into(), modified.into());
    }
    put(&mut object, "location", &meta.location);
    put(&mut object, "version", &meta.version);
    Value::Object(object)
}

/// A User resource (RFC 7643 §4.1, §4.3, §8.2).
pub fn user_json(user: &proto::ScimUser) -> Value {
    let mut schemas = vec![USER_SCHEMA];
    let mut object = Map::new();
    object.insert("id".into(), user.id.clone().into());
    put(&mut object, "externalId", &user.external_id);
    object.insert("userName".into(), user.user_name.clone().into());
    if let Some(name) = &user.name {
        let mut inner = Map::new();
        put(&mut inner, "formatted", &name.formatted);
        put(&mut inner, "familyName", &name.family_name);
        put(&mut inner, "givenName", &name.given_name);
        put(&mut inner, "middleName", &name.middle_name);
        put(&mut inner, "honorificPrefix", &name.honorific_prefix);
        put(&mut inner, "honorificSuffix", &name.honorific_suffix);
        object.insert("name".into(), Value::Object(inner));
    }
    put(&mut object, "displayName", &user.display_name);
    if !user.emails.is_empty() {
        let emails: Vec<Value> = user
            .emails
            .iter()
            .map(|e| json!({ "value": e.value, "type": e.r#type, "primary": e.primary }))
            .collect();
        object.insert("emails".into(), emails.into());
    }
    if !user.phone_numbers.is_empty() {
        let phones: Vec<Value> = user
            .phone_numbers
            .iter()
            .map(|p| json!({ "value": p.value, "type": p.r#type, "primary": p.primary }))
            .collect();
        object.insert("phoneNumbers".into(), phones.into());
    }
    put(&mut object, "title", &user.title);
    object.insert("active".into(), user.active.into());
    if !user.groups.is_empty() {
        let groups: Vec<Value> = user
            .groups
            .iter()
            .map(|g| json!({ "value": g.value, "display": g.display }))
            .collect();
        object.insert("groups".into(), groups.into());
    }
    if !user.department.is_empty() {
        schemas.push(ENTERPRISE_SCHEMA);
        object.insert(
            ENTERPRISE_SCHEMA.into(),
            json!({ "department": user.department }),
        );
    }
    if let Some(meta) = &user.meta {
        object.insert("meta".into(), meta_json(meta));
    }
    object.insert("schemas".into(), json!(schemas));
    Value::Object(object)
}

/// A Group resource (RFC 7643 §4.2, §8.4).
pub fn group_json(group: &proto::ScimGroup) -> Value {
    let members: Vec<Value> = group
        .members
        .iter()
        .map(|m| {
            let mut member = Map::new();
            member.insert("value".into(), m.value.clone().into());
            put(&mut member, "display", &m.display);
            Value::Object(member)
        })
        .collect();
    let mut object = Map::new();
    object.insert("schemas".into(), json!([GROUP_SCHEMA]));
    object.insert("id".into(), group.id.clone().into());
    object.insert("displayName".into(), group.display_name.clone().into());
    object.insert("members".into(), members.into());
    if let Some(meta) = &group.meta {
        object.insert("meta".into(), meta_json(meta));
    }
    Value::Object(object)
}

/// The service provider configuration (RFC 7643 §5).
fn service_provider_config_json(config: &proto::ScimServiceProviderConfig) -> Value {
    let supported = |support: &Option<proto::ScimConfigSupport>| json!({ "supported": support.as_ref().is_some_and(|s| s.supported) });
    let bulk = config.bulk.unwrap_or_default();
    let schemes: Vec<Value> = config
        .authentication_schemes
        .iter()
        .map(|scheme| {
            let mut object = Map::new();
            object.insert("type".into(), scheme.r#type.clone().into());
            object.insert("name".into(), scheme.name.clone().into());
            object.insert("description".into(), scheme.description.clone().into());
            put(&mut object, "specUri", &scheme.spec_uri);
            put(&mut object, "documentationUri", &scheme.documentation_uri);
            object.insert("primary".into(), scheme.primary.into());
            Value::Object(object)
        })
        .collect();
    let mut object = Map::new();
    object.insert("schemas".into(), json!([SERVICE_PROVIDER_CONFIG_SCHEMA]));
    put(&mut object, "documentationUri", &config.documentation_uri);
    object.insert("patch".into(), supported(&config.patch));
    object.insert(
        "bulk".into(),
        json!({
            "supported": bulk.supported,
            "maxOperations": bulk.max_operations,
            "maxPayloadSize": bulk.max_payload_size,
        }),
    );
    object.insert(
        "filter".into(),
        json!({
            "supported": config.filter.as_ref().is_some_and(|f| f.supported),
            "maxResults": config.max_results,
        }),
    );
    object.insert("changePassword".into(), supported(&config.change_password));
    object.insert("sort".into(), supported(&config.sort));
    object.insert("etag".into(), supported(&config.etag));
    object.insert("authenticationSchemes".into(), schemes.into());
    if let Some(meta) = &config.meta {
        object.insert("meta".into(), meta_json(meta));
    }
    Value::Object(object)
}

/// A resource type (RFC 7643 §6).
fn resource_type_json(resource_type: &proto::ScimResourceType) -> Value {
    let mut object = Map::new();
    object.insert("schemas".into(), json!([RESOURCE_TYPE_SCHEMA]));
    object.insert("id".into(), resource_type.id.clone().into());
    object.insert("name".into(), resource_type.name.clone().into());
    put(&mut object, "description", &resource_type.description);
    object.insert("endpoint".into(), resource_type.endpoint.clone().into());
    object.insert("schema".into(), resource_type.schema.clone().into());
    if let Some(meta) = &resource_type.meta {
        object.insert("meta".into(), meta_json(meta));
    }
    Value::Object(object)
}

/// A schema (RFC 7643 §7).
fn schema_json(schema: &proto::ScimSchema) -> Value {
    let mut object = Map::new();
    object.insert("schemas".into(), json!([SCHEMA_SCHEMA]));
    object.insert("id".into(), schema.id.clone().into());
    object.insert("name".into(), schema.name.clone().into());
    put(&mut object, "description", &schema.description);
    let attributes: Vec<Value> = schema.attributes.iter().map(attribute_json).collect();
    object.insert("attributes".into(), attributes.into());
    if let Some(meta) = &schema.meta {
        object.insert("meta".into(), meta_json(meta));
    }
    Value::Object(object)
}

/// A schema attribute (RFC 7643 §7).
fn attribute_json(attribute: &proto::ScimSchemaAttribute) -> Value {
    let mut object = Map::new();
    object.insert("name".into(), attribute.name.clone().into());
    object.insert("type".into(), attribute.r#type.clone().into());
    object.insert("multiValued".into(), attribute.multi_valued.into());
    put(&mut object, "description", &attribute.description);
    object.insert("required".into(), attribute.required.into());
    object.insert("caseExact".into(), attribute.case_exact.into());
    put(&mut object, "mutability", &attribute.mutability);
    put(&mut object, "returned", &attribute.returned);
    put(&mut object, "uniqueness", &attribute.uniqueness);
    if !attribute.sub_attributes.is_empty() {
        let sub: Vec<Value> = attribute
            .sub_attributes
            .iter()
            .map(attribute_json)
            .collect();
        object.insert("subAttributes".into(), sub.into());
    }
    Value::Object(object)
}

/// An answer with `status` and the SCIM JSON `body` (RFC 7644 §3.1).
fn scim_json(status: u16, body: &Value) -> Response<HttpBody> {
    raw(status, SCIM_JSON, body.to_string().into_bytes())
}

/// 201 with the created resource and its `Location` (RFC 7644 §3.3).
fn created(resource: Value) -> Response<HttpBody> {
    let location = resource["meta"]["location"].as_str().map(str::to_owned);
    let mut response = scim_json(201, &resource);
    if let Some(location) = location.and_then(|l| l.parse().ok()) {
        response.metadata_mut().insert("location", location);
    }
    response
}

/// 204 with no body (RFC 7644 §3.6).
fn no_content() -> Response<HttpBody> {
    raw(204, "", Vec::new())
}

fn raw(status: u16, content_type: &str, data: Vec<u8>) -> Response<HttpBody> {
    let mut response = Response::new(HttpBody {
        content_type: content_type.to_owned(),
        data,
        extensions: Vec::new(),
    });
    response
        .metadata_mut()
        .insert("x-http-code", MetadataValue::from(u32::from(status)));
    response
}

/// The RFC 7644 §3.12 error response with `status`, `scim_type` and
/// `detail`.
fn scim_error(status: u16, scim_type: Option<&str>, detail: &str) -> Response<HttpBody> {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        // RFC 7644 §3.12: the status code as a string.
        "status": status.to_string(),
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = scim_type.into();
    }
    if !detail.is_empty() {
        body["detail"] = detail.into();
    }
    scim_json(status, &body)
}

/// A body that is not a SCIM request: `invalidSyntax` (RFC 7644 §3.12).
fn invalid_syntax(detail: &str) -> Refused {
    Refused {
        scim_type: "invalidSyntax",
        detail: detail.into(),
    }
}

/// An attribute whose value has the wrong JSON type: `invalidValue`
/// (RFC 7644 §3.12). The value itself is not repeated.
fn invalid_value(attribute: &str) -> Refused {
    Refused {
        scim_type: "invalidValue",
        detail: format!("{attribute} has a value of the wrong type"),
    }
}

/// Whether the request presents a bearer token (RFC 6750 §2.1).
fn bearer_presented(metadata: &MetadataMap) -> bool {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
}

/// The HTTP answer to a refusal of the typed operation (RFC 7644 §3.12): the
/// status its code stands for, the `scimType` its ErrorInfo names. An
/// authentication failure is 401 with a `Bearer` challenge, naming
/// `invalid_token` when a token was presented (RFC 6750 §3, §3.1); a
/// server-side condition says when to retry when the refusal does
/// (RFC 9110 §10.2.3) and never describes itself.
pub fn refusal(status: &Status, token_presented: bool) -> Response<HttpBody> {
    let scim_type = extract_error_info(status).and_then(|(_, _, mut m)| m.remove(SCIM_TYPE));
    let code = match status.code() {
        Code::Unauthenticated => 401,
        Code::PermissionDenied => 403,
        Code::NotFound => 404,
        Code::AlreadyExists | Code::Aborted => 409,
        Code::InvalidArgument | Code::OutOfRange | Code::FailedPrecondition => 400,
        Code::ResourceExhausted => 429,
        Code::Unimplemented => 501,
        Code::Unavailable => 503,
        _ => 500,
    };
    let detail = if code >= 500 { "" } else { status.message() };
    let mut response = scim_error(code, scim_type.as_deref(), detail);
    let metadata = response.metadata_mut();
    if code == 401 {
        metadata.insert(
            "www-authenticate",
            MetadataValue::from_static(if token_presented {
                r#"Bearer error="invalid_token""#
            } else {
                "Bearer"
            }),
        );
    }
    if let Some(delay) = extract_retry_delay(status) {
        let seconds = delay.as_secs() + u64::from(delay.subsec_nanos() > 0);
        metadata.insert("retry-after", MetadataValue::from(seconds));
    }
    response
}

#[cfg(test)]
mod tests;
