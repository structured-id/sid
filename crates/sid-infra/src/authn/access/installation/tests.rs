use super::*;
use crate::authn::access::{CredentialKind, PermissionTarget};

const LIST: &str = "/acme.v1.Orders/ListOrders";
const SHIP: &str = "/acme.v1.Orders/ShipOrder";
const CANCEL: &str = "/acme.v1.Orders/CancelOrder";
const STATUS: &str = "/acme.v1.Orders/Status";
const MINE: &str = "/acme.v1.Orders/MyOrders";
const AUDIT: &str = "/acme.v1.Audit/ReadAudit";

fn permission(action: &str) -> Option<Permission> {
    Some(Permission {
        action: action.to_owned(),
        target: PermissionTarget::Resource,
    })
}

/// Orders: a read and a write scope, permissions per action, an open status,
/// a method only for the caller's own session, and a handler-decided audit.
fn rules() -> AccessRules {
    let mut rules = AccessRules::default();
    let delegated = [CredentialKind::Delegated];
    rules.insert(
        LIST,
        AccessRule::protected(&delegated, &["orders.read"], permission("orders.list")),
    );
    rules.insert(
        SHIP,
        AccessRule::protected(&delegated, &["orders.write"], permission("orders.ship")),
    );
    rules.insert(
        CANCEL,
        AccessRule::protected(&delegated, &["orders.write"], permission("orders.cancel")),
    );
    rules.insert(STATUS, AccessRule::Open);
    rules.insert(
        MINE,
        AccessRule::protected(&[CredentialKind::OwnSession], &[], None),
    );
    rules.insert(
        AUDIT,
        AccessRule::protected(&delegated, &["audit.read"], None),
    );
    rules
}

fn seed(json: serde_json::Value) -> Seed {
    serde_json::from_value(json).expect("a seed")
}

fn refused(json: serde_json::Value) -> String {
    seed(json).resolve(&rules()).expect_err("refused")
}

// The vocabulary is every scope the services' protected methods declare,
// once and sorted; open and own-session methods add none.
#[test]
fn a_resource_has_the_scopes_its_services_declare() {
    let input = seed(serde_json::json!({
        "resources": [{
            "key": "orders",
            "name": "Orders API",
            "services": ["acme.v1.Orders", "acme.v1.Audit"]
        }]
    }))
    .resolve(&rules())
    .unwrap();
    assert_eq!(
        input.resources,
        [ResourceVocabulary {
            key: "orders".into(),
            name: "Orders API".into(),
            scopes: vec![
                "audit.read".into(),
                "orders.read".into(),
                "orders.write".into()
            ],
        }]
    );
}

// A role's permissions are its methods' declared actions plus the ones no
// method declares, sorted; a role with none carries only administration.
#[test]
fn a_role_has_the_actions_of_its_methods() {
    let input = seed(serde_json::json!({
        "roles": [
            {
                "key": "shipper",
                "name": "Shipper",
                "description": "Ships orders",
                "methods": [SHIP, LIST],
                "permissions": ["orders.export"]
            },
            {"key": "administration", "name": "Administration"}
        ]
    }))
    .resolve(&rules())
    .unwrap();
    assert_eq!(
        input.roles,
        [
            RoleDefinition {
                key: "administration".into(),
                name: "Administration".into(),
                description: None,
                permissions: vec![],
            },
            RoleDefinition {
                key: "shipper".into(),
                name: "Shipper".into(),
                description: Some("Ships orders".into()),
                permissions: vec![
                    "orders.export".into(),
                    "orders.list".into(),
                    "orders.ship".into(),
                ],
            },
        ]
    );
}

// A requirement asks for the scopes of the methods its integration calls,
// once each.
#[test]
fn a_requirement_has_the_scopes_of_its_methods() {
    let input = seed(serde_json::json!({
        "requirements": [{
            "key": "fulfilment",
            "resource": "orders",
            "methods": [SHIP, CANCEL, LIST]
        }]
    }))
    .resolve(&rules())
    .unwrap();
    assert_eq!(
        input.requirements,
        [Requirement {
            key: "fulfilment".into(),
            resource: "orders".into(),
            scopes: vec!["orders.read".into(), "orders.write".into()],
        }]
    );
}

// The same seed resolves to the same input, whatever order it lists things
// in: an applied installation item compares by content.
#[test]
fn the_input_does_not_depend_on_the_seed_order() {
    let a = seed(serde_json::json!({
        "roles": [
            {"key": "b", "name": "B", "methods": [SHIP, LIST]},
            {"key": "a", "name": "A", "methods": [LIST]}
        ],
        "requirements": [{"key": "r", "resource": "orders", "methods": [SHIP, LIST]}]
    }))
    .resolve(&rules())
    .unwrap();
    let b = seed(serde_json::json!({
        "roles": [
            {"key": "a", "name": "A", "methods": [LIST]},
            {"key": "b", "name": "B", "methods": [LIST, SHIP]}
        ],
        "requirements": [{"key": "r", "resource": "orders", "methods": [LIST, SHIP]}]
    }))
    .resolve(&rules())
    .unwrap();
    assert_eq!(a, b);
}

// Names the schema does not declare, and methods that cannot carry what
// they are listed for, fail the seed instead of widening or narrowing it.
#[test]
fn what_the_schema_does_not_declare_fails_the_seed() {
    assert!(
        refused(serde_json::json!({
            "resources": [{"key": "x", "name": "X", "services": ["acme.v1.Missing"]}]
        }))
        .contains("no service acme.v1.Missing")
    );
    assert!(
        refused(serde_json::json!({
            "roles": [{"key": "r", "name": "R", "methods": ["/acme.v1.Orders/Missing"]}]
        }))
        .contains("no method /acme.v1.Orders/Missing")
    );
    assert!(
        refused(serde_json::json!({
            "roles": [{"key": "r", "name": "R", "methods": [STATUS]}]
        }))
        .contains("is open")
    );
    assert!(
        refused(serde_json::json!({
            "roles": [{"key": "r", "name": "R", "methods": [AUDIT]}]
        }))
        .contains("declares no receiver permission")
    );
    assert!(
        refused(serde_json::json!({
            "requirements": [{"key": "q", "resource": "orders", "methods": [STATUS]}]
        }))
        .contains("is open")
    );
    assert!(
        refused(serde_json::json!({
            "requirements": [{"key": "q", "resource": "orders", "methods": [MINE]}]
        }))
        .contains("only the caller's own session")
    );
    assert!(
        refused(serde_json::json!({
            "requirements": [{"key": "q", "resource": "orders", "methods": []}]
        }))
        .contains("names no method")
    );
}

// A method only the caller's own session calls is no integration's, even
// when it declares scopes: no token reaches it, whatever it carries. Bug
// prevented: such a method was read as callable because its scope list was
// not empty, and the requirement asked for scopes that admit nothing.
#[test]
fn an_own_session_method_with_scopes_is_no_requirement() {
    let mut rules = rules();
    let profile = "/acme.v1.Orders/MyProfile";
    rules.insert(
        profile,
        AccessRule::protected(&[CredentialKind::OwnSession], &["profile.read"], None),
    );
    let why = seed(serde_json::json!({
        "requirements": [{"key": "q", "resource": "orders", "methods": [profile]}]
    }))
    .resolve(&rules)
    .expect_err("refused");
    assert!(why.contains("only the caller's own session"), "{why}");
}

// A resource whose services declare no scope offers nothing to request.
#[test]
fn a_resource_without_scopes_fails_the_seed() {
    let mut rules = AccessRules::default();
    rules.insert("/acme.v1.Public/Ping", AccessRule::Open);
    let why = seed(serde_json::json!({
        "resources": [{"key": "p", "name": "P", "services": ["acme.v1.Public"]}]
    }))
    .resolve(&rules)
    .expect_err("refused");
    assert!(why.contains("declare no scope"), "{why}");
}

// The input is what an installation reads back: it round-trips, and a field
// the format does not know is refused rather than ignored.
#[test]
fn the_input_round_trips_and_refuses_unknown_fields() {
    let input = seed(serde_json::json!({
        "resources": [{"key": "orders", "name": "Orders", "services": ["acme.v1.Orders"]}],
        "roles": [{"key": "a", "name": "A", "methods": [LIST]}],
        "requirements": [{"key": "r", "resource": "orders", "methods": [LIST]}]
    }))
    .resolve(&rules())
    .unwrap();
    let text = serde_json::to_string(&input).unwrap();
    assert_eq!(
        serde_json::from_str::<InstallationInput>(&text).unwrap(),
        input
    );
    assert!(
        serde_json::from_value::<InstallationInput>(serde_json::json!({"grants": []})).is_err()
    );
}
