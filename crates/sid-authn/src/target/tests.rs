use super::*;
use chrono::{SubsecRound, Utc};
use sid_core::models::{
    Application, ApplicationId, AuditEntry, IssuerAuthority, IssuerHandle, IssuerSigningKey,
    MutationContext, OAuth2Client, OidcIssuer, Organization, ProjectId, ProtectedResource,
    ResourceAccess, ResourceId, ResourceState,
};
use sid_storage::sqlite::SqliteBackend;

fn ctx() -> MutationContext {
    AuditEntry::system("test", "target").into()
}

fn indicator(path: &str) -> ResourceIndicator {
    ResourceIndicator::parse(&format!("https://resources.example/{path}")).unwrap()
}

/// A store with the installation's issuer, an Orders and a Wiki resource,
/// and a client with access to Orders only.
struct Fixture {
    storage: SqliteBackend,
    issuer: IssuerId,
    orders: ProtectedResource,
    wiki: ProtectedResource,
    client: OAuth2Client,
}

async fn fixture() -> Fixture {
    let storage = SqliteBackend::new_in_memory().await.unwrap();
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let now = Utc::now().trunc_subsecs(3);
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org.id,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: issuer.id,
        generation: 1,
        key_id: "kid".into(),
        public_key: [1; 32],
        sealed_private_key: vec![1],
        created_at: now,
    };
    storage
        .insert_oidc_issuer(&issuer, &key, ctx())
        .await
        .unwrap();

    let app = |name: &str| Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::system(),
        name: name.into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = |app: &Application, path: &str| ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: indicator(path),
        scopes: vec!["read".into(), "write".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let orders_app = app("Orders");
    let orders = resource(&orders_app, "orders");
    storage
        .create_application(&orders_app, None, Some(&orders), ctx())
        .await
        .unwrap();
    let wiki_app = app("Wiki");
    let wiki = resource(&wiki_app, "wiki");
    storage
        .create_application(&wiki_app, None, Some(&wiki), ctx())
        .await
        .unwrap();

    let web_app = app("Web");
    let client = crate::test_support::client_of(&web_app, org.id);
    storage
        .create_application(&web_app, Some(&client), None, ctx())
        .await
        .unwrap();
    storage
        .set_resource_access(
            &ResourceAccess {
                client_id: client.client_id.clone(),
                resource_id: orders.id,
                scopes: vec!["read".into()],
                created_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    Fixture {
        storage,
        issuer: issuer.id,
        orders,
        wiki,
        client,
    }
}

// --- requested_indicator (RFC 8707 §2) --------------------------------------

#[test]
fn no_resource_parameter_names_no_target() {
    assert_eq!(requested_indicator(&[]), Ok(None));
}

#[test]
fn a_repeated_identical_resource_is_one_target() {
    // RFC 8707 §2: repeated identical values do not make a second target.
    let orders = "https://resources.example/orders".to_string();
    assert_eq!(
        requested_indicator(&[orders.clone(), orders]),
        Ok(Some(indicator("orders")))
    );
}

#[test]
fn several_distinct_resources_are_refused() {
    // SID issues a token for one resource; several targets need several
    // tokens (target isolation).
    assert_eq!(
        requested_indicator(&[
            "https://resources.example/orders".into(),
            "https://resources.example/wiki".into(),
        ]),
        Err(TargetRefusal::Several)
    );
}

#[test]
fn a_malformed_resource_is_refused() {
    for bad in ["/orders", "https://resources.example/orders#x", ""] {
        assert!(
            matches!(
                requested_indicator(&[bad.to_string()]),
                Err(TargetRefusal::Malformed(_))
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn every_refusal_is_invalid_target() {
    // RFC 8707 §2: invalid_target for an invalid, unknown or unpermitted target.
    for refusal in [
        TargetRefusal::Several,
        TargetRefusal::Malformed("x".into()),
        TargetRefusal::Unknown,
        TargetRefusal::Inactive,
        TargetRefusal::NotPermitted,
        TargetRefusal::NoneNamed,
        TargetRefusal::Different,
        TargetRefusal::Conflicting,
        TargetRefusal::NotExchangeable,
    ] {
        assert_eq!(refusal.oauth_error(), "invalid_target");
    }
}

// --- exchange_indicator (RFC 8693 §2.1) -------------------------------------

#[test]
fn an_exchange_names_its_target_by_resource_or_audience() {
    let orders = "https://resources.example/orders".to_string();
    assert_eq!(exchange_indicator(&[], &[]), Ok(None));
    assert_eq!(
        exchange_indicator(std::slice::from_ref(&orders), &[]),
        Ok(Some(indicator("orders")))
    );
    assert_eq!(
        exchange_indicator(&[], std::slice::from_ref(&orders)),
        Ok(Some(indicator("orders")))
    );
    assert_eq!(
        exchange_indicator(std::slice::from_ref(&orders), std::slice::from_ref(&orders)),
        Ok(Some(indicator("orders")))
    );
}

#[test]
fn an_exchange_naming_different_targets_is_refused() {
    let orders = "https://resources.example/orders".to_string();
    let wiki = "https://resources.example/wiki".to_string();
    assert_eq!(
        exchange_indicator(std::slice::from_ref(&orders), std::slice::from_ref(&wiki)),
        Err(TargetRefusal::Conflicting)
    );
    assert_eq!(
        exchange_indicator(&[], &[orders, wiki]),
        Err(TargetRefusal::Several)
    );
    assert!(matches!(
        exchange_indicator(&[], &["orders-api".to_string()]),
        Err(TargetRefusal::Malformed(_))
    ));
}

// --- select_target ----------------------------------------------------------

#[tokio::test]
async fn a_permitted_resource_is_the_target() {
    let f = fixture().await;
    let target = select_target(&f.storage, f.issuer, &f.client, Some(&f.orders.indicator))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.audience(), &f.orders.indicator);
    assert_eq!(target.resource_id(), f.orders.id);
    // Only scopes the access grants and the resource supports.
    assert_eq!(
        target.granted_scopes(&["read".into(), "write".into(), "openid".into()]),
        vec!["read".to_string()]
    );
}

#[tokio::test]
async fn an_unknown_or_unpermitted_resource_is_refused() {
    let f = fixture().await;
    assert_eq!(
        select_target(&f.storage, f.issuer, &f.client, Some(&indicator("nowhere")))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::Unknown
    );
    // Wiki exists in the same issuer and project, but this client has no
    // access to it: sharing an issuer grants nothing.
    assert_eq!(
        select_target(&f.storage, f.issuer, &f.client, Some(&f.wiki.indicator))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
    // Another issuer's registry does not name this resource.
    assert_eq!(
        select_target(
            &f.storage,
            IssuerId::generate(),
            &f.client,
            Some(&f.orders.indicator)
        )
        .await
        .unwrap()
        .unwrap_err(),
        TargetRefusal::Unknown
    );
}

#[tokio::test]
async fn an_inactive_resource_is_refused() {
    let f = fixture().await;
    let mut inactive = f.orders.clone();
    inactive.state = ResourceState::Inactive;
    assert!(
        f.storage
            .update_protected_resource(&inactive, ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        select_target(&f.storage, f.issuer, &f.client, Some(&f.orders.indicator))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::Inactive
    );
}

/// A connector's only target is its directory resource: named or not, the
/// token is for it; any other resource of the issuer, or the directory of
/// another issuer, is refused, as is an inactive directory.
#[tokio::test]
async fn a_connector_targets_only_its_directory() {
    let f = fixture().await;
    let directory = &f.orders.indicator;
    for requested in [None, Some(directory)] {
        let target = connector_target(&f.storage, f.issuer, directory, requested)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(target.id, f.orders.id);
    }
    assert_eq!(
        connector_target(&f.storage, f.issuer, directory, Some(&f.wiki.indicator))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
    assert_eq!(
        connector_target(&f.storage, IssuerId::generate(), directory, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::Unknown
    );
    let mut inactive = f.orders.clone();
    inactive.state = ResourceState::Inactive;
    assert!(
        f.storage
            .update_protected_resource(&inactive, ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        connector_target(&f.storage, f.issuer, directory, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::Inactive
    );
}

#[tokio::test]
async fn no_resource_uses_only_an_explicit_permitted_default() {
    let f = fixture().await;
    // Without a default nothing is substituted: not the client id, not the
    // issuer, not the first resource found.
    assert_eq!(
        select_target(&f.storage, f.issuer, &f.client, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NoneNamed
    );

    let mut with_default = f.client.clone();
    with_default.default_resource = Some(f.orders.id);
    let target = select_target(&f.storage, f.issuer, &with_default, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.audience(), &f.orders.indicator);

    // A default the client has no access to is not used.
    with_default.default_resource = Some(f.wiki.id);
    assert_eq!(
        select_target(&f.storage, f.issuer, &with_default, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
}

#[tokio::test]
async fn revoked_access_stops_further_issuance() {
    let f = fixture().await;
    assert!(
        f.storage
            .remove_resource_access(&f.client.client_id, f.orders.id, ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        select_target(&f.storage, f.issuer, &f.client, Some(&f.orders.indicator))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
}

#[tokio::test]
async fn a_machine_user_names_its_target() {
    use sid_core::models::MachineUser;
    use sid_core::models::machine_user::OwnerType;
    let f = fixture().await;
    let ci = MachineUser::new(
        ProjectId::system(),
        "ci".to_string(),
        "CI",
        OwnerType::System,
        "system",
    );
    f.storage.create_machine_user(&ci, ctx()).await.unwrap();

    // Without access the resource is refused; a machine user has no default.
    assert_eq!(
        select_target(&f.storage, f.issuer, &ci, Some(&f.orders.indicator))
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
    f.storage
        .set_resource_access(
            &ResourceAccess {
                client_id: ci.client_id.clone(),
                resource_id: f.orders.id,
                scopes: vec!["write".into()],
                created_at: Utc::now().trunc_subsecs(3),
            },
            ctx(),
        )
        .await
        .unwrap();
    assert_eq!(
        select_target(&f.storage, f.issuer, &ci, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NoneNamed
    );
    let target = select_target(&f.storage, f.issuer, &ci, Some(&f.orders.indicator))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.audience(), &f.orders.indicator);
    assert_eq!(
        target.granted_scopes(&["read".into(), "write".into()]),
        vec!["write".to_string()]
    );
}

// --- resume_target (code, refresh, device) ----------------------------------

#[tokio::test]
async fn a_bound_target_cannot_be_substituted() {
    let f = fixture().await;
    // Redemption and refresh keep the target the grant was issued for; the
    // same indicator again is accepted, another one is refused.
    let target = resume_target(&f.storage, f.issuer, &f.client, f.orders.id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.audience(), &f.orders.indicator);
    assert!(
        resume_target(
            &f.storage,
            f.issuer,
            &f.client,
            f.orders.id,
            Some(&f.orders.indicator)
        )
        .await
        .unwrap()
        .is_ok()
    );
    assert_eq!(
        resume_target(
            &f.storage,
            f.issuer,
            &f.client,
            f.orders.id,
            Some(&f.wiki.indicator)
        )
        .await
        .unwrap()
        .unwrap_err(),
        TargetRefusal::Different
    );
}

#[tokio::test]
async fn a_bound_target_follows_the_registry() {
    let f = fixture().await;
    // Access removed or the resource retired after the grant: no new token.
    f.storage
        .remove_resource_access(&f.client.client_id, f.orders.id, ctx())
        .await
        .unwrap();
    assert_eq!(
        resume_target(&f.storage, f.issuer, &f.client, f.orders.id, None)
            .await
            .unwrap()
            .unwrap_err(),
        TargetRefusal::NotPermitted
    );
    assert_eq!(
        resume_target(
            &f.storage,
            f.issuer,
            &f.client,
            ResourceId::generate(),
            None
        )
        .await
        .unwrap()
        .unwrap_err(),
        TargetRefusal::Unknown
    );
}
