// SPDX-License-Identifier: AGPL-3.0-only
//! Applications and their roles: a client role, a protected-resource role or
//! both, stored together; resource indicators reserved for ever within their
//! issuer; explicit client-to-resource access.

use super::{create_test_oauth2_client, instance_org, test_audit};
use chrono::{SubsecRound, Utc};
use sid_core::Error as SidError;
use sid_core::models::{
    Application, ApplicationId, IssuerAuthority, IssuerHandle, IssuerId, IssuerSigningKey,
    OAuth2Client, OidcIssuer, Project, ProjectId, ProtectedResource, ResourceAccess, ResourceId,
    ResourceIndicator, ResourceState,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

/// The installation organization's local issuer, provisioned on first use.
pub async fn instance_issuer(backend: &dyn StorageBackend) -> IssuerId {
    let org = instance_org(backend).await;
    let now = Utc::now().trunc_subsecs(3);
    let id = IssuerId::generate();
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id,
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: id,
        generation: 1,
        key_id: format!("kid-{id}"),
        public_key: [7; 32],
        sealed_private_key: vec![1, 2, 3],
        created_at: now,
    };
    backend
        .insert_oidc_issuer(&issuer, &key, test_audit())
        .await
        .unwrap();
    backend
        .oidc_issuer_for(IssuerAuthority::Local, org)
        .await
        .unwrap()
        .unwrap()
        .id
}

/// A new application in `project`, stored at millisecond precision so what is
/// read back equals it exactly.
pub fn application(project_id: ProjectId, name: &str) -> Application {
    let now = Utc::now().trunc_subsecs(3);
    Application {
        id: ApplicationId::generate(),
        project_id,
        name: name.to_owned(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// The application a test client names, in its project.
pub fn application_of(client: &OAuth2Client) -> Application {
    let now = Utc::now().trunc_subsecs(3);
    Application {
        id: client.application_id,
        project_id: client.project_id,
        name: client.client_name.clone(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// Store `client` with an application of its own.
pub async fn store_client(
    backend: &dyn StorageBackend,
    client: &OAuth2Client,
    ctx: sid_core::models::MutationContext,
) -> sid_core::Result<()> {
    backend
        .create_application(&application_of(client), Some(client), None, ctx)
        .await
}

fn unique_indicator() -> ResourceIndicator {
    ResourceIndicator::parse(&format!(
        "https://resources.example/{}",
        Uuid::now_v7().simple()
    ))
    .unwrap()
}

pub fn resource(app: &Application, issuer: IssuerId) -> ProtectedResource {
    let now = Utc::now().trunc_subsecs(3);
    ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer,
        indicator: unique_indicator(),
        scopes: vec!["orders.read".into(), "orders.write".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

/// A registered resource of the installation's issuer, the target a test
/// grant (code, refresh token, device code) is issued for.
pub async fn grant_resource(backend: &dyn StorageBackend) -> ResourceId {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let app = application(project, "Grant target");
    let target = resource(&app, issuer);
    backend
        .create_application(&app, None, Some(&target), test_audit())
        .await
        .unwrap();
    target.id
}

fn client_of(app: &Application) -> OAuth2Client {
    let mut client = create_test_oauth2_client(&format!("app-{}", Uuid::now_v7().simple()));
    client.application_id = app.id;
    client.project_id = app.project_id;
    client
}

fn access(client: &OAuth2Client, resource: &ProtectedResource, scopes: &[&str]) -> ResourceAccess {
    ResourceAccess {
        client_id: client.client_id.clone(),
        resource_id: resource.id,
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        created_at: Utc::now().trunc_subsecs(3),
    }
}

async fn system_project(backend: &dyn StorageBackend) -> ProjectId {
    backend.ensure_system_project(test_audit()).await.unwrap();
    ProjectId::system()
}

fn is_conflict<T: std::fmt::Debug>(result: sid_core::Result<T>) -> bool {
    matches!(result, Err(SidError::Conflict(_)))
}

/// An application is stored with the roles it starts with, all or nothing.
pub async fn test_application_roles_are_stored_together(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;

    // Both roles.
    let app = application(project, "Orders");
    let client = client_of(&app);
    let api = resource(&app, issuer);
    backend
        .create_application(&app, Some(&client), Some(&api), test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend.get_application(app.id).await.unwrap(),
        Some(app.clone())
    );
    let stored_client = backend
        .oauth2_client_of_application(app.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_client.client_id, client.client_id);
    assert_eq!(stored_client.application_id, app.id);
    assert_eq!(
        backend
            .protected_resource_of_application(app.id)
            .await
            .unwrap(),
        Some(api.clone())
    );
    assert_eq!(
        backend.get_protected_resource(api.id).await.unwrap(),
        Some(api.clone())
    );
    assert_eq!(
        backend
            .protected_resource_by_indicator(issuer, &api.indicator)
            .await
            .unwrap(),
        Some(api.clone())
    );

    // Resource only: no client, no secret, no callback.
    let resource_only = application(project, "Wiki API");
    let wiki = resource(&resource_only, issuer);
    backend
        .create_application(&resource_only, None, Some(&wiki), test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .oauth2_client_of_application(resource_only.id)
            .await
            .unwrap()
            .is_none()
    );

    // An indicator already registered under the issuer refuses the whole
    // application: neither it nor its client is stored.
    let clash = application(project, "Clash");
    let clash_client = client_of(&clash);
    let mut clash_resource = resource(&clash, issuer);
    clash_resource.indicator = api.indicator.clone();
    assert!(is_conflict(
        backend
            .create_application(
                &clash,
                Some(&clash_client),
                Some(&clash_resource),
                test_audit()
            )
            .await
    ));
    assert!(backend.get_application(clash.id).await.unwrap().is_none());
    assert!(
        backend
            .get_oauth2_client(&clash_client.client_id)
            .await
            .unwrap()
            .is_none()
    );

    // A role naming another application is refused and stores nothing.
    let stray = application(project, "Stray");
    let foreign_role = resource(&app, issuer);
    assert!(
        backend
            .create_application(&stray, None, Some(&foreign_role), test_audit())
            .await
            .is_err()
    );
    assert!(backend.get_application(stray.id).await.unwrap().is_none());

    // One role of each kind per application.
    assert!(is_conflict(
        backend
            .create_protected_resource(&resource(&app, issuer), test_audit())
            .await
    ));
    assert!(is_conflict(
        backend
            .create_oauth2_client(&client_of(&app), test_audit())
            .await
    ));

    // A client role added later to a resource-only application.
    let wiki_client = client_of(&resource_only);
    backend
        .create_oauth2_client(&wiki_client, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .oauth2_client_of_application(resource_only.id)
            .await
            .unwrap()
            .unwrap()
            .client_id,
        wiki_client.client_id
    );

    // A role of an application that does not exist, or in another project
    // than its application, is refused.
    let orphan = client_of(&application(project, "Ghost"));
    assert!(
        backend
            .create_oauth2_client(&orphan, test_audit())
            .await
            .is_err()
    );
    let other = Project::new("Other", None);
    backend.create_project(&other, test_audit()).await.unwrap();
    let elsewhere = application(other.id, "Elsewhere");
    backend
        .create_application(&elsewhere, None, None, test_audit())
        .await
        .unwrap();
    let mut misplaced = client_of(&elsewhere);
    misplaced.project_id = project;
    assert!(
        backend
            .create_oauth2_client(&misplaced, test_audit())
            .await
            .is_err()
    );
    assert!(
        backend
            .get_oauth2_client(&misplaced.client_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Concurrent registrations of one indicator: exactly one resource is stored.
pub async fn test_concurrent_indicator_registration(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let (a, b) = (application(project, "A"), application(project, "B"));
    let ra = resource(&a, issuer);
    let mut rb = resource(&b, issuer);
    rb.indicator = ra.indicator.clone();
    let (first, second) = tokio::join!(
        backend.create_application(&a, None, Some(&ra), test_audit()),
        backend.create_application(&b, None, Some(&rb), test_audit()),
    );
    assert!(first.is_ok() ^ second.is_ok(), "{first:?} {second:?}");
    let loser = if first.is_ok() { &b } else { &a };
    assert!(backend.get_application(loser.id).await.unwrap().is_none());
}

/// A system integration exists once: of replicas provisioning it together at
/// most one succeeds, every other gets `Conflict`, and all of them then read
/// the one that was stored. The database may already hold it from an earlier
/// provisioning, in which case both attempts conflict.
pub async fn test_system_integration_exists_once(backend: &dyn StorageBackend) {
    use sid_core::models::SystemIntegration;
    let project = system_project(backend).await;
    let mut a = application(project, "Account A");
    a.system = Some(SystemIntegration::Account);
    let mut b = application(project, "Account B");
    b.system = Some(SystemIntegration::Account);
    let (first, second) = tokio::join!(
        backend.create_application(&a, None, None, test_audit()),
        backend.create_application(&b, None, None, test_audit()),
    );
    for result in [&first, &second] {
        assert!(
            matches!(result, Ok(()) | Err(SidError::Conflict(_))),
            "{result:?}"
        );
    }
    assert!(
        !(first.is_ok() && second.is_ok()),
        "two system integrations"
    );
    let stored = backend
        .system_application(SystemIntegration::Account)
        .await
        .unwrap()
        .expect("the integration is stored");
    assert_eq!(stored.system, Some(SystemIntegration::Account));
    if first.is_ok() {
        assert_eq!(stored, a);
    }
    if second.is_ok() {
        assert_eq!(stored, b);
    }
    // An administrator's application is no integration.
    let plain = application(project, "Plain");
    backend
        .create_application(&plain, None, None, test_audit())
        .await
        .unwrap();
    let read = backend.get_application(plain.id).await.unwrap().unwrap();
    assert_eq!(read.system, None);
}

/// An application's name is updated over the revision it was read at.
pub async fn test_application_update_and_list(backend: &dyn StorageBackend) {
    let project = Project::new(format!("apps-{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let first = application(project.id, "First");
    let second = application(project.id, "Second");
    for app in [&first, &second] {
        backend
            .create_application(app, None, None, test_audit())
            .await
            .unwrap();
    }
    let listed = backend
        .list_applications_by_project(project.id, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![first.id, second.id]
    );
    assert_eq!(
        backend
            .list_applications_by_project(project.id, 1, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let mut renamed = first.clone();
    renamed.name = "Renamed".into();
    renamed.updated_at = Utc::now().trunc_subsecs(3);
    assert!(
        backend
            .update_application(&renamed, test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_application(first.id).await.unwrap().unwrap();
    assert_eq!(stored.name, "Renamed");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.created_at, first.created_at);
    // A write over a stale revision applies nothing.
    renamed.name = "Stale".into();
    assert!(
        !backend
            .update_application(&renamed, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend
            .get_application(first.id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "Renamed"
    );
    // The project never changes through an update.
    let mut moved = stored.clone();
    moved.project_id = ProjectId::system();
    assert!(
        !backend
            .update_application(&moved, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .update_application(&application(project.id, "Ghost"), test_audit())
            .await
            .unwrap()
    );
}

/// A resource's scopes and state change over its revision; it is retired
/// only with its application and its indicator is never registered again.
pub async fn test_resource_update_and_retirement(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let app = application(project, "Orders");
    let client = client_of(&app);
    let api = resource(&app, issuer);
    backend
        .create_application(&app, Some(&client), Some(&api), test_audit())
        .await
        .unwrap();
    let caller = client_of(&application(project, "Caller"));
    store_client(backend, &caller, test_audit()).await.unwrap();
    backend
        .set_resource_access(&access(&caller, &api, &["orders.read"]), test_audit())
        .await
        .unwrap();

    let mut changed = api.clone();
    changed.scopes = vec!["orders.read".into()];
    changed.state = ResourceState::Inactive;
    assert!(
        backend
            .update_protected_resource(&changed, test_audit())
            .await
            .unwrap()
    );
    let stored = backend
        .get_protected_resource(api.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.scopes, changed.scopes);
    assert_eq!(stored.state, ResourceState::Inactive);
    assert_eq!(stored.revision, 1);
    // Stale revision.
    assert!(
        !backend
            .update_protected_resource(&changed, test_audit())
            .await
            .unwrap()
    );
    // Identity fields never change and retiring is not an update.
    let identity_changes: [fn(&mut ProtectedResource); 3] = [
        |r| r.indicator = unique_indicator(),
        |r| r.application_id = Some(ApplicationId::generate()),
        |r| r.state = ResourceState::Retired,
    ];
    for mutate in identity_changes {
        let mut attempt = stored.clone();
        mutate(&mut attempt);
        assert!(
            !backend
                .update_protected_resource(&attempt, test_audit())
                .await
                .unwrap()
        );
    }
    let mut reactivated = stored.clone();
    reactivated.state = ResourceState::Active;
    assert!(
        backend
            .update_protected_resource(&reactivated, test_audit())
            .await
            .unwrap()
    );

    // Removing the application retires the resource and ends every access.
    assert!(
        backend
            .delete_application(app.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .delete_application(app.id, test_audit())
            .await
            .unwrap()
    );
    assert!(backend.get_application(app.id).await.unwrap().is_none());
    assert!(
        backend
            .get_oauth2_client(&client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    let retired = backend
        .get_protected_resource(api.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.state, ResourceState::Retired);
    assert_eq!(retired.application_id, None);
    assert_eq!(retired.indicator, api.indicator);
    assert!(
        backend
            .list_resource_access_by_resource(api.id)
            .await
            .unwrap()
            .is_empty()
    );
    // A retired resource is never updated again.
    let mut revive = retired.clone();
    revive.state = ResourceState::Active;
    revive.application_id = None;
    assert!(
        !backend
            .update_protected_resource(&revive, test_audit())
            .await
            .unwrap()
    );
    // Its indicator is not given to another resource of the issuer.
    let successor = application(project, "Successor");
    let mut reuse = resource(&successor, issuer);
    reuse.indicator = api.indicator.clone();
    assert!(is_conflict(
        backend
            .create_application(&successor, None, Some(&reuse), test_audit())
            .await
    ));
}

/// Access is explicit, replaced as a whole and removed with its client.
pub async fn test_resource_access(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let api_app = application(project, "API");
    let api = resource(&api_app, issuer);
    backend
        .create_application(&api_app, None, Some(&api), test_audit())
        .await
        .unwrap();
    let web = client_of(&application(project, "Web"));
    store_client(backend, &web, test_audit()).await.unwrap();

    assert!(
        backend
            .resource_access(&web.client_id, api.id)
            .await
            .unwrap()
            .is_none()
    );
    let granted = access(&web, &api, &["orders.read"]);
    backend
        .set_resource_access(&granted, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .resource_access(&web.client_id, api.id)
            .await
            .unwrap(),
        Some(granted.clone())
    );

    // Setting again replaces the scopes and keeps the creation time; two
    // writers of one pair leave one access.
    let mut wider = access(&web, &api, &["orders.read", "orders.write"]);
    wider.created_at = granted.created_at + chrono::Duration::seconds(5);
    let (a, b) = tokio::join!(
        backend.set_resource_access(&wider, test_audit()),
        backend.set_resource_access(&wider, test_audit()),
    );
    a.unwrap();
    b.unwrap();
    let stored = backend
        .resource_access(&web.client_id, api.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.scopes, wider.scopes);
    assert_eq!(stored.created_at, granted.created_at);
    assert_eq!(
        backend
            .list_resource_access_by_client(&web.client_id)
            .await
            .unwrap(),
        vec![stored.clone()]
    );
    assert_eq!(
        backend
            .list_resource_access_by_resource(api.id)
            .await
            .unwrap(),
        vec![stored]
    );

    // Access for a client or resource that does not exist is refused.
    let ghost = client_of(&application(project, "Ghost"));
    assert!(
        backend
            .set_resource_access(&access(&ghost, &api, &["orders.read"]), test_audit())
            .await
            .is_err()
    );
    let mut unknown = api.clone();
    unknown.id = ResourceId::generate();
    assert!(
        backend
            .set_resource_access(&access(&web, &unknown, &["orders.read"]), test_audit())
            .await
            .is_err()
    );

    assert!(
        backend
            .remove_resource_access(&web.client_id, api.id, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .remove_resource_access(&web.client_id, api.id, test_audit())
            .await
            .unwrap()
    );

    // Deleting a client ends its access; its role-less application goes with
    // it, an application still holding a resource stays.
    backend
        .set_resource_access(&granted, test_audit())
        .await
        .unwrap();
    backend
        .delete_oauth2_client(&web.client_id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .list_resource_access_by_resource(api.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        backend
            .get_application(web.application_id)
            .await
            .unwrap()
            .is_none()
    );
    let both = application(project, "Both");
    let both_client = client_of(&both);
    backend
        .create_application(
            &both,
            Some(&both_client),
            Some(&resource(&both, issuer)),
            test_audit(),
        )
        .await
        .unwrap();
    backend
        .delete_oauth2_client(&both_client.client_id, test_audit())
        .await
        .unwrap();
    assert!(backend.get_application(both.id).await.unwrap().is_some());
    assert!(
        backend
            .protected_resource_of_application(both.id)
            .await
            .unwrap()
            .is_some()
    );

    // A retired resource accepts no new access.
    let retiring = application(project, "Retiring");
    let retiring_api = resource(&retiring, issuer);
    backend
        .create_application(&retiring, None, Some(&retiring_api), test_audit())
        .await
        .unwrap();
    backend
        .delete_application(retiring.id, test_audit())
        .await
        .unwrap();
    let late = client_of(&application(project, "Late"));
    store_client(backend, &late, test_audit()).await.unwrap();
    assert!(
        backend
            .set_resource_access(
                &access(&late, &retiring_api, &["orders.read"]),
                test_audit()
            )
            .await
            .is_err()
    );
}

/// A machine user is a client too: it is given access by its client id,
/// listed with the resource's other clients, and loses the access with its
/// own deletion.
pub async fn test_machine_user_resource_access(backend: &dyn StorageBackend) {
    use sid_core::models::MachineUser;
    use sid_core::models::machine_user::OwnerType;

    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let api_app = application(project, "API");
    let api = resource(&api_app, issuer);
    backend
        .create_application(&api_app, None, Some(&api), test_audit())
        .await
        .unwrap();
    let web = client_of(&application(project, "Web"));
    store_client(backend, &web, test_audit()).await.unwrap();
    let ci = MachineUser::new(
        project,
        format!("ci-{}", Uuid::now_v7().simple()),
        "ci",
        OwnerType::System,
        "system",
    );
    backend
        .create_machine_user(&ci, test_audit())
        .await
        .unwrap();

    let granted = ResourceAccess {
        client_id: ci.client_id.clone(),
        resource_id: api.id,
        scopes: vec!["orders.read".into()],
        created_at: Utc::now().trunc_subsecs(3),
    };
    backend
        .set_resource_access(&granted, test_audit())
        .await
        .unwrap();
    backend
        .set_resource_access(&access(&web, &api, &["orders.write"]), test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .resource_access(&ci.client_id, api.id)
            .await
            .unwrap(),
        Some(granted.clone())
    );
    assert_eq!(
        backend
            .list_resource_access_by_client(&ci.client_id)
            .await
            .unwrap(),
        vec![granted.clone()]
    );
    assert_eq!(
        backend
            .list_resource_access_by_resource(api.id)
            .await
            .unwrap()
            .len(),
        2
    );

    // Setting again replaces the scopes, as for any client.
    let mut wider = granted.clone();
    wider.scopes = vec!["orders.read".into(), "orders.write".into()];
    backend
        .set_resource_access(&wider, test_audit())
        .await
        .unwrap();
    assert_eq!(
        backend
            .resource_access(&ci.client_id, api.id)
            .await
            .unwrap()
            .unwrap()
            .scopes,
        wider.scopes
    );

    // Deleting the machine user ends its access and only its access.
    backend
        .delete_machine_user(ci.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .resource_access(&ci.client_id, api.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        backend
            .list_resource_access_by_resource(api.id)
            .await
            .unwrap()
            .iter()
            .map(|a| a.client_id.as_str())
            .collect::<Vec<_>>(),
        vec![web.client_id.as_str()]
    );
}

/// Every resource is listed, retired ones included, and a resource moves to
/// another store as it is: its id, state and revision are kept, a repeated
/// import writes nothing, and a different resource under the same indicator
/// is refused.
pub async fn test_resource_listing_and_import(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let live_app = application(project, "Live");
    let live = resource(&live_app, issuer);
    backend
        .create_application(&live_app, None, Some(&live), test_audit())
        .await
        .unwrap();
    let gone_app = application(project, "Gone");
    let gone = resource(&gone_app, issuer);
    backend
        .create_application(&gone_app, None, Some(&gone), test_audit())
        .await
        .unwrap();
    backend
        .delete_application(gone_app.id, test_audit())
        .await
        .unwrap();

    let mut listed = Vec::new();
    let mut offset = 0;
    loop {
        let page = backend.list_protected_resources(offset, 50).await.unwrap();
        if page.is_empty() {
            break;
        }
        offset += page.len() as u64;
        listed.extend(page);
    }
    let live_listed = listed
        .iter()
        .find(|r| r.id == live.id)
        .expect("live listed");
    assert_eq!(live_listed, &live);
    let retired = listed
        .iter()
        .find(|r| r.id == gone.id)
        .expect("retired listed");
    assert_eq!(retired.state, ResourceState::Retired);

    // Importing what is already stored writes nothing.
    assert!(
        !backend
            .import_protected_resource(retired, test_audit())
            .await
            .unwrap()
    );
    // A different resource under a taken indicator is a conflict.
    let mut impostor = retired.clone();
    impostor.id = ResourceId::generate();
    assert!(is_conflict(
        backend
            .import_protected_resource(&impostor, test_audit())
            .await
    ));
    // A retired resource imported into a fresh indicator keeps its state.
    let mut moved = retired.clone();
    moved.id = ResourceId::generate();
    moved.indicator = unique_indicator();
    moved.revision = 4;
    assert!(
        backend
            .import_protected_resource(&moved, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        backend.get_protected_resource(moved.id).await.unwrap(),
        Some(moved.clone())
    );
}

/// A client's default resource is stored and read back.
pub async fn test_client_default_resource(backend: &dyn StorageBackend) {
    let issuer = instance_issuer(backend).await;
    let project = system_project(backend).await;
    let api_app = application(project, "API");
    let api = resource(&api_app, issuer);
    backend
        .create_application(&api_app, None, Some(&api), test_audit())
        .await
        .unwrap();
    let mut web = client_of(&application(project, "Web"));
    web.default_resource = Some(api.id);
    store_client(backend, &web, test_audit()).await.unwrap();
    assert_eq!(
        backend
            .get_oauth2_client(&web.client_id)
            .await
            .unwrap()
            .unwrap()
            .default_resource,
        Some(api.id)
    );
    // A default naming no resource is refused.
    let mut dangling = client_of(&application(project, "Dangling"));
    dangling.default_resource = Some(ResourceId::generate());
    assert!(
        store_client(backend, &dangling, test_audit())
            .await
            .is_err()
    );
}
