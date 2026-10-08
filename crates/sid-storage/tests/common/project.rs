// SPDX-License-Identifier: AGPL-3.0-only
//! Project and OAuth client listings: counted and paged, pages of one
//! project disjoint and complete, never another project's clients.

use sid_core::models::{Project, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

fn tag() -> String {
    Uuid::now_v7().simple().to_string()
}

async fn own_project(backend: &dyn StorageBackend) -> ProjectId {
    let project = Project::new(format!("listing-{}", tag()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    project.id
}

/// Created projects are counted and listed, and a limit caps the page. Other writers share the store, so the count only grows by at
/// least the projects made here.
pub async fn test_projects_count_and_listing(backend: &dyn StorageBackend) {
    let mut made = Vec::new();
    for _ in 0..3 {
        made.push(own_project(backend).await);
    }
    // Other scenarios create and delete projects at the same time, so only
    // this scenario's own projects bound the count.
    assert!(backend.count_projects().await.unwrap() >= 3);

    let page = backend.list_projects(0, 500).await.unwrap();
    let ids: Vec<_> = page.iter().map(|p| p.id).collect();
    for id in &made {
        assert!(ids.contains(id), "a created project is not listed");
    }
    assert_eq!(backend.list_projects(0, 2).await.unwrap().len(), 2);
}

/// A project's clients page without overlap and together hold all of
/// them, never a client of another project; the store-wide listing holds
/// them too.
pub async fn test_oauth2_clients_by_project_paging(backend: &dyn StorageBackend) {
    let project = own_project(backend).await;
    let other = own_project(backend).await;
    let mut made = Vec::new();
    for _ in 0..5 {
        let mut client = super::create_test_oauth2_client(&format!("paged-{}", tag()));
        client.project_id = project;
        super::application::store_client(backend, &client, test_audit())
            .await
            .unwrap();
        made.push(client.client_id);
    }
    let mut foreign = super::create_test_oauth2_client(&format!("foreign-{}", tag()));
    foreign.project_id = other;
    super::application::store_client(backend, &foreign, test_audit())
        .await
        .unwrap();

    let mut seen = Vec::new();
    for offset in [0, 2, 4] {
        let page = backend
            .list_oauth2_clients_by_project(project, offset, 2)
            .await
            .unwrap();
        assert!(page.len() <= 2);
        seen.extend(page.into_iter().map(|c| c.client_id));
    }
    assert!(
        backend
            .list_oauth2_clients_by_project(project, 6, 2)
            .await
            .unwrap()
            .is_empty()
    );
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "pages overlap: {seen:?}");
    let mut expected = made.clone();
    expected.sort();
    assert_eq!(
        sorted, expected,
        "pages miss a client or hold another project's"
    );

    let all: Vec<_> = backend
        .list_oauth2_clients(0, 500)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.client_id)
        .collect();
    for id in made.iter().chain([&foreign.client_id]) {
        assert!(all.contains(id), "the store-wide listing misses {id}");
    }
}
