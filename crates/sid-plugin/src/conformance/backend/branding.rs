// SPDX-License-Identifier: AGPL-3.0-only
//! Branding configurations: a draft is edited over the revision it was read
//! at, published in one write that archives the previous publication, and a
//! project has at most one published config.

use chrono::Utc;
use sid_core::models::{BrandingConfig, BrandingConfigId, BrandingStatus, Project, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

async fn project(backend: &dyn StorageBackend) -> ProjectId {
    let project = Project::new(format!("brand_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    project.id
}

fn draft(project_id: ProjectId) -> BrandingConfig {
    let now = Utc::now();
    BrandingConfig {
        id: BrandingConfigId::new(),
        project_id,
        status: BrandingStatus::Draft,
        assets: Default::default(),
        tokens: Default::default(),
        dark_mode: Default::default(),
        text: Default::default(),
        revision: 0,
        created_at: now,
        updated_at: now,
    }
}

async fn stored(backend: &dyn StorageBackend, id: BrandingConfigId) -> BrandingConfig {
    backend
        .get_branding_config(id)
        .await
        .unwrap()
        .expect("config stored")
}

/// A second create never replaces a config; a draft edit over a stale
/// revision, or on a config no longer a draft, writes nothing.
pub async fn test_branding_draft_write_contract(backend: &dyn StorageBackend) {
    let project_id = project(backend).await;
    let config = draft(project_id);
    backend
        .create_branding_config(&config, test_audit())
        .await
        .unwrap();
    assert!(matches!(
        backend.create_branding_config(&config, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));

    let read = stored(backend, config.id).await;
    let mut first = read.clone();
    first.tokens.color_primary = "#111111".into();
    assert!(
        backend
            .update_branding_draft(&first, test_audit())
            .await
            .unwrap()
    );
    let mut stale = read;
    stale.tokens.color_primary = "#222222".into();
    assert!(
        !backend
            .update_branding_draft(&stale, test_audit())
            .await
            .unwrap(),
        "an edit over a stale revision must not apply"
    );
    let current = stored(backend, config.id).await;
    assert_eq!(current.tokens.color_primary, "#111111");
    assert_eq!(current.revision, 1);

    assert!(
        backend
            .publish_branding_config(config.id, project_id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    let published = stored(backend, config.id).await;
    assert_eq!(published.status, BrandingStatus::Published);
    let mut edit_live = published;
    edit_live.tokens.color_primary = "#333333".into();
    assert!(
        !backend
            .update_branding_draft(&edit_live, test_audit())
            .await
            .unwrap(),
        "a published config is not edited in place"
    );
    assert_eq!(
        stored(backend, config.id).await.tokens.color_primary,
        "#111111"
    );
}

/// Publishing archives the previous publication in the same write, only for
/// a draft of the named project; a published config is never deleted.
pub async fn test_branding_publish_contract(backend: &dyn StorageBackend) {
    let project_id = project(backend).await;
    let other_project = project(backend).await;
    let first = draft(project_id);
    let second = draft(project_id);
    let foreign = draft(other_project);
    for config in [&first, &second, &foreign] {
        backend
            .create_branding_config(config, test_audit())
            .await
            .unwrap();
    }
    assert!(
        backend
            .publish_branding_config(foreign.id, other_project, Utc::now(), test_audit())
            .await
            .unwrap()
    );

    assert!(
        !backend
            .publish_branding_config(first.id, other_project, Utc::now(), test_audit())
            .await
            .unwrap(),
        "a draft is published in its own project only"
    );
    assert_eq!(
        stored(backend, foreign.id).await.status,
        BrandingStatus::Published,
        "another project's branding was archived"
    );

    assert!(
        backend
            .publish_branding_config(first.id, project_id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend
            .publish_branding_config(second.id, project_id, Utc::now(), test_audit())
            .await
            .unwrap()
    );
    assert_eq!(
        stored(backend, first.id).await.status,
        BrandingStatus::Archived
    );
    assert_eq!(
        backend
            .get_published_branding(project_id)
            .await
            .unwrap()
            .expect("published")
            .id,
        second.id
    );
    assert!(
        !backend
            .publish_branding_config(first.id, project_id, Utc::now(), test_audit())
            .await
            .unwrap(),
        "an archived config is not published again"
    );

    assert!(
        !backend
            .delete_branding_config(second.id, test_audit())
            .await
            .unwrap(),
        "a published config is never deleted"
    );
    assert!(
        backend
            .delete_branding_config(first.id, test_audit())
            .await
            .unwrap()
    );
}

/// Two drafts of one project published at once: exactly one is published.
pub async fn test_branding_concurrent_publish(backend: &dyn StorageBackend) {
    let project_id = project(backend).await;
    let a = draft(project_id);
    let b = draft(project_id);
    backend
        .create_branding_config(&a, test_audit())
        .await
        .unwrap();
    backend
        .create_branding_config(&b, test_audit())
        .await
        .unwrap();
    let (ra, rb) = tokio::join!(
        backend.publish_branding_config(a.id, project_id, Utc::now(), test_audit()),
        backend.publish_branding_config(b.id, project_id, Utc::now(), test_audit()),
    );
    // Each publish either wins, or waits and then archives the other.
    assert!(ra.unwrap() && rb.unwrap());
    let published = backend
        .list_branding_configs(project_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.status == BrandingStatus::Published)
        .count();
    assert_eq!(published, 1, "a project has one published config");
}
