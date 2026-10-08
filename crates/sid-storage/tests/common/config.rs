// SPDX-License-Identifier: AGPL-3.0-only
//! Installation and project configuration: flow configurations put whole
//! per project and flow type, and the email provider stored as one
//! configuration or refused with nothing stored.

use std::collections::HashMap;

use sid_core::models::{FlowConfig, FlowType, Project};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

fn flow(project: sid_core::models::ProjectId, flow_type: FlowType, timeout: u32) -> FlowConfig {
    FlowConfig {
        project_id: project,
        flow_type,
        steps: HashMap::new(),
        timeout_seconds: timeout,
        updated_at: chrono::Utc::now(),
    }
}

/// A flow configuration is one per project and flow type: a second save
/// replaces it (also two at once leave one), configurations list per project
/// and another project's are never returned.
pub async fn test_flow_configs(backend: &dyn StorageBackend) {
    let project = Project::new(format!("flows-{}", Uuid::now_v7().simple()), None);
    let other = Project::new(format!("flows-{}", Uuid::now_v7().simple()), None);
    for p in [&project, &other] {
        backend.create_project(p, test_audit()).await.unwrap();
    }
    assert!(
        backend
            .get_flow_config(project.id, FlowType::Authentication)
            .await
            .unwrap()
            .is_none()
    );

    for config in [
        flow(project.id, FlowType::Authentication, 300),
        flow(project.id, FlowType::Registration, 600),
        flow(other.id, FlowType::Authentication, 900),
    ] {
        backend
            .save_flow_config(&config, test_audit())
            .await
            .unwrap();
    }
    let (a, b) = (
        flow(project.id, FlowType::Authentication, 120),
        flow(project.id, FlowType::Authentication, 180),
    );
    let (ra, rb) = tokio::join!(
        backend.save_flow_config(&a, test_audit()),
        backend.save_flow_config(&b, test_audit()),
    );
    ra.unwrap();
    rb.unwrap();

    let stored = backend
        .get_flow_config(project.id, FlowType::Authentication)
        .await
        .unwrap()
        .unwrap();
    assert!(
        [120, 180].contains(&stored.timeout_seconds),
        "the configuration holds neither save: {}",
        stored.timeout_seconds
    );
    let mut types: Vec<_> = backend
        .list_flow_configs(project.id)
        .await
        .unwrap()
        .into_iter()
        .map(|c| (format!("{:?}", c.flow_type), c.project_id))
        .collect();
    types.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(
        types,
        vec![
            ("Authentication".to_string(), project.id),
            ("Registration".to_string(), project.id)
        ]
    );
    assert_eq!(
        backend
            .get_flow_config(other.id, FlowType::Authentication)
            .await
            .unwrap()
            .unwrap()
            .timeout_seconds,
        900,
        "another project's configuration changed"
    );
}

/// The email provider is one configuration of the installation: a second
/// write replaces it. A backend that does not store it refuses the write
/// and keeps nothing, never answering success for a write it dropped.
pub async fn test_email_provider_config(backend: &dyn StorageBackend) {
    use secrecy::SecretBox;
    use sid_core::models::{EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};

    let config = |host: &str| EmailProviderConfig {
        smtp_host: host.into(),
        smtp_port: 587,
        from_address: "noreply@sid.example.com".into(),
        from_display_name: "SID".into(),
        reply_to: String::new(),
        encryption: SmtpEncryption::Starttls,
        auth_type: SmtpAuthMethod::None,
        username: String::new(),
        password: SecretBox::new(Box::new(String::new())),
        xoauth2: None,
    };

    match backend
        .upsert_email_provider_config(&config("smtp1.sid.example.com"), test_audit())
        .await
    {
        Ok(()) => {
            let stored = backend.get_email_provider_config().await.unwrap().unwrap();
            assert_eq!(stored.smtp_host, "smtp1.sid.example.com");
            backend
                .upsert_email_provider_config(&config("smtp2.sid.example.com"), test_audit())
                .await
                .unwrap();
            let stored = backend.get_email_provider_config().await.unwrap().unwrap();
            assert_eq!(stored.smtp_host, "smtp2.sid.example.com");
            assert_eq!(stored.encryption, SmtpEncryption::Starttls);
        }
        Err(_) => {
            assert!(
                backend.get_email_provider_config().await.unwrap().is_none(),
                "a refused write left a configuration behind"
            );
        }
    }
}
