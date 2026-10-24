use super::*;

#[tokio::test]
async fn test_disabled_service_returns_defaults() {
    let svc = FeatureFlagService::disabled();

    // Default for maintenance_mode is false
    assert!(!svc.is_maintenance_mode().await);
    // Default for registration_enabled is true
    assert!(svc.is_registration_enabled().await);
    // Default for trial_creation_enabled is false (closed beta)
    assert!(!svc.is_trial_creation_enabled().await);
}

#[tokio::test]
async fn test_is_enabled_returns_default_for_unknown_flag() {
    let svc = FeatureFlagService::disabled();

    assert!(svc.is_enabled("unknown_flag", true).await);
    assert!(!svc.is_enabled("unknown_flag", false).await);
}

#[tokio::test]
async fn test_flags_can_be_set_directly() {
    let svc = FeatureFlagService::disabled();
    {
        let mut flags = svc.flags.write().await;
        flags.insert("maintenance_mode".into(), true);
        flags.insert("registration_enabled".into(), false);
    }

    assert!(svc.is_maintenance_mode().await);
    assert!(!svc.is_registration_enabled().await);
}

#[tokio::test]
async fn test_flag_names_are_correct() {
    assert_eq!(flags::MAINTENANCE_MODE, "maintenance_mode");
    assert_eq!(flags::REGISTRATION_ENABLED, "registration_enabled");
    assert_eq!(flags::TRIAL_CREATION_ENABLED, "trial_creation_enabled");
}

#[tokio::test]
async fn test_service_is_clone() {
    let svc = FeatureFlagService::disabled();
    let svc2 = svc.clone();

    // Shared state
    {
        svc.flags.write().await.insert("test".into(), true);
    }
    assert!(svc2.is_enabled("test", false).await);
}

#[test]
fn test_config_creation() {
    let config = FeatureFlagConfig {
        api_url: "https://gitlab.example.com/api/v4/feature_flags/unleash/42".into(),
        instance_id: "test-instance-id".into(),
        app_name: "development".into(),
        poll_interval_secs: 15,
    };
    assert_eq!(config.poll_interval_secs, 15);
    assert_eq!(config.app_name, "development");
}

#[test]
fn test_unleash_response_deserialization() {
    let json = r#"{
            "version": 1,
            "features": [
                { "name": "maintenance_mode", "enabled": true, "strategies": [] },
                { "name": "registration_enabled", "enabled": false, "strategies": [] }
            ]
        }"#;
    let response: UnleashResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.features.len(), 2);
    assert_eq!(response.features[0].name, "maintenance_mode");
    assert!(response.features[0].enabled);
    assert_eq!(response.features[1].name, "registration_enabled");
    assert!(!response.features[1].enabled);
}

#[test]
fn test_unleash_response_empty_features() {
    let json = r#"{ "version": 1, "features": [] }"#;
    let response: UnleashResponse = serde_json::from_str(json).unwrap();
    assert!(response.features.is_empty());
}
