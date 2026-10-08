use super::*;
use chrono::Duration;
use sid_core::models::ProfileId;

fn retention(pairs: &[(&str, &str)]) -> Result<AuditRetention, String> {
    AuditRetention::from_lookup(|k| {
        pairs
            .iter()
            .find(|(name, _)| *name == k)
            .map(|(_, v)| v.to_string())
    })
}

/// Unset: a year, archived (records are kept until an archive holds them).
#[test]
fn audit_retention_defaults_to_a_year_archived() {
    assert_eq!(
        retention(&[]).unwrap(),
        AuditRetention {
            days: 365,
            action: RetentionAction::Archive
        }
    );
    assert_eq!(
        retention(&[
            ("SID_AUDIT_RETENTION_DAYS", "30"),
            ("SID_AUDIT_RETENTION_ACTION", "delete")
        ])
        .unwrap(),
        AuditRetention {
            days: 30,
            action: RetentionAction::Delete
        }
    );
}

/// A value that does not parse, or is out of range, stops startup instead of
/// becoming the default (a bad setting once silently meant 365 days).
#[test]
fn audit_retention_refuses_bad_settings() {
    for days in ["", "abc", "0", "-5", "36501"] {
        assert!(
            retention(&[("SID_AUDIT_RETENTION_DAYS", days)]).is_err(),
            "{days:?}"
        );
    }
    assert!(retention(&[("SID_AUDIT_RETENTION_ACTION", "purge")]).is_err());
}

fn make_profile(migration_pending: bool, started_days_ago: Option<i64>) -> Profile {
    let now = Utc::now();
    Profile {
        id: ProfileId::generate(),
        profile_type: sid_core::models::ProfileType::Personal,
        username: Some("test".to_string()),
        given_name: Some("Test".to_string()),
        family_name: Some("User".to_string()),
        middle_name: None,
        honorific_prefix: None,
        honorific_suffix: None,
        roles: vec![],
        status: ProfileStatus::Active,
        visibility: sid_core::models::ProfileVisibility::Private,
        max_assurance: sid_core::models::ProfileAssurance::Anonymous,
        manager_id: None,
        migration_pending,
        migration_started_at: started_days_ago.map(|d| now - Duration::days(d)),
        migration_completed_at: None,
        revision: 0,
        created_at: now - Duration::days(started_days_ago.unwrap_or(0)),
        updated_at: now,
    }
}

#[test]
fn test_is_migration_expired_within_deadline() {
    let profile = make_profile(true, Some(30));
    let now = Utc::now();
    assert!(!is_migration_expired(&profile, 180, now));
}

#[test]
fn test_is_migration_expired_past_deadline() {
    let profile = make_profile(true, Some(200));
    let now = Utc::now();
    assert!(is_migration_expired(&profile, 180, now));
}

#[test]
fn test_is_migration_expired_exactly_at_deadline() {
    let profile = make_profile(true, Some(180));
    let now = Utc::now();
    assert!(is_migration_expired(&profile, 180, now));
}

#[test]
fn test_is_migration_expired_uses_created_at_fallback() {
    // No migration_started_at — falls back to created_at.
    let mut profile = make_profile(true, None);
    profile.migration_started_at = None;
    profile.created_at = Utc::now() - Duration::days(200);
    let now = Utc::now();
    assert!(is_migration_expired(&profile, 180, now));
}

#[test]
fn test_is_migration_expired_created_recently() {
    let mut profile = make_profile(true, None);
    profile.migration_started_at = None;
    profile.created_at = Utc::now() - Duration::days(10);
    let now = Utc::now();
    assert!(!is_migration_expired(&profile, 180, now));
}

#[test]
fn test_default_deadline_days_constant() {
    assert_eq!(DEFAULT_MIGRATION_DEADLINE_DAYS, 180);
}
