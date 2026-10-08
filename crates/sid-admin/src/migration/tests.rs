use super::*;

fn sample_user(email: &str) -> ImportedUser {
    ImportedUser {
        username: email.split('@').next().unwrap().to_string(),
        email: email.to_string(),
        email_verified: true,
        display_name: Some("Test User".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone: None,
        enabled: true,
        password_hash: Some("$2b$12$LJ3m4ys3Lk...hash".to_string()),
        hash_algorithm: Some("bcrypt".to_string()),
        totp_seed: None,
        roles: vec!["user".to_string()],
        groups: vec![],
        external_id: "ext-123".to_string(),
        attributes: std::collections::HashMap::new(),
    }
}

#[test]
fn test_import_result_default_counts() {
    let result = ImportResult {
        total_parsed: 10,
        imported: 7,
        skipped: 2,
        failed: 1,
        errors: vec![ImportError {
            identifier: "bad@example.com".to_string(),
            reason: "duplicate".to_string(),
        }],
    };
    assert_eq!(
        result.total_parsed,
        result.imported + result.skipped + result.failed
    );
}

#[test]
fn test_sample_user_construction() {
    let user = sample_user("alice@sid.example.com");
    assert_eq!(user.username, "alice");
    assert_eq!(user.email, "alice@sid.example.com");
    assert!(user.email_verified);
    assert!(user.password_hash.is_some());
}

#[test]
fn test_import_error_display() {
    let err = ImportUserError::Storage("connection refused".to_string());
    assert!(err.to_string().contains("connection refused"));
}

/// Regression: an imported email became the login handle exactly as the
/// export spelled it, so the account answered no other spelling, and no
/// contact was stored. The principal holds the key, the linked contact the
/// export's spelling; another spelling of an imported handle is skipped as
/// the same account; a malformed address fails instead of being stored.
#[tokio::test]
async fn imported_emails_are_keyed_and_keep_their_spelling() {
    let storage: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let service = MigrationImportService::new(storage.clone());
    let mut first = sample_user("ann.smith@sid.example.com");
    first.email = "Ann.Smith+old@SID.example.com".into();
    let mut again = sample_user("annsmith2@sid.example.com");
    again.email = "annsmith@sid.example.com".into();
    let broken = sample_user("x@sid.example.com");
    let mut broken = broken;
    broken.email = "ann..smith@sid.example.com".into();

    let result = service.import_users(vec![first, again, broken]).await;
    assert_eq!((result.imported, result.skipped, result.failed), (1, 1, 1));

    let profile = storage
        .get_profile_by_principal(PrincipalType::Email, "annsmith@sid.example.com")
        .await
        .unwrap()
        .expect("the key finds the account");
    let contacts = storage.list_profile_emails(profile.id).await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].email, "Ann.Smith+old@sid.example.com");
    let principal = storage
        .get_principals_by_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .unwrap();
    assert_eq!(principal.source_email_id, Some(contacts[0].id));
}
