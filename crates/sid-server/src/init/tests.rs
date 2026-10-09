// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// Explicit malformed security settings must stop startup, never disable
/// proof verification or silently select a different policy.
#[test]
fn zkpp_settings_refuse_malformed_security_configuration() {
    use std::env::VarError::NotPresent;
    for value in ["TRUE", "", "tru", "yes"] {
        assert!(zkpp_settings(Ok(value.into()), Err(NotPresent), Err(NotPresent)).is_err());
        assert!(zkpp_settings(Ok("true".into()), Ok(value.into()), Err(NotPresent)).is_err());
    }
    for value in ["", "garbage", "0", "4294967296", "2"] {
        assert!(zkpp_settings(Ok("true".into()), Err(NotPresent), Ok(value.into())).is_err());
    }
    assert!(zkpp_settings(Ok("false".into()), Ok("true".into()), Err(NotPresent)).is_err());
    assert!(zkpp_settings(Ok("false".into()), Err(NotPresent), Err(NotPresent)).is_err());
    assert!(
        zkpp_settings(
            Ok("true".into()),
            Err(std::env::VarError::NotUnicode("bad".into())),
            Err(NotPresent)
        )
        .is_err()
    );
    assert!(
        zkpp_settings(
            Ok("true".into()),
            Err(NotPresent),
            Err(std::env::VarError::NotUnicode("bad".into()))
        )
        .is_err()
    );
    assert!(
        zkpp_settings(
            Err(std::env::VarError::NotUnicode("bad".into())),
            Err(NotPresent),
            Err(NotPresent)
        )
        .is_err()
    );
}

/// Fresh installations require proofs; only an explicit false/0 permits
/// policy-unverified setup. Missing configuration cannot weaken this default.
#[test]
fn zkpp_settings_preserve_documented_defaults() {
    use std::env::VarError::NotPresent;
    let (enabled, config) =
        zkpp_settings(Err(NotPresent), Err(NotPresent), Err(NotPresent)).unwrap();
    assert!(enabled);
    assert!(config.require_proof);
    assert_eq!(config.policy_version, 1);
    let (enabled, config) =
        zkpp_settings(Err(NotPresent), Ok("false".into()), Err(NotPresent)).unwrap();
    assert!(enabled);
    assert!(!config.require_proof);
    let (enabled, config) =
        zkpp_settings(Ok("false".into()), Ok("false".into()), Err(NotPresent)).unwrap();
    assert!(!enabled && !config.require_proof);
    for value in ["true", "1"] {
        let (enabled, config) =
            zkpp_settings(Ok(value.into()), Err(NotPresent), Err(NotPresent)).unwrap();
        assert!(enabled && config.require_proof);
        for optional in ["false", "0"] {
            let (_, config) =
                zkpp_settings(Ok(value.into()), Ok(optional.into()), Ok("1".into())).unwrap();
            assert!(!config.require_proof);
        }
    }
}

/// The history-epoch cutoff is absent unless set; a set value is a past RFC
/// 3339 instant. Malformed, non-Unicode or future values stop startup rather
/// than silently disabling or perpetually repeating epoch replacement.
#[test]
fn history_epoch_cutoff_accepts_only_a_past_instant() {
    use std::env::VarError::{NotPresent, NotUnicode};
    assert_eq!(history_epoch_cutoff(Err(NotPresent)).unwrap(), None);
    let past = history_epoch_cutoff(Ok("2026-10-01T12:00:00Z".into()))
        .unwrap()
        .unwrap();
    assert_eq!(past.to_rfc3339(), "2026-10-01T12:00:00+00:00");
    let offset = history_epoch_cutoff(Ok("2026-10-01T15:00:00+03:00".into()))
        .unwrap()
        .unwrap();
    assert_eq!(offset, past, "an offset names the same instant");
    for refused in ["", "yesterday", "2026-10-01", "2026-10-01 12:00:00"] {
        assert!(
            history_epoch_cutoff(Ok(refused.into())).is_err(),
            "{refused:?}"
        );
    }
    let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    assert!(history_epoch_cutoff(Ok(future)).is_err());
    assert!(history_epoch_cutoff(Err(NotUnicode("bad".into()))).is_err());
}

/// A machine-credential alert keeps its id across scans (relayed once) and
/// a different alert (another credential or another day) gets another id.
#[test]
fn test_credential_alert_id_is_stable_per_alert() {
    let expired = credential_alert_id("expired:kid-1");
    assert_eq!(expired, credential_alert_id("expired:kid-1"));
    assert!(uuid::Uuid::parse_str(&expired).is_ok());
    assert_ne!(expired, credential_alert_id("expired:kid-2"));
    assert_ne!(
        credential_alert_id("expiring:kid-1:3"),
        credential_alert_id("expiring:kid-1:2")
    );
}

/// The account integration is configured by its URL and its BFF's key file
/// together; neither means no account UI, anything partial or unreadable
/// stops the start instead of provisioning with invented settings.
#[test]
fn account_settings_need_the_url_and_the_keys() {
    assert!(account_settings(None, None).unwrap().is_none());
    assert!(account_settings(Some(""), Some("")).unwrap().is_none());
    assert!(account_settings(Some("https://account.sid.example.com"), None).is_err());
    assert!(account_settings(None, Some("/nonexistent/jwks.json")).is_err());
    assert!(
        account_settings(
            Some("https://account.sid.example.com"),
            Some("/nonexistent/jwks.json")
        )
        .is_err()
    );

    let dir = std::env::temp_dir().join(format!("sid-jwks-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let public = dir.join("public.json");
    std::fs::write(
        &public,
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"bff"}]}"#,
    )
    .unwrap();
    let private = dir.join("private.json");
    std::fs::write(
        &private,
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kid":"bff"}]}"#,
    )
    .unwrap();
    let settings = account_settings(Some("https://account.sid.example.com"), public.to_str())
        .unwrap()
        .unwrap();
    assert_eq!(
        settings.callback(),
        "https://account.sid.example.com/auth/callback"
    );
    // The BFF's private key never belongs in SID's configuration.
    assert!(account_settings(Some("https://account.sid.example.com"), private.to_str()).is_err());
    assert!(account_settings(Some("http://account.sid.example.com"), public.to_str()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn store() -> sid_storage::sqlite::SqliteBackend {
    sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap()
}

fn keys() -> sid_keys::SoftwareKeyManager {
    sid_keys::SoftwareKeyManager::new(
        secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
        vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
        Arc::new(sid_keys::RustCryptoPrimitives::new()),
    )
    .expect("test key manager")
}

/// A fresh instance opens its administrator claim at start; a start of an
/// instance that has an administrator opens none. No start grants a role.
#[tokio::test]
async fn start_opens_the_claim_only_without_an_admin() {
    let (storage, keys) = (store().await, keys());
    announce_admin_claim(&storage, &keys).await.unwrap();
    assert!(
        storage
            .get_instance_secret(sid_core::models::InstanceSecret::AdminClaim)
            .await
            .unwrap()
            .is_some()
    );
    assert!(!storage.admin_exists().await.unwrap());

    let (storage, keys) = (store().await, keys);
    let mut root = sid_core::models::Profile::new(Some("root"));
    root.roles = vec!["admin".into()];
    storage
        .create_profile(&root, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    announce_admin_claim(&storage, &keys).await.unwrap();
    assert!(
        storage
            .get_instance_secret(sid_core::models::InstanceSecret::AdminClaim)
            .await
            .unwrap()
            .is_none()
    );
}

/// A store that cannot be read stops the start.
#[tokio::test]
async fn unreadable_store_stops_the_start() {
    let (storage, keys) = (store().await, keys());
    sqlx::query("DROP TABLE profiles")
        .execute(storage.pool())
        .await
        .unwrap();
    assert!(announce_admin_claim(&storage, &keys).await.is_err());
}
