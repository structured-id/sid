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

/// Without an evaluator address the evaluator runs in this server with the
/// epoch cutoff. A remote evaluator needs its resource, the token issuer,
/// this server's own client and the shared operation key; the cutoff is then
/// the evaluator's setting and is refused here. A partial configuration
/// stops the start rather than running history without its evaluator.
#[tokio::test]
async fn the_history_evaluator_runs_here_unless_a_remote_one_is_complete() {
    use crate::grpc::password_operation::PasswordHistoryAuthority;
    use std::env::VarError;

    let storage = store().await;
    let field_keys: Arc<dyn sid_keys::KeyManager> = Arc::new(keys());
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("caller.secret");
    std::fs::write(&secret, "caller-secret").unwrap();
    let operation_key = dir.path().join("operation.key");
    let complete = [
        (
            "SID_PASSWORD_HISTORY_EVALUATOR",
            "http://history.sid.example.com:50051".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE",
            "https://history.sid.example.com/".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_TOKEN_UPSTREAM",
            "http://sid.example.com:50051".to_owned(),
        ),
        (
            "SID_PASSWORD_OPERATION_KEY_FILE",
            operation_key.display().to_string(),
        ),
        (
            "SID_PASSWORD_HISTORY_CALLER_CLIENT_ID",
            "credential-service".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_CALLER_ISSUER",
            "https://sid.example.com/i/0123456789abcdef0123456789abcdef".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_CALLER_METHOD",
            "client_secret_basic".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_CALLER_SECRET_FILE",
            secret.display().to_string(),
        ),
    ];
    let authority = |missing: &str, extra: Option<(&str, &str)>| {
        let vars: Vec<(String, String)> = complete
            .iter()
            .filter(|(name, _)| *name != missing)
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .chain(extra.map(|(n, v)| (n.to_owned(), v.to_owned())))
            .collect();
        let storage = &storage;
        let field_keys = field_keys.clone();
        async move {
            password_history_authority(
                |name| {
                    vars.iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| value.clone())
                        .ok_or(VarError::NotPresent)
                },
                storage,
                field_keys,
                "https://sid.example.com",
            )
            .await
        }
    };

    let local = password_history_authority(
        |name| match name {
            "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE" => Ok("2026-10-01T12:00:00Z".into()),
            _ => Err(VarError::NotPresent),
        },
        &storage,
        field_keys.clone(),
        "https://sid.example.com",
    )
    .await
    .unwrap();
    assert!(matches!(
        local,
        PasswordHistoryAuthority::InProcess {
            epoch_cutoff: Some(_),
            ..
        }
    ));

    assert!(matches!(
        authority("", None).await.unwrap(),
        PasswordHistoryAuthority::Remote { .. }
    ));
    assert!(
        operation_key.exists(),
        "the shared operation key is a file of its own"
    );
    for (name, _) in &complete[1..] {
        assert!(authority(name, None).await.is_err(), "{name} is required");
    }
    assert!(
        authority(
            "",
            Some((
                "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE",
                "2026-10-01T12:00:00Z"
            ))
        )
        .await
        .is_err(),
        "the cutoff belongs to the remote evaluator"
    );
    // The evaluator's resource is an RFC 8707 indicator here as on the
    // evaluator: an invalid one stops the start instead of failing every
    // token request later.
    for invalid in ["", "history", "https://history.sid.example.com/#part"] {
        assert!(
            authority(
                "SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE",
                Some(("SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE", invalid))
            )
            .await
            .is_err(),
            "resource {invalid:?} was accepted"
        );
    }

    // An evaluator address that is set but unreadable is not "unset": the
    // start fails rather than handing this server the history keys.
    let unreadable = password_history_authority(
        |name| match name {
            "SID_PASSWORD_HISTORY_EVALUATOR" => Err(VarError::NotUnicode("\u{fffd}".into())),
            _ => Err(VarError::NotPresent),
        },
        &storage,
        field_keys.clone(),
        "https://sid.example.com",
    )
    .await;
    assert!(unreadable.is_err());
}

/// The server that holds the history keys serves the evaluator to a remote
/// credential service when it names that service's caller: it then admits
/// network preparation from that caller alone, for the evaluator's resource,
/// and seals operations with the key it shares with that service. Each of
/// the three settings needs the others; the address of a remote evaluator
/// excludes them.
#[tokio::test]
async fn the_history_evaluator_is_served_to_a_named_credential_service() {
    use crate::grpc::password_operation::PasswordHistoryAuthority;
    use std::env::VarError;

    let storage = store().await;
    let field_keys: Arc<dyn sid_keys::KeyManager> = Arc::new(keys());
    let dir = tempfile::tempdir().unwrap();
    let operation_key = dir.path().join("operation.key");
    let complete = [
        (
            "SID_PASSWORD_HISTORY_PREPARE_CALLER",
            "machine:credential-service".to_owned(),
        ),
        (
            "SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE",
            "https://history.sid.example.com/".to_owned(),
        ),
        (
            "SID_PASSWORD_OPERATION_KEY_FILE",
            operation_key.display().to_string(),
        ),
    ];
    let authority = |missing: &str, extra: Option<(&str, &str)>| {
        let vars: Vec<(String, String)> = complete
            .iter()
            .filter(|(name, _)| *name != missing)
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .chain(extra.map(|(n, v)| (n.to_owned(), v.to_owned())))
            .collect();
        let storage = &storage;
        let field_keys = field_keys.clone();
        async move {
            password_history_authority(
                |name| {
                    vars.iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| value.clone())
                        .ok_or(VarError::NotPresent)
                },
                storage,
                field_keys,
                "https://sid.example.com",
            )
            .await
        }
    };

    match authority("", None).await.unwrap() {
        PasswordHistoryAuthority::InProcess {
            serve: Some(serve), ..
        } => {
            assert_eq!(serve.caller, "machine:credential-service");
            assert_eq!(serve.resource.as_str(), "https://history.sid.example.com/");
        }
        _ => panic!("not served to the credential service"),
    }
    for (name, _) in &complete[1..] {
        assert!(authority(name, None).await.is_err(), "{name} is required");
    }
    assert!(
        authority(
            "",
            Some((
                "SID_PASSWORD_HISTORY_EVALUATOR",
                "http://history.sid.example.com:50051"
            ))
        )
        .await
        .is_err(),
        "a server is either the evaluator or its client"
    );
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
