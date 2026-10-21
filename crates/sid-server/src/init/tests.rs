// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_plugin::{CredentialStore, InstanceSecretStore};

/// The bundled bus serves the single-binary installation, which runs no
/// separate receiver: unset owes facts to nobody there, rather than to an
/// absent service whose work would pile up. On an external bus the receivers
/// are part of the deployment: unset stops startup instead of guessing. A
/// list names each receiver, `none` names none, and a name that is not an
/// address token stops startup instead of being dropped.
#[test]
fn required_receivers_from_setting() {
    use crate::embedded_nats::EventBusMode;
    let external = EventBusMode::External("nats://nats.sid.example.com:4222".into());
    let names = |mode: &EventBusMode, setting| {
        required_receivers(mode, setting)
            .unwrap()
            .into_iter()
            .map(|r| {
                assert!(r.event_types.is_empty(), "a receiver is owed every fact");
                r.recipient.to_string()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&EventBusMode::Embedded, None), Vec::<String>::new());
    assert_eq!(
        names(&EventBusMode::Embedded, Some(" ")),
        Vec::<String>::new()
    );
    assert!(
        required_receivers(&external, None).is_err(),
        "external unset"
    );
    assert!(
        required_receivers(&external, Some("")).is_err(),
        "external empty"
    );
    assert_eq!(names(&external, Some("none")), Vec::<String>::new());
    assert_eq!(
        names(&external, Some("sid-notify, audit-sink")),
        ["sid-notify", "audit-sink"]
    );
    assert_eq!(
        names(&EventBusMode::Embedded, Some("sid-notify")),
        ["sid-notify"]
    );
    for invalid in ["sid.notify", "a,,b", "sid-notify,*"] {
        assert!(
            required_receivers(&external, Some(invalid)).is_err(),
            "{invalid}"
        );
    }
}

/// The in-process bus keeps no addressed work, so a receiver named for it
/// would be owed facts nothing can ever hand over: naming one stops startup.
/// Unset and `none` name none, as on the bundled bus.
#[test]
fn in_process_bus_takes_no_required_receivers() {
    use crate::embedded_nats::EventBusMode;
    let mode = EventBusMode::InProcess;
    for none in [None, Some(""), Some(" "), Some("none")] {
        assert!(
            required_receivers(&mode, none).unwrap().is_empty(),
            "{none:?}"
        );
    }
    for named in ["sid-notify", " scim-outbound ", "sid-notify, audit-sink"] {
        let refused = required_receivers(&mode, Some(named))
            .expect_err("a receiver needs a durable bus")
            .to_string();
        assert!(refused.contains("in-process"), "{named}: {refused}");
    }
}

/// A separate history evaluator reports its cleanup settlements on the bus
/// as addressed work; the in-process bus cannot carry them, so that pairing
/// stops startup instead of retrying the consumer forever. The in-process
/// evaluator needs no bus, and both NATS modes carry the settlements.
#[test]
fn a_separate_history_evaluator_needs_a_durable_bus() {
    use crate::embedded_nats::EventBusMode;
    let external = EventBusMode::External("nats://nats.sid.example.com:4222".into());
    assert!(bus_carries_history_evaluator(&EventBusMode::InProcess, false).is_ok());
    let refused = bus_carries_history_evaluator(&EventBusMode::InProcess, true)
        .expect_err("settlements need a durable bus")
        .to_string();
    assert!(
        refused.contains("SID_PASSWORD_HISTORY_EVALUATOR"),
        "{refused}"
    );
    for mode in [EventBusMode::Embedded, external] {
        assert!(bus_carries_history_evaluator(&mode, true).is_ok());
        assert!(bus_carries_history_evaluator(&mode, false).is_ok());
    }
}

/// A generated key goes to a new file only: an existing key is never
/// overwritten, and a private key is readable by its owner alone.
#[test]
fn a_generated_key_file_is_new_and_private_keys_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("jwt_private.pem");
    let public = dir.path().join("jwt_public.pem");
    write_new_key_file(private.to_str().unwrap(), b"private", true).unwrap();
    write_new_key_file(public.to_str().unwrap(), b"public", false).unwrap();
    assert_eq!(std::fs::read(&private).unwrap(), b"private");
    assert!(
        write_new_key_file(private.to_str().unwrap(), b"other", true).is_err(),
        "an existing key is kept"
    );
    assert_eq!(std::fs::read(&private).unwrap(), b"private");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&private), 0o600);
        assert_ne!(mode(&public) & 0o044, 0, "the public key stays readable");
    }
}

/// The first start makes a matching pair, a later start keeps the pair it
/// finds, and a half pair (one file without the other, e.g. after a partial
/// restore) stops startup without writing anything: generating the missing
/// half would pair it with an unrelated key, and tokens the server signs
/// would not verify against the public key it advertises.
#[test]
fn the_jwt_key_pair_is_made_whole_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("jwt_private.pem");
    let public = dir.path().join("jwt_public.pem");
    let (private_path, public_path) = (private.to_str().unwrap(), public.to_str().unwrap());

    assert!(ensure_jwt_key_pair(private_path, public_path).unwrap());
    let (made_private, made_public) = (
        std::fs::read(&private).unwrap(),
        std::fs::read(&public).unwrap(),
    );
    sid_authn::jwt::JwtService::new(
        &made_private,
        &made_public,
        "https://sid.example.com".into(),
    )
    .expect("the pair matches");
    assert!(!ensure_jwt_key_pair(private_path, public_path).unwrap());
    assert_eq!(
        std::fs::read(&private).unwrap(),
        made_private,
        "kept as found"
    );

    std::fs::remove_file(&private).unwrap();
    let refused = ensure_jwt_key_pair(private_path, public_path)
        .expect_err("half a pair")
        .to_string();
    assert!(
        refused.contains(private_path) && refused.contains(public_path),
        "{refused}"
    );
    assert!(!private.exists(), "nothing written");
    assert_eq!(std::fs::read(&public).unwrap(), made_public);

    std::fs::remove_file(&public).unwrap();
    std::fs::write(&private, &made_private).unwrap();
    assert!(ensure_jwt_key_pair(private_path, public_path).is_err());
    assert!(!public.exists(), "nothing written");
}

/// Work already addressed to a receiver (a delivery, or a fan-out plan that
/// names receivers) can only be handed over by a durable bus: switching an
/// installation holding it to the in-process bus would leave it retrying
/// forever, so it is counted and startup refuses. Ended work, plans with no
/// receiver and other kinds are not owed to anyone.
#[test]
fn addressed_work_still_owed_is_counted() {
    use sid_core::models::event::{
        EVENT_DELIVERY_KIND, EVENT_FANOUT_KIND, EventDelivery, EventFanout, WorkRecipient,
    };
    use sid_core::models::{WorkId, WorkKind, WorkRecord, WorkSnapshot, WorkState};
    let snapshot = |kind: &str, state: WorkState, payload: Vec<u8>| WorkSnapshot {
        record: WorkRecord {
            id: WorkId(uuid::Uuid::now_v7()),
            kind: WorkKind::new(kind).unwrap(),
            state,
            attempts: 0,
            max_attempts: 5,
            generation: 0,
            last_error: None,
            ambiguous: false,
            result: None,
            not_before: chrono::Utc::now(),
            expires_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        },
        payload,
    };
    let notify = WorkRecipient::new("sid-notify").unwrap();
    let event = sid_core::models::event::Event::new("test", "sid.session.revoked.v1");
    let delivery = serde_json::to_vec(&EventDelivery {
        recipient: notify.clone(),
        event: event.clone(),
    })
    .unwrap();
    let plan = |receivers: Vec<WorkRecipient>| {
        serde_json::to_vec(&EventFanout {
            event: event.clone(),
            receivers,
        })
        .unwrap()
    };

    assert_eq!(owed_addressed_work(&[]), 0);
    let owed = [
        snapshot(EVENT_DELIVERY_KIND, WorkState::Pending, delivery.clone()),
        snapshot(EVENT_DELIVERY_KIND, WorkState::Claimed, delivery.clone()),
        snapshot(
            EVENT_FANOUT_KIND,
            WorkState::Pending,
            plan(vec![notify.clone()]),
        ),
    ];
    assert_eq!(owed_addressed_work(&owed), 3);
    let not_owed = [
        snapshot(EVENT_DELIVERY_KIND, WorkState::Completed, delivery.clone()),
        snapshot(EVENT_DELIVERY_KIND, WorkState::Failed, delivery),
        snapshot(EVENT_FANOUT_KIND, WorkState::Pending, plan(Vec::new())),
        snapshot("backchannel.logout", WorkState::Pending, b"{}".to_vec()),
    ];
    assert_eq!(owed_addressed_work(&not_owed), 0);
}

/// The in-process bus holds an exclusive lock beside its database for the
/// life of the process: a second process opening the same file with it is
/// refused, so no two processes publish each other's facts to nobody. The
/// lock frees when its holder ends.
#[test]
fn the_in_process_bus_holds_its_database_alone() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("auth.db");
    let database = database.to_str().unwrap();
    let held = hold_single_process(database).expect("first holder");
    let refused = hold_single_process(database)
        .expect_err("a second holder")
        .to_string();
    assert!(refused.contains("another process"), "{refused}");
    drop(held);
    hold_single_process(database).expect("free again after its holder ended");
}

/// The in-process bus reaches the subscribers of one process only. Over
/// storage several replicas share (PostgreSQL), the replica that claims a
/// fact's fan-out would publish it to its own subscribers alone and the
/// others would silently miss it, so that pairing stops startup. A SQLite
/// file serves one process, and both NATS modes reach every replica.
#[test]
fn the_in_process_bus_needs_single_process_storage() {
    use crate::embedded_nats::EventBusMode;
    assert!(bus_fits_storage(&EventBusMode::InProcess, false).is_ok());
    let refused = bus_fits_storage(&EventBusMode::InProcess, true)
        .expect_err("replicas would miss live events")
        .to_string();
    assert!(refused.contains("in-process"), "{refused}");
    let external = EventBusMode::External("nats://nats.sid.example.com:4222".into());
    for mode in [EventBusMode::Embedded, external] {
        assert!(bus_fits_storage(&mode, true).is_ok());
        assert!(bus_fits_storage(&mode, false).is_ok());
    }
}

/// The SQLite file is named by `SID_STORAGE_SQLITE_PATH`. The old name
/// `SID_SQLITE_PATH` is refused rather than ignored: ignoring it would open
/// the default file and start a deployment that set it as a new one.
#[test]
fn sqlite_path_refuses_the_old_setting_name() {
    assert!(refuse_renamed_setting(None).is_ok());
    let refused = refuse_renamed_setting(Some("/data/old.db"))
        .expect_err("the old name is not read")
        .to_string();
    assert!(refused.contains("SID_STORAGE_SQLITE_PATH"), "{refused}");
}

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
    assert!(zkpp_settings(Ok("false".into()), Ok("false".into()), Err(NotPresent)).is_err());
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

/// Proofs are required unless `SID_ZKPP_SKIP_PROOF` explicitly says true/1:
/// an unset flag, false/0 keep them required, and an empty or unknown value
/// stops startup, so no mistyped or blank setting weakens the default.
#[test]
fn zkpp_settings_require_proofs_unless_explicitly_skipped() {
    use std::env::VarError::NotPresent;
    let settings = zkpp_settings(Err(NotPresent), Err(NotPresent), Err(NotPresent)).unwrap();
    assert!(settings.enabled());
    assert!(settings.config().require_proof);
    assert_eq!(settings.config().policy_version, 1);
    for skip in ["true", "1"] {
        let settings = zkpp_settings(Err(NotPresent), Ok(skip.into()), Err(NotPresent)).unwrap();
        assert!(settings.enabled());
        assert!(!settings.config().require_proof);
    }
    for keep in ["false", "0"] {
        let settings = zkpp_settings(Err(NotPresent), Ok(keep.into()), Err(NotPresent)).unwrap();
        assert!(settings.config().require_proof);
    }
    for unclear in ["", " ", "yes", "TRUE", "off"] {
        assert!(
            zkpp_settings(Err(NotPresent), Ok(unclear.into()), Err(NotPresent)).is_err(),
            "{unclear:?} must stop startup"
        );
    }
}

/// Without verifiers no proof can be checked: that is accepted only with an
/// explicit skip, never by turning the verifiers off alone.
#[test]
fn disabled_verifiers_need_an_explicit_skip() {
    use std::env::VarError::NotPresent;
    assert!(zkpp_settings(Ok("false".into()), Err(NotPresent), Err(NotPresent)).is_err());
    assert!(zkpp_settings(Ok("false".into()), Ok("false".into()), Err(NotPresent)).is_err());
    let settings = zkpp_settings(Ok("false".into()), Ok("true".into()), Err(NotPresent)).unwrap();
    assert!(!settings.enabled() && !settings.config().require_proof);
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

/// Without an evaluator address the evaluator runs in this server over its
/// local store. With one, this server calls the separate evaluator's
/// internal listener and opens no evaluator store; a malformed address stops
/// the start. The history write cutoff setting is raised into this server's
/// own durable cutoff in both cases, and into the in-process evaluator's; an
/// earlier setting lowers neither.
#[tokio::test]
async fn the_history_evaluator_runs_here_unless_a_remote_one_is_named() {
    use sid_authn::password_operation::PasswordHistoryAuthority;
    use std::env::VarError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let storage = store().await;
    let opened = AtomicUsize::new(0);
    let local = || {
        opened.fetch_add(1, Ordering::SeqCst);
        let store: Arc<dyn sid_plugin::history_keys::HistoryKeyStore> =
            Arc::new(storage.history_keys());
        async move { Ok(store) }
    };
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("master.key");
    let complete = [(
        "SID_PASSWORD_HISTORY_EVALUATOR",
        "http://history.sid.example.com:50051".to_owned(),
    )];
    let authority = |missing: &str, extra: Option<(&str, &str)>| {
        let vars: Vec<(String, String)> = complete
            .iter()
            .filter(|(name, _)| *name != missing)
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .chain(extra.map(|(n, v)| (n.to_owned(), v.to_owned())))
            .collect();
        let master = &master;
        let storage = &storage;
        async move {
            password_history_authority(
                |name| {
                    vars.iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| value.clone())
                        .ok_or(VarError::NotPresent)
                },
                storage,
                local,
                master,
            )
            .await
        }
    };
    let at = |instant: &str| {
        chrono::DateTime::parse_from_rfc3339(instant)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    // The credential cutoff in force: an earlier raise changes nothing and
    // reports it.
    let credential_cutoff = async || {
        storage
            .raise_history_write_cutoff(
                at("2000-01-01T00:00:00Z"),
                AuditEntry::system("test", "cutoff").into(),
            )
            .await
            .unwrap()
    };

    let here = password_history_authority(
        |name| match name {
            "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE" => Ok("2026-10-01T12:00:00Z".into()),
            _ => Err(VarError::NotPresent),
        },
        &storage,
        local,
        &master,
    )
    .await
    .unwrap();
    let PasswordHistoryAuthority::InProcess { store, .. } = here else {
        panic!("the evaluator runs here");
    };
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    // Its keys are sealed under versions its own store records, not the
    // credential service's field-key versions.
    assert_eq!(store.list_key_versions().await.unwrap().len(), 1);
    assert_eq!(credential_cutoff().await, at("2026-10-01T12:00:00Z"));
    assert_eq!(
        store.write_cutoff().await.unwrap(),
        Some(at("2026-10-01T12:00:00Z"))
    );

    assert!(matches!(
        authority("", None).await.unwrap(),
        PasswordHistoryAuthority::Remote(_)
    ));
    assert_eq!(
        opened.load(Ordering::SeqCst),
        1,
        "a client of a remote evaluator opens no evaluator store"
    );
    // A client of a remote evaluator fences its own commits: a later
    // cutoff is raised here too, and an earlier setting lowers nothing.
    assert!(
        authority(
            "",
            Some((
                "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE",
                "2026-10-02T12:00:00Z"
            ))
        )
        .await
        .is_ok()
    );
    assert_eq!(credential_cutoff().await, at("2026-10-02T12:00:00Z"));
    assert!(
        authority(
            "",
            Some((
                "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE",
                "2026-09-01T12:00:00Z"
            ))
        )
        .await
        .is_ok()
    );
    assert_eq!(
        credential_cutoff().await,
        at("2026-10-02T12:00:00Z"),
        "an earlier setting lowers nothing"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    // An evaluator address that is not a gRPC endpoint stops the start
    // instead of failing every preparation later.
    assert!(
        authority(
            "SID_PASSWORD_HISTORY_EVALUATOR",
            Some(("SID_PASSWORD_HISTORY_EVALUATOR", "not an address"))
        )
        .await
        .is_err(),
        "a malformed evaluator address was accepted"
    );

    // An evaluator address that is set but unreadable is not "unset": the
    // start fails rather than handing this server the history keys.
    let unreadable = password_history_authority(
        |name| match name {
            "SID_PASSWORD_HISTORY_EVALUATOR" => Err(VarError::NotUnicode("\u{fffd}".into())),
            _ => Err(VarError::NotPresent),
        },
        &storage,
        local,
        &master,
    )
    .await;
    assert!(unreadable.is_err());
}

/// A database restored from a snapshot taken before a cutoff carries no
/// cutoff of its own; the deployment's setting, kept outside the snapshot,
/// restores it at start before anything is served: a history commit under a
/// key created before it is refused again, in the credential store and the
/// evaluator's, while a replacement prepared under a later key applies.
#[tokio::test]
async fn a_restored_database_gets_the_configured_cutoff_back() {
    use sid_core::models::{
        Credential, CredentialData, CredentialType, HistoryCommit, HistoryEpochDescriptor,
        HistoryEpochId, HistoryEvidence, HistoryKsf, HistorySuite, Profile,
    };

    let storage = store().await;
    let ctx = || AuditEntry::system("test", "restore").into();
    let profile = Profile::new(Some("restored"));
    storage.create_profile(&profile, ctx()).await.unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"p0".to_vec(), None);
    storage.create_credential(&password, ctx()).await.unwrap();
    let at = |instant: &str| {
        chrono::DateTime::parse_from_rfc3339(instant)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let epoch = |created_at| HistoryEpochDescriptor {
        id: HistoryEpochId::generate(),
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [1; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [2; 32],
        created_at,
    };
    let withdrawn = epoch(at("2026-09-01T00:00:00Z"));
    let commit = |revision, epochs: Vec<HistoryEpochDescriptor>| HistoryCommit {
        owner: profile.id,
        expected_revision: revision,
        entries: vec![(epochs[0].id, [revision as u8; 32])],
        epochs,
        evidence: HistoryEvidence {
            operation: uuid::Uuid::now_v7(),
            policy_version: 1,
        },
        depth: 3,
        max_age_days: 0,
    };
    let next = |data: &[u8]| {
        let mut new = password.clone();
        new.data = CredentialData::new(data.to_vec());
        new
    };
    // The snapshot: history written before the cutoff, no cutoff recorded.
    assert!(
        storage
            .change_password(
                password.id,
                b"p0",
                &next(b"p1"),
                Some(&commit(0, vec![withdrawn])),
                ctx()
            )
            .await
            .unwrap()
    );

    let master_dir = tempfile::tempdir().unwrap();
    let authority = password_history_authority(
        |name| match name {
            "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE" => Ok("2026-10-01T00:00:00Z".into()),
            _ => Err(std::env::VarError::NotPresent),
        },
        &storage,
        || {
            let store: Arc<dyn sid_plugin::history_keys::HistoryKeyStore> =
                Arc::new(storage.history_keys());
            async move { Ok(store) }
        },
        &master_dir.path().join("master.key"),
    )
    .await
    .unwrap();
    let sid_authn::password_operation::PasswordHistoryAuthority::InProcess { store, .. } =
        authority
    else {
        panic!("the evaluator runs here");
    };
    assert_eq!(
        store.write_cutoff().await.unwrap(),
        Some(at("2026-10-01T00:00:00Z"))
    );

    let err = storage
        .change_password(
            password.id,
            b"p1",
            &next(b"p2"),
            Some(&commit(1, vec![withdrawn])),
            ctx(),
        )
        .await
        .expect_err("a commit under the withdrawn key after the restore");
    assert!(matches!(err, sid_core::Error::Fenced(_)), "{err:?}");
    let current = epoch(at("2026-10-02T00:00:00Z"));
    assert!(
        storage
            .change_password(
                password.id,
                b"p1",
                &next(b"p2"),
                Some(&commit(1, vec![current, withdrawn])),
                ctx()
            )
            .await
            .unwrap()
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

/// A centrally managed start removes a claim stored earlier and opens none,
/// starts again unchanged, and keeps the policy when started unset.
#[tokio::test]
async fn central_start_offers_no_claim() {
    let (storage, keys) = (store().await, keys());
    announce_admin_claim(&storage, &keys).await.unwrap();
    apply_bootstrap_policy(&storage, Some("central"))
        .await
        .unwrap();
    announce_admin_claim(&storage, &keys).await.unwrap();
    let claim = || async {
        storage
            .get_instance_secret(sid_core::models::InstanceSecret::AdminClaim)
            .await
            .unwrap()
    };
    assert!(claim().await.is_none());

    for setting in [Some("central"), None] {
        apply_bootstrap_policy(&storage, setting).await.unwrap();
        announce_admin_claim(&storage, &keys).await.unwrap();
        assert!(claim().await.is_none(), "{setting:?}");
    }
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        sid_core::models::BootstrapPolicy::CentrallyManaged
    );
}

/// A centrally managed installation never starts self-managed, and a claimed
/// self-managed one never starts centrally managed; neither start changes it.
#[tokio::test]
async fn start_refuses_a_policy_change() {
    let (storage, _) = (store().await, keys());
    apply_bootstrap_policy(&storage, Some("central"))
        .await
        .unwrap();
    assert!(
        apply_bootstrap_policy(&storage, Some("self"))
            .await
            .is_err()
    );
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        sid_core::models::BootstrapPolicy::CentrallyManaged
    );

    let storage = store().await;
    let mut root = sid_core::models::Profile::new(Some("root"));
    root.roles = vec!["admin".into()];
    storage
        .create_profile(&root, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    assert!(
        apply_bootstrap_policy(&storage, Some("central"))
            .await
            .is_err()
    );
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        sid_core::models::BootstrapPolicy::SelfManaged
    );
}

/// An unset setting is none; one that is no text stops the start, naming it,
/// rather than reading as unset: an unset management setting would let a
/// self-managed claim open, an unset cookie name would share the default
/// cookie with another authority on the host.
#[test]
fn setting_refuses_non_text() {
    const NAME: &str = "SID_BROWSER_SESSION_COOKIE";
    assert_eq!(
        setting(NAME, Err(std::env::VarError::NotPresent)).unwrap(),
        None
    );
    assert_eq!(
        setting(NAME, Ok("central".into())).unwrap().as_deref(),
        Some("central")
    );
    let error = setting(
        NAME,
        Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "x",
        ))),
    )
    .expect_err("a value that is no text was read as unset");
    assert!(error.to_string().contains(NAME), "{error}");
}

/// A setting other than `central` or `self` stops the start.
#[tokio::test]
async fn unknown_policy_setting_stops_the_start() {
    let storage = store().await;
    for setting in ["Central", "", "managed"] {
        assert!(
            apply_bootstrap_policy(&storage, Some(setting))
                .await
                .is_err(),
            "{setting:?}"
        );
    }
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
