use super::*;

fn recipient(name: &str) -> WorkRecipient {
    WorkRecipient::new(name).unwrap()
}

/// The event type keeps its tokens after the family prefix; a pattern or a
/// type outside the catalogue's naming has no subject.
#[test]
fn test_subjects_keep_the_type() {
    let t = Topology::default();
    assert_eq!(
        t.history_subject("sid.session.revoked.v1").as_deref(),
        Some("sid.events.identity.session.revoked.v1")
    );
    assert_eq!(
        t.work_subject(&recipient("sid-notify"), "sid.session.revoked.v1")
            .as_deref(),
        Some("sid.work.identity.sid-notify.session.revoked.v1")
    );
    for not_a_type in ["sid.", "sid.user.*", "sid.>", "other.v1", "sid.a b.v1"] {
        assert_eq!(t.history_subject(not_a_type), None, "{not_a_type}");
    }
}

/// Type patterns become subject filters with the same meaning: a trailing
/// `*` takes any suffix (several tokens), nothing outside the catalogue.
#[test]
fn test_filters_translate_patterns() {
    let t = Topology::default();
    assert_eq!(t.history_filters(&[]).unwrap(), ["sid.events.identity.>"]);
    assert_eq!(
        t.history_filters(&["sid.user.*".into(), "sid.session.created.v1".into()])
            .unwrap(),
        [
            "sid.events.identity.user.>",
            "sid.events.identity.session.created.v1"
        ]
    );
    assert_eq!(
        t.history_filters(&["sid.security.>".into()]).unwrap(),
        ["sid.events.identity.security.>"]
    );
    assert_eq!(
        t.work_filters(&recipient("r"), &[]).unwrap(),
        ["sid.work.identity.r.>"]
    );
    assert!(t.history_filters(&["user.*".into()]).is_err());
}

/// History and work never share a subject, and the work stream keeps its
/// messages regardless of age, refuses new ones when full and allows no
/// purge or delete.
#[test]
fn test_stream_definitions() {
    let t = Topology::default();
    let history = t.history_config();
    let work = t.work_config();
    assert_eq!(history.name, "SID_IDENTITY_EVENTS");
    assert_eq!(history.subjects, ["sid.events.identity.>"]);
    assert_eq!(history.retention, stream::RetentionPolicy::Limits);
    assert_eq!(history.max_age, t.history_max_age);
    assert_eq!(work.name, "SID_IDENTITY_WORK");
    assert_eq!(work.subjects, ["sid.work.identity.>"]);
    assert_eq!(work.retention, stream::RetentionPolicy::WorkQueue);
    assert_eq!(work.storage, stream::StorageType::File);
    assert_eq!(work.max_age, Duration::ZERO);
    assert_eq!(work.discard, stream::DiscardPolicy::New);
    assert!(work.max_messages > 0 && work.max_bytes > 0);
    assert!(work.deny_delete && work.deny_purge);
    assert!(!work.allow_message_ttl && !work.allow_rollup);
    assert_eq!(
        work.metadata.get(VERSION_KEY).map(String::as_str),
        Some("1")
    );
    assert_eq!(differs(&work, &work), None);
    let mut aged = work.clone();
    aged.max_age = Duration::from_secs(60);
    assert_eq!(differs(&aged, &work).as_deref(), Some("max_age"));
}

/// Every control that can remove a message unsettled is part of the
/// definition: a stream that allows per-message TTL or rollup differs.
#[test]
fn test_removal_controls_are_compared() {
    let work = Topology::default().work_config();
    let mut ttl = work.clone();
    ttl.allow_message_ttl = true;
    assert_eq!(differs(&ttl, &work).as_deref(), Some("allow_message_ttl"));
    let mut rollup = work.clone();
    rollup.allow_rollup = true;
    assert_eq!(differs(&rollup, &work).as_deref(), Some("allow_rollup"));
}

/// A subject root is one token; stream names follow it.
#[test]
fn test_root_is_one_token() {
    let t = Topology::with_root("t-1a").unwrap();
    assert_eq!(t.history_stream(), "T_1A_IDENTITY_EVENTS");
    assert_eq!(
        t.history_subject("sid.user.created.v1").as_deref(),
        Some("t-1a.events.identity.user.created.v1")
    );
    for invalid in ["", "a.b", "a>", "a*"] {
        assert!(Topology::with_root(invalid).is_err(), "{invalid:?}");
    }
}

/// Distinct roots never share stream names: a root another one would be
/// written as (upper case, `_` for `-`) is refused, so `team-a` and `sid`
/// keep their streams to themselves.
#[test]
fn test_roots_never_share_stream_names() {
    for ambiguous in ["SID", "Team-a", "team_a"] {
        assert!(
            Topology::with_root(ambiguous).is_err(),
            "{ambiguous:?} would share its streams with another root"
        );
    }
    assert_ne!(
        Topology::with_root("team-a").unwrap().history_stream(),
        Topology::with_root("teama").unwrap().history_stream()
    );
}
