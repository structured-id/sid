use super::*;

/// A hold that ran out stays out: the event may already be another
/// replica's, and a late renewal the server accepts must not hand it back.
#[test]
fn an_expired_hold_is_never_renewed() {
    let now = tokio::time::Instant::now();
    let second = std::time::Duration::from_secs(1);
    assert!(may_renew(now + second, now), "a live hold is renewed");
    assert!(!may_renew(now, now), "a hold ending now was renewed");
    assert!(!may_renew(now - second, now), "an expired hold was renewed");
}

/// An existing durable that strips payloads would have every piece of work
/// settled as malformed, and one whose redelivery follows a backoff instead
/// of the acknowledgement wait would hand a held event to another replica
/// before its hold ends: both are refused like any other differing setting.
#[test]
fn a_durable_that_strips_payloads_or_backs_off_is_refused() {
    use jetstream::consumer::IntoConsumerConfig;
    let wanted = jetstream::consumer::pull::Config {
        durable_name: Some("receiver".into()),
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        ack_wait: std::time::Duration::from_secs(30),
        max_deliver: -1,
        filter_subjects: vec!["sid.work.identity.receiver.>".into()],
        ..Default::default()
    };
    let same = wanted.clone().into_consumer_config();
    assert_eq!(durable_differs(&same, &wanted), None);

    let mut headers_only = same.clone();
    headers_only.headers_only = true;
    assert_eq!(
        durable_differs(&headers_only, &wanted),
        Some("payload delivery")
    );

    let mut backoff = same;
    backoff.backoff = vec![std::time::Duration::from_secs(1)];
    assert_eq!(
        durable_differs(&backoff, &wanted),
        Some("redelivery backoff")
    );
}
