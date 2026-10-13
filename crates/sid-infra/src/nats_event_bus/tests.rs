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
