// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::binding_passport::AssuranceLevel;

fn held(until: i64) -> HeldAnchors {
    HeldAnchors {
        revision: 1,
        anchors: vec![vec![1; 8]],
        // The view keeps results; status is checked before one is kept.
        status: vec![sid_plugin::platform_ca::AnchorStatus::default()],
        until,
        renew_at: until,
    }
}

/// The view of a held answer ending at `until`, read again then.
fn view(until: i64) -> AnchorView {
    AnchorView::new(held(until), until)
}

// A view read again before the held answer ends (to ask the source for a
// newer set) bounds its results to that moment too, and never extends past
// the held answer.
#[tokio::test]
async fn a_view_renewed_early_bounds_its_results() {
    let renewed = AnchorView::new(held(1_000), 400);
    renewed
        .keep(Box::from(&b"k"[..]), passport(1), 900, 100)
        .await;
    assert_eq!(renewed.reused(b"k", 399).await, Some(passport(1)));
    assert!(!renewed.current(400));
    assert!(!AnchorView::new(held(300), 10_000).current(300));
}

fn passport(n: u8) -> Passport {
    Passport {
        binding_id: uuid::Uuid::from_bytes([n; 16]),
        source_org: Some(uuid::Uuid::from_bytes([2; 16])),
        recipient_org: uuid::Uuid::from_bytes([3; 16]),
        merkle_root: [n; 32],
        instance_id: "sid.example.com".into(),
        assurance_level: AssuranceLevel::Loa1,
    }
}

// A result is reused before its own end and not from that second on.
#[tokio::test]
async fn a_result_holds_until_its_end() {
    let view = view(1_000);
    view.keep(Box::from(&b"k"[..]), passport(1), 500, 100).await;
    assert_eq!(view.reused(b"k", 499).await, Some(passport(1)));
    assert_eq!(view.reused(b"k", 500).await, None);
    assert_eq!(view.reused(b"other", 100).await, None);
}

// The view's own end bounds a result whose certificates last longer: a
// result never outlives the anchor answer it rested on.
#[tokio::test]
async fn a_result_never_outlives_its_view() {
    let view = view(300);
    view.keep(Box::from(&b"k"[..]), passport(1), 10_000, 100)
        .await;
    assert_eq!(view.reused(b"k", 299).await, Some(passport(1)));
    assert_eq!(view.reused(b"k", 300).await, None);
    assert!(view.current(299));
    assert!(!view.current(300));
}

// Past the bound an ended result goes first, then the one ending soonest;
// the others stay reusable.
#[tokio::test]
async fn the_bound_drops_the_soonest_ending_result() {
    let view = view(i64::MAX);
    for n in 0..MAX_PATHS {
        let key = (n as u64).to_be_bytes();
        view.keep(Box::from(&key[..]), passport(1), 1_000 + n as i64, 0)
            .await;
    }
    view.keep(Box::from(&b"new"[..]), passport(2), 5_000, 0)
        .await;
    assert_eq!(view.reused(&0u64.to_be_bytes(), 1).await, None);
    assert_eq!(view.reused(&1u64.to_be_bytes(), 1).await, Some(passport(1)));
    assert_eq!(view.reused(b"new", 1).await, Some(passport(2)));
}

// Every input the acceptance depends on is part of the key, and the parts
// cannot run into each other: the allocation, the recipient, and where the
// passport ends and the chain begins.
#[test]
fn the_key_separates_every_input() {
    let recipient = uuid::Uuid::from_bytes([3; 16]);
    let base = key(0, recipient, b"ab", &[b"c".to_vec()]);
    assert_ne!(base, key(1, recipient, b"ab", &[b"c".to_vec()]));
    assert_ne!(
        base,
        key(0, uuid::Uuid::from_bytes([4; 16]), b"ab", &[b"c".to_vec()])
    );
    assert_ne!(base, key(0, recipient, b"a", &[b"bc".to_vec()]));
    assert_ne!(base, key(0, recipient, b"abc", &[]));
    assert_eq!(base, key(0, recipient, b"ab", &[b"c".to_vec()]));
}
