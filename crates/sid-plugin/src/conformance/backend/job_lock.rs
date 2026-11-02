// SPDX-License-Identifier: AGPL-3.0-only
//! Background job locks: one holder at a time across every instance that
//! shares the store.

use sid_plugin::storage::StorageBackend;

/// A job number no other test uses.
fn unique_job() -> i64 {
    i64::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap()) & i64::MAX
}

/// Two instances `a` and `b` on one store: while `a` holds a job's lock, `b`
/// cannot take it; once `a` releases it, `b` can, and after `b` releases it
/// `a` can again. Repeated rounds catch a release that frees nothing.
pub async fn test_job_lock_exclusive_across_instances<B: StorageBackend>(a: &B, b: &B) {
    let job = unique_job();
    for round in 0..3 {
        let held = a.try_job_lock(job).await.unwrap();
        assert!(held.is_some(), "round {round}: a free job lock was refused");
        assert!(
            b.try_job_lock(job).await.unwrap().is_none(),
            "round {round}: a second instance took a held job lock"
        );
        held.unwrap().release().await.unwrap();

        let held = b.try_job_lock(job).await.unwrap();
        assert!(
            held.is_some(),
            "round {round}: a released job lock stayed held"
        );
        assert!(
            a.try_job_lock(job).await.unwrap().is_none(),
            "round {round}: the first instance took a held job lock"
        );
        held.unwrap().release().await.unwrap();
    }
}

/// A holder that goes away without releasing (a crash, a dropped guard) does
/// not keep the job from running forever.
pub async fn test_dropped_job_lock_is_freed<B: StorageBackend>(a: &B, b: &B) {
    let job = unique_job();
    let held = a.try_job_lock(job).await.unwrap();
    assert!(held.is_some());
    drop(held);

    // Freeing a dropped lock may happen in the background; give it a moment.
    for _ in 0..50 {
        if let Some(lock) = b.try_job_lock(job).await.unwrap() {
            lock.release().await.unwrap();
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("a dropped job lock was never freed");
}

/// Different jobs do not exclude each other.
pub async fn test_job_locks_are_per_job<B: StorageBackend>(a: &B, b: &B) {
    let first = a.try_job_lock(unique_job()).await.unwrap();
    let second = b.try_job_lock(unique_job()).await.unwrap();
    assert!(first.is_some() && second.is_some());
    first.unwrap().release().await.unwrap();
    second.unwrap().release().await.unwrap();
}
