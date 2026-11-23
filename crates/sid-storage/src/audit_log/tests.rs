use super::*;

#[test]
fn test_generate_id_is_unique() {
    let id1 = PostgresAuditLog::generate_id();
    let id2 = PostgresAuditLog::generate_id();
    assert_ne!(id1, id2);
}

#[test]
fn test_generate_id_is_valid_uuid() {
    let id = PostgresAuditLog::generate_id();
    assert!(uuid::Uuid::parse_str(&id).is_ok());
}

/// A record stamped with a sub-microsecond clock (Linux) still verifies after
/// the round trip through `timestamptz`, which keeps microseconds only. The
/// hash was computed over nanoseconds the database never stored, so every
/// chain written on such a clock read back as broken.
#[tokio::test]
async fn test_a_nanosecond_clock_keeps_the_chain_verifiable() {
    let pool = crate::testing::prepared_storage_postgres()
        .await
        .pool()
        .clone();
    let chain_id = format!("profile:{}", uuid::Uuid::now_v7());
    let at = Timestamp::new(1_790_000_000, 123_456_789).expect("valid instant");

    let mut tx = pool.begin().await.unwrap();
    for _ in 0..2 {
        PostgresAuditLog::append_at(
            &mut tx,
            &chain_id,
            AuditEntry::system("test", "nanosecond clock"),
            at,
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let result = PostgresAuditLog::new(pool)
        .verify_chain(&chain_id)
        .await
        .unwrap();
    assert!(
        result.valid,
        "chain broken at {:?}",
        result.first_broken_record
    );
}
