use super::*;
use sid_storage::sqlite::SqliteBackend;

async fn service() -> OperationServiceImpl {
    OperationServiceImpl::new(Arc::new(SqliteBackend::new_in_memory().await.unwrap()))
}

/// An unauthenticated caller gets the current period; asking again within
/// its acceptance answers the same one, accepting new commands until after
/// now.
#[tokio::test]
async fn test_get_operation_period_answers_the_current_period() {
    let svc = service().await;
    let first = svc
        .get_operation_period(Request::new(GetOperationPeriodRequest {}))
        .await
        .unwrap()
        .into_inner();
    let again = svc
        .get_operation_period(Request::new(GetOperationPeriodRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(first.period > 0);
    assert_eq!(first, again);
    let until = first.accepted_until.expect("an acceptance bound");
    assert!(until.seconds > chrono::Utc::now().timestamp());
}
