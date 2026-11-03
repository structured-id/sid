use std::time::Duration;

use fred::types::CustomCommand;

use super::*;

#[test]
fn test_redis_cache_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RedisCacheBackend>();
}

fn redis_url() -> String {
    std::env::var("SID_TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:63799".to_string())
}

/// A client outside the backend, to act on the server.
async fn admin() -> Client {
    let client = Client::new(Config::from_url(&redis_url()).unwrap(), None, None, None);
    client.init().await.expect("the test cache is running");
    client
}

/// Close, from the server side, the connection named after `client`, as a
/// restart or a proxy closing an idle connection would.
async fn drop_connection_of(client: &str) {
    let admin = admin().await;
    let list: String = admin
        .custom(
            CustomCommand::new_static("CLIENT", None, false),
            vec!["LIST"],
        )
        .await
        .unwrap();
    let id = list
        .lines()
        .find(|line| {
            line.split(' ')
                .any(|field| field == format!("name={client}"))
        })
        .and_then(|line| line.split(' ').find_map(|field| field.strip_prefix("id=")))
        .unwrap_or_else(|| panic!("no connection named {client}"))
        .to_owned();
    let killed: i64 = admin
        .custom(
            CustomCommand::new_static("CLIENT", None, false),
            vec!["KILL", "ID", &id],
        )
        .await
        .unwrap();
    assert_eq!(killed, 1);
}

/// A dropped connection must not leave the cache unusable: a caller that
/// waits for an answer that never comes fails only at its own deadline (a UI
/// host's sign-in answered 504 that way with Redis up).
#[tokio::test]
async fn test_commands_work_after_the_connection_drops() {
    let cache = RedisCacheBackend::connect(&redis_url()).await.unwrap();
    let key = format!("test:reconnect:{}", uuid::Uuid::now_v7());
    cache
        .set(&key, b"before", Duration::from_secs(60))
        .await
        .unwrap();

    drop_connection_of(cache.client.id()).await;

    let written = tokio::time::timeout(
        Duration::from_secs(10),
        cache.set(&key, b"after", Duration::from_secs(60)),
    )
    .await;
    assert!(
        matches!(written, Ok(Ok(()))),
        "a write after the drop did not succeed: {written:?}"
    );
    assert_eq!(
        cache.get(&key).await.unwrap().as_deref(),
        Some(&b"after"[..])
    );
}

/// A subscription whose connection drops misses what was published in the
/// meantime, so its stream ends: a consumer such as the revocation cache
/// must learn of the gap instead of believing it received everything.
#[tokio::test]
async fn test_a_subscription_ends_when_its_connection_drops() {
    let channel = format!("test:subscription:{}", uuid::Uuid::now_v7());
    let client = subscriber(Config::from_url(&redis_url()).unwrap())
        .build()
        .unwrap();
    let name = client.id().to_owned();
    let mut received = subscribed(client, &channel).await.unwrap();

    drop_connection_of(&name).await;

    let ended = tokio::time::timeout(Duration::from_secs(10), received.recv()).await;
    assert!(
        matches!(ended, Ok(None)),
        "the stream did not end after its connection dropped: {ended:?}"
    );
}
