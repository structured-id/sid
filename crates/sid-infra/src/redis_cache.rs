// SPDX-License-Identifier: AGPL-3.0-only
//! Redis/Dragonfly cache backend.
//!
//! Production CacheBackend implementation using `fred` async Redis client.
//! Compatible with Redis 6+, Valkey, and Dragonfly.

use async_trait::async_trait;
use fred::interfaces::{ClientLike, EventInterface, KeysInterface, PubsubInterface};
use fred::prelude::*;
use fred::types::ExpireOptions;
use sid_plugin::cache::{CacheBackend, CacheError, CacheResult};
use std::time::Duration;
use tokio::sync::mpsc;

/// Redis-backed distributed cache.
///
/// Supports key-value caching with TTL and pub/sub for cross-instance invalidation.
pub struct RedisCacheBackend {
    client: Client,
}

impl RedisCacheBackend {
    /// Connect to Redis server.
    ///
    /// `redis_url` format: `redis://host:port` or `redis://user:pass@host:port/db`
    pub async fn connect(redis_url: &str) -> CacheResult<Self> {
        let config = Config::from_url(redis_url)
            .map_err(|e| CacheError::Connection(format!("invalid Redis URL: {e}")))?;

        let client = Client::new(config, None, None, None);
        client
            .init()
            .await
            .map_err(|e| CacheError::Connection(format!("Redis connect: {e}")))?;

        Ok(Self { client })
    }

    /// Create from an existing connected client (for testing/custom configs).
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }
}

/// The bytes of a string reply; `None` for a missing key.
fn value_bytes(value: Value) -> Option<Vec<u8>> {
    match value {
        Value::Null => None,
        Value::Bytes(b) => Some(b.to_vec()),
        Value::String(s) => Some(s.as_bytes().to_vec()),
        other => Some(
            other
                .into_bytes()
                .map(|b: fred::bytes::Bytes| b.to_vec())
                .unwrap_or_default(),
        ),
    }
}

#[async_trait]
impl CacheBackend for RedisCacheBackend {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        let result: Value = KeysInterface::get(&self.client, key)
            .await
            .map_err(|e| CacheError::Other(format!("GET {key}: {e}")))?;
        Ok(value_bytes(result))
    }

    /// `GETDEL key` — one command, so of two clients taking the same key
    /// exactly one receives the value.
    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        let result: Value = KeysInterface::getdel(&self.client, key)
            .await
            .map_err(|e| CacheError::Other(format!("GETDEL {key}: {e}")))?;
        Ok(value_bytes(result))
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        let expiration = Some(Expiration::PX(ttl.as_millis() as i64));
        KeysInterface::set::<Value, _, _>(
            &self.client,
            key,
            value.to_vec(),
            expiration,
            None,
            false,
        )
        .await
        .map_err(|e| CacheError::Other(format!("SET {key}: {e}")))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<()> {
        KeysInterface::del::<Value, _>(&self.client, key)
            .await
            .map_err(|e| CacheError::Other(format!("DEL {key}: {e}")))?;

        Ok(())
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let count: i64 = KeysInterface::exists(&self.client, key)
            .await
            .map_err(|e| CacheError::Other(format!("EXISTS {key}: {e}")))?;

        Ok(count > 0)
    }

    /// `SET key value NX PX ttl` — one command, so two clients racing for the
    /// same key produce exactly one winner.
    ///
    /// The trait's default is a check followed by a set, which is two commands
    /// and therefore no lock at all: every caller of this method (JTI replay
    /// rejection, refresh locks, single-use authorization state) is asking for
    /// mutual exclusion across instances and would silently not get it.
    async fn set_nx(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<bool> {
        let set: Value = KeysInterface::set(
            &self.client,
            key,
            value.to_vec(),
            Some(Expiration::PX(ttl.as_millis() as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .map_err(|e| CacheError::Other(format!("SET NX {key}: {e}")))?;

        // The reply is the string OK when the key was set and nil when NX
        // refused it.
        Ok(!set.is_null())
    }

    /// `INCR`, then set the expiry on the increment that created the key.
    ///
    /// The trait's default reads and writes back, which loses increments under
    /// concurrency — for a rate limiter or a brute-force counter that means
    /// undercounting exactly when the counting matters. `INCR` is atomic, so
    /// precisely one caller sees 1 and is the one to set the TTL; `NX` on the
    /// expiry keeps a later caller from extending the window.
    async fn incr(&self, key: &str, ttl: Duration) -> CacheResult<u64> {
        let count: i64 = KeysInterface::incr(&self.client, key)
            .await
            .map_err(|e| CacheError::Other(format!("INCR {key}: {e}")))?;

        if count == 1 {
            let _: Value = KeysInterface::expire(
                &self.client,
                key,
                ttl.as_secs().max(1) as i64,
                Some(ExpireOptions::NX),
            )
            .await
            .map_err(|e| CacheError::Other(format!("EXPIRE {key}: {e}")))?;
        }

        Ok(count.max(0) as u64)
    }

    async fn publish(&self, channel: &str, message: &[u8]) -> CacheResult<()> {
        PubsubInterface::publish::<Value, _, _>(&self.client, channel, message.to_vec())
            .await
            .map_err(|e| CacheError::Other(format!("PUBLISH {channel}: {e}")))?;

        Ok(())
    }

    async fn subscribe(&self, channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        // Create a separate subscriber client from the main client's config.
        let config = self.client.client_config();
        let subscriber = Client::new(config, None, None, None);
        subscriber
            .init()
            .await
            .map_err(|e| CacheError::Other(format!("subscriber init: {e}")))?;

        PubsubInterface::subscribe(&subscriber, channel)
            .await
            .map_err(|e| CacheError::Other(format!("SUBSCRIBE {channel}: {e}")))?;

        let (tx, rx) = mpsc::unbounded_channel();
        let mut message_stream = subscriber.message_rx();
        let channel_owned = channel.to_string();

        tokio::spawn(async move {
            // Keep subscriber alive in the spawned task.
            let _subscriber = subscriber;
            while let Ok(message) = message_stream.recv().await {
                let ch_str: String = message.channel.to_string();
                if ch_str == channel_owned
                    && let Some(bytes) = message.value.into_bytes()
                    && tx.send(bytes.to_vec()).is_err()
                {
                    break;
                }
            }
        });

        Ok(rx)
    }

    async fn health_check(&self) -> CacheResult<()> {
        ClientLike::ping::<Value>(&self.client, None)
            .await
            .map_err(|e| CacheError::Connection(format!("PING: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_cache_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RedisCacheBackend>();
    }
}
