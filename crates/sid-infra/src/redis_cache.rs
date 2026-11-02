// SPDX-License-Identifier: AGPL-3.0-only
//! Redis/Dragonfly cache backend.
//!
//! Production CacheBackend implementation using `fred` async Redis client.
//! Compatible with Redis 6+, Valkey, and Dragonfly.

use async_trait::async_trait;
use fred::interfaces::{ClientLike, EventInterface, KeysInterface, LuaInterface, PubsubInterface};
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

        let client = commands(config)
            .build()
            .map_err(|e| CacheError::Connection(format!("Redis client: {e}")))?;
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

/// A command the cache has not answered in this time fails. The cache runs
/// beside its callers; waiting longer only moves the failure to the caller's
/// own deadline.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// The client every command goes through. A dropped connection is opened
/// again, retrying without limit, 100 ms doubling up to 5 s apart; commands
/// sent meanwhile wait for it within [`COMMAND_TIMEOUT`]. Each connection is
/// named after the client, so the server can tell them apart.
fn commands(config: Config) -> Builder {
    let mut builder = Builder::from_config(config);
    builder
        .set_policy(ReconnectPolicy::new_exponential(0, 100, 5_000, 2))
        .with_performance_config(|p| p.default_command_timeout = COMMAND_TIMEOUT)
        .with_connection_config(|c| c.auto_client_setname = true);
    builder
}

/// The client of one subscription. It is not reconnected: whatever was
/// published while it was down is lost, so the subscription ends instead
/// and its consumer subscribes again knowing there was a gap.
fn subscriber(config: Config) -> Builder {
    let mut builder = Builder::from_config(config);
    builder.with_connection_config(|c| c.auto_client_setname = true);
    builder
}

/// Subscribe `subscriber` to `channel` and hand its messages to the stream,
/// which ends when the connection fails or messages were dropped.
async fn subscribed(
    subscriber: Client,
    channel: &str,
) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
    subscriber
        .init()
        .await
        .map_err(|e| CacheError::Other(format!("subscriber init: {e}")))?;

    PubsubInterface::subscribe(&subscriber, channel)
        .await
        .map_err(|e| CacheError::Other(format!("SUBSCRIBE {channel}: {e}")))?;

    let (tx, rx) = mpsc::unbounded_channel();
    let mut message_stream = subscriber.message_rx();
    let mut errors = subscriber.error_rx();
    let channel_owned = channel.to_string();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                message = message_stream.recv() => {
                    // A lagged receiver skipped messages: the same gap as a
                    // dropped connection.
                    let Ok(message) = message else { break };
                    let ch_str: String = message.channel.to_string();
                    if ch_str == channel_owned
                        && let Some(bytes) = message.value.into_bytes()
                        && tx.send(bytes.to_vec()).is_err()
                    {
                        break;
                    }
                }
                error = errors.recv() => {
                    tracing::warn!(channel = %channel_owned, error = ?error, "subscription connection failed");
                    break;
                }
            }
        }
        if let Err(e) = subscriber.quit().await {
            tracing::debug!(error = %e, "subscriber did not close cleanly");
        }
    });

    Ok(rx)
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

    /// One script, so the comparison and the write run as one command:
    /// scripts execute atomically (Redis "EVAL", "Atomicity of scripts").
    async fn compare_and_set(
        &self,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> CacheResult<bool> {
        const SCRIPT: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then \
             redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3]) return 1 \
             else return 0 end";
        let replaced: i64 = LuaInterface::eval(
            &self.client,
            SCRIPT,
            key,
            vec![
                Value::Bytes(fred::bytes::Bytes::copy_from_slice(expected)),
                Value::Bytes(fred::bytes::Bytes::copy_from_slice(value)),
                Value::from(ttl.as_millis() as i64),
            ],
        )
        .await
        .map_err(|e| CacheError::Other(format!("compare-and-set {key}: {e}")))?;
        Ok(replaced == 1)
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
        let subscriber = subscriber(self.client.client_config())
            .build()
            .map_err(|e| CacheError::Other(format!("subscriber client: {e}")))?;
        subscribed(subscriber, channel).await
    }

    async fn health_check(&self) -> CacheResult<()> {
        ClientLike::ping::<Value>(&self.client, None)
            .await
            .map_err(|e| CacheError::Connection(format!("PING: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
