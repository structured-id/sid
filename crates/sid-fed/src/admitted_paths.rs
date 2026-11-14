// SPDX-License-Identifier: AGPL-3.0-only
//! The held platform anchors and the passports accepted under them, kept in
//! process: a full path validation runs once for a given passport and chain,
//! and its result is reused while its inputs and evidence stay valid, with no
//! store read or signature check to recheck the same chain.
//!
//! A view belongs to one held revision of the platform set. It is replaced
//! when that revision stops being current: at its refresh time or at the
//! first overlap end among its anchors, or at once when this process applies
//! a new set or records new status. The accepted paths live inside the view,
//! so a replaced view takes every result that rested on it along. Another
//! replica learns of a new set at its own view's end at the latest; nothing
//! extends that deadline.

use std::collections::HashMap;

use sid_plugin::platform_ca::HeldAnchors;
use tokio::sync::Mutex;

use crate::recipient::Accepted;

/// The most accepted paths one view keeps; the oldest-ending one goes first.
const MAX_PATHS: usize = 1024;

/// One held revision's anchors and what was accepted under them.
pub(crate) struct AnchorView {
    pub(crate) held: HeldAnchors,
    /// When the view is read again: the held answer's end, or earlier when
    /// the configured source is to be asked for a newer set.
    until: i64,
    paths: Mutex<HashMap<Box<[u8]>, Reused>>,
}

/// An accepted passport, with what was known of its status, and the moment
/// its acceptance stops holding.
#[derive(Clone)]
struct Reused {
    accepted: Accepted,
    until: i64,
}

impl AnchorView {
    /// The view of `held`, read again at `until` (at the latest at the held
    /// answer's own end).
    pub(crate) fn new(held: HeldAnchors, until: i64) -> Self {
        let until = until.min(held.until);
        Self {
            held,
            until,
            paths: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the view is still current at `now`.
    pub(crate) fn current(&self, now: i64) -> bool {
        now < self.until
    }

    /// The passport accepted under `key` before, while its acceptance holds
    /// at `now`.
    pub(crate) async fn reused(&self, key: &[u8], now: i64) -> Option<Accepted> {
        let paths = self.paths.lock().await;
        paths
            .get(key)
            .filter(|reused| now < reused.until)
            .map(|reused| reused.accepted.clone())
    }

    /// Keep `accepted`, accepted under `key`, until `until` or the view's
    /// own end, whichever comes first.
    pub(crate) async fn keep(&self, key: Box<[u8]>, accepted: Accepted, until: i64, now: i64) {
        let until = until.min(self.until);
        let mut paths = self.paths.lock().await;
        if paths.len() >= MAX_PATHS && !paths.contains_key(&key) {
            paths.retain(|_, reused| now < reused.until);
            if paths.len() >= MAX_PATHS
                && let Some(first) = paths
                    .iter()
                    .min_by_key(|(_, reused)| reused.until)
                    .map(|(key, _)| key.clone())
            {
                paths.remove(&first);
            }
        }
        paths.insert(key, Reused { accepted, until });
    }
}

/// The exact inputs a passport's acceptance depends on besides the anchors:
/// the profile allocation, the status policy it was decided under (its
/// `policy` tag), the recipient, the passport and the presented chain, each
/// length-prefixed. A result reached under one policy is never another's.
pub(crate) fn key(
    allocation: u8,
    policy: &[u8],
    recipient: uuid::Uuid,
    certificate: &[u8],
    chain: &[Vec<u8>],
) -> Box<[u8]> {
    let size = 1
        + policy.len()
        + 16
        + 4
        + certificate.len()
        + chain.iter().map(|c| 4 + c.len()).sum::<usize>();
    let mut key = Vec::with_capacity(size);
    key.push(allocation);
    key.extend_from_slice(policy);
    key.extend_from_slice(recipient.as_bytes());
    for part in std::iter::once(certificate).chain(chain.iter().map(Vec::as_slice)) {
        // A certificate is far below 4 GiB; the length only separates parts.
        key.extend_from_slice(&(part.len() as u32).to_be_bytes());
        key.extend_from_slice(part);
    }
    key.into_boxed_slice()
}

#[cfg(test)]
mod tests;
