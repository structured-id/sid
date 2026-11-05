// SPDX-License-Identifier: AGPL-3.0-only
//! Compiled policy sets. Every decision reads its applicable policies from
//! storage; their compilation is a pure function of the policies' ids and
//! texts, so a set compiled once serves every later decision under exactly
//! the same policies. An edit, disable or removal changes what is read and
//! so the set asked for: the cache holds no authority and needs no
//! invalidation, and each replica keeps its own.

use std::sync::Arc;

use cedar_policy::PolicySet;
use dashmap::DashMap;

use crate::cedar::{CedarError, CedarService};

/// The most sets kept at once.
const CAPACITY: usize = 256;

/// A set compiled from its (id, text) policies, or why it does not compile.
type Compiled = Result<Arc<PolicySet>, String>;

/// The compiled sets, keyed by the policies themselves: a hit compares
/// every id and text, so no other set ever answers for one.
#[derive(Default)]
pub(crate) struct PolicySets {
    sets: DashMap<Vec<(String, String)>, Compiled>,
}

impl PolicySets {
    /// `policies` compiled, from the cache when compiled before.
    pub(crate) fn get(&self, policies: &[(String, String)]) -> Result<Arc<PolicySet>, CedarError> {
        if let Some(hit) = self.sets.get(policies) {
            return hit.value().clone().map_err(CedarError::InvalidPolicy);
        }
        let compiled: Compiled =
            CedarService::compile(policies)
                .map(Arc::new)
                .map_err(|e| match e {
                    CedarError::InvalidPolicy(e) => e,
                    other => other.to_string(),
                });
        // Any set may go: a set asked for again is compiled again. Every miss
        // evicts until it is under the bound, so concurrent misses can pass
        // it only by the misses in flight, and the next miss repairs that.
        while self.sets.len() >= CAPACITY {
            let evicted = self.sets.iter().next().map(|entry| entry.key().clone());
            match evicted {
                Some(evicted) => {
                    self.sets.remove(&evicted);
                }
                None => break,
            }
        }
        self.sets.insert(policies.to_vec(), compiled.clone());
        compiled.map_err(CedarError::InvalidPolicy)
    }
}

#[cfg(test)]
mod tests;
