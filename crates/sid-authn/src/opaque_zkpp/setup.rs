// SPDX-License-Identifier: AGPL-3.0-only
//! The ZKPP server a credential service runs: its proof settings and the
//! verifying keys made in the background on the service's own OPAQUE setup.
//! Every credential authority that installs passwords composes it the same
//! way; reading the settings from its environment stays with the host.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

use super::{ZkppConfig, ZkppOpaqueServer};
use crate::opaque::OpaqueRouter;

/// The ZKPP server once its verifying keys are ready; `None` until then, and
/// for good when keygen fails, so password operations report unavailable.
pub type ZkppSlot = Arc<ArcSwap<Option<Arc<ZkppOpaqueServer>>>>;

/// Proof settings: whether proofs are verified at all, and what is required.
#[derive(Debug, Clone)]
pub struct ZkppSettings {
    pub enabled: bool,
    pub config: ZkppConfig,
}

/// Why proof settings are refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ZkppSettingsError {
    #[error("{0} must be true, false, 1 or 0")]
    NotBoolean(&'static str),
    #[error(
        "with SID_ZKPP_ENABLED=false no proof can be verified: set SID_ZKPP_SKIP_PROOF=true to accept that"
    )]
    ProofsWithoutVerifiers,
    #[error("SID_ZKPP_POLICY_VERSION must be an unsigned policy version")]
    MalformedPolicyVersion,
    #[error("SID_ZKPP_POLICY_VERSION selects an unknown policy")]
    UnknownPolicyVersion,
}

impl ZkppSettings {
    /// The settings `SID_ZKPP_ENABLED`, `SID_ZKPP_SKIP_PROOF` and
    /// `SID_ZKPP_POLICY_VERSION` give, each `None` when unset. An empty or
    /// unknown value is refused, never read as either answer; proofs are
    /// required unless explicitly skipped, so an unset flag cannot weaken
    /// them.
    pub fn parse(
        enabled: Option<&str>,
        skip: Option<&str>,
        version: Option<&str>,
    ) -> Result<Self, ZkppSettingsError> {
        fn boolean(
            name: &'static str,
            value: Option<&str>,
            default: bool,
        ) -> Result<bool, ZkppSettingsError> {
            match value {
                None => Ok(default),
                Some("true" | "1") => Ok(true),
                Some("false" | "0") => Ok(false),
                Some(_) => Err(ZkppSettingsError::NotBoolean(name)),
            }
        }
        let enabled = boolean("SID_ZKPP_ENABLED", enabled, true)?;
        // Governs every installed password: registration, change and reset
        // all run as password operations.
        let require_proof = !boolean("SID_ZKPP_SKIP_PROOF", skip, false)?;
        if !enabled && require_proof {
            return Err(ZkppSettingsError::ProofsWithoutVerifiers);
        }
        let policy_version = match version {
            None => 1,
            Some(v) => v
                .parse::<u32>()
                .map_err(|_| ZkppSettingsError::MalformedPolicyVersion)?,
        };
        if sid_pake_core::policy::get_policy(sid_pake_core::types::PolicyVersion(policy_version))
            .is_none()
        {
            return Err(ZkppSettingsError::UnknownPolicyVersion);
        }
        Ok(Self {
            enabled,
            config: ZkppConfig {
                require_proof,
                policy_version,
            },
        })
    }
}

/// The ZKPP server on `router`'s setup under `settings`. With proofs
/// disabled it is ready at once and installs every password
/// policy-unverified (D018). Otherwise its verifying keys, one per supported
/// number of history comparison domains, are made in the background from
/// the parameters cached under `cache_dir` (made and cached on first use);
/// the slot stays empty until they are ready. A router the server cannot
/// serve (another primary curve) is refused here, at start, when proofs are
/// verified; with proofs disabled it leaves password operations unavailable.
pub fn spawn_zkpp_server(
    router: &Arc<OpaqueRouter>,
    settings: &ZkppSettings,
    cache_dir: &Path,
) -> sid_core::Result<ZkppSlot> {
    let slot: ZkppSlot = Arc::new(ArcSwap::from_pointee(None));
    let unverified = ZkppOpaqueServer::new(
        router,
        vec![],
        ZkppConfig {
            require_proof: false,
            policy_version: settings.config.policy_version,
        },
    );
    if !settings.enabled {
        match unverified {
            Ok(server) => slot.store(Arc::new(Some(Arc::new(server)))),
            Err(e) => tracing::warn!("password operations unavailable: {e}"),
        }
        return Ok(slot);
    }
    unverified?;

    let config = settings.config.clone();
    // The verifying key is built for this policy: its minimums are fixed
    // columns of the key, so this is the policy every accepted proof meets.
    let policy = sid_pake_core::policy::get_policy(sid_pake_core::types::PolicyVersion(
        config.policy_version,
    ))
    .ok_or_else(|| sid_core::Error::Internal("unknown ZKPP policy version".into()))?;
    let cache_path = cache_dir.join("zkpp");
    tracing::info!(
        "ZKPP verifying keys preparing in background (k={}) — non-ZKPP traffic is served meanwhile",
        sid_pake_core::circuit::ZKPP_K
    );
    let ready = slot.clone();
    let router = Arc::clone(router);
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let params = match std::fs::File::open(cache_path.join("zkpp_params.bin"))
                .ok()
                .and_then(|mut f| sid_pake_core::keygen::read_params(&mut f).ok())
            {
                Some(params) => params,
                None => {
                    let params =
                        sid_pake_core::keygen::generate_params(sid_pake_core::circuit::ZKPP_K);
                    if let Err(e) = sid_pake_core::keygen::save_params_cache(&cache_path, &params) {
                        tracing::warn!("Failed to cache ZKPP params: {}", e);
                    }
                    params
                }
            };
            (1..=sid_core::models::password_history::MAX_HISTORY_DOMAINS)
                .map(|history_domains| {
                    let shape = sid_pake_core::circuit::CircuitShape {
                        policy,
                        history_domains,
                    };
                    sid_pake_core::keygen::generate_vk(&params, shape).map(|vk| {
                        sid_pake_core::verifier::ZkppVerifier::new(params.clone(), vk, shape)
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .await;
        match result {
            Ok(Ok(verifiers)) => match ZkppOpaqueServer::new(&router, verifiers, config.clone()) {
                Ok(server) => {
                    ready.store(Arc::new(Some(Arc::new(server))));
                    tracing::info!(
                        "ZKPP verifying keys ready ({}s, require_proof={}, policy_version={})",
                        start.elapsed().as_secs(),
                        config.require_proof,
                        config.policy_version
                    );
                }
                Err(e) => tracing::error!("ZKPP: {e} — password operations remain unavailable"),
            },
            Ok(Err(e)) => tracing::warn!(
                "ZKPP keygen failed: {:?} — password operations remain unavailable",
                e
            ),
            Err(e) => tracing::error!(
                "ZKPP keygen task panicked: {} — password operations remain unavailable",
                e
            ),
        }
    });
    Ok(slot)
}

#[cfg(test)]
mod tests;
