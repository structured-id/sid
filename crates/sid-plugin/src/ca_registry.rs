// SPDX-License-Identifier: AGPL-3.0-only
//! CA generation registry: the lifecycle every issuance obeys. A generation is
//! prepared, gets its certificate and both recovery confirmations, is
//! activated as its scope's one current generation, issues, and is retired by
//! its successor or revoked. Every transition names the revision it expects,
//! is atomic, and writes its audit entry in the same transaction.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{
    CaGeneration, CaGenerationId, CaScope, MutationContext, NewCaGeneration, RecoveryConfirmation,
    SerialAllocation,
};

#[async_trait]
pub trait CaRegistry: Send + Sync {
    /// Record `new` as its scope's next generation, prepared. The same
    /// generation again (same id, scope and keys) is an exact retry and returns
    /// the stored one; the same id with other content is a `Conflict`.
    async fn prepare_generation(
        &self,
        new: &NewCaGeneration,
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// A generation by id.
    async fn ca_generation(&self, id: CaGenerationId) -> Result<Option<CaGeneration>>;

    /// The scope's current generation, if one is active.
    async fn current_ca_generation(&self, scope: CaScope) -> Result<Option<CaGeneration>>;

    /// Record the certificate of a prepared generation that has no recovery
    /// confirmation yet (confirmations bind the certified material). The same
    /// certificate again returns the stored generation; another one, or any
    /// other state, is a `Conflict`.
    async fn record_ca_certificate(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        certificate: &[u8],
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// Confirm that a database recovery point holds this certified, prepared
    /// generation.
    async fn confirm_database_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        confirmation: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// Confirm that this certified, prepared generation's keys and their
    /// custody dependencies are preserved apart from the database.
    async fn confirm_key_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        confirmation: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// Make an activatable generation ([`CaGeneration::activatable`]) its
    /// scope's current one, retiring the previous current one, in one
    /// transaction. A generation already current returns as stored; anything
    /// not activatable, or a revision other than `expected_revision`, is a
    /// `Conflict`. Concurrent activations in one scope leave one current.
    async fn activate_ca_generation(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// Withdraw a generation, whatever its state; containment needs no
    /// confirmation. Repeating it returns the revoked generation.
    async fn revoke_ca_generation(
        &self,
        id: CaGenerationId,
        ctx: MutationContext,
    ) -> Result<CaGeneration>;

    /// The next serial number of a generation that is current at
    /// `expected_revision`, atomically: distinct and increasing under
    /// concurrency, never reused. A generation not current, or at another
    /// revision, allocates nothing (`Conflict`). The issuance commit records
    /// the generation and revision of the allocation.
    async fn allocate_ca_serial(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
    ) -> Result<SerialAllocation>;
}
