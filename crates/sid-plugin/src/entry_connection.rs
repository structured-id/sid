// SPDX-License-Identifier: AGPL-3.0-only
//! The store of an installation's registered entry connections
//! ([`EntryConnection`]): read on every entry, so every replica sees a
//! change at once.
//!
//! One issuer has one connection: the issuer is what an identity recorded
//! here is found by, so a second registration of the same issuer is refused
//! rather than held beside the first. A change is written only over the
//! revision it was read at and never alters what identifies the
//! registration.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{EntryConnection, EntryHandle, MutationContext};

/// The registered entry connections of one installation.
#[async_trait]
pub trait EntryConnectionStore: Send + Sync {
    /// The connection `handle` names.
    async fn entry_connection(&self, handle: EntryHandle) -> Result<Option<EntryConnection>>;

    /// The connection registered for exactly `issuer`.
    async fn entry_connection_of_issuer(&self, issuer: &str) -> Result<Option<EntryConnection>>;

    /// Every connection, enabled or not, oldest first, then by handle.
    async fn list_entry_connections(&self) -> Result<Vec<EntryConnection>>;

    /// Hold a new connection as given, its revision included (0 for one just
    /// registered; a moved installation's keeps the one it had). An existing
    /// handle or issuer is `Conflict`: nothing is replaced.
    async fn create_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> Result<()>;

    /// Write `connection` over the revision it was read at and move the
    /// revision on; `false` when it was removed or changed since. What
    /// identifies the registration
    /// ([`EntryConnection::same_registration`]) is never written: a change
    /// that alters it is `Validation` and nothing is written.
    async fn update_entry_connection(
        &self,
        connection: &EntryConnection,
        ctx: MutationContext,
    ) -> Result<bool>;

    /// Remove the connection `handle` names at `revision`; `false` when it
    /// is gone or changed since.
    async fn remove_entry_connection(
        &self,
        handle: EntryHandle,
        revision: u64,
        ctx: MutationContext,
    ) -> Result<bool>;
}
