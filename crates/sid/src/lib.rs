// SPDX-License-Identifier: AGPL-3.0-only
//! The StructuredID CE engine library above `sid-authn` and `sid-authz`:
//! opening an installation, the required work it owes and its lifecycle on
//! the host's runtime. It has no transport, configuration source or concrete
//! store: a service binary and an embedding application hand it the same
//! parts.

pub mod account;
pub mod authorization;
pub mod email_provider;
pub mod enrollment;
pub mod identity;
pub mod installation;
pub mod lifecycle;
pub mod machines;
pub mod maintenance;
pub mod projects;
mod wire;

pub use installation::{Installation, InstallationError, InstallationSettings, Management};
pub use lifecycle::{Engine, EngineError, EngineParts, Running};
pub use maintenance::{AuditRetention, CeMaintenance, Maintenance, RetentionAction};
