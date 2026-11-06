// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine composition above `sid-authn` and `sid-authz`: the required
//! work an installation owes and its lifecycle on the host's runtime. It has
//! no transport, configuration source or concrete store: a service binary
//! and an embedding application hand it the same parts.

pub mod lifecycle;
pub mod maintenance;

pub use lifecycle::{Engine, EngineError, EngineParts, Running};
pub use maintenance::{AuditRetention, CeMaintenance, Maintenance, RetentionAction};
