// SPDX-License-Identifier: AGPL-3.0-only
//! The StructuredID CE engine library above `sid-authn` and `sid-authz`:
//! opening an installation, the required work it owes and its lifecycle on
//! the host's runtime. It has no transport, configuration source or concrete
//! store: a service binary and an embedding application hand it the same
//! parts.

pub mod account;
pub mod admin;
pub mod authorization;
pub mod branding;
pub mod email_provider;
pub mod enrollment;
pub mod flows;
pub mod identity;
pub mod installation;
pub mod lifecycle;
pub mod machines;
pub mod maintenance;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod password_operation;
pub mod pats;
pub mod projects;
pub mod provisioning;
pub mod rate_limit;
pub mod registration;
pub mod security;
pub mod sign_in;
pub mod upstream;
mod wire;

#[cfg(test)]
mod test_support;

pub use installation::{Installation, InstallationError, InstallationSettings, Management};
pub use lifecycle::{Engine, EngineError, EngineParts, Running};
pub use maintenance::{AuditRetention, CeMaintenance, Maintenance, RetentionAction};
