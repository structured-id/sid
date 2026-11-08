// SPDX-License-Identifier: AGPL-3.0-only
//! The gRPC entry points of the authentication core every service shares:
//! each reads the request's metadata, calls the owning [`sid_authn`]
//! decision and answers its typed outcome with the one canonical status.

pub mod caller;
pub mod ceremony;
pub mod credential_enrollment;
pub mod operation;
pub mod own_token;
pub mod resource;
pub mod second_factor;
pub mod sign_in_refusal;

#[cfg(feature = "password-operation")]
pub mod password_operation;
#[cfg(feature = "password-operation")]
pub mod password_sign_in;
