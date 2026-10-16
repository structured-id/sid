// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance scenarios of the storage capabilities: what every backend owes
//! its caller, whatever engine and account type it uses. A backend's test
//! harness constructs that backend and runs every scenario against it.

pub mod grant_store;
pub mod work_store;
