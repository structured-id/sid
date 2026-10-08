// SPDX-License-Identifier: AGPL-3.0-only
//! Concurrent session limit enforcement.
//!
//! Session limits are now enforced atomically in `StorageBackend::create_session_atomic()`
//! using `pg_advisory_xact_lock` to prevent TOCTOU race conditions (#515).
//!
//! The old `enforce_session_limit()` function was removed — it used a
//! non-atomic check-then-act pattern vulnerable to race conditions.
//!
//! CE default constant: `CE_SESSION_MAX_CONCURRENT` in `sid_core::models::security_policy`.
