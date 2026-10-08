// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC TestService implementation (dev-only, gated behind `dev-perf-test` feature).
//!
//! Provides:
//! 1. Performance testing endpoints that simulate OPAQUE flows without DB writes.
//! 2. Functional auth testing with in-memory user registry, dynamic password policy,
//!    and password history enforcement.
//!
//! All state is ephemeral (DashMap with 5-min TTL for perf cache, persistent for auth users
//! within session — cleared via AuthTestReset).

use dashmap::DashMap;
use sid_proto::sid::v1::test_service_server::TestService;
use sid_proto::sid::v1::*;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// Ephemeral cache entry with expiration (perf tests).
struct CacheEntry {
    _data: Vec<u8>,
    expires_at: Instant,
}

// ── Dynamic Password Policy ──

/// Configurable password policy (modifiable via SetPolicy RPC).
#[derive(Clone, Debug)]
struct PasswordPolicy {
    min_length: u32,
    require_uppercase: bool,
    require_digit: bool,
    require_special: bool,
    history_size: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_digit: false,
            require_special: false,
            history_size: 0,
        }
    }
}

fn policy_to_proto(p: &PasswordPolicy) -> AuthTestPasswordPolicy {
    AuthTestPasswordPolicy {
        min_length: p.min_length,
        require_uppercase: p.require_uppercase,
        require_digit: p.require_digit,
        require_special: p.require_special,
        history_size: p.history_size,
    }
}

// ── Test User ──

/// In-memory test user with password history.
struct TestUser {
    password_hash: Vec<u8>,
    /// Previous password hashes (most recent first), capped by policy history_size.
    password_history: Vec<Vec<u8>>,
}

impl TestUser {
    fn new(password: &str) -> Self {
        Self {
            password_hash: Self::hash_password(password),
            password_history: Vec::new(),
        }
    }

    fn verify(&self, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        self.password_hash
            .ct_eq(&Self::hash_password(password))
            .into()
    }

    /// Update password, pushing old hash into history ring buffer.
    fn update_password(&mut self, new_password: &str, history_size: u32) {
        let old_hash =
            std::mem::replace(&mut self.password_hash, Self::hash_password(new_password));
        if history_size > 0 {
            self.password_history.insert(0, old_hash);
            self.password_history.truncate(history_size as usize);
        }
    }

    /// Check if password hash matches any entry in the history ring.
    fn is_in_history(&self, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        let hash = Self::hash_password(password);
        // Evaluate all entries — no early return to prevent timing leaks.
        let mut found = 0u8;
        for h in &self.password_history {
            found |= h.ct_eq(&hash).unwrap_u8();
        }
        found == 1
    }

    fn hash_password(password: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"sid-test-salt:");
        hasher.update(password.as_bytes());
        hasher.finalize().to_vec()
    }
}

// ── Policy Enforcement ──

/// Minimum password length — base floor, non-disableable.
const MIN_PASSWORD_LENGTH: u32 = 8;

/// Check password against dynamic policy. Returns list of violations (empty = valid).
fn check_password_against_policy(password: &str, policy: &PasswordPolicy) -> Vec<String> {
    let mut violations = Vec::new();

    // Minimum length (enforce floor of 8)
    let effective_min = policy.min_length.max(MIN_PASSWORD_LENGTH) as usize;
    if password.len() < effective_min {
        violations.push(format!(
            "password too short: {} chars, minimum {}",
            password.len(),
            effective_min
        ));
    }

    // Base rules (always enforced)
    if password.chars().all(|c| c.is_ascii_lowercase()) {
        violations.push("password contains only lowercase letters".to_string());
    }

    if password.chars().all(|c| c.is_ascii_digit()) {
        violations.push("password contains only digits".to_string());
    }

    if password.trim().is_empty() {
        violations.push("password is empty or whitespace-only".to_string());
    }

    if password.contains('\0') {
        violations.push("password contains null byte".to_string());
    }

    // Dynamic policy rules (additive)
    if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        violations.push("password must contain at least one uppercase letter".to_string());
    }

    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push("password must contain at least one digit".to_string());
    }

    if policy.require_special
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
    {
        violations.push("password must contain at least one special character".to_string());
    }

    violations
}

// ── TestService Implementation ──

/// TestService implementation for performance benchmarking and functional auth testing.
pub struct TestServiceImpl {
    /// Ephemeral perf test cache (5-min TTL).
    cache: Arc<DashMap<String, CacheEntry>>,
    /// In-memory user registry (cleared via AuthTestReset).
    users: Arc<DashMap<String, TestUser>>,
    /// Current active password policy.
    policy: Arc<RwLock<PasswordPolicy>>,
    ttl: Duration,
}

impl Default for TestServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl TestServiceImpl {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
            policy: Arc::new(RwLock::new(PasswordPolicy::default())),
            ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    fn cache_put(&self, suite: &str, data: Vec<u8>) -> String {
        let key = format!("{}:{}", suite, Uuid::new_v4());
        self.cache.insert(
            key.clone(),
            CacheEntry {
                _data: data,
                expires_at: Instant::now() + self.ttl,
            },
        );
        key
    }

    #[allow(clippy::result_large_err)]
    fn cache_take(&self, key: &str) -> Result<(), Status> {
        match self.cache.remove(key) {
            Some((_, entry)) => {
                if Instant::now() > entry.expires_at {
                    Err(Status::not_found("cache entry expired"))
                } else {
                    Ok(())
                }
            }
            None => Err(Status::not_found("cache key not found")),
        }
    }

    fn mock_response_bytes(suite: &str) -> Vec<u8> {
        let size = match suite {
            "ristretto255" => 64,
            "p256" => 65,
            "p384" => 97,
            "p521" => 133,
            _ => 64,
        };
        vec![0xAB; size]
    }

    fn simulate_compute(suite: &str) {
        use sha2::{Digest, Sha256};

        let iterations: u32 = match suite {
            "ristretto255" => 100,
            "p256" => 150,
            "p384" => 200,
            "p521" => 300,
            _ => 100,
        };

        let mut hash = vec![0u8; 32];
        for _ in 0..iterations {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hash = hasher.finalize().to_vec();
        }
    }

    /// Periodic cleanup of expired perf cache entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| now < entry.expires_at);
    }
}

#[tonic::async_trait]
impl TestService for TestServiceImpl {
    // ── Performance benchmarks ──

    async fn perf_registration_start(
        &self,
        request: Request<PerfTestRequest>,
    ) -> Result<Response<PerfTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        Self::simulate_compute(&req.suite);
        let result = Self::mock_response_bytes(&req.suite);
        let cache_key = self.cache_put(&req.suite, result.clone());
        Ok(Response::new(PerfTestResponse {
            suite: req.suite,
            result,
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            cache_key,
        }))
    }

    async fn perf_registration_finish(
        &self,
        request: Request<PerfTestFinishRequest>,
    ) -> Result<Response<PerfTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        self.cache_take(&req.cache_key)?;
        Self::simulate_compute(&req.suite);
        Ok(Response::new(PerfTestResponse {
            suite: req.suite,
            result: Self::mock_response_bytes("ristretto255"),
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            cache_key: String::new(),
        }))
    }

    async fn perf_login_start(
        &self,
        request: Request<PerfTestRequest>,
    ) -> Result<Response<PerfTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        Self::simulate_compute(&req.suite);
        let result = Self::mock_response_bytes(&req.suite);
        let cache_key = self.cache_put(&req.suite, result.clone());
        Ok(Response::new(PerfTestResponse {
            suite: req.suite,
            result,
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            cache_key,
        }))
    }

    async fn perf_login_finish(
        &self,
        request: Request<PerfTestFinishRequest>,
    ) -> Result<Response<PerfTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        self.cache_take(&req.cache_key)?;
        Self::simulate_compute(&req.suite);
        Ok(Response::new(PerfTestResponse {
            suite: req.suite,
            result: Self::mock_response_bytes("ristretto255"),
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            cache_key: String::new(),
        }))
    }

    async fn perf_verify_envelope(
        &self,
        request: Request<PerfTestRequest>,
    ) -> Result<Response<PerfTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        Self::simulate_compute(&req.suite);
        Self::simulate_compute(&req.suite);
        Ok(Response::new(PerfTestResponse {
            suite: req.suite,
            result: vec![0x01],
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            cache_key: String::new(),
        }))
    }

    // ── Functional auth tests ──

    async fn auth_test_register(
        &self,
        request: Request<AuthTestRequest>,
    ) -> Result<Response<AuthTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        if self.users.contains_key(&req.username) {
            return Ok(Response::new(AuthTestResponse {
                success: false,
                error: format!("user '{}' already registered", req.username),
                server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            }));
        }

        let policy = self.policy.read().unwrap();
        let violations = check_password_against_policy(&req.password, &policy);
        if !violations.is_empty() {
            return Ok(Response::new(AuthTestResponse {
                success: false,
                error: format!("policy violation: {}", violations.join("; ")),
                server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            }));
        }

        self.users
            .insert(req.username.clone(), TestUser::new(&req.password));

        Ok(Response::new(AuthTestResponse {
            success: true,
            error: String::new(),
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }))
    }

    async fn auth_test_login(
        &self,
        request: Request<AuthTestRequest>,
    ) -> Result<Response<AuthTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        match self.users.get(&req.username) {
            Some(user) => {
                if user.verify(&req.password) {
                    Ok(Response::new(AuthTestResponse {
                        success: true,
                        error: String::new(),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }))
                } else {
                    Ok(Response::new(AuthTestResponse {
                        success: false,
                        error: "invalid password".to_string(),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }))
                }
            }
            None => Ok(Response::new(AuthTestResponse {
                success: false,
                error: format!("user '{}' not found", req.username),
                server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            })),
        }
    }

    async fn auth_test_change_password(
        &self,
        request: Request<AuthTestChangePasswordRequest>,
    ) -> Result<Response<AuthTestResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        match self.users.get_mut(&req.username) {
            Some(mut user) => {
                // Verify old password
                if !user.verify(&req.old_password) {
                    return Ok(Response::new(AuthTestResponse {
                        success: false,
                        error: "old password is incorrect".to_string(),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }));
                }

                let policy = self.policy.read().unwrap();

                // Check new password policy
                let violations = check_password_against_policy(&req.new_password, &policy);
                if !violations.is_empty() {
                    return Ok(Response::new(AuthTestResponse {
                        success: false,
                        error: format!("new password policy violation: {}", violations.join("; ")),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }));
                }

                // Same password check
                if req.old_password == req.new_password {
                    return Ok(Response::new(AuthTestResponse {
                        success: false,
                        error: "new password must differ from old password".to_string(),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }));
                }

                // Password history check
                if policy.history_size > 0 && user.is_in_history(&req.new_password) {
                    return Ok(Response::new(AuthTestResponse {
                        success: false,
                        error: "new password was recently used (password history check)"
                            .to_string(),
                        server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    }));
                }

                user.update_password(&req.new_password, policy.history_size);
                Ok(Response::new(AuthTestResponse {
                    success: true,
                    error: String::new(),
                    server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                }))
            }
            None => Ok(Response::new(AuthTestResponse {
                success: false,
                error: format!("user '{}' not found", req.username),
                server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            })),
        }
    }

    async fn auth_test_check_policy(
        &self,
        request: Request<AuthTestCheckPolicyRequest>,
    ) -> Result<Response<AuthTestCheckPolicyResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let policy = self.policy.read().unwrap();
        let violations = check_password_against_policy(&req.password, &policy);
        Ok(Response::new(AuthTestCheckPolicyResponse {
            valid: violations.is_empty(),
            violations,
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }))
    }

    async fn auth_test_reset(
        &self,
        _request: Request<AuthTestResetRequest>,
    ) -> Result<Response<AuthTestResetResponse>, Status> {
        let start = Instant::now();
        let count = self.users.len() as u32;
        self.users.clear();
        self.cache.clear();

        // Reset policy to defaults
        let default_policy = PasswordPolicy::default();
        *self.policy.write().unwrap() = default_policy.clone();

        Ok(Response::new(AuthTestResetResponse {
            cleared_count: count,
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
            policy: Some(policy_to_proto(&default_policy)),
        }))
    }

    // ── Dynamic Policy ──

    async fn auth_test_set_policy(
        &self,
        request: Request<AuthTestSetPolicyRequest>,
    ) -> Result<Response<AuthTestSetPolicyResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        let proto_policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("policy is required"))?;

        let new_policy = PasswordPolicy {
            min_length: proto_policy.min_length.max(MIN_PASSWORD_LENGTH),
            require_uppercase: proto_policy.require_uppercase,
            require_digit: proto_policy.require_digit,
            require_special: proto_policy.require_special,
            history_size: proto_policy.history_size,
        };

        *self.policy.write().unwrap() = new_policy.clone();

        Ok(Response::new(AuthTestSetPolicyResponse {
            policy: Some(policy_to_proto(&new_policy)),
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }))
    }

    async fn auth_test_get_policy(
        &self,
        _request: Request<AuthTestGetPolicyRequest>,
    ) -> Result<Response<AuthTestGetPolicyResponse>, Status> {
        let start = Instant::now();
        let policy = self.policy.read().unwrap().clone();

        Ok(Response::new(AuthTestGetPolicyResponse {
            policy: Some(policy_to_proto(&policy)),
            server_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }))
    }
}
