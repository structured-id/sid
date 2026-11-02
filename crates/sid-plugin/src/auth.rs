// SPDX-License-Identifier: AGPL-3.0-only
//! Authentication provider plugin traits.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::Profile;

use crate::Protocol;

/// Context provided to authentication providers during authentication.
#[derive(Debug)]
pub struct AuthContext {
    /// The protocol being used for authentication.
    pub protocol: Protocol,
    /// Raw request data (protocol-specific).
    pub request_data: Vec<u8>,
    /// Client IP address.
    pub client_ip: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
}

/// Result of a successful authentication.
#[derive(Debug)]
pub struct AuthResult {
    /// The authenticated profile.
    pub profile: Profile,
    /// Session token or identifier.
    pub session_id: String,
    /// Additional claims or attributes.
    pub claims: std::collections::HashMap<String, serde_json::Value>,
}

/// Authentication provider plugin trait.
///
/// Implement this trait to add new authentication methods to StructuredID.
#[async_trait]
pub trait AuthProvider: Send + Sync + 'static {
    /// Returns the unique name of this provider.
    fn name(&self) -> &'static str;

    /// Returns the protocols supported by this provider.
    fn supported_protocols(&self) -> &[Protocol];

    /// Returns the priority of this provider (higher wins).
    fn priority(&self) -> i32 {
        0
    }

    /// Authenticate a user with the given context.
    async fn authenticate(&self, ctx: AuthContext) -> Result<AuthResult>;
}
