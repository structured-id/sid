// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Plugin API
//!
//! Traits and types for extending StructuredID with custom functionality.
//! This crate defines the plugin interfaces extensions implement.

// The key manager the registry holds belongs to `sid-keys`, which an
// application can link on its own to encrypt its stored fields.
use sid_keys::KeyManager;

pub mod audit;
pub mod auth;
pub mod authz;
pub mod blob_store;
pub mod cache;
pub mod crypto;
pub mod event_bus;
pub mod geoip;
pub mod http;
pub mod legacy_hash;
pub mod mfa;
pub mod notification;
pub mod otp;
pub mod storage;
pub mod upstream;
pub mod work_store;

pub use audit::{AuditLog, VerifyResult};
pub use auth::{AuthContext, AuthProvider, AuthResult};
pub use authz::{AuthzCheckRequest, AuthzCheckResponse, AuthzEngine, AuthzError};
pub use blob_store::BlobStore;
pub use cache::{CacheBackend, CacheError, CacheResult, NoCacheBackend};
pub use crypto::{
    CurveId, LoginState, OpaqueError, OpaqueOperations, OpaqueSetupHandle, SessionKey,
    StoredCredential,
};
pub use event_bus::{EventBus, EventBusError, EventBusResult, InProcessEventBus};
pub use geoip::{GeoIpError, GeoIpProvider, GeoLocation};
pub use http::client_builder;
pub use legacy_hash::{HashError, LegacyHashVerifier};
pub use mfa::{
    AuthLevel, ChallengeResponse, EnrollmentChallenge, EnrollmentResponse, FactorProperties,
    MfaChallenge, MfaContext, MfaCredential, MfaError, MfaProvider, MfaVerification,
};
pub use notification::{
    DeliveryError, DeliveryReceipt, DeliveryStatus, NotificationChannel, NotificationPriority,
    Recipient, RenderedMessage,
};
pub use otp::{Locale, OtpChannel, OtpContext, OtpDeliveryResult, OtpTransport, OtpTransportError};
pub use sid_keys::KeyVersionParams;
pub use storage::StorageBackend;
pub use upstream::{UpstreamAuthState, UpstreamIdpProvider};
pub use work_store::WorkStore;

/// Protocol supported by an authentication provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// OAuth 2.0
    OAuth2,
    /// OpenID Connect
    Oidc,
    /// WebAuthn/Passkeys
    WebAuthn,
    /// OPAQUE password authentication
    Opaque,
    /// SAML 2.0
    Saml2,
    /// LDAP/Active Directory
    Ldap,
}

/// Plugin registry for managing loaded plugins.
pub struct PluginRegistry {
    auth_providers: Vec<Box<dyn AuthProvider>>,
    mfa_providers: Vec<Box<dyn MfaProvider>>,
    otp_transports: Vec<Box<dyn OtpTransport>>,
    storage_backends: Vec<Box<dyn StorageBackend>>,
    cache_backend: Option<Box<dyn CacheBackend>>,
    blob_store: Option<Box<dyn BlobStore>>,
    event_bus: Option<Box<dyn EventBus>>,
    key_manager: Option<Box<dyn KeyManager>>,
    audit_log: Option<Box<dyn AuditLog>>,
}

impl PluginRegistry {
    /// Create a new empty plugin registry.
    pub fn new() -> Self {
        Self {
            auth_providers: Vec::new(),
            mfa_providers: Vec::new(),
            otp_transports: Vec::new(),
            storage_backends: Vec::new(),
            cache_backend: None,
            blob_store: None,
            event_bus: None,
            key_manager: None,
            audit_log: None,
        }
    }

    /// Register an authentication provider.
    pub fn register_auth_provider(&mut self, provider: Box<dyn AuthProvider>) {
        self.auth_providers.push(provider);
    }

    /// Register an MFA provider.
    pub fn register_mfa_provider(&mut self, provider: Box<dyn MfaProvider>) {
        self.mfa_providers.push(provider);
    }

    /// Register an OTP transport.
    pub fn register_otp_transport(&mut self, transport: Box<dyn OtpTransport>) {
        self.otp_transports.push(transport);
    }

    /// Register a storage backend.
    pub fn register_storage_backend(&mut self, backend: Box<dyn StorageBackend>) {
        self.storage_backends.push(backend);
    }

    /// Set the cache backend. Replaces any previously set backend.
    pub fn set_cache_backend(&mut self, backend: Box<dyn CacheBackend>) {
        self.cache_backend = Some(backend);
    }

    /// Get the cache backend, or `NoCacheBackend` if none was registered.
    pub fn cache_backend(&self) -> &dyn CacheBackend {
        self.cache_backend.as_deref().unwrap_or(&NoCacheBackend)
    }

    /// Set the blob store. Replaces any previously set store.
    pub fn set_blob_store(&mut self, store: Box<dyn BlobStore>) {
        self.blob_store = Some(store);
    }

    /// Get the blob store, if one was registered.
    pub fn blob_store(&self) -> Option<&dyn BlobStore> {
        self.blob_store.as_deref()
    }

    /// Set the event bus. Replaces any previously set bus.
    /// Defaults to `InProcessEventBus` if not set.
    pub fn set_event_bus(&mut self, bus: Box<dyn EventBus>) {
        self.event_bus = Some(bus);
    }

    /// Get the event bus, if one was registered.
    pub fn event_bus(&self) -> Option<&dyn EventBus> {
        self.event_bus.as_deref()
    }

    /// Set the key manager. Replaces any previously set manager.
    /// CE default: `SoftwareKeyManager`.
    pub fn set_key_manager(&mut self, km: Box<dyn KeyManager>) {
        self.key_manager = Some(km);
    }

    /// Get the key manager, if one was registered.
    pub fn key_manager(&self) -> Option<&dyn KeyManager> {
        self.key_manager.as_deref()
    }

    /// Set the audit log. Replaces any previously set log.
    pub fn set_audit_log(&mut self, log: Box<dyn AuditLog>) {
        self.audit_log = Some(log);
    }

    /// Get the audit log, if one was registered.
    pub fn audit_log(&self) -> Option<&dyn AuditLog> {
        self.audit_log.as_deref()
    }

    /// Get all registered auth providers.
    pub fn auth_providers(&self) -> &[Box<dyn AuthProvider>] {
        &self.auth_providers
    }

    /// Get all registered MFA providers.
    pub fn mfa_providers(&self) -> &[Box<dyn MfaProvider>] {
        &self.mfa_providers
    }

    /// Find an auth provider by protocol (highest priority wins).
    pub fn find_auth_provider(&self, protocol: Protocol) -> Option<&dyn AuthProvider> {
        self.auth_providers
            .iter()
            .filter(|p| p.supported_protocols().contains(&protocol))
            .max_by_key(|p| p.priority())
            .map(|p| p.as_ref())
    }

    /// Find an MFA provider by method ID.
    pub fn find_mfa_provider(&self, method_id: &str) -> Option<&dyn MfaProvider> {
        self.mfa_providers
            .iter()
            .find(|p| p.method_id() == method_id)
            .map(|p| p.as_ref())
    }

    /// Get all registered OTP transports.
    pub fn otp_transports(&self) -> &[Box<dyn OtpTransport>] {
        &self.otp_transports
    }

    /// Find an OTP transport by channel (highest priority wins).
    pub fn find_otp_transport(&self, channel: OtpChannel) -> Option<&dyn OtpTransport> {
        self.otp_transports
            .iter()
            .filter(|t| t.channel() == channel)
            .max_by_key(|t| t.priority())
            .map(|t| t.as_ref())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
