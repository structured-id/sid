// SPDX-License-Identifier: AGPL-3.0-only
//! Secrets of the whole instance that every replica must share, stored sealed.

/// A secret the instance creates once and every replica reads back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstanceSecret {
    /// Serialized OPAQUE server setup (OPRF seed and server keypair). Every
    /// stored password record depends on it, so it never changes.
    OpaqueServerSetup,
    /// HMAC key signing proof-of-work CAPTCHA challenges. Every replica must
    /// verify a challenge any other replica issued.
    CaptchaKey,
    /// Token that makes its holder the first administrator. Exists only
    /// while the instance has no administrator; claiming it removes it.
    AdminClaim,
}

impl InstanceSecret {
    /// Stable storage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpaqueServerSetup => "opaque_server_setup",
            Self::CaptchaKey => "captcha_key",
            Self::AdminClaim => "admin_claim",
        }
    }
}

impl core::fmt::Display for InstanceSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
