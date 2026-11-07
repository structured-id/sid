// SPDX-License-Identifier: AGPL-3.0-only
//! Solving the CAPTCHA a sign-in was asked for: the provider verifies the
//! solution, and the gate turns a solved challenge it issued into the pass
//! that answers that sign-in's retry.

use std::net::IpAddr;

use sid_authn::captcha::CaptchaError;

use super::SignIn;

/// Why a CAPTCHA solution earns no pass.
#[derive(Debug, thiserror::Error)]
pub enum CaptchaSolveError {
    /// The provider did not accept the solution; its reason stays in the log.
    #[error("the CAPTCHA solution was not accepted")]
    Rejected,
    /// The challenge expired, was already used, or no sign-in asked it.
    #[error("the CAPTCHA challenge expired")]
    Expired,
    /// The provider cannot answer now; the client retries.
    #[error("CAPTCHA provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// The gate that issued the challenge cannot answer now.
    #[error("CAPTCHA gate unavailable: {0}")]
    GateUnavailable(String),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl SignIn {
    /// The pass for the sign-in that was asked `challenge_id`, once the
    /// provider accepts `token` as its solution from `client_ip`. A solution
    /// counts once, and only for a challenge a sign-in was asked.
    pub async fn solve_captcha(
        &self,
        challenge_id: &str,
        token: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<String, CaptchaSolveError> {
        let result = self
            .captcha_provider
            .verify(challenge_id, token, client_ip.as_ref())
            .await
            .map_err(|e| match e {
                CaptchaError::Expired => CaptchaSolveError::Expired,
                CaptchaError::ProviderError(e) => CaptchaSolveError::ProviderUnavailable(e),
                CaptchaError::NotConfigured => {
                    tracing::error!(operation = "verify CAPTCHA", "provider not configured");
                    CaptchaSolveError::Internal
                }
                e => {
                    tracing::warn!(error = %e, "CAPTCHA solution rejected");
                    CaptchaSolveError::Rejected
                }
            })?;
        if !result.success {
            return Err(CaptchaSolveError::Rejected);
        }
        self.captcha_gate
            .solved(challenge_id)
            .await
            .map_err(|e| CaptchaSolveError::GateUnavailable(e.to_string()))?
            .ok_or(CaptchaSolveError::Expired)
    }
}

#[cfg(test)]
mod tests;
