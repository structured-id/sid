// SPDX-License-Identifier: AGPL-3.0-only
//! What an authorization request asks of the user's authentication and of
//! the interaction: OIDC `prompt` and `max_age` (OpenID Connect Core
//! §3.1.2.1).

use chrono::{DateTime, Duration, Utc};

use super::AuthorizeError;

/// The `prompt` values of one request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prompt {
    none: bool,
    login: bool,
    consent: bool,
    select_account: bool,
}

impl Prompt {
    /// The space-separated `value`; absent or empty asks for nothing.
    /// An unknown value, a repeated one, or `none` with another is refused.
    pub fn parse(value: Option<&str>) -> Result<Self, AuthorizeError> {
        let mut prompt = Self::default();
        for word in value.unwrap_or_default().split_ascii_whitespace() {
            let slot = match word {
                "none" => &mut prompt.none,
                "login" => &mut prompt.login,
                "consent" => &mut prompt.consent,
                "select_account" => &mut prompt.select_account,
                _ => return Err(AuthorizeError::InvalidPrompt),
            };
            if std::mem::replace(slot, true) {
                return Err(AuthorizeError::InvalidPrompt);
            }
        }
        if prompt.none && (prompt.login || prompt.consent || prompt.select_account) {
            return Err(AuthorizeError::InvalidPrompt);
        }
        Ok(prompt)
    }

    /// `none`: no user interface may be shown.
    pub fn none(self) -> bool {
        self.none
    }

    /// Interaction other than authentication the request asks for:
    /// `consent` or `select_account`.
    pub fn asks_interaction(self) -> bool {
        self.consent || self.select_account
    }

    /// The oldest authentication the request accepts, at `now`: `login` and
    /// `max_age=0` accept only authentication that happens after the request,
    /// `max_age=N` authentication in the last N seconds; otherwise any.
    pub fn authenticated_after(
        self,
        max_age: Option<u32>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        match (self.login, max_age) {
            (true, _) | (_, Some(0)) => Some(now),
            (false, Some(seconds)) => Some(now - Duration::seconds(i64::from(seconds))),
            (false, None) => None,
        }
    }
}

#[cfg(test)]
mod tests;
