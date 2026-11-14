// SPDX-License-Identifier: AGPL-3.0-only
//! What an installation requires to be known of withdrawals before it
//! relies on a presented certificate.
//!
//! In plain words: an identity's certificate can be withdrawn by whoever
//! issued it, and the issuer says so in a list it publishes for a limited
//! time. An installation that has that list within its time knows the
//! certificate still stands. One that has no list, or an old one, does not
//! know. This policy says what the installation does then.
//!
//! Two things never depend on the policy. A withdrawal the installation has
//! seen refuses the certificate, in every mode and at any age of the list
//! that stated it. And a certificate that is expired, issued for another
//! recipient or wrongly signed is refused before status is looked at.
//!
//! The policy only decides the remaining case, where nothing says the
//! certificate was withdrawn and nothing current says it was not. The
//! strict requirement refuses to decide without a list in its time. The
//! offline one admits within the limits it names, and the result still
//! records that the status was stale or unknown: it is never reported as
//! shown good. Which requirement applies is the installation's stored
//! choice; an unreachable issuer never switches it.

use serde::{Deserialize, Serialize};

/// What is required of the status one authority publishes of the
/// certificates it issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusRequirement {
    /// A list of the authority within its time. Without one the certificate
    /// is not decided.
    #[default]
    Fresh,
    /// Admitted without a list in its time, within these limits.
    Offline(OfflineLimits),
}

/// What an offline requirement admits. It names each absence it permits:
/// nothing is permitted by not being mentioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OfflineLimits {
    /// Whether a certificate is admitted when no list of its issuer was
    /// ever held.
    pub missing: bool,
    /// How long past its time (seconds) a held list still admits; `None`
    /// sets no limit, `Some(0)` admits no expired list.
    pub max_stale: Option<u64>,
}

impl OfflineLimits {
    /// Every absence permitted, at any age.
    pub const ANY: Self = Self {
        missing: true,
        max_stale: None,
    };
}

/// What was known of a certificate's status when it was relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusEvidence {
    /// A list of the issuer within its time did not withdraw it.
    Fresh,
    /// The last list held did not withdraw it, and its time has passed.
    Stale,
    /// No list of the issuer was ever held.
    Unknown,
}

impl StatusRequirement {
    /// What is known of a certificate no held list withdraws, at `now`
    /// (seconds since the epoch), given the end `until` of the issuer's held
    /// list (`None` when none was ever held), and until when that answer
    /// holds (`None`: no end of its own). `None` when the requirement does
    /// not admit it on that evidence: not decided, never refused.
    pub fn weigh(self, until: Option<i64>, now: i64) -> Option<(StatusEvidence, Option<i64>)> {
        match (until, self) {
            (Some(until), _) if now <= until => Some((StatusEvidence::Fresh, Some(until))),
            (
                Some(_),
                Self::Offline(OfflineLimits {
                    max_stale: None, ..
                }),
            ) => Some((StatusEvidence::Stale, None)),
            (
                Some(until),
                Self::Offline(OfflineLimits {
                    max_stale: Some(limit),
                    ..
                }),
            ) => {
                // A limit beyond the representable time is no limit.
                let end = i64::try_from(limit)
                    .ok()
                    .and_then(|limit| until.checked_add(limit));
                match end {
                    Some(end) if now > end => None,
                    end => Some((StatusEvidence::Stale, end)),
                }
            }
            (None, Self::Offline(OfflineLimits { missing: true, .. })) => {
                Some((StatusEvidence::Unknown, None))
            }
            _ => None,
        }
    }
}

/// The installation's status policy for the identities presented to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusPolicy {
    /// Of the issuer of the presented Binding Passport itself: the platform
    /// for a Personal Profile's, the issuing organization for a Corporate
    /// Profile's.
    pub issuer: StatusRequirement,
    /// Of the authorities above that issuer on the path, and of the
    /// platform's statement of which of its generations stand.
    pub authorities: StatusRequirement,
}

impl Default for StatusPolicy {
    /// A list in its time from the passport's issuer; the authorities above
    /// it on what the installation holds, without asking the platform on
    /// every sign-in.
    fn default() -> Self {
        Self {
            issuer: StatusRequirement::Fresh,
            authorities: StatusRequirement::Offline(OfflineLimits::ANY),
        }
    }
}

impl StatusPolicy {
    /// The policy as a few bytes: equal policies give equal bytes, so a
    /// result reached under one policy is never reused under another.
    pub fn tag(&self) -> [u8; 20] {
        let part = |requirement: StatusRequirement| -> [u8; 10] {
            let mut bytes = [0u8; 10];
            if let StatusRequirement::Offline(limits) = requirement {
                bytes[0] = 1 + u8::from(limits.missing);
                bytes[1] = u8::from(limits.max_stale.is_some());
                bytes[2..].copy_from_slice(&limits.max_stale.unwrap_or(0).to_be_bytes());
            }
            bytes
        };
        let mut tag = [0u8; 20];
        tag[..10].copy_from_slice(&part(self.issuer));
        tag[10..].copy_from_slice(&part(self.authorities));
        tag
    }

    /// The policy [`Self::tag`] encodes: a store keeps a policy as those
    /// bytes. `None` for bytes no policy encodes, so a damaged value is
    /// never read as some other policy.
    pub fn from_tag(tag: &[u8]) -> Option<Self> {
        let part = |bytes: &[u8]| -> Option<StatusRequirement> {
            let limit = u64::from_be_bytes(bytes[2..10].try_into().ok()?);
            match (bytes[0], bytes[1], limit) {
                (0, 0, 0) => Some(StatusRequirement::Fresh),
                (kind @ (1 | 2), with_limit @ (0 | 1), limit) if with_limit == 1 || limit == 0 => {
                    Some(StatusRequirement::Offline(OfflineLimits {
                        missing: kind == 2,
                        max_stale: (with_limit == 1).then_some(limit),
                    }))
                }
                _ => None,
            }
        };
        if tag.len() != 20 {
            return None;
        }
        Some(Self {
            issuer: part(&tag[..10])?,
            authorities: part(&tag[10..])?,
        })
    }
}

#[cfg(test)]
mod tests;
