// SPDX-License-Identifier: AGPL-3.0-only
//! The user's decision on a device authorization (RFC 8628 §3.3): the user
//! code entered on the IdP's page, approved or denied by the user's own
//! installation session.

use sid_authn::caller::{CallerError, Verified};
use sid_authn::login_policy::{LoginDecision, Unmet};
use sid_core::Error as SidError;
use sid_core::models::{AuditEntry, DeviceAuthDecision, MutationContext, SessionId};
use sid_proto::sid::v1::{SubmitDeviceUserCodeRequest, SubmitDeviceUserCodeResponse};
use tracing::info;

use super::{OAuth, OAuthError};
use crate::sign_in::SignIn;

/// Why a device authorization decision is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum DeviceApprovalError {
    /// The user code names no current device authorization; an unknown and
    /// an expired one answer alike, so the user starts again on the device.
    #[error("not a current device code")]
    NotCurrent,
    /// The approving session ended or may not authorize now.
    #[error("the session has ended")]
    SessionEnded,
    /// The application's login requirements ask for more first.
    #[error("a step-up is required")]
    StepUp(Unmet),
    /// The device authorization was already decided.
    #[error("the device authorization is already decided")]
    AlreadyDecided,
    /// The caller's token may not decide (an application's, not the IdP
    /// session's).
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The application's requirements could not be stated, or the policy
    /// changed while the decision committed.
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl OAuth {
    /// Decide the device authorization `request`'s user code names, as the
    /// installation session `verified` stands for. An approval grants
    /// another client access as an authorization does: the approving session
    /// is judged against the application's login requirements now, and the
    /// decision commits only under their fence. A denial grants nothing and
    /// needs no judgement. Only a pending request takes a decision, once.
    pub async fn submit_device_user_code(
        &self,
        sign_in: &SignIn,
        verified: &Verified,
        request: SubmitDeviceUserCodeRequest,
    ) -> Result<SubmitDeviceUserCodeResponse, DeviceApprovalError> {
        // An authorization decision of the IdP session, never of an
        // application's token.
        verified.require_installation()?;
        let profile_id = verified.caller.profile_id;
        let normalized = sid_authn::device_auth::normalize_user_code(&request.user_code);
        let auth = self
            .storage
            .get_device_auth_by_user_code(&normalized)
            .await?
            .filter(|auth| !auth.is_expired())
            .ok_or(DeviceApprovalError::NotCurrent)?;

        let mut fence = None;
        let mut decision = DeviceAuthDecision::Deny;
        if request.approve {
            let session_id = SessionId::parse(&verified.claims.sid).map_err(|e| {
                tracing::error!(error = %e, "read session id of a verified token");
                DeviceApprovalError::Internal
            })?;
            let now = chrono::Utc::now();
            let session = self
                .storage
                .get_session(session_id)
                .await?
                .filter(|session| session.profile_id == profile_id)
                .filter(|session| sign_in.authorizes(session, now))
                .ok_or(DeviceApprovalError::SessionEnded)?;
            let client = self
                .storage
                .get_oauth2_client(&auth.client_id)
                .await?
                .ok_or(DeviceApprovalError::NotCurrent)?;
            let requirements = self
                .login_requirements(Some(&auth.client_id))
                .await?
                .with_client(&client, None)
                .for_account(self.storage.as_ref(), profile_id)
                .await?;
            match requirements.decide(&session, now) {
                LoginDecision::Allow { audited } => {
                    if !audited.is_empty() {
                        info!(
                            client = %auth.client_id,
                            unmet = ?audited,
                            "Login requirements unmet, device approval allowed by audit enforcement"
                        );
                    }
                }
                LoginDecision::StepUp(unmet) => return Err(DeviceApprovalError::StepUp(unmet)),
            }
            fence = requirements.fence;
            // The device's tokens report the authentication approved under,
            // and are issued only while it is still admitted.
            decision = DeviceAuthDecision::Authorize {
                profile: profile_id,
                authentication: session.grant_authentication(),
            };
        }
        let mut ctx: MutationContext = AuditEntry::user(
            profile_id.to_string(),
            "device_authorization.submit",
            format!(
                "user_code={}, approve={}, client_id={}",
                normalized, request.approve, auth.client_id
            ),
        )
        .into();
        if let Some(fence) = fence {
            ctx = ctx.fenced_by(fence);
        }
        // A concurrent approval and denial cannot both apply, and a
        // resolved request is not changed.
        let decided = match self
            .storage
            .decide_device_auth(auth.id, decision, ctx)
            .await
        {
            Ok(decided) => decided,
            Err(SidError::Fenced(_)) => return Err(OAuthError::PolicyChanged.into()),
            Err(e) => return Err(e.into()),
        };
        if !decided {
            return Err(DeviceApprovalError::AlreadyDecided);
        }
        info!(
            "Device user code submitted: code={}, approve={}, profile={:?}",
            normalized, request.approve, profile_id
        );
        Ok(SubmitDeviceUserCodeResponse {
            client_id: auth.client_id,
            scope: auth.scope,
            completed: true,
        })
    }
}
