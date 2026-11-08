// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-ins completed on a verification made elsewhere, or renewed: a
//! password's first factor, an upstream identity provider's sign-in, an
//! explicitly trusted issuer's admitted evidence (with its recoverable
//! repeat) and a native session's renewal. Each completes as every sign-in
//! does, through the same rules, session and delivery.

use std::net::IpAddr;

use chrono::Utc;
use sid_authn::dpop::DPopValidator;
use sid_authn::login_policy::{LoginDecision, LoginPolicySource};
use sid_authn::native_session::{NativePolicy, RefreshRequest};
use sid_authn::sign_in_delivery::{CeremonyClient, RetainedDelivery, SignedIn};
use sid_authn::sign_in_security::{AttemptAuthentication, SignInRefusal, device_id};
use sid_core::models::session::{AuthLevel, SessionAuthentication};
use sid_core::models::{
    ActorFence, OperationKey, PrincipalAssignmentFence, Profile, ProfileId, Session, SignInProof,
};
use sid_ids::OpaqueLoginId;

use super::{
    ADMITTED_METHOD, ADMITTED_NAMESPACE, AttemptContext, FirstFactorSignedIn, LoginMethod,
    RetainedSignIn, SignIn, SignInError, admitted_inputs, internal, organization_requirements,
    requirements_for,
};

/// The host's keyed operation an admitted sign-in completes: a repeat of it
/// is answered with the same session (see [`SignIn::admitted_sign_in`]).
pub struct AdmittedCompletion<'a> {
    /// The operation's stable reference, its key.
    pub operation: &'a str,
    /// When the operation ends; nothing is delivered again after.
    pub deadline: chrono::DateTime<Utc>,
}

impl AdmittedCompletion<'_> {
    fn key(&self) -> Result<OperationKey, SignInError> {
        OperationKey::parse(self.operation)
            .map_err(|e| internal("the admitted sign-in's operation reference", e))
    }
}

/// Who completes a sign-in: its client, its address and what the rules
/// weigh beside the authentication.
#[derive(Clone, Copy)]
pub struct Completer<'a> {
    pub client: CeremonyClient,
    pub client_ip: Option<IpAddr>,
    pub context: AttemptContext<'a>,
}

impl SignIn {
    /// Finish the password sign-in `login` with the client's credential
    /// finalization: the password verified, the rules judging its first
    /// factor under the organization's requirements, then the session or its
    /// pending second-factor context delivered to `completer`'s client. A
    /// native client that proved the application key `native_key` gets the
    /// session's refresh generation.
    pub async fn password_sign_in(
        &self,
        login_policy: &dyn LoginPolicySource,
        login: &OpaqueLoginId,
        credential_finalization: &[u8],
        completer: Completer<'_>,
        native_key: Option<&str>,
    ) -> Result<FirstFactorSignedIn, SignInError> {
        let verified = self
            .password_finish(login, credential_finalization, completer.client_ip)
            .await?;
        let profile = verified.account;
        let method = LoginMethod::Password;
        let requirements = organization_requirements(login_policy).await?;
        let admission = self
            .first_factor(
                profile.id,
                completer.client_ip,
                (
                    "opaque",
                    method.auth_level(self.policy.auth.passkey_satisfies_mfa),
                    &method.amr(),
                ),
                completer.context,
                &requirements,
            )
            .await?;
        let signed_in = self
            .complete_first_factor(
                &profile,
                method,
                completer.context.user_agent.map(device_id),
                completer.client_ip,
                completer.client,
                native_key,
                Some(&verified.proved_by),
                admission,
            )
            .await?;
        tracing::info!("OPAQUE login for profile {}", profile.id);
        Ok(signed_in)
    }

    /// Sign `profile` in after an upstream identity provider verified the
    /// user, as every other sign-in completes: only an active Profile, after
    /// the sign-in rules under the organization's requirements, with a
    /// session of this authority's lifetime and limit. The provider, not
    /// SID, verified the user: the session names no `amr` method (RFC 8176
    /// §1) and has basic assurance.
    pub async fn upstream_sign_in(
        &self,
        login_policy: &dyn LoginPolicySource,
        profile: &Profile,
        completer: Completer<'_>,
    ) -> Result<SignedIn, SignInError> {
        if !profile.status.can_authenticate() {
            return Err(SignInError::AuthenticationFailed);
        }
        let authentication = AttemptAuthentication::Local {
            method: "upstream",
            assurance: AuthLevel::Basic,
            amr: &[],
        };
        let policy = self
            .admitted_by_rules(
                login_policy,
                profile.id,
                completer.client_ip,
                (authentication, completer.context),
                None,
            )
            .await?;
        let mut session = self.new_session(profile.id, completer.client_ip);
        session.device_id = completer.context.user_agent.map(device_id);
        self.sign_in(profile, session, completer.client, None, None, policy, None)
            .await
    }

    /// Sign `profile` in on the accepted evidence of an explicitly trusted
    /// issuer: a host admitted a federated entry (its exact issuer, client
    /// and subject), resolved its Profile through `assignment` (the current
    /// assignment of that issuer's subject), and `authentication` is what the
    /// evidence attests. The session commits only while `assignment` still
    /// holds, and a repeat is delivered only while it does: a retired
    /// association admits nothing. It completes as every sign-in does: only
    /// an active Profile, after the sign-in rules and this authority's
    /// policy weigh that authentication under the login requirements of
    /// `client_id` (the application the sign-in continues to), with a
    /// session of this authority's lifetime and limit recording it. The
    /// browser at `client_ip` gets the IdP session cookie.
    ///
    /// With `completion`, the host's keyed operation (a federated entry's
    /// return), the session commits with that operation's completion and its
    /// delivery sealed for a lost response: a repeat of the operation gets
    /// the same live session again, after the current checks, never a second
    /// one (the recoverable federation callback completion contract).
    #[allow(clippy::too_many_arguments)]
    pub async fn admitted_sign_in(
        &self,
        login_policy: &dyn LoginPolicySource,
        profile: &Profile,
        assignment: PrincipalAssignmentFence,
        authentication: &SessionAuthentication,
        client_id: &str,
        completion: Option<AdmittedCompletion<'_>>,
        client_ip: Option<IpAddr>,
        context: AttemptContext<'_>,
    ) -> Result<SignedIn, SignInError> {
        if !profile.status.can_authenticate() || assignment.profile != profile.id {
            return Err(SignInError::AuthenticationFailed);
        }
        // An operation past its end admits nothing, neither a repeat nor a
        // new sign-in: its retained delivery is gone with it.
        if completion
            .as_ref()
            .is_some_and(|c| c.deadline <= Utc::now())
        {
            return Err(SignInError::AuthenticationFailed);
        }
        // The rules this request meets now (address, lockout, anomalies and
        // requirements), a repeat of a completed operation included: a
        // retained credential is never delivered where the sign-in itself
        // would be refused.
        let attempt = || AttemptAuthentication::Accepted(authentication);
        // A repeat of an operation already committed is judged by the rules
        // of its own request but records no further sign-in; the admission
        // it repeats answers a CAPTCHA from the address it was made from.
        if let Some(completion) = &completion
            && let Some((delivery, session)) = self.admitted_session(completion, assignment).await?
        {
            let requirements = requirements_for(login_policy, Some(client_id)).await?;
            self.check(
                profile.id,
                client_ip,
                (attempt(), context),
                &requirements,
                session.ip_address,
            )
            .await?;
            return self
                .deliver_admitted(login_policy, delivery, &session, client_id, assignment)
                .await;
        }
        let proved_by = Some(SignInProof::Assignment(assignment));
        let policy = self
            .admitted_by_rules(
                login_policy,
                profile.id,
                client_ip,
                (attempt(), context),
                Some(client_id),
            )
            .await?;
        let mut session = self.new_session(profile.id, client_ip);
        session.device_id = context.user_agent.map(device_id);
        session.assurance_level = authentication.assurance_level;
        session.elevation = authentication.elevation;
        session.authenticated_at = authentication.authenticated_at;
        session.amr = authentication.amr.clone();
        let Some(completion) = completion else {
            return self
                .sign_in(
                    profile,
                    session,
                    CeremonyClient::Browser,
                    None,
                    proved_by,
                    policy,
                    None,
                )
                .await;
        };
        // The delivery lives no longer than the operation, nor than the
        // session it delivers.
        let retained = RetainedSignIn {
            keys: self.keys.as_ref(),
            completion_key: completion.key()?,
            context: self.admitted_context(&completion),
            deadline: completion.deadline.min(session.expires_at),
            inputs: admitted_inputs(assignment),
        };
        match self
            .sign_in(
                profile,
                session,
                CeremonyClient::Browser,
                None,
                proved_by,
                policy,
                Some(retained),
            )
            .await
        {
            // A concurrent repeat committed first: its session is this one.
            // Anything else keeps its refusal.
            Err(refused) => match self
                .redeliver_admitted(login_policy, &completion, client_id, assignment)
                .await
            {
                Ok(Some(signed_in)) => Ok(signed_in),
                Ok(None) | Err(_) => Err(refused),
            },
            Ok(signed_in) => Ok(signed_in),
        }
    }

    /// Renew a native session with one credential of its current generation
    /// and a fresh proof by its application key, recorded by `proofs`, or
    /// deliver again the generation a lost response of the same exchange
    /// carried. An account that can no longer authenticate gets no access
    /// token, however its session renewed.
    pub async fn refresh_native(
        &self,
        proofs: &DPopValidator,
        request: RefreshRequest<'_>,
    ) -> Result<SignedIn, SignInError> {
        let policy = NativePolicy::from_session_policy(&self.policy.session)
            .map_err(|e| internal("read the native session policy", e))?;
        let refreshed = sid_authn::native_session::refresh(
            self.storage.as_ref(),
            self.keys.as_ref(),
            proofs,
            &self.revocation,
            request,
            policy,
        )
        .await?;
        let profile = self
            .storage
            .get_profile(refreshed.session.profile_id)
            .await?
            .filter(|p| p.status.can_authenticate())
            .ok_or(SignInError::SessionEnded)?;
        self.native_access(&profile, &refreshed.session, Some(refreshed.set))
            .await
    }

    /// The sign-in rules for `profile_id`'s verified sign-in from
    /// `client_ip` under the login requirements of `client_id` (none: the
    /// organization's), recorded once admitted as evidence for later
    /// sign-ins. Returns the policy fence the session commits under.
    async fn admitted_by_rules(
        &self,
        login_policy: &dyn LoginPolicySource,
        profile_id: ProfileId,
        client_ip: Option<IpAddr>,
        attempt: (AttemptAuthentication<'_>, AttemptContext<'_>),
        client_id: Option<&str>,
    ) -> Result<Option<ActorFence>, SignInError> {
        let requirements = requirements_for(login_policy, client_id).await?;
        self.evaluate(profile_id, client_ip, attempt, &requirements)
            .await?;
        Ok(requirements.fence)
    }

    /// The sealing context of an admitted sign-in's delivery: its operation
    /// at this issuer.
    fn admitted_context(&self, completion: &AdmittedCompletion<'_>) -> String {
        format!("admitted-sign-in:{}:{}", self.issuer, completion.operation)
    }

    /// The sign-in `completion` already committed for `assignment`'s
    /// Profile, delivered again (see [`Self::deliver_admitted`]); `None`
    /// when the operation has not committed.
    async fn redeliver_admitted(
        &self,
        login_policy: &dyn LoginPolicySource,
        completion: &AdmittedCompletion<'_>,
        client_id: &str,
        assignment: PrincipalAssignmentFence,
    ) -> Result<Option<SignedIn>, SignInError> {
        match self.admitted_session(completion, assignment).await? {
            Some((delivery, session)) => self
                .deliver_admitted(login_policy, delivery, &session, client_id, assignment)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    /// The live session `completion` committed under `assignment` and its
    /// retained delivery: before the operation's deadline, while the session
    /// lives and its Profile can sign in. `None` when the operation has not
    /// committed; a refusal when it has but under another assignment, or may
    /// not be delivered again.
    async fn admitted_session(
        &self,
        completion: &AdmittedCompletion<'_>,
        assignment: PrincipalAssignmentFence,
    ) -> Result<Option<(RetainedDelivery, Session)>, SignInError> {
        let Some(record) = self
            .storage
            .get_operation_result(ADMITTED_NAMESPACE, &completion.key()?)
            .await?
        else {
            return Ok(None);
        };
        if !record.matches(
            ADMITTED_METHOD,
            &admitted_inputs(assignment),
            // The sign-in ceremony's own record, under no period.
            None,
        ) {
            return Err(SignInError::AuthenticationFailed);
        }
        let delivery = RetainedDelivery::open(
            self.keys.as_ref(),
            &self.admitted_context(completion),
            &record.completion.result,
        )
        .await
        .map_err(|e| internal("open the retained sign-in delivery", e))?;
        if delivery.deadline <= Utc::now() {
            return Err(SignInError::AuthenticationFailed);
        }
        // The commit is the whole sign-in: what it owes (its evictions'
        // revocations) committed with it as owed work, so the same session
        // is delivered again from the moment it committed.
        let session = self
            .storage
            .get_session(delivery.session_id)
            .await?
            .filter(|session| !session.is_expired() && session.profile_id == assignment.profile)
            .ok_or(SignInError::AuthenticationFailed)?;
        self.storage
            .get_profile(session.profile_id)
            .await?
            .filter(|profile| profile.status.can_authenticate())
            .ok_or(SignInError::AuthenticationFailed)?;
        Ok(Some((delivery, session)))
    }

    /// `session`'s retained `delivery`, while `assignment` still assigns the
    /// session's Profile and its authentication meets `client_id`'s current
    /// requirements: a retired or moved association delivers nothing again.
    async fn deliver_admitted(
        &self,
        login_policy: &dyn LoginPolicySource,
        delivery: RetainedDelivery,
        session: &Session,
        client_id: &str,
        assignment: PrincipalAssignmentFence,
    ) -> Result<SignedIn, SignInError> {
        let current = self
            .storage
            .get_principal(assignment.principal)
            .await?
            .is_some_and(|p| {
                p.assigned_profile_id == Some(session.profile_id)
                    && p.assignment_revision == assignment.revision
            });
        if !current || assignment.profile != session.profile_id {
            return Err(SignInError::AuthenticationFailed);
        }
        // The requirements the sign-in itself was weighed under, read now;
        // the client's own are applied where the sign-in continues.
        let requirements = self
            .for_account(
                &requirements_for(login_policy, Some(client_id)).await?,
                session.profile_id,
            )
            .await?;
        if let LoginDecision::StepUp(unmet) = requirements.decide(session, Utc::now()) {
            return Err(SignInRefusal::StepUp(unmet).into());
        }
        delivery
            .signed_in(&self.cookie, session)
            .ok_or(SignInError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests;
