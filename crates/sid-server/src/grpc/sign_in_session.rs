// SPDX-License-Identifier: AGPL-3.0-only
//! Completing a sign-in ceremony: the session is stored under the
//! installation's concurrent-session limit and its credential is delivered
//! as the ceremony's client takes it. Every ceremony that signs a user in
//! (password, passkey, upstream provider) completes through this one path.

use chrono::Utc;
use sid_authn::browser_session::BrowserCsrf;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::sign_in_delivery::{BrowserCredential, CeremonyClient, Delivery, SignedIn};
use sid_authn::sign_in_refusal::authentication_failed;
use sid_core::models::event::{Event, event_types};
use sid_core::models::{
    ActorFence, AuditEntry, CredentialFence, MutationContext, Profile, Session, SessionEnd,
    SessionId,
};
use sid_plugin::storage::StorageBackend;
use tonic::Status;
use tracing::{info, warn};

use sid_core::grpc_error::refuse::{internal, storage_failure};

/// The keyed operation a browser sign-in completes, whose result is its
/// delivery sealed for a lost response: the session commits with that
/// completion, and a repeat of the operation finds it instead of a second
/// session.
pub(crate) struct RetainedSignIn<'a> {
    pub keys: &'a dyn sid_keys::KeyManager,
    pub completion_key: sid_core::models::OperationKey,
    /// The sealing context: this operation of this issuer.
    pub context: String,
    /// The end of the operation; the delivery is never redelivered after.
    pub deadline: chrono::DateTime<Utc>,
}

/// The namespace of admitted sign-ins' completions.
pub(crate) const ADMITTED_NAMESPACE: &str = "admitted-sign-in";

/// The method name an admitted sign-in's completion records.
const ADMITTED_METHOD: &str = "admitted_sign_in";

/// What completing a sign-in uses, borrowed from the service that ran the
/// ceremony.
pub(crate) struct SignInSessions<'a> {
    pub storage: &'a dyn StorageBackend,
    pub jwt: &'a JwtService,
    pub revocation: &'a RevocationCache,
    /// The issuer whose events announce the session.
    pub issuer: &'a str,
    /// This authority's IdP session cookie.
    pub cookie: &'a sid_authn::browser_session::BrowserCookie,
    /// The most sessions a profile keeps; the oldest are ended beyond it.
    pub max_concurrent_sessions: u32,
}

/// The refusal of a sign-in whose keyed operation already completed.
fn operation_completed() -> Status {
    sid_core::grpc_error::ApiError::new(
        sid_core::grpc_error::ErrorReason::ConcurrentModification,
        "the sign-in already completed",
    )
    .into()
}

impl SignInSessions<'_> {
    /// Store `session` and deliver its credential to `client`: the browser
    /// sign-in page gets the IdP session cookie, a fresh secret whose hash
    /// the session stores, and no access token; a native client gets the
    /// session's access token. `proved_by` is the credential the sign-in
    /// proved, which must still be current when the session commits, and
    /// `policy` the login policy it was admitted under, which must be too.
    /// A browser sign-in completing `retained` commits with that operation's
    /// completion, its sealed delivery.
    pub async fn sign_in(
        &self,
        profile: &Profile,
        session: Session,
        client: CeremonyClient,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
        retained: Option<RetainedSignIn<'_>>,
    ) -> Result<SignedIn, Status> {
        let limit = self.max_concurrent_sessions;
        self.deliver(
            profile, session, client, proved_by, policy, limit, None, retained,
        )
        .await
        .map(|(signed_in, _)| signed_in)
    }

    /// Sign `profile` in as [`Self::sign_in`] does with `session`, the
    /// completion of the pending second-factor context `pending`: the
    /// context ends (owing what its end names) in the session's own commit,
    /// which applies only while the context exists.
    pub async fn complete_pending(
        &self,
        profile: &Profile,
        pending: (SessionId, &SessionEnd),
        session: Session,
        client: CeremonyClient,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
    ) -> Result<SignedIn, Status> {
        let limit = self.max_concurrent_sessions;
        self.deliver(
            profile,
            session,
            client,
            proved_by,
            policy,
            limit,
            Some(pending),
            None,
        )
        .await
        .map(|(signed_in, _)| signed_in)
    }

    /// Store a sign-in's pending second-factor context and deliver its
    /// credential as [`Self::sign_in`] does, with the CSRF token a browser
    /// completes it with. It takes no place under the session limit: the
    /// session it completes into does.
    pub async fn sign_in_pending(
        &self,
        profile: &Profile,
        session: Session,
        client: CeremonyClient,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
    ) -> Result<(SignedIn, Option<String>), Status> {
        self.deliver(profile, session, client, proved_by, policy, 0, None, None)
            .await
    }

    /// Store `session` under `limit` (completing `pending` when given, with
    /// `retained`'s completion when given) and deliver its credential, with
    /// the browser's encoded CSRF token for a browser.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &self,
        profile: &Profile,
        mut session: Session,
        client: CeremonyClient,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
        limit: u32,
        pending: Option<(SessionId, &SessionEnd)>,
        retained: Option<RetainedSignIn<'_>>,
    ) -> Result<(SignedIn, Option<String>), Status> {
        match client {
            CeremonyClient::Browser => {
                let credential = BrowserCredential::bind(&mut session);
                let csrf = session.browser_csrf.as_ref().map(BrowserCsrf::encode);
                let completion = match retained {
                    Some(retained) => {
                        let sealed = credential
                            .retain(
                                retained.keys,
                                &retained.context,
                                &session,
                                retained.deadline,
                            )
                            .await
                            .map_err(|e| internal("seal the sign-in delivery", e))?;
                        // Kept no longer than it can be delivered again.
                        Some(
                            sid_core::models::OperationCompletion::new(
                                ADMITTED_NAMESPACE,
                                retained.completion_key,
                                ADMITTED_METHOD,
                                profile.id.to_string().as_bytes(),
                                sealed,
                            )
                            .retained_until(retained.deadline),
                        )
                    }
                    None => None,
                };
                self.persist(
                    profile, &session, proved_by, policy, limit, pending, completion,
                )
                .await?;
                Ok((credential.signed_in(self.cookie, &session), csrf))
            }
            CeremonyClient::Native => {
                self.persist(profile, &session, proved_by, policy, limit, pending, None)
                    .await?;
                let sub = profile.id.to_string();
                let access_token = self
                    .jwt
                    .issue_access_token(
                        &sub,
                        Some(&sub),
                        profile,
                        &session,
                        &session.scopes,
                        None,
                        None,
                    )
                    .map_err(|e| internal("issue access token", e))?;
                // The token expires with the session when the session is shorter.
                let expires_in = self
                    .jwt
                    .access_token_ttl_secs()
                    .min((session.expires_at - Utc::now()).num_seconds());
                Ok((
                    SignedIn {
                        session_id: session.id.to_string(),
                        expires_in,
                        delivery: Delivery::Bearer(access_token.into()),
                    },
                    None,
                ))
            }
        }
    }

    /// Store `session` under the concurrent-session `limit` (0: none) and
    /// announce it, while `policy` still holds; with `pending`, as the
    /// completion of that pending context, which ends in the same commit;
    /// with `completion`, committing that keyed operation's completion.
    #[allow(clippy::too_many_arguments)]
    async fn persist(
        &self,
        profile: &Profile,
        session: &Session,
        proved_by: Option<&CredentialFence>,
        policy: Option<ActorFence>,
        limit: u32,
        pending: Option<(SessionId, &SessionEnd)>,
        completion: Option<sid_core::models::OperationCompletion>,
    ) -> Result<(), Status> {
        // The storage counts, evicts and inserts in one serialized step, and
        // owes each evicted session's client a logout; the same commit owes
        // the session.created event.
        let _audit_start = std::time::Instant::now();
        let created = Event::new(self.issuer, event_types::SESSION_CREATED)
            .with_subject(format!("session/{}", session.id))
            .with_data(serde_json::json!({
                "profile_id": profile.id.to_string(),
                "session_id": session.id.to_string(),
            }));
        let mut ctx = MutationContext::from(AuditEntry::user(
            profile.id.to_string(),
            "session.create",
            session.id.to_string(),
        ))
        .with_work(created.relay());
        if let Some(fence) = policy {
            ctx = ctx.fenced_by(fence);
        }
        if let Some(completion) = completion {
            ctx = ctx.with_operation(completion);
        }
        let stored = match pending {
            Some((pending, end)) => {
                self.storage
                    .complete_pending_session(pending, end, session, limit, proved_by, ctx)
                    .await
            }
            None => {
                self.storage
                    .create_session_atomic(session, limit, proved_by, ctx)
                    .await
            }
        };
        let evicted = match stored {
            Ok(evicted) => evicted,
            // The credential or the login policy changed after its check, or
            // the pending context ended: the sign-in completes nothing and is
            // started again.
            Err(sid_core::Error::Fenced(_)) => return Err(authentication_failed()),
            // The keyed operation already committed its session: the caller
            // redelivers that one.
            Err(sid_core::Error::OperationCompleted(_)) => return Err(operation_completed()),
            Err(e) => return Err(storage_failure(e)),
        };
        if !evicted.is_empty() {
            info!(
                profile_id = %profile.id,
                evicted_count = evicted.len(),
                "Session limit enforced: evicted oldest sessions"
            );
        }
        // An evicted session's access tokens stop at once in every process.
        // Its revocation committed as owed work with the eviction: one not
        // published now is published by the work runner, and the committed
        // sign-in stands either way (refusing it would revoke nothing).
        for ended in &evicted {
            if let Err(e) = self.revocation.revoke_session(ended.to_string()).await {
                warn!(session_id = %ended, error = %e, "evicted session revocation left to its owed work");
            }
        }
        #[cfg(feature = "telemetry")]
        {
            use opentelemetry::{KeyValue, global};
            global::meter("sid")
                .f64_histogram("sid_audit_write_seconds")
                .build()
                .record(
                    _audit_start.elapsed().as_secs_f64(),
                    &[KeyValue::new("chain_scope", "session")],
                );
        }
        Ok(())
    }
}
