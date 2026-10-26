// SPDX-License-Identifier: AGPL-3.0-only
//! Completing a sign-in ceremony: the session is stored under the
//! installation's concurrent-session limit and its credential is delivered
//! as the ceremony's client takes it. Every ceremony that signs a user in
//! (password, passkey, upstream provider) completes through this one path.

use chrono::Utc;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::sign_in_delivery::{BrowserCredential, CeremonyClient, Delivery, SignedIn};
use sid_authn::sign_in_refusal::authentication_failed;
use sid_core::models::event::{Event, event_types};
use sid_core::models::{AuditEntry, CredentialFence, MutationContext, Profile, Session};
use sid_plugin::storage::StorageBackend;
use tonic::Status;
use tracing::info;

use sid_core::grpc_error::refuse::{dependency_unavailable, internal, storage_failure};

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

impl SignInSessions<'_> {
    /// Store `session` and deliver its credential to `client`: the browser
    /// sign-in page gets the IdP session cookie, a fresh secret whose hash
    /// the session stores, and no access token; a native client gets the
    /// session's access token. `proved_by` is the credential the sign-in
    /// proved, which must still be current when the session commits.
    pub async fn sign_in(
        &self,
        profile: &Profile,
        mut session: Session,
        client: CeremonyClient,
        proved_by: Option<&CredentialFence>,
    ) -> Result<SignedIn, Status> {
        match client {
            CeremonyClient::Browser => {
                let credential = BrowserCredential::bind(&mut session);
                self.persist(profile, &session, proved_by).await?;
                Ok(credential.signed_in(self.cookie, &session))
            }
            CeremonyClient::Native => {
                self.persist(profile, &session, proved_by).await?;
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
                Ok(SignedIn {
                    session_id: session.id.to_string(),
                    expires_in,
                    delivery: Delivery::Bearer(access_token.into()),
                })
            }
        }
    }

    /// Store `session` under the concurrent-session limit and announce it.
    async fn persist(
        &self,
        profile: &Profile,
        session: &Session,
        proved_by: Option<&CredentialFence>,
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
        let ctx = MutationContext::from(AuditEntry::user(
            profile.id.to_string(),
            "session.create",
            session.id.to_string(),
        ))
        .with_work(created.relay());
        let evicted = match self
            .storage
            .create_session_atomic(session, self.max_concurrent_sessions, proved_by, ctx)
            .await
        {
            Ok(evicted) => evicted,
            // The credential changed after its check: a wrong password then.
            Err(sid_core::Error::Fenced(_)) => return Err(authentication_failed()),
            Err(e) => return Err(storage_failure(e)),
        };
        if !evicted.is_empty() {
            info!(
                profile_id = %profile.id,
                evicted_count = evicted.len(),
                "Session limit enforced: evicted oldest sessions"
            );
        }
        // An evicted session's access tokens stop at once in every process;
        // when that cannot be propagated the sign-in fails rather than leave
        // them live elsewhere.
        for ended in &evicted {
            self.revocation
                .revoke_session(ended.to_string())
                .await
                .map_err(|e| dependency_unavailable("session revocation", e))?;
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
