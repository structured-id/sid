// SPDX-License-Identifier: AGPL-3.0-only
//! Asking sid-authz whether the subject of an original request may act
//! (D054 request-bound evaluation): the asking service authenticates as
//! itself with its own credential for the authorization API and hands over
//! the request's access token as the evidence of whose permission is
//! decided. Forward auth and protected gRPC services ask through this one
//! path.

use crate::credential::ClientCredential;

use super::jwt::ForwardAuthClaims;

/// A permission question about one original request.
#[derive(Clone, Copy)]
pub struct Question<'a> {
    /// What asks, for the log: the protected application or service.
    pub asking: &'a str,
    /// The exact issuer of the target resource.
    pub issuer: &'a str,
    pub resource: sid_core::models::ResourceId,
    pub action: &'a str,
    /// The object of the action within the resource; empty for the resource
    /// itself.
    pub object: &'a str,
    /// The request's access token, the evidence of whose permission is asked.
    pub token: &'a str,
    pub claims: &'a ForwardAuthClaims,
    /// The original request's method and external URI, as its sender proof
    /// was checked against them.
    pub method: &'a str,
    pub uri: &'a str,
}

/// What sid-authz decided about a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Allowed,
    Denied,
    /// The request's token is no usable evidence although its signature
    /// verified: revoked, its sign-in ended, its subject no longer active.
    /// The request is unauthenticated.
    TokenRefused,
}

/// sid-authz gave no decision: no credential, a refused or unreachable
/// call, or an answer that is neither allow nor deny.
#[derive(Debug, thiserror::Error)]
#[error("authorization check unavailable")]
pub struct NoDecision;

/// The field sid-authz names when the request's own token is refused.
const EVIDENCE_FIELD: &str = "request.access_token";

/// What sid-authz decides about `question`'s subject and its action;
/// anything else is [`NoDecision`]. A token the authorization API stopped
/// accepting is replaced once, and an answer that did not arrive is asked
/// for once more: the question concerns the same pending request, with the
/// same confirmation, and asking changes nothing, so asking again is safe.
pub async fn ask(
    checker: Option<&ClientCredential>,
    authz: &tonic::transport::Channel,
    question: Question<'_>,
) -> Result<Permission, NoDecision> {
    use sid_proto::sid::v1::authz::check_permission_request::Evaluation;
    use sid_proto::sid::v1::authz::permission_target::Scope;
    use sid_proto::sid::v1::authz::{
        CheckPermissionRequest, PermissionOutcome, PermissionTarget, RequestEvaluation,
    };
    let Some(checker) = checker else {
        tracing::error!(
            asking = question.asking,
            "no credential for the authorization API; the request is refused"
        );
        return Err(NoDecision);
    };
    // The token goes only to the authorization API of its own issuer, the
    // one that can verify it.
    if checker.issuer() != question.issuer {
        tracing::error!(
            asking = question.asking,
            "the authorization API credential belongs to another issuer; the request is refused"
        );
        return Err(NoDecision);
    }
    // A sender-bound token goes with the confirmation of the proof the asker
    // checked and consumed; the proof is never sent or consumed again. Made
    // once, so a retry concerns the same pending request.
    let confirmation = question.claims.cnf.as_ref().map(|cnf| {
        dpop_confirmation(
            &cnf.jkt,
            question.method,
            question.uri,
            question.claims.exp,
            chrono::Utc::now(),
        )
    });
    let request = CheckPermissionRequest {
        action: question.action.to_owned(),
        target: Some(PermissionTarget {
            scope: Some(Scope::Resource(question.resource.into())),
            object: question.object.to_owned(),
        }),
        evaluation: Some(Evaluation::Request(RequestEvaluation {
            access_token: question.token.to_owned(),
            confirmation,
        })),
        ..Default::default()
    };
    let mut client =
        sid_proto::sid::v1::authz_service_client::AuthzServiceClient::new(authz.clone());
    let (mut renewed, mut asked_again) = (false, false);
    let answer = loop {
        let authorization = match checker.authorization().await {
            Ok(authorization) => authorization,
            Err(e) => {
                tracing::error!(error = %e, "no token for the authorization API");
                return Err(NoDecision);
            }
        };
        let mut call = tonic::Request::new(request.clone());
        call.metadata_mut()
            .insert("authorization", authorization.clone());
        match client.check_permission(call).await {
            Ok(answer) => break answer.into_inner(),
            Err(status) if status.code() == tonic::Code::Unauthenticated && !renewed => {
                checker.refused(&authorization).await;
                renewed = true;
            }
            Err(status) if status.code() == tonic::Code::Unavailable && !asked_again => {
                tracing::warn!(
                    asking = question.asking,
                    message = status.message(),
                    "no answer from the authorization API; asking once more"
                );
                asked_again = true;
            }
            Err(status) if refuses_evidence(&status) => {
                tracing::debug!(
                    asking = question.asking,
                    "the request's token is no longer usable"
                );
                return Ok(Permission::TokenRefused);
            }
            Err(status) => {
                tracing::error!(
                    asking = question.asking,
                    code = ?status.code(),
                    message = status.message(),
                    "authorization check refused or unavailable"
                );
                return Err(NoDecision);
            }
        }
    };
    match answer.outcome() {
        PermissionOutcome::Allowed => Ok(Permission::Allowed),
        PermissionOutcome::Denied => {
            tracing::debug!(
                asking = question.asking,
                action = question.action,
                "permission denied"
            );
            Ok(Permission::Denied)
        }
        outcome @ (PermissionOutcome::EvidenceRequired | PermissionOutcome::Unspecified) => {
            tracing::error!(
                asking = question.asking,
                ?outcome,
                "authorization check gave no decision"
            );
            Err(NoDecision)
        }
    }
}

/// Whether `status` is sid-authz refusing the request's own token as
/// evidence: INVALID_ARGUMENT naming exactly that field. Any other refusal
/// concerns the question or the asker, not the request.
fn refuses_evidence(status: &tonic::Status) -> bool {
    use tonic_types::StatusExt;
    status.code() == tonic::Code::InvalidArgument
        && status.get_details_bad_request().is_some_and(|bad| {
            bad.field_violations
                .iter()
                .any(|violation| violation.field == EVIDENCE_FIELD)
        })
}

/// How long sid-authz may use a confirmation of a checked proof: enough to
/// retry the question about the same pending request.
const CONFIRMATION_WINDOW: chrono::Duration = chrono::Duration::seconds(30);

/// What the asker confirms about an original request whose DPoP proof it
/// checked (and whose `jti` it consumed) for a token bound to `jkt`: the
/// method, the external URI without query and fragment (the `htu`,
/// RFC 9449 §4.2), one identifier for the pending request, and a short
/// window never beyond the token's expiry. The proof itself is not sent.
pub(crate) fn dpop_confirmation(
    jkt: &str,
    method: &str,
    uri: &str,
    exp: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> sid_proto::sid::v1::authz::RequestConfirmation {
    use sid_proto::sid::v1::authz::{RequestConfirmation, SenderProofProfile};
    let htu = uri.split(['?', '#']).next().unwrap_or(uri);
    let until = std::cmp::min(now + CONFIRMATION_WINDOW, {
        chrono::DateTime::from_timestamp(exp, 0).unwrap_or(now)
    });
    let at = |t: chrono::DateTime<chrono::Utc>| prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: i32::try_from(t.timestamp_subsec_nanos()).unwrap_or(0),
    };
    RequestConfirmation {
        profile: SenderProofProfile::Dpop.into(),
        method: method.to_owned(),
        uri: htu.to_owned(),
        request_id: uuid::Uuid::new_v4().into_bytes().to_vec(),
        jkt: jkt.to_owned(),
        verified_at: Some(at(now)),
        valid_until: Some(at(until)),
    }
}

#[cfg(test)]
mod tests;
