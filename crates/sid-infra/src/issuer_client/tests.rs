// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const INSTALLATION: &str = "https://sid.example.com";
const HANDLE: &str = "0123456789abcdef0123456789abcdef";
/// The `kid` of the BFF's key, registered for the client.
const KID: &str = "bff-key";

fn bundle() -> ClientConnection {
    ClientConnection {
        issuer: format!("{INSTALLATION}/i/{HANDLE}"),
        client_id: "account-web".into(),
        resource: format!("{INSTALLATION}/account"),
        scopes: vec!["openid".into(), "account".into()],
        redirect_uri: "https://account.sid.example.com/auth/callback".into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
        key_ids: vec!["previous-key".into(), KID.into()],
    }
}

/// The account API's answer is the same representation: converted, it is
/// accepted as the same connection.
#[test]
fn the_account_api_answer_is_the_same_connection() {
    let b = bundle();
    let answer = AccountConnection {
        issuer: b.issuer.clone(),
        client_id: b.client_id.clone(),
        resource: b.resource.clone(),
        scopes: b.scopes.clone(),
        redirect_uri: b.redirect_uri.clone(),
        token_endpoint_auth_method: b.token_endpoint_auth_method.clone(),
    };
    assert_eq!(
        Connection::accept(answered(answer, KID)).unwrap(),
        Connection::accept(b).unwrap()
    );
}

/// A delivered bundle file is read and validated; one that cannot be read is
/// an error, never a fallback.
#[test]
fn a_delivered_bundle_file_is_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("connection.json");
    std::fs::write(&path, serde_json::to_string(&bundle()).unwrap()).unwrap();
    assert_eq!(
        load_connection(&path, KID).unwrap(),
        Connection::accept(bundle()).unwrap()
    );
    let missing = dir.path().join("missing.json");
    assert!(load_connection(&missing, KID).is_err());
}

/// A lazy channel to nowhere.
fn unreachable() -> crate::deadline::IssuerChannel {
    crate::deadline::bounded_channel("http://127.0.0.1:1", std::time::Duration::from_millis(100))
        .unwrap()
}

fn key() -> ClientKey {
    ClientKey::generate_ed25519().unwrap().0
}

/// Without the issuer the connection is not learned, and the next call asks
/// again instead of keeping the failure.
#[tokio::test]
async fn an_unreachable_issuer_is_asked_again() {
    let client = RpClient::new(key(), INSTALLATION.into(), unreachable()).unwrap();
    assert!(matches!(
        client.connection().await,
        Err(RpClientError::Rpc(_))
    ));
    assert!(client.connection.get().is_none());
    assert!(client.connection().await.is_err());
}

/// A client given its connection by the deployment never asks the issuer for
/// one: the unreachable channel is not called.
#[tokio::test]
async fn a_delivered_connection_needs_no_discovery() {
    let connection = Connection::accept(bundle()).unwrap();
    let client = RpClient::delivered(
        key(),
        INSTALLATION.into(),
        unreachable(),
        connection.clone(),
    )
    .unwrap();
    assert_eq!(client.connection().await.unwrap(), &connection);
}

/// A key that names no key id cannot be this client's: the registration
/// lists the client's keys by id, and connection proofs are issued by it.
#[tokio::test]
async fn a_key_without_an_id_is_refused() {
    let (_, pem) = ClientKey::generate_ed25519().unwrap();
    let unnamed = ClientKey::from_pem(&pem, "EdDSA", None).unwrap();
    assert!(matches!(
        RpClient::new(unnamed, INSTALLATION.into(), unreachable()),
        Err(RpClientError::Invalid(_))
    ));
}

/// A call whose answer was lost or broken may have taken effect; an
/// exhausted issuer did nothing; any other answer refused the call; a call
/// that never left was not sent. Browser sessions keep a session through the
/// first two and end it on a refused refresh, so the line between them
/// decides whether a user is signed out.
#[test]
fn a_failed_call_says_what_it_did() {
    use tonic::{Code, Status};
    for code in [
        Code::Unavailable,
        Code::Cancelled,
        Code::DeadlineExceeded,
        Code::Unknown,
        Code::Internal,
        Code::Aborted,
        Code::DataLoss,
    ] {
        assert!(
            matches!(
                GrantFailure::from(RpClientError::Rpc(Status::new(code, "lost"))),
                GrantFailure::Uncertain(_)
            ),
            "{code:?}"
        );
    }
    assert!(matches!(
        GrantFailure::from(RpClientError::Rpc(Status::resource_exhausted("busy"))),
        GrantFailure::Declined(_)
    ));
    for code in [
        Code::InvalidArgument,
        Code::Unauthenticated,
        Code::PermissionDenied,
        Code::NotFound,
        Code::FailedPrecondition,
        Code::Unimplemented,
    ] {
        assert!(
            matches!(
                GrantFailure::from(RpClientError::Rpc(Status::new(code, "refused"))),
                GrantFailure::Refused(_)
            ),
            "{code:?}"
        );
    }
    assert!(matches!(
        GrantFailure::from(RpClientError::Invalid("no key id".into())),
        GrantFailure::NotSent(_)
    ));
}
