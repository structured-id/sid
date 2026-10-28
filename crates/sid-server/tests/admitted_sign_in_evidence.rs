// SPDX-License-Identifier: AGPL-3.0-only
//! A repeat of an admitted sign-in's operation is no further sign-in: it is
//! judged by the rules of its own request but records no evidence for later
//! sign-ins, so a few callback retries cannot make an address or a country
//! look familiar.

mod common;

use std::net::{IpAddr, SocketAddr};

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_core::models::Profile;
use tonic::Request;
use tonic::transport::server::TcpConnectInfo;

fn from(ip: IpAddr) -> Request<()> {
    let mut request = Request::new(());
    request.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(SocketAddr::new(ip, 40000)),
    });
    request
}

/// One admitted sign-in and two repeats of its operation record one success
/// for the address. Before, every repeat was recorded as another sign-in.
#[tokio::test]
async fn repeats_record_no_further_sign_in() {
    let profile = Profile::new(Some("admitted"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let ip: IpAddr = "198.51.100.40".parse().unwrap();
    let authentication = sid_core::models::session::AcceptedEvidence::new(
        Some("urn:sid:acr:basic"),
        vec!["pwd".into()],
        chrono::Utc::now(),
    )
    .authentication(chrono::Utc::now())
    .unwrap();
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);
    let completion = || sid_server::grpc::auth_service::AdmittedCompletion {
        operation: "entry-evidence",
        deadline,
    };

    for _ in 0..3 {
        svc.auth
            .complete_admitted_sign_in(
                &from(ip),
                &profile,
                &authentication,
                "an-application",
                Some(completion()),
            )
            .await
            .expect("signed in, then delivered again");
    }

    let successes = svc
        .mock_storage
        .ip_reputation_events()
        .into_iter()
        .filter(|event| *event == (ip.to_string(), true))
        .count();
    assert_eq!(successes, 1);
}
