// SPDX-License-Identifier: AGPL-3.0-only
//! Who may call the template API. Every call carries an access token for the
//! installation's account API resource, the resource the administration UI
//! signs in to; this service is one more process serving it. The shared
//! receiver verifies the token, bounds it by the credential kinds and scopes
//! each method declares in the schema, and asks the issuer whether its
//! subject may perform the method's declared action, which also establishes
//! that the token, its session and its subject are current.

use std::sync::Arc;

use sid_auth::receiver::{Guarded, Receiver};
use sid_infra::authn::access::AccessRules;

/// `service` served behind `receiver`, each call admitted by the access rule
/// its method declares.
pub fn guarded<S: tonic::server::NamedService>(
    service: S,
    receiver: &Arc<Receiver>,
) -> anyhow::Result<Guarded<S>> {
    let rules = AccessRules::from_descriptors(sid_proto::FILE_DESCRIPTOR_SET)
        .map_err(|e| anyhow::anyhow!("the template API's access rules: {e}"))?;
    Guarded::new(service, receiver.clone(), Arc::new(rules))
        .map_err(|e| anyhow::anyhow!("the template API: {e}"))
}
