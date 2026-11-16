// SPDX-License-Identifier: AGPL-3.0-only
//! Who may call the attestation API. Every call carries an access token for
//! the installation's account API resource; this service is one more process
//! serving it. The shared receiver bounds the token by the credential kinds
//! and scopes each method declares in the schema. A device's owner acts on
//! its keys by this service's own rule; any other caller, the installation's
//! administrator among them, is decided by the issuer for that device. The
//! receiver asks the issuer at admission whether the token is current, since
//! an owner's call asks no permission question.

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
        .map_err(|e| anyhow::anyhow!("the attestation API's access rules: {e}"))?;
    Guarded::new(service, receiver.clone(), Arc::new(rules))
        .map_err(|e| anyhow::anyhow!("the attestation API: {e}"))
}
