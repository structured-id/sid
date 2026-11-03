// SPDX-License-Identifier: AGPL-3.0-only
//! Who may call the attestation API. Every call carries an access token for
//! the installation's account API resource; this service is one more process
//! serving it. A device's owner acts on its keys by this service's own rule;
//! any other caller, the installation's administrator among them, is decided
//! by the issuer for that device. The receiver asks the issuer at admission
//! whether the token is current, since an owner's call asks no permission
//! question. Methods are mapped one by one: a method without an action here
//! is never served.

use std::sync::Arc;

use sid_auth::receiver::{Action, Actions, Guarded, Receiver};

/// Reading a device's key attestation.
pub const DEVICE_READ: &str = "attestation.device.read";
/// Registering, rotating or revoking a device's key.
pub const DEVICE_CHANGE: &str = "attestation.device.change";
/// Listing a Profile's device key attestations.
pub const PROFILE_READ: &str = "attestation.profile.read";

/// The action a call to `path` (`/package.Service/Method`) performs.
pub fn action(path: &str) -> Option<Action> {
    let method = path.strip_prefix("/sid.v1.attestation.AttestationService/")?;
    Some(Action::OwnedObject(match method {
        "GetDeviceAttestation" => DEVICE_READ,
        "RegisterDeviceKey" | "RotateDeviceKey" | "RevokeDeviceKey" => DEVICE_CHANGE,
        "ListDeviceAttestations" => PROFILE_READ,
        _ => return None,
    }))
}

/// `service` served behind `receiver`: only admitted calls reach it.
pub fn guarded<S>(service: S, receiver: &Arc<Receiver>) -> Guarded<S> {
    let actions: Actions = Arc::new(action);
    Guarded::new(service, receiver.clone(), actions)
}
