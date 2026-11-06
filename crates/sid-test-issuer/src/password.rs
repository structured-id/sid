// SPDX-License-Identifier: AGPL-3.0-only
//! The client side of the password ceremonies (OPAQUE on Pallas), for the
//! tests that sign a user in at the test issuer the way a native client does.

use ff::PrimeField;
use pasta_curves::pallas;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use sid_pake_core::pallas_opaque::PallasCipherSuite;

/// A registration's first message and the state its finish reads.
pub(crate) struct RegistrationStart {
    pub(crate) request: Vec<u8>,
    state: ClientRegistration<PallasCipherSuite>,
}

/// Start registering `password`, with an OPRF blind a policy-proof circuit
/// can hold (its bytes are also a base field element), as the password
/// clients choose it.
pub(crate) fn start_registration(password: &[u8]) -> RegistrationStart {
    loop {
        let started =
            ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password)
                .expect("registration start");
        // The state begins with the blind (`OprfClient`: blind, then the
        // blinded element).
        let mut repr = <pallas::Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(&started.state.serialize()[..32]);
        if bool::from(pallas::Base::from_repr(repr).is_some()) {
            return RegistrationStart {
                request: started.message.serialize().to_vec(),
                state: started.state,
            };
        }
    }
}

/// The registration record of `password` from the server's `response`.
pub(crate) fn finish_registration(
    started: RegistrationStart,
    password: &[u8],
    response: &[u8],
) -> Vec<u8> {
    started
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            password,
            RegistrationResponse::deserialize(response).expect("a registration response"),
            ClientRegistrationFinishParameters::default(),
        )
        .expect("registration finish")
        .message
        .serialize()
        .to_vec()
}

/// A login's first message and the state its finish reads.
pub(crate) struct LoginStart {
    pub(crate) request: Vec<u8>,
    state: sid_opaque_ke::ClientLogin<PallasCipherSuite>,
}

pub(crate) fn start_login(password: &[u8]) -> LoginStart {
    let started = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password)
        .expect("login start");
    LoginStart {
        request: started.message.serialize().to_vec(),
        state: started.state,
    }
}

/// The finalization of a login of `password` from the server's `response`;
/// for a wrong password it is whatever bytes a client sends then.
pub(crate) fn finish_login(started: LoginStart, password: &[u8], response: &[u8]) -> Vec<u8> {
    let response = CredentialResponse::<PallasCipherSuite>::deserialize(response)
        .expect("a credential response");
    started
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map(|done| done.message.serialize().to_vec())
        .unwrap_or_else(|_| vec![0u8; 64])
}
