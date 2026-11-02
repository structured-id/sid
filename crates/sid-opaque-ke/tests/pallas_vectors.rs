//! Case 0 of the published `opaque-vectors.json`, which the TypeScript client
//! replays byte for byte: OPAQUE on Pallas must produce the same messages and
//! keys whichever crate defines the suite. An integration test, because the
//! crate's own tests blind differently for their RFC vectors.

use rand::{SeedableRng, rngs::StdRng};
use sid_opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, PallasCipherSuite, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};

/// The vectors' generator draws every word through `fill_bytes`, which on
/// `StdRng` gives other values than its `next_u64`; replaying it needs the same.
struct FillOnly(StdRng);

impl rand_core::TryRng for FillOnly {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::Rng::fill_bytes(&mut self.0, dest);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FillOnly {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_run_matches_the_published_vector() {
    let password = b"Str0ngP@ssword!";
    let mut server_rng = StdRng::seed_from_u64(1_000);
    let setup = ServerSetup::<PallasCipherSuite>::new(&mut server_rng);

    let mut reg_rng = FillOnly(StdRng::seed_from_u64(2_000));
    let start = ClientRegistration::<PallasCipherSuite>::start(&mut reg_rng, password).unwrap();
    assert_eq!(
        hex(&start.message.serialize()),
        "4d0ea205a46bc9962af4cb1bea39a447cdc4e10a513a81e8a25935804665dc35"
    );
    let response =
        ServerRegistration::<PallasCipherSuite>::start(&setup, start.message, b"credential")
            .unwrap();
    assert_eq!(
        hex(&response.message.serialize()),
        "4f98c1e176ea52f7583da970d349adc2cbfba32428dbff794599732d68f7dd17e0444568aef18328bf12fa6defbd7629998fc5f548e19815f983e9a0a86fe689"
    );
    let finished = start
        .state
        .finish(
            &mut reg_rng,
            password,
            response.message,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    assert_eq!(
        hex(&finished.message.serialize()),
        "c0a66841345cfd6f89b7aea9b8ce6e76f89f19103a64ed8a1ca426a08b14282bdcdd983a988eacb03b48988dca2773b4b81cfa187ae50a19f66ce5919b005b5e52171f497804d21a8f9110f22db43718ceda44ff4a8bd83ea730ea0d2b4dc6e9aa73d0d3203b4274ce1de2a1258b443a14e5dd370af546f58a3b91ca0a0de16d"
    );
    let file = ServerRegistration::<PallasCipherSuite>::finish(finished.message);

    let mut login_rng = FillOnly(StdRng::seed_from_u64(3_000));
    let login = ClientLogin::<PallasCipherSuite>::start(&mut login_rng, password).unwrap();
    let server_login = ServerLogin::<PallasCipherSuite>::start(
        &mut server_rng,
        &setup,
        Some(file),
        login.message,
        b"credential",
        ServerLoginParameters::default(),
    )
    .unwrap();
    let done = login
        .state
        .finish(
            &mut login_rng,
            password,
            server_login.message,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    assert_eq!(
        hex(&done.message.serialize()),
        "bd726ce8923aeb9f2203c6ece5872d6bc0cba5cdc45fe5771d9dce7465db06c1"
    );
    assert_eq!(
        hex(&done.session_key),
        "5964d2f724accb16487e0e5a91c2d4e537f8de1cc9e68b71d0133674af70db12"
    );
    assert_eq!(
        hex(&done.export_key),
        "b390e9e1e83e8c049139b750d60b290b77102cac8c3f47d15577f97581411625"
    );
}
