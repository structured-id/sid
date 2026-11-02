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
        "3b6c499c59c2a119f4cc6bc4fbe083f7ec0a886196df4a03cabfb63718ac0fa6"
    );
    let response =
        ServerRegistration::<PallasCipherSuite>::start(&setup, start.message, b"credential")
            .unwrap();
    assert_eq!(
        hex(&response.message.serialize()),
        "2b0d5ea31ecb55a9082234102086eba3bde2fefb06808c17f614ab741c55db01e0444568aef18328bf12fa6defbd7629998fc5f548e19815f983e9a0a86fe689"
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
        "dd77f4c45251e35586db73aafa7f4c0c0cdd2301cc86f09faa2ab76aeb59ba368b6c2814175626750b1dedc6eaa46401a16288d3ce0ca6c1f36159c894c38f3e52171f497804d21a8f9110f22db43718ceda44ff4a8bd83ea730ea0d2b4dc6e910245de87b44aeb1c2ea80f58f85ed22c57309f8a9527c6338d519e224f35b1c"
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
        "e9338ad92638d99ab8b0152656e232ccb95c980b7b7df7477f661a590397eb2a"
    );
    assert_eq!(
        hex(&done.session_key),
        "64a7e110934f5191bcd28da4bfe8f76fd9efb8f8f0487a2ac591a6fcd079d04c"
    );
    assert_eq!(
        hex(&done.export_key),
        "5f629e93c5ad406ac43c2bcab2ce10640f7e6a3fcde3827ebbb9a7c0171f6f45"
    );
}
