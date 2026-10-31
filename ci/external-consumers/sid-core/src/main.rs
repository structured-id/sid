use sid_core::models::{ProfileId, Session};

fn main() {
    let address = "192.0.2.1".parse().ok();
    let session = Session::new_provisional(ProfileId::generate(), address);
    assert_eq!(session.ip_address, address);
}
