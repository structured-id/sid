use sid_core::models::{ProfileId, Session};

fn main() {
    let session = Session::new_provisional(ProfileId::generate(), "192.0.2.1".to_string());
    assert_eq!(session.ip_address, "192.0.2.1");
}
