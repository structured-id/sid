// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

// Nothing is admitted until an administrator turns an admission on, and
// incoming federated sign-in is the OR of the two, with no third value.
// Bug prevented: a fresh installation admitting external identities, or
// one admission implying the other.
#[test]
fn federated_sign_in_is_the_or_of_two_independent_admissions() {
    assert_eq!(
        LoginSettings::default(),
        LoginSettings {
            allow_personal_profiles: false,
            allow_foreign_corporate_profiles: false,
        }
    );
    for (personal, corporate) in [(false, false), (true, false), (false, true), (true, true)] {
        let settings = LoginSettings {
            allow_personal_profiles: personal,
            allow_foreign_corporate_profiles: corporate,
        };
        assert_eq!(settings.admits_federated_sign_in(), personal || corporate);
    }
}
