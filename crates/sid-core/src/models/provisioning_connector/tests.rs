use super::*;

/// Retired is final; active and disabled switch and both retire; a state
/// does not "change" into itself.
#[test]
fn lifecycle_steps() {
    use ConnectorState::*;
    for (from, to, allowed) in [
        (Active, Disabled, true),
        (Disabled, Active, true),
        (Active, Retired, true),
        (Disabled, Retired, true),
        (Retired, Active, false),
        (Retired, Disabled, false),
        (Active, Active, false),
        (Disabled, Disabled, false),
        (Retired, Retired, false),
    ] {
        assert_eq!(from.may_become(to), allowed, "{from:?} -> {to:?}");
    }
}

/// Stored forms read back as the same value; an unknown form is an error,
/// not a default.
#[test]
fn stored_forms_round_trip() {
    for state in [
        ConnectorState::Active,
        ConnectorState::Disabled,
        ConnectorState::Retired,
    ] {
        assert_eq!(state.as_str().parse::<ConnectorState>().unwrap(), state);
    }
    for direction in [
        ProvisioningDirection::Inbound,
        ProvisioningDirection::Outbound,
    ] {
        assert_eq!(
            direction.as_str().parse::<ProvisioningDirection>().unwrap(),
            direction
        );
    }
    for kind in [
        ConnectorCredentialKind::ScimBearer,
        ConnectorCredentialKind::ClientSecret,
    ] {
        assert_eq!(
            kind.as_str().parse::<ConnectorCredentialKind>().unwrap(),
            kind
        );
    }
    assert!("paused".parse::<ConnectorState>().is_err());
    assert!("both".parse::<ProvisioningDirection>().is_err());
    assert!("private_key".parse::<ConnectorCredentialKind>().is_err());
}

/// A new connector is active at its first revision, with its own random
/// client_id that is not its ID.
#[test]
fn new_connector_is_active() {
    let c = ProvisioningConnector::new(OrgId::generate(), ProvisioningDirection::Inbound, "HR");
    assert!(c.is_active());
    assert_eq!(c.revision, 1);
    assert_eq!(c.direction, ProvisioningDirection::Inbound);
    assert!(c.client_id.starts_with(CONNECTOR_CLIENT_ID_PREFIX));
    assert_eq!(c.client_id.len(), CONNECTOR_CLIENT_ID_PREFIX.len() + 24);
    assert!(!c.client_id.contains(&c.id.to_string()));
    let other = ProvisioningConnector::new(c.org_id, ProvisioningDirection::Inbound, "HR");
    assert_ne!(c.client_id, other.client_id);
}

/// The two credential kinds are issued with different prefixes, so a client
/// secret is never taken for a SCIM bearer or the other way round.
#[test]
fn credential_kinds_have_their_own_prefixes() {
    assert_ne!(
        ConnectorCredentialKind::ScimBearer.secret_prefix(),
        ConnectorCredentialKind::ClientSecret.secret_prefix()
    );
    assert!(
        !CONNECTOR_CLIENT_SECRET_PREFIX.starts_with(SCIM_BEARER_PREFIX)
            && !SCIM_BEARER_PREFIX.starts_with(CONNECTOR_CLIENT_SECRET_PREFIX)
    );
}

/// A credential works while active or in its grace and before its expiry;
/// never once revoked or expired, nor at the exact end of its validity.
#[test]
fn credential_usability() {
    let now = Utc::now();
    let mut c = ProvisioningCredential::new(
        ProvisioningConnectorId::generate(),
        ConnectorCredentialKind::ScimBearer,
        "v",
    );
    assert!(c.is_usable_at(now));

    c.status = CredentialStatus::GracePeriod;
    c.expires_at = Some(now + Duration::hours(1));
    assert!(c.is_usable_at(now));
    assert!(!c.is_usable_at(now + Duration::hours(1)));

    c.status = CredentialStatus::Revoked;
    c.expires_at = None;
    assert!(!c.is_usable_at(now));

    c.status = CredentialStatus::Expired;
    assert!(!c.is_usable_at(now));
}
