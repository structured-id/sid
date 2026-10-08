use super::*;

fn test_org_ctx() -> ScimOrgContext {
    ScimOrgContext {
        org_domain: "acme.corp".into(),
        project_id: sid_core::models::ProjectId::new(),
    }
}

fn test_create_request() -> proto::ScimCreateUserRequest {
    proto::ScimCreateUserRequest {
        external_id: "EMP-42".into(),
        user_name: "alice.smith".into(),
        name: Some(proto::ScimName {
            formatted: "Alice Smith".into(),
            given_name: "Alice".into(),
            family_name: "Smith".into(),
            ..Default::default()
        }),
        display_name: "Alice Smith".into(),
        emails: vec![proto::ScimEmail {
            value: "alice.smith@acme.com".into(),
            r#type: "work".into(),
            primary: true,
        }],
        phone_numbers: vec![proto::ScimPhoneNumber {
            value: "+1-555-0100".into(),
            r#type: "work".into(),
            primary: true,
        }],
        department: "Engineering".into(),
        title: "Senior Engineer".into(),
        active: true,
    }
}

fn mapped(req: &proto::ScimCreateUserRequest) -> CreateUserMapping {
    scim_create_user_to_sid(req, &test_org_ctx()).unwrap()
}

#[test]
fn test_create_user_profile_is_corporate_provisioned() {
    let mapping = mapped(&test_create_request());

    assert_eq!(mapping.profile.profile_type, ProfileType::Corporate);
    assert_eq!(mapping.profile.status, ProfileStatus::Provisioned);
    assert_eq!(mapping.profile.visibility, ProfileVisibility::Private);
    // Structured name from SCIM name object
    assert_eq!(mapping.profile.given_name.as_deref(), Some("Alice"));
    assert_eq!(mapping.profile.family_name.as_deref(), Some("Smith"));
    // Corporate profiles use profileId as DB placeholder username
    assert_eq!(
        mapping.profile.username,
        Some(mapping.profile.id.to_string())
    );
}

#[test]
fn test_create_user_corporate_login_principal() {
    let mapping = mapped(&test_create_request());

    let login = mapping
        .principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Username)
        .expect("should have corporate login principal");

    assert_eq!(login.value, "alice.smith#acme.corp");
    assert!(!login.verified); // Awaiting claim
}

/// An installation's SCIM logins carry its organization's own domain (the
/// `login#domain` federated username), never a guessed or configured one.
#[test]
fn test_installation_context_uses_the_organization_domain() {
    let org = sid_core::models::Organization::implicit_community("corp.sid.example.com");
    let ctx = ScimOrgContext::installation(&org);
    assert_eq!(ctx.org_domain, "corp.sid.example.com");
    assert_eq!(ctx.project_id, sid_core::models::ProjectId::system());

    let mapping = scim_create_user_to_sid(&test_create_request(), &ctx).unwrap();
    let login = mapping
        .principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Username)
        .unwrap();
    assert_eq!(login.value, "alice.smith#corp.sid.example.com");
}

#[test]
fn test_create_user_email_principal() {
    let mapping = mapped(&test_create_request());

    let email = mapping
        .principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .expect("should have email principal");

    // The organization's login handle is its resolution key.
    assert_eq!(email.value, "alicesmith@acme.com");
    assert!(!email.verified);
    assert!(email.is_primary);
}

/// Regression: a SCIM email became the login handle exactly as sent and its
/// contact was lowercased. The principal holds the key; the contact keeps
/// the directory's spelling, which mail goes to.
#[test]
fn test_create_user_email_keeps_its_spelling() {
    let mut req = test_create_request();
    req.emails[0].value = "Alice.Smith+HR@Acme.com".into();
    let mapping = mapped(&req);
    let email = mapping
        .principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Email)
        .unwrap();
    assert_eq!(email.value, "alicesmith@acme.com");
    assert_eq!(mapping.emails[0].email, "Alice.Smith+HR@acme.com");
}

/// A malformed SCIM email is refused, not stored as a login handle.
#[test]
fn test_create_user_malformed_email_is_refused() {
    let mut req = test_create_request();
    req.emails[0].value = "alice..smith@acme.com".into();
    assert!(matches!(
        scim_create_user_to_sid(&req, &test_org_ctx()),
        Err(MappingError::InvalidEmail(..))
    ));
}

#[test]
fn test_create_user_phone_principal() {
    let mapping = mapped(&test_create_request());

    let phone = mapping
        .principals
        .iter()
        .find(|p| p.principal_type == PrincipalType::Phone)
        .expect("should have phone principal");

    assert_eq!(phone.value, "+1-555-0100");
    assert!(!phone.verified);
}

#[test]
fn test_create_user_metadata() {
    let mapping = mapped(&test_create_request());

    let keys: Vec<&str> = mapping.metadata.iter().map(|m| m.key.as_str()).collect();
    assert!(keys.contains(&"employee_id"));
    assert!(keys.contains(&"department"));
    assert!(keys.contains(&"title"));
    // given_name/family_name are Profile fields, NOT metadata
    assert!(!keys.contains(&"given_name"));
    assert!(!keys.contains(&"family_name"));

    let dept = mapping
        .metadata
        .iter()
        .find(|m| m.key == "department")
        .unwrap();
    assert_eq!(dept.value.as_str(), Some("Engineering"));
}

#[test]
fn test_sid_to_scim_user_roundtrip() {
    let ctx = test_org_ctx();
    let mapping = mapped(&test_create_request());

    let scim_user = sid_to_scim_user(
        &mapping.profile,
        &mapping.principals,
        &mapping.emails,
        &mapping.metadata,
        &[],
        &ctx.org_domain,
        "https://sid.example.com",
    );

    assert_eq!(scim_user.user_name, "alice.smith");
    assert_eq!(scim_user.display_name, "Alice Smith");
    assert_eq!(scim_user.external_id, "EMP-42");
    assert_eq!(scim_user.department, "Engineering");
    assert_eq!(scim_user.title, "Senior Engineer");
    assert!(scim_user.active); // Provisioned is not Suspended
    assert_eq!(scim_user.emails.len(), 1);
    assert_eq!(scim_user.emails[0].value, "alice.smith@acme.com");
    assert_eq!(scim_user.phone_numbers.len(), 1);
    assert!(scim_user.meta.is_some());
}

#[test]
fn test_structured_name_from_scim() {
    let req = proto::ScimCreateUserRequest {
        user_name: "bob".into(),
        name: Some(proto::ScimName {
            given_name: "Bob".into(),
            family_name: "Jones".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mapping = mapped(&req);
    assert_eq!(mapping.profile.given_name.as_deref(), Some("Bob"));
    assert_eq!(mapping.profile.family_name.as_deref(), Some("Jones"));
    // formatted_name() computes "Bob Jones"
    assert_eq!(
        mapping.profile.formatted_name().as_deref(),
        Some("Bob Jones")
    );
}

#[test]
fn test_suspended_user_active_false() {
    let ctx = test_org_ctx();
    let mut mapping = mapped(&test_create_request());
    mapping.profile.status = ProfileStatus::Suspended;

    let scim_user = sid_to_scim_user(
        &mapping.profile,
        &mapping.principals,
        &mapping.emails,
        &mapping.metadata,
        &[],
        &ctx.org_domain,
        "https://sid.example.com",
    );
    assert!(!scim_user.active);
}

#[test]
fn test_group_mapping() {
    let project_id = sid_core::models::ProjectId::new();
    let req = proto::ScimCreateGroupRequest {
        display_name: "Engineering".into(),
        members: vec![],
    };
    let group = scim_create_group_to_sid(&req, project_id);
    assert_eq!(group.name, "Engineering");
    assert_eq!(group.project_id, project_id);
}

#[test]
fn test_group_to_scim_with_members() {
    let project_id = sid_core::models::ProjectId::new();
    let group = Group::new(project_id, "Engineering");
    let pid = ProfileId::generate();
    let members = vec![(pid, "Alice Smith".to_string())];

    let scim_group = sid_to_scim_group(&group, &members, "https://sid.example.com");
    assert_eq!(scim_group.display_name, "Engineering");
    assert_eq!(scim_group.members.len(), 1);
    assert_eq!(scim_group.members[0].display, "Alice Smith");
    assert!(scim_group.meta.is_some());
}

// ── Multi-valued contacts ──

#[test]
fn test_create_user_produces_profile_email() {
    let mapping = mapped(&test_create_request());

    assert_eq!(mapping.emails.len(), 1);
    assert_eq!(mapping.emails[0].email, "alice.smith@acme.com"); // lowercase
    assert!(mapping.emails[0].is_primary);
    assert!(!mapping.emails[0].verified);
    assert_eq!(mapping.emails[0].label, EmailLabel::Work);
    assert_eq!(mapping.emails[0].profile_id, mapping.profile.id);
}

#[test]
fn test_create_user_produces_profile_phone() {
    let mapping = mapped(&test_create_request());

    assert_eq!(mapping.phones.len(), 1);
    assert_eq!(mapping.phones[0].e164, 15550100); // "+1-555-0100" → digits "15550100"
    assert!(mapping.phones[0].is_primary);
    assert!(!mapping.phones[0].verified);
    assert_eq!(mapping.phones[0].label, PhoneLabel::Work);
    assert!(mapping.phones[0].can_receive_sms);
}

#[test]
fn test_create_user_multiple_emails() {
    let req = proto::ScimCreateUserRequest {
        user_name: "multi".into(),
        emails: vec![
            proto::ScimEmail {
                value: "work@acme.com".into(),
                r#type: "work".into(),
                primary: true,
            },
            proto::ScimEmail {
                value: "personal@gmail.com".into(),
                r#type: "home".into(),
                primary: false,
            },
        ],
        ..Default::default()
    };
    let mapping = mapped(&req);

    assert_eq!(mapping.emails.len(), 2);
    assert_eq!(mapping.emails[0].label, EmailLabel::Work);
    assert_eq!(mapping.emails[1].label, EmailLabel::Personal); // "home" → Personal
    assert!(mapping.emails[0].is_primary);
    assert!(!mapping.emails[1].is_primary);
}

/// RFC 7643 §2.4: `primary` true appears at most once per attribute.
#[test]
fn test_create_user_two_primary_emails_refused() {
    let mut req = test_create_request();
    req.emails.push(proto::ScimEmail {
        value: "second@acme.com".into(),
        r#type: "home".into(),
        primary: true,
    });
    assert_eq!(
        scim_create_user_to_sid(&req, &test_org_ctx()).err(),
        Some(MappingError::MultiplePrimary("emails"))
    );
}

#[test]
fn test_create_user_two_primary_phones_refused() {
    let mut req = test_create_request();
    req.phone_numbers.push(proto::ScimPhoneNumber {
        value: "+15550101".into(),
        r#type: "home".into(),
        primary: true,
    });
    assert_eq!(
        scim_create_user_to_sid(&req, &test_org_ctx()).err(),
        Some(MappingError::MultiplePrimary("phoneNumbers"))
    );
}

/// A phone that is not a number is refused instead of stored as 0.
#[test]
fn test_create_user_unreadable_phone_refused() {
    let mut req = test_create_request();
    req.phone_numbers[0].value = "call reception".into();
    assert!(matches!(
        scim_create_user_to_sid(&req, &test_org_ctx()),
        Err(MappingError::InvalidPhone(_))
    ));
}

/// RFC 3966 global numbers: `tel:` prefix and visual separators are dropped.
#[test]
fn test_phone_digits() {
    assert_eq!(phone_digits("+1-555-0100"), Ok(15550100));
    assert_eq!(phone_digits("+380501234567"), Ok(380501234567));
    assert_eq!(phone_digits("12025551234"), Ok(12025551234));
    assert_eq!(phone_digits("tel:+1-201-555-0123"), Ok(12015550123));
    assert_eq!(phone_digits("+1 (201) 555.0123"), Ok(12015550123));
    assert!(phone_digits("").is_err());
    assert!(phone_digits("+1-555-CALL").is_err());
    assert!(phone_digits("+0").is_err());
}

#[test]
fn test_scim_email_type_to_label_variants() {
    assert_eq!(scim_email_type_to_label("work"), EmailLabel::Work);
    assert_eq!(scim_email_type_to_label("home"), EmailLabel::Personal);
    assert_eq!(scim_email_type_to_label("personal"), EmailLabel::Personal);
    assert_eq!(scim_email_type_to_label("school"), EmailLabel::School);
    assert_eq!(scim_email_type_to_label("other"), EmailLabel::Other);
    assert_eq!(scim_email_type_to_label("unknown"), EmailLabel::Work); // default
}

#[test]
fn test_scim_phone_type_to_label_variants() {
    assert_eq!(scim_phone_type_to_label("work"), PhoneLabel::Work);
    assert_eq!(scim_phone_type_to_label("home"), PhoneLabel::Home);
    assert_eq!(scim_phone_type_to_label("mobile"), PhoneLabel::Mobile);
    assert_eq!(scim_phone_type_to_label("fax"), PhoneLabel::Fax);
    assert_eq!(scim_phone_type_to_label("pager"), PhoneLabel::Pager);
    assert_eq!(scim_phone_type_to_label("other"), PhoneLabel::Other);
    assert_eq!(scim_phone_type_to_label("unknown"), PhoneLabel::Work); // default
}
