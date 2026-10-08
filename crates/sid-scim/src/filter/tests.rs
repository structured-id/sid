use super::*;

#[test]
fn test_simple_eq() {
    let f = parse_filter(r#"userName eq "alice""#).unwrap();
    assert_eq!(
        f,
        ScimFilter::Compare {
            attr: "userName".into(),
            op: CompareOp::Eq,
            value: "alice".into(),
        }
    );
}

#[test]
fn test_contains() {
    let f = parse_filter(r#"emails.value co "@acme.com""#).unwrap();
    assert_eq!(
        f,
        ScimFilter::Compare {
            attr: "emails.value".into(),
            op: CompareOp::Co,
            value: "@acme.com".into(),
        }
    );
}

#[test]
fn test_starts_with() {
    let f = parse_filter(r#"displayName sw "A""#).unwrap();
    assert_eq!(
        f,
        ScimFilter::Compare {
            attr: "displayName".into(),
            op: CompareOp::Sw,
            value: "A".into(),
        }
    );
}

#[test]
fn test_presence() {
    let f = parse_filter("emails pr").unwrap();
    assert_eq!(
        f,
        ScimFilter::Present {
            attr: "emails".into()
        }
    );
}

#[test]
fn test_boolean_value() {
    let f = parse_filter("active eq true").unwrap();
    assert_eq!(
        f,
        ScimFilter::Compare {
            attr: "active".into(),
            op: CompareOp::Eq,
            value: "true".into(),
        }
    );
}

#[test]
fn test_and() {
    let f = parse_filter(r#"userName eq "alice" and active eq true"#).unwrap();
    match f {
        ScimFilter::And(left, right) => {
            assert!(matches!(*left, ScimFilter::Compare { ref attr, .. } if attr == "userName"));
            assert!(matches!(*right, ScimFilter::Compare { ref attr, .. } if attr == "active"));
        }
        _ => panic!("expected And"),
    }
}

#[test]
fn test_or() {
    let f = parse_filter(r#"department eq "Eng" or department eq "Sales""#).unwrap();
    assert!(matches!(f, ScimFilter::Or(_, _)));
}

#[test]
fn test_not() {
    let f = parse_filter(r#"not active eq true"#).unwrap();
    assert!(matches!(f, ScimFilter::Not(_)));
}

#[test]
fn test_unknown_operator() {
    let result = parse_filter(r#"userName xx "alice""#);
    assert!(matches!(result, Err(FilterError::UnknownOperator(_))));
}

#[test]
fn test_empty_filter() {
    let result = parse_filter("");
    assert!(matches!(result, Err(FilterError::UnexpectedEnd)));
}

/// A filter names the emails attribute through any branch; other attributes
/// sharing its prefix as text do not count.
#[test]
fn test_references() {
    let emails = parse_filter(r#"active eq true and not emails.value co "@a.com""#).unwrap();
    assert!(emails.references("emails"));
    assert!(parse_filter("emails pr").unwrap().references("emails"));
    let other = parse_filter(r#"emailsLegacy eq "x" or userName eq "a""#).unwrap();
    assert!(!other.references("emails"));
}

// ── Filter matching tests ──

fn test_user() -> proto::ScimUser {
    proto::ScimUser {
        id: "test-id".into(),
        user_name: "alice.smith".into(),
        display_name: "Alice Smith".into(),
        external_id: "EMP-42".into(),
        department: "Engineering".into(),
        title: "Senior Engineer".into(),
        active: true,
        name: Some(proto::ScimName {
            formatted: "Alice Smith".into(),
            given_name: "Alice".into(),
            family_name: "Smith".into(),
            ..Default::default()
        }),
        emails: vec![
            proto::ScimEmail {
                value: "alice@acme.com".into(),
                r#type: "work".into(),
                primary: true,
            },
            proto::ScimEmail {
                value: "alice.personal@mail.com".into(),
                r#type: "home".into(),
                primary: false,
            },
        ],
        phone_numbers: vec![proto::ScimPhoneNumber {
            value: "+1-555-0100".into(),
            r#type: "work".into(),
            primary: true,
        }],
        ..Default::default()
    }
}

#[test]
fn test_match_username_eq() {
    let user = test_user();
    let f = parse_filter(r#"userName eq "alice.smith""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_username_eq_case_insensitive() {
    let user = test_user();
    let f = parse_filter(r#"userName eq "Alice.Smith""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_username_ne() {
    let user = test_user();
    let f = parse_filter(r#"userName ne "bob""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_display_name_co() {
    let user = test_user();
    let f = parse_filter(r#"displayName co "Smith""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_display_name_sw() {
    let user = test_user();
    let f = parse_filter(r#"displayName sw "Alice""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_active_eq_true() {
    let user = test_user();
    let f = parse_filter("active eq true").unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_active_eq_false_no_match() {
    let user = test_user();
    let f = parse_filter("active eq false").unwrap();
    assert!(!matches_user(&f, &user));
}

#[test]
fn test_match_department_eq() {
    let user = test_user();
    let f = parse_filter(r#"department eq "Engineering""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_and_filter() {
    let user = test_user();
    let f = parse_filter(r#"userName eq "alice.smith" and active eq true"#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_and_filter_fails() {
    let user = test_user();
    let f = parse_filter(r#"userName eq "alice.smith" and active eq false"#).unwrap();
    assert!(!matches_user(&f, &user));
}

#[test]
fn test_match_or_filter() {
    let user = test_user();
    let f = parse_filter(r#"department eq "Sales" or department eq "Engineering""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_not_filter() {
    let user = test_user();
    let f = parse_filter("not active eq false").unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_email_multivalued() {
    let user = test_user();
    let f = parse_filter(r#"emails.value co "@acme.com""#).unwrap();
    assert!(matches_user_multivalued(&f, &user));
}

#[test]
fn test_match_email_multivalued_second_value() {
    let user = test_user();
    let f = parse_filter(r#"emails.value co "@mail.com""#).unwrap();
    assert!(matches_user_multivalued(&f, &user));
}

#[test]
fn test_match_email_multivalued_no_match() {
    let user = test_user();
    let f = parse_filter(r#"emails.value co "@unknown.com""#).unwrap();
    assert!(!matches_user_multivalued(&f, &user));
}

#[test]
fn test_match_name_given_name() {
    let user = test_user();
    let f = parse_filter(r#"name.givenName eq "Alice""#).unwrap();
    assert!(matches_user(&f, &user));
}

#[test]
fn test_match_external_id() {
    let user = test_user();
    let f = parse_filter(r#"externalId eq "EMP-42""#).unwrap();
    assert!(matches_user(&f, &user));
}
