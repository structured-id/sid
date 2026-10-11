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

// ── Translation to the directory query ──
// What a translated filter matches is the storage contract, run against
// every engine by the storage conformance suite.

fn directory(input: &str) -> Result<DirectoryFilter, FilterError> {
    to_directory(&parse_filter(input).unwrap())
}

/// Every attribute the directory holds is named case-insensitively; a
/// multi-valued attribute by itself means its values; the enterprise
/// department may be named by its URN.
#[test]
fn test_attributes_translate() {
    for (path, attribute) in [
        ("userName", DirectoryAttribute::UserName),
        ("USERNAME", DirectoryAttribute::UserName),
        ("displayName", DirectoryAttribute::DisplayName),
        ("name.givenName", DirectoryAttribute::GivenName),
        ("name.familyName", DirectoryAttribute::FamilyName),
        ("name.formatted", DirectoryAttribute::FormattedName),
        ("externalId", DirectoryAttribute::ExternalId),
        ("title", DirectoryAttribute::Title),
        ("department", DirectoryAttribute::Department),
        (
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            DirectoryAttribute::Department,
        ),
        ("emails", DirectoryAttribute::Email),
        ("emails.value", DirectoryAttribute::Email),
        ("phoneNumbers.value", DirectoryAttribute::Phone),
    ] {
        assert_eq!(
            directory(&format!(r#"{path} eq "x""#)).unwrap(),
            DirectoryFilter::Compare {
                attribute,
                operator: DirectoryOperator::Eq,
                value: "x".into(),
            },
            "{path}"
        );
    }
    assert_eq!(
        directory("active eq true").unwrap(),
        DirectoryFilter::Compare {
            attribute: DirectoryAttribute::Active,
            operator: DirectoryOperator::Eq,
            value: "true".into(),
        }
    );
}

/// Every operator and every logical form keeps its meaning.
#[test]
fn test_operators_and_logic_translate() {
    for (op, operator) in [
        ("ne", DirectoryOperator::Ne),
        ("co", DirectoryOperator::Contains),
        ("sw", DirectoryOperator::StartsWith),
        ("ew", DirectoryOperator::EndsWith),
        ("gt", DirectoryOperator::Greater),
        ("ge", DirectoryOperator::GreaterOrEqual),
        ("lt", DirectoryOperator::Less),
        ("le", DirectoryOperator::LessOrEqual),
    ] {
        assert!(matches!(
            directory(&format!(r#"title {op} "x""#)).unwrap(),
            DirectoryFilter::Compare { operator: o, .. } if o == operator
        ));
    }
    assert!(matches!(
        directory(r#"title eq "a" and not emails pr or userName sw "b""#).unwrap(),
        DirectoryFilter::And(_, _)
    ));
    assert_eq!(
        directory("emails pr").unwrap(),
        DirectoryFilter::Present(DirectoryAttribute::Email)
    );
}

/// An attribute the directory does not hold, anywhere in the filter, is an
/// invalid filter: answering with nothing would read as "no such user".
#[test]
fn test_unknown_attribute_is_refused() {
    for input in [
        r#"nickName eq "x""#,
        r#"userName eq "a" or emailsArchive eq "x""#,
        "not groups pr",
    ] {
        assert!(
            matches!(directory(input), Err(FilterError::UnknownAttribute(_))),
            "{input}"
        );
    }
}
