// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM filter expression parser (RFC 7644 §3.4.2.2).
//!
//! Parses filter strings like `userName eq "john"` or `emails.value co "@acme.com"`.
//! CE supports basic operators: eq, ne, co, sw, ew, gt, lt, ge, le.

use sid_proto::sid::v1 as proto;

/// A parsed SCIM filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum ScimFilter {
    /// Attribute comparison: `attrPath op value`
    Compare {
        attr: String,
        op: CompareOp,
        value: String,
    },
    /// Logical AND of two filters.
    And(Box<ScimFilter>, Box<ScimFilter>),
    /// Logical OR of two filters.
    Or(Box<ScimFilter>, Box<ScimFilter>),
    /// Negation.
    Not(Box<ScimFilter>),
    /// Presence check: `attrPath pr`
    Present { attr: String },
}

/// SCIM comparison operators.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompareOp {
    /// Equal
    Eq,
    /// Not equal
    Ne,
    /// Contains
    Co,
    /// Starts with
    Sw,
    /// Ends with
    Ew,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Greater or equal
    Ge,
    /// Less or equal
    Le,
}

/// Parse error.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("unexpected end of filter expression")]
    UnexpectedEnd,
    #[error("unknown operator: {0}")]
    UnknownOperator(String),
    #[error("expected quoted string value")]
    ExpectedQuotedValue,
    #[error("syntax error at position {0}: {1}")]
    SyntaxError(usize, String),
}

/// Parse a SCIM filter string into a structured filter.
pub fn parse_filter(input: &str) -> Result<ScimFilter, FilterError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(FilterError::UnexpectedEnd);
    }

    // Handle logical operators (AND, OR, NOT) — split at top level
    // For CE, support simple single-level expressions first
    if let Some(rest) = input
        .strip_prefix("not ")
        .or_else(|| input.strip_prefix("NOT "))
    {
        let inner = parse_filter(rest)?;
        return Ok(ScimFilter::Not(Box::new(inner)));
    }

    // Check for AND/OR (case-insensitive)
    if let Some((left, right)) = split_logical(input, " and ") {
        return Ok(ScimFilter::And(
            Box::new(parse_filter(left)?),
            Box::new(parse_filter(right)?),
        ));
    }
    if let Some((left, right)) = split_logical(input, " or ") {
        return Ok(ScimFilter::Or(
            Box::new(parse_filter(left)?),
            Box::new(parse_filter(right)?),
        ));
    }

    // Simple comparison: attrPath op value
    parse_comparison(input)
}

fn split_logical<'a>(input: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    // Case-insensitive search for separator, avoiding matches inside quoted strings
    let lower = input.to_lowercase();
    let mut in_quotes = false;
    for (i, c) in input.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        if !in_quotes && lower[i..].starts_with(sep) {
            return Some((&input[..i], &input[i + sep.len()..]));
        }
    }
    None
}

fn parse_comparison(input: &str) -> Result<ScimFilter, FilterError> {
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return Err(FilterError::SyntaxError(
            0,
            "expected: attrPath op [value]".into(),
        ));
    }

    let attr = parts[0].to_string();
    let op_str = parts[1].to_lowercase();

    // Presence check: attrPath pr
    if op_str == "pr" {
        return Ok(ScimFilter::Present { attr });
    }

    let op = match op_str.as_str() {
        "eq" => CompareOp::Eq,
        "ne" => CompareOp::Ne,
        "co" => CompareOp::Co,
        "sw" => CompareOp::Sw,
        "ew" => CompareOp::Ew,
        "gt" => CompareOp::Gt,
        "lt" => CompareOp::Lt,
        "ge" => CompareOp::Ge,
        "le" => CompareOp::Le,
        _ => return Err(FilterError::UnknownOperator(op_str)),
    };

    if parts.len() < 3 {
        return Err(FilterError::ExpectedQuotedValue);
    }

    let value_str = parts[2];
    // Strip quotes if present
    let value = if value_str.starts_with('"') && value_str.ends_with('"') && value_str.len() >= 2 {
        value_str[1..value_str.len() - 1].to_string()
    } else {
        // Unquoted value (boolean, number)
        value_str.to_string()
    };

    Ok(ScimFilter::Compare { attr, op, value })
}

/// Check if a SCIM User resource matches a parsed filter.
///
/// Evaluates the filter against ScimUser fields in-memory.
/// CE supports: userName, displayName, externalId, active, emails.value,
/// phoneNumbers.value, department, title.
pub fn matches_user(filter: &ScimFilter, user: &proto::ScimUser) -> bool {
    match filter {
        ScimFilter::Compare { attr, op, value } => {
            let field_value = resolve_user_attr(attr, user);
            match field_value {
                Some(v) => compare_str(&v, op, value),
                None => false,
            }
        }
        ScimFilter::And(left, right) => matches_user(left, user) && matches_user(right, user),
        ScimFilter::Or(left, right) => matches_user(left, user) || matches_user(right, user),
        ScimFilter::Not(inner) => !matches_user(inner, user),
        ScimFilter::Present { attr } => resolve_user_attr(attr, user).is_some(),
    }
}

/// Resolve a SCIM attribute path to a string value from a ScimUser.
fn resolve_user_attr(attr: &str, user: &proto::ScimUser) -> Option<String> {
    match attr {
        "userName" => Some(user.user_name.clone()),
        "displayName" => Some(user.display_name.clone()),
        "externalId" => Some(user.external_id.clone()),
        "title" => Some(user.title.clone()),
        "department" => Some(user.department.clone()),
        "active" => Some(user.active.to_string()),
        "name.givenName" => user.name.as_ref().map(|n| n.given_name.clone()),
        "name.familyName" => user.name.as_ref().map(|n| n.family_name.clone()),
        "name.formatted" => user.name.as_ref().map(|n| n.formatted.clone()),
        "emails.value" => {
            // Multi-valued: match if ANY email matches
            if user.emails.is_empty() {
                None
            } else {
                // Return first email for presence check; compare checks all
                Some(user.emails[0].value.clone())
            }
        }
        "phoneNumbers.value" => {
            if user.phone_numbers.is_empty() {
                None
            } else {
                Some(user.phone_numbers[0].value.clone())
            }
        }
        _ => None,
    }
}

/// Compare a field value against a filter value using the given operator.
fn compare_str(field: &str, op: &CompareOp, filter_value: &str) -> bool {
    match op {
        CompareOp::Eq => field.eq_ignore_ascii_case(filter_value),
        CompareOp::Ne => !field.eq_ignore_ascii_case(filter_value),
        CompareOp::Co => field.to_lowercase().contains(&filter_value.to_lowercase()),
        CompareOp::Sw => field
            .to_lowercase()
            .starts_with(&filter_value.to_lowercase()),
        CompareOp::Ew => field.to_lowercase().ends_with(&filter_value.to_lowercase()),
        CompareOp::Gt => field > filter_value,
        CompareOp::Lt => field < filter_value,
        CompareOp::Ge => field >= filter_value,
        CompareOp::Le => field <= filter_value,
    }
}

impl ScimFilter {
    /// Whether any comparison or presence check names an attribute under
    /// `prefix` (`"emails"` for `emails.value`, `emails`).
    pub fn references(&self, prefix: &str) -> bool {
        match self {
            Self::Compare { attr, .. } | Self::Present { attr } => {
                attr == prefix || attr.starts_with(&format!("{prefix}."))
            }
            Self::And(a, b) | Self::Or(a, b) => a.references(prefix) || b.references(prefix),
            Self::Not(inner) => inner.references(prefix),
        }
    }
}

/// Multi-valued attribute comparison: for emails.value and phoneNumbers.value,
/// check if ANY value in the collection matches.
pub fn matches_user_multivalued(filter: &ScimFilter, user: &proto::ScimUser) -> bool {
    match filter {
        ScimFilter::Compare { attr, op, value } if attr == "emails.value" => {
            user.emails.iter().any(|e| compare_str(&e.value, op, value))
        }
        ScimFilter::Compare { attr, op, value } if attr == "phoneNumbers.value" => user
            .phone_numbers
            .iter()
            .any(|p| compare_str(&p.value, op, value)),
        _ => matches_user(filter, user),
    }
}

#[cfg(test)]
mod tests;
