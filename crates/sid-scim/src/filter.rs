// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM filter expression parser (RFC 7644 §3.4.2.2).
//!
//! Parses filter strings like `userName eq "john"` or `emails.value co "@acme.com"`.
//! CE supports basic operators: eq, ne, co, sw, ew, gt, lt, ge, le.

use sid_core::models::{DirectoryAttribute, DirectoryFilter, DirectoryOperator};

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
    #[error("cannot filter on attribute: {0}")]
    UnknownAttribute(String),
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

/// The User attribute a filter names (RFC 7644 §3.4.2.2: attribute names are
/// case-insensitive; the enterprise extension's `department` may be named by
/// its full URN). `None` for an attribute this directory cannot filter on.
fn user_attribute(path: &str) -> Option<DirectoryAttribute> {
    const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:";
    let path = path.to_ascii_lowercase();
    let path = path.strip_prefix(ENTERPRISE).unwrap_or(&path);
    Some(match path {
        "username" => DirectoryAttribute::UserName,
        "displayname" => DirectoryAttribute::DisplayName,
        "name.givenname" => DirectoryAttribute::GivenName,
        "name.familyname" => DirectoryAttribute::FamilyName,
        "name.formatted" => DirectoryAttribute::FormattedName,
        "externalid" => DirectoryAttribute::ExternalId,
        "title" => DirectoryAttribute::Title,
        "department" => DirectoryAttribute::Department,
        "active" => DirectoryAttribute::Active,
        // A multi-valued attribute filtered by itself means its values.
        "emails" | "emails.value" => DirectoryAttribute::Email,
        "phonenumbers" | "phonenumbers.value" => DirectoryAttribute::Phone,
        _ => return None,
    })
}

/// The directory query a User filter asks: an attribute the directory does
/// not hold is an `invalidFilter` (RFC 7644 §3.12), never an empty result.
pub fn to_directory(filter: &ScimFilter) -> Result<DirectoryFilter, FilterError> {
    let attribute =
        |attr: &str| user_attribute(attr).ok_or_else(|| FilterError::UnknownAttribute(attr.into()));
    Ok(match filter {
        ScimFilter::Compare { attr, op, value } => DirectoryFilter::Compare {
            attribute: attribute(attr)?,
            operator: match op {
                CompareOp::Eq => DirectoryOperator::Eq,
                CompareOp::Ne => DirectoryOperator::Ne,
                CompareOp::Co => DirectoryOperator::Contains,
                CompareOp::Sw => DirectoryOperator::StartsWith,
                CompareOp::Ew => DirectoryOperator::EndsWith,
                CompareOp::Gt => DirectoryOperator::Greater,
                CompareOp::Ge => DirectoryOperator::GreaterOrEqual,
                CompareOp::Lt => DirectoryOperator::Less,
                CompareOp::Le => DirectoryOperator::LessOrEqual,
            },
            value: value.clone(),
        },
        ScimFilter::Present { attr } => DirectoryFilter::Present(attribute(attr)?),
        ScimFilter::And(a, b) => {
            DirectoryFilter::And(Box::new(to_directory(a)?), Box::new(to_directory(b)?))
        }
        ScimFilter::Or(a, b) => {
            DirectoryFilter::Or(Box::new(to_directory(a)?), Box::new(to_directory(b)?))
        }
        ScimFilter::Not(inner) => DirectoryFilter::Not(Box::new(to_directory(inner)?)),
    })
}

#[cfg(test)]
mod tests;
