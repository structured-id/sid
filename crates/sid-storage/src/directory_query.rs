// SPDX-License-Identifier: AGPL-3.0-only
//! The user directory filter as SQL: the condition both engines apply to
//! `profiles p` before pagination. Every value is a bound parameter; only
//! fixed column names, metadata keys and status literals are written into the
//! statement.

use sid_core::models::{
    DirectoryAttribute as Attr, DirectoryFilter, DirectoryOperator as Op, DirectoryQuery,
    directory_query::metadata_keys,
};
use sid_core::{Error as SidError, Result as SidResult};

/// The SQL dialect a condition is written for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Dialect {
    #[cfg(feature = "storage-pg")]
    Postgres,
    #[cfg(feature = "storage-sqlite")]
    Sqlite,
}

/// A compiled condition and the text values bound to its placeholders, in
/// order.
#[derive(Debug)]
pub(crate) struct Condition {
    pub sql: String,
    pub binds: Vec<String>,
}

/// The condition selecting the directory's users matching `query.filter`:
/// retired profiles (closed, purged) are never part of the directory.
pub(crate) fn condition(dialect: Dialect, query: &DirectoryQuery) -> SidResult<Condition> {
    let mut out = Writer {
        dialect,
        sql: String::from("p.status NOT IN ('closed', 'purged')"),
        binds: Vec::new(),
        suffix: format!("#{}", query.org_domain),
    };
    if let Some(filter) = &query.filter {
        out.sql.push_str(" AND (");
        out.filter(filter)?;
        out.sql.push(')');
    }
    Ok(Condition {
        sql: out.sql,
        binds: out.binds,
    })
}

/// The page's users in their order, each with its own principals, emails and
/// metadata from the batch reads.
pub(crate) fn assemble(
    profiles: Vec<sid_core::models::Profile>,
    principals: Vec<sid_core::models::Principal>,
    emails: Vec<sid_core::models::ProfileEmail>,
    metadata: Vec<sid_core::models::ProfileMetadata>,
) -> Vec<sid_core::models::DirectoryUser> {
    use std::collections::HashMap;
    let mut principals_of: HashMap<_, Vec<_>> = HashMap::new();
    for principal in principals {
        principals_of
            .entry(principal.profile_id)
            .or_default()
            .push(principal);
    }
    let mut emails_of: HashMap<_, Vec<_>> = HashMap::new();
    for email in emails {
        emails_of.entry(email.profile_id).or_default().push(email);
    }
    let mut metadata_of: HashMap<_, Vec<_>> = HashMap::new();
    for entry in metadata {
        metadata_of.entry(entry.profile_id).or_default().push(entry);
    }
    profiles
        .into_iter()
        .map(|profile| sid_core::models::DirectoryUser {
            principals: principals_of.remove(&profile.id).unwrap_or_default(),
            emails: emails_of.remove(&profile.id).unwrap_or_default(),
            metadata: metadata_of.remove(&profile.id).unwrap_or_default(),
            profile,
        })
        .collect()
}

/// Placeholder `n` (from 1) of a text value.
pub(crate) fn placeholder(dialect: Dialect, n: usize) -> String {
    match dialect {
        // Typed, so functions overloaded on several types resolve.
        #[cfg(feature = "storage-pg")]
        Dialect::Postgres => format!("${n}::text"),
        #[cfg(feature = "storage-sqlite")]
        Dialect::Sqlite => format!("?{n}"),
    }
}

struct Writer {
    dialect: Dialect,
    sql: String,
    binds: Vec<String>,
    /// `#{domain}`: what ends a corporate login.
    suffix: String,
}

impl Writer {
    /// A numbered placeholder bound to `value`: it may appear several times
    /// in the statement (a userName column is used in more than one place).
    fn bind(&mut self, value: String) -> String {
        self.binds.push(value);
        placeholder(self.dialect, self.binds.len())
    }

    fn filter(&mut self, filter: &DirectoryFilter) -> SidResult<()> {
        match filter {
            DirectoryFilter::And(a, b) | DirectoryFilter::Or(a, b) => {
                let joint = if matches!(filter, DirectoryFilter::And(..)) {
                    " AND "
                } else {
                    " OR "
                };
                self.sql.push('(');
                self.filter(a)?;
                self.sql.push_str(joint);
                self.filter(b)?;
                self.sql.push(')');
            }
            DirectoryFilter::Not(inner) => {
                self.sql.push_str("NOT (");
                self.filter(inner)?;
                self.sql.push(')');
            }
            DirectoryFilter::Present(attr) => self.present(*attr),
            DirectoryFilter::Compare {
                attribute,
                operator,
                value,
            } => self.compare(*attribute, *operator, value)?,
        }
        Ok(())
    }

    /// `pr`: a non-empty value.
    fn present(&mut self, attr: Attr) {
        match attr {
            Attr::Active => self.sql.push_str("TRUE"),
            Attr::UserName | Attr::Email | Attr::Phone => {
                let (source, owner, value) = self.values_of(attr);
                self.sql.push_str(&format!(
                    "p.id IN (SELECT {owner} FROM {source} AND {value} <> '')"
                ));
            }
            _ => {
                let value = self.single(attr);
                self.sql.push_str(&format!("{value} IS NOT NULL"));
            }
        }
    }

    fn compare(&mut self, attr: Attr, op: Op, value: &str) -> SidResult<()> {
        match attr {
            Attr::Active => {
                // RFC 7644 §3.4.2.2: a boolean compares only by eq/ne.
                let wanted = match value.to_ascii_lowercase().as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(SidError::Validation(
                            "active compares with true or false".into(),
                        ));
                    }
                };
                let wanted = match op {
                    Op::Eq => wanted,
                    Op::Ne => !wanted,
                    _ => {
                        return Err(SidError::Validation(
                            "active compares by eq or ne only".into(),
                        ));
                    }
                };
                self.sql.push_str(if wanted {
                    "p.status <> 'suspended'"
                } else {
                    "p.status = 'suspended'"
                });
            }
            Attr::UserName | Attr::Email | Attr::Phone => {
                // A semi-join by `IN`, not a correlated `EXISTS`: SQLite
                // rewrites that `EXISTS` into a join and counted OFFSET over
                // the joined rows, so a user with two matching emails moved
                // the page.
                let (source, owner, column) = self.values_of(attr);
                let mut matches = self.comparison(&column, op, value, attr.case_exact());
                if attr == Attr::UserName && op == Op::Eq {
                    // The same match as the whole login, so the login index
                    // (principal_type, lower(value)) finds it without a scan.
                    let login = self.bind(format!("{value}{}", self.suffix));
                    matches.push_str(&format!(" AND lower(pr.value) = lower({login})"));
                }
                self.sql.push_str(&format!(
                    "p.id IN (SELECT {owner} FROM {source} AND {column} <> '' AND {matches})"
                ));
            }
            _ => {
                let column = self.single(attr);
                let matches = self.comparison(&column, op, value, attr.case_exact());
                // A missing value matches no comparison, under `not` too.
                self.sql.push_str(&format!("coalesce({matches}, FALSE)"));
            }
        }
        Ok(())
    }

    /// `column op value`, with case folded unless the attribute is case-exact
    /// (RFC 7644 §3.4.2.2).
    fn comparison(&mut self, column: &str, op: Op, value: &str, case_exact: bool) -> String {
        let fold = |s: String| {
            if case_exact { s } else { format!("lower({s})") }
        };
        // Ordering compares code points, the same on both engines.
        let (contains, collate) = match self.dialect {
            #[cfg(feature = "storage-pg")]
            Dialect::Postgres => ("strpos", " COLLATE \"C\""),
            #[cfg(feature = "storage-sqlite")]
            Dialect::Sqlite => ("instr", ""),
        };
        let a = fold(column.to_string());
        let b = fold(self.bind(value.to_string()));
        match op {
            Op::Eq => format!("{a} = {b}"),
            Op::Ne => format!("{a} <> {b}"),
            Op::Contains => format!("{contains}({a}, {b}) > 0"),
            Op::StartsWith => format!("substr({a}, 1, length({b})) = {b}"),
            Op::EndsWith => format!(
                "length({a}) >= length({b}) AND substr({a}, length({a}) - length({b}) + 1) = {b}"
            ),
            Op::Greater => format!("{a}{collate} > {b}"),
            Op::GreaterOrEqual => format!("{a}{collate} >= {b}"),
            Op::Less => format!("{a}{collate} < {b}"),
            Op::LessOrEqual => format!("{a}{collate} <= {b}"),
        }
    }

    /// The value of a single-valued attribute of `p`, NULL when empty.
    fn single(&mut self, attr: Attr) -> String {
        let display = "nullif(concat_ws(' ', nullif(p.honorific_prefix, ''), nullif(p.given_name, ''), \
             nullif(p.middle_name, ''), nullif(p.family_name, ''), nullif(p.honorific_suffix, '')), '')";
        match attr {
            Attr::GivenName => "nullif(p.given_name, '')".into(),
            Attr::FamilyName => "nullif(p.family_name, '')".into(),
            Attr::DisplayName => display.into(),
            Attr::FormattedName => format!(
                "CASE WHEN coalesce(p.given_name, '') <> '' OR coalesce(p.family_name, '') <> '' \
                 THEN {display} END"
            ),
            Attr::ExternalId => self.metadata(metadata_keys::EXTERNAL_ID),
            Attr::Title => self.metadata(metadata_keys::TITLE),
            Attr::Department => self.metadata(metadata_keys::DEPARTMENT),
            Attr::Active | Attr::UserName | Attr::Email | Attr::Phone => {
                unreachable!("{attr:?} is not compared as a single value")
            }
        }
    }

    /// The string value of metadata `key` of `p`, NULL when absent, empty or
    /// not a string.
    fn metadata(&self, key: &'static str) -> String {
        match self.dialect {
            #[cfg(feature = "storage-pg")]
            Dialect::Postgres => format!(
                "nullif((SELECT m.value #>> '{{}}' FROM profile_metadata m \
                 WHERE m.profile_id = p.id AND m.key = '{key}' \
                 AND jsonb_typeof(m.value) = 'string'), '')"
            ),
            #[cfg(feature = "storage-sqlite")]
            Dialect::Sqlite => format!(
                "nullif((SELECT json_extract(m.value, '$') FROM profile_metadata m \
                 WHERE m.profile_id = p.id AND m.key = '{key}' \
                 AND json_type(m.value) = 'text'), '')"
            ),
        }
    }

    /// The rows holding the values of a row-backed attribute (up to their
    /// `WHERE`, ready for more conditions), the column naming the profile a
    /// row belongs to, and the value column.
    fn values_of(&mut self, attr: Attr) -> (String, &'static str, String) {
        let bound = |kind: &str| {
            format!(
                "principals pr JOIN principal_bindings pb ON pb.principal_id = pr.id \
                 WHERE pr.principal_type = '{kind}'"
            )
        };
        match attr {
            Attr::Email => (
                "profile_emails e WHERE TRUE".into(),
                "e.profile_id",
                "e.email".into(),
            ),
            Attr::Phone => (bound("phone"), "pb.profile_id", "pr.value".into()),
            Attr::UserName => {
                // A corporate login is `{userName}#{domain}`: only logins of
                // this domain carry a userName, the suffix stripped.
                let suffix = self.bind(self.suffix.clone());
                (
                    format!(
                        "{} AND length(pr.value) > length({suffix}) \
                         AND substr(pr.value, length(pr.value) - length({suffix}) + 1) = {suffix}",
                        bound("username")
                    ),
                    "pb.profile_id",
                    format!("substr(pr.value, 1, length(pr.value) - length({suffix}))"),
                )
            }
            _ => unreachable!("{attr:?} is a single value"),
        }
    }
}
