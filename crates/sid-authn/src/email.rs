// SPDX-License-Identifier: AGPL-3.0-only
//! Email login handles: one validated mailbox, its SID resolution key and the
//! delivery address kept apart from it.
//!
//! Parsing and validation belong to `structured-email-address`; this module
//! only chooses its configuration per namespace and derives SID's equality
//! key from the parsed mailbox components. The key decides resolution and
//! uniqueness; it is never a delivery address, so mail always goes to the
//! spelling that was validated.

use structured_email_address::{Config, EmailAddress, Strictness};

/// Which spellings of one mailbox SID treats as the same login handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Equality {
    /// Compare the local part case-insensitively.
    pub lowercase_local: bool,
    /// Ignore dots in the local part (never in the domain).
    pub ignore_dots: bool,
    /// Ignore the first `+` and everything after it in the local part.
    pub ignore_tag: bool,
}

impl Equality {
    /// The fixed Personal rules: all three transformations, for every domain.
    pub const PERSONAL: Self = Self {
        lowercase_local: true,
        ignore_dots: true,
        ignore_tag: true,
    };
}

/// Which mailboxes a namespace admits at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// Accept non-ASCII characters in the local part (RFC 6531).
    pub unicode_local: bool,
    /// Accept internationalized domains, in Unicode or A-label spelling.
    pub idn_domain: bool,
    /// Accept a domain without a dot (an installation-local mail domain).
    pub single_label_domain: bool,
    /// Require the domain to end in a Public Suffix List suffix.
    pub public_suffix: bool,
}

/// The equality and admission rules of one email namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailPolicy {
    pub equality: Equality,
    pub admission: Admission,
    /// Which revision of the namespace's rules these are: a key records it,
    /// and only keys of the revision a lookup uses route.
    pub revision: i64,
}

impl EmailPolicy {
    /// The global SaaS/federated Personal namespace: ASCII only, no IDN in
    /// either spelling, a public mail domain.
    pub const GLOBAL_PERSONAL: Self = Self {
        equality: Equality::PERSONAL,
        admission: Admission {
            unicode_local: false,
            idn_domain: false,
            single_label_domain: false,
            public_suffix: true,
        },
        revision: 1,
    };

    /// An organization's Corporate namespace before it sets its own rules:
    /// the Personal values for equality and character admission, without
    /// requiring a public suffix, so an internal corporate mail domain stays
    /// usable.
    pub const CORPORATE_BASELINE: Self = Self {
        equality: Equality::PERSONAL,
        admission: Admission {
            unicode_local: false,
            idn_domain: false,
            single_label_domain: true,
            public_suffix: false,
        },
        revision: 1,
    };

    /// An installation's own managed accounts (standalone): the fixed
    /// Personal equality, without the global namespace's admission limits,
    /// so internal mail domains and existing internationalized handles stay
    /// usable.
    pub const LOCAL: Self = Self {
        equality: Equality::PERSONAL,
        admission: Admission {
            unicode_local: true,
            idn_domain: true,
            single_label_domain: true,
            public_suffix: false,
        },
        revision: sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION,
    };
}

/// Why an address is not an admissible email login handle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    /// Not a single valid mailbox.
    #[error("not a valid email address: {0}")]
    Invalid(String),
    /// A non-ASCII character in a namespace admitting ASCII only.
    #[error("only ASCII email addresses are accepted")]
    NonAscii,
    /// An internationalized domain in a namespace not admitting one.
    #[error("internationalized email domains are not accepted")]
    InternationalizedDomain,
    /// Nothing left of the local part once the equality rules apply.
    #[error("the address leaves an empty login handle")]
    EmptyKey,
}

/// A validated email login handle. Serializable so a multi-step ceremony
/// (registration start to finish) keeps it as validated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EmailHandle {
    /// The mailbox exactly as validated, local-part spelling (case, dots,
    /// `+tag`) preserved; the domain in its canonical ASCII form. Mail goes here.
    pub delivery: String,
    /// The SID resolution key: equal for every spelling the policy equates.
    pub key: String,
    /// The policy revision the key was derived under.
    pub revision: i64,
}

/// Validate `input` as one mailbox of the namespace `policy` governs and
/// derive its resolution key. The whole input is validated (tag and length
/// included) before anything is folded; an invalid address is refused, never
/// repaired into another.
pub fn parse(input: &str, policy: &EmailPolicy) -> Result<EmailHandle, EmailError> {
    let admission = &policy.admission;
    if !admission.unicode_local && !admission.idn_domain && !input.is_ascii() {
        return Err(EmailError::NonAscii);
    }
    let mailbox = EmailAddress::parse_with(input, &config(admission))
        .map_err(|e| EmailError::Invalid(e.to_string()))?;
    let (local, domain) = (mailbox.local_part(), mailbox.domain());
    if !admission.unicode_local && !local.is_ascii() {
        return Err(EmailError::NonAscii);
    }
    // A Unicode domain reaches here IDNA-encoded, so its A-labels cover both
    // spellings.
    if !admission.idn_domain
        && domain.split('.').any(|label| {
            label
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case("xn--"))
        })
    {
        return Err(EmailError::InternationalizedDomain);
    }
    let key_local = equality_key(local, &policy.equality);
    if key_local.is_empty() {
        return Err(EmailError::EmptyKey);
    }
    Ok(EmailHandle {
        delivery: mailbox.canonical(),
        key: format!("{}@{domain}", serialize_local(&key_local)),
        revision: policy.revision,
    })
}

/// The parser configuration for `admission`: an RFC 5321 mailbox (dot-atom
/// or quoted local part; no comments, display name or address literal),
/// with every equality transformation off so the components keep their
/// spelling and SID applies its own rules.
fn config(admission: &Admission) -> Config {
    let builder = Config::builder()
        .strictness(Strictness::Strict)
        .allow_quoted_local_part()
        .preserve_case()
        .dots_preserve()
        .preserve_subaddress();
    let builder = if admission.single_label_domain {
        builder.allow_single_label_domain()
    } else {
        builder
    };
    let builder = if admission.public_suffix {
        builder.domain_check_psl()
    } else {
        builder.domain_check_syntax()
    };
    builder.build()
}

/// `local` (the semantic local part, unquoted) under `rules`.
fn equality_key(local: &str, rules: &Equality) -> String {
    let cased = if rules.lowercase_local {
        local.to_lowercase()
    } else {
        local.to_string()
    };
    let untagged = match (rules.ignore_tag, cased.split_once('+')) {
        (true, Some((base, _))) => base.to_string(),
        _ => cased,
    };
    if rules.ignore_dots {
        untagged.replace('.', "")
    } else {
        untagged
    }
}

/// `local` as the local part of a key: quoted when it is not a dot-atom
/// (RFC 5321 §4.1.2), so two different local parts never serialize alike.
fn serialize_local(local: &str) -> String {
    let dot_atom = !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|c| {
            c.is_ascii_alphanumeric() || !c.is_ascii() || "!#$%&'*+-/=?^_`{|}~.".contains(c)
        });
    if dot_atom {
        return local.to_string();
    }
    let mut quoted = String::with_capacity(local.len() + 2);
    quoted.push('"');
    for c in local.chars() {
        if c == '"' || c == '\\' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests;
