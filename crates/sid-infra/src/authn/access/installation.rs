// SPDX-License-Identifier: AGPL-3.0-only
//! What a product brings to the installations that serve or call its APIs,
//! resolved against the access its schema declares.
//!
//! The product writes a [`Seed`] against its own methods: the resources it
//! serves (by their services), its built-in roles (by the methods each may
//! call) and what its integrations need at another resource (by the methods
//! they call). [`Seed::resolve`] turns it into an [`InstallationInput`]: each
//! resource's scope vocabulary, each role's permissions and each
//! requirement's scopes, taken from the methods' declarations rather than
//! written again. An installation consumes that input; its deployment only
//! binds keys to indicators, addresses and credentials. A requirement is what
//! a caller asks for, not a grant: the installation decides whether to bind it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{AccessRule, AccessRules, Permission};

/// A product's own description of what it brings, against its methods, each
/// named by its gRPC path `/package.Service/Method`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    #[serde(default)]
    pub resources: Vec<SeedResource>,
    #[serde(default)]
    pub roles: Vec<SeedRole>,
    #[serde(default)]
    pub requirements: Vec<SeedRequirement>,
}

/// A resource the product serves: the services behind it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedResource {
    pub key: String,
    pub name: String,
    /// Full service names, `package.Service`.
    pub services: Vec<String>,
}

/// A built-in role: the methods its holder may call, and the permissions no
/// method declares (a domain permission of the product's own catalogue). A
/// role with neither carries only the administration of other roles.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRole {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// What one integration of the product needs at a resource: the methods it
/// calls there.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRequirement {
    pub key: String,
    /// The resource's key as the installation names it.
    pub resource: String,
    pub methods: Vec<String>,
}

/// A seed resolved against the schema: what an installation consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationInput {
    #[serde(default)]
    pub resources: Vec<ResourceVocabulary>,
    #[serde(default)]
    pub roles: Vec<RoleDefinition>,
    #[serde(default)]
    pub requirements: Vec<Requirement>,
}

/// A resource and every scope its methods declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceVocabulary {
    pub key: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// A built-in role and its permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDefinition {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

/// The scopes an integration asks for at one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub key: String,
    pub resource: String,
    pub scopes: Vec<String>,
}

impl Seed {
    /// The seed resolved against `rules`, every list sorted. A name the
    /// schema does not declare, or a method that cannot carry what it is
    /// listed for, fails the whole seed.
    pub fn resolve(&self, rules: &AccessRules) -> Result<InstallationInput, String> {
        let mut input = InstallationInput::default();
        for resource in &self.resources {
            let mut scopes = BTreeSet::new();
            for service in &resource.services {
                if !rules.declares(service) {
                    return Err(format!(
                        "resource {}: the schema declares no service {service}",
                        resource.key
                    ));
                }
                for (_, rule) in rules.methods_of(service) {
                    if let AccessRule::Protected {
                        scopes: declared, ..
                    } = rule
                    {
                        scopes.extend(declared.iter().cloned());
                    }
                }
            }
            if scopes.is_empty() {
                return Err(format!(
                    "resource {}: its services declare no scope",
                    resource.key
                ));
            }
            input.resources.push(ResourceVocabulary {
                key: resource.key.clone(),
                name: resource.name.clone(),
                scopes: scopes.into_iter().collect(),
            });
        }
        for role in &self.roles {
            let mut permissions: BTreeSet<String> = role.permissions.iter().cloned().collect();
            for method in &role.methods {
                let (_, permission) =
                    protected(rules, method).map_err(|why| format!("role {}: {why}", role.key))?;
                let permission = permission.ok_or_else(|| {
                    format!(
                        "role {}: {method} declares no receiver permission",
                        role.key
                    )
                })?;
                permissions.insert(permission.action.clone());
            }
            input.roles.push(RoleDefinition {
                key: role.key.clone(),
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: permissions.into_iter().collect(),
            });
        }
        for requirement in &self.requirements {
            if requirement.methods.is_empty() {
                return Err(format!("requirement {}: names no method", requirement.key));
            }
            let mut scopes = BTreeSet::new();
            for method in &requirement.methods {
                let (declared, _) = protected(rules, method)
                    .map_err(|why| format!("requirement {}: {why}", requirement.key))?;
                if declared.is_empty() {
                    return Err(format!(
                        "requirement {}: {method} admits only the caller's own session",
                        requirement.key
                    ));
                }
                scopes.extend(declared.iter().cloned());
            }
            input.requirements.push(Requirement {
                key: requirement.key.clone(),
                resource: requirement.resource.clone(),
                scopes: scopes.into_iter().collect(),
            });
        }
        input.resources.sort_by(|a, b| a.key.cmp(&b.key));
        input.roles.sort_by(|a, b| a.key.cmp(&b.key));
        input.requirements.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(input)
    }
}

/// The scopes and receiver permission the protected `method` declares.
fn protected<'a>(
    rules: &'a AccessRules,
    method: &str,
) -> Result<(&'a [String], Option<&'a Permission>), String> {
    match rules.rule(method) {
        None => Err(format!("the schema declares no method {method}")),
        Some(AccessRule::Open) => Err(format!("{method} is open")),
        Some(AccessRule::Protected {
            scopes, permission, ..
        }) => Ok((scopes, permission.as_ref())),
    }
}

#[cfg(test)]
mod tests;
