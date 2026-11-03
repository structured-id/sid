// SPDX-License-Identifier: AGPL-3.0-only
//! How each CE method that changes state is safe to retry (the durable
//! operation result contract): its record, checked against the proto by the
//! `operation_coverage` test.

/// What makes a retry of a method safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Requires an operation key; a retry returns the result recorded with
    /// the first commit.
    Keyed,
    /// A protocol ceremony with its own single-use or replay rule, named.
    Ceremony(&'static str),
    /// The effect is the same however often it is applied, for the reason
    /// named.
    Natural(&'static str),
}

/// Every mutating CE method and its coverage, by full method name.
pub const COVERAGE: &[(&str, Coverage)] = &[
    (
        "sid.v1.projects.ProjectService/AddClientRole",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/AddResourceRole",
        Coverage::Keyed,
    ),
    ("sid.v1.projects.ProjectService/AddRole", Coverage::Keyed),
    (
        "sid.v1.projects.ProjectService/CreateApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/CreateInitialAccessToken",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/CreateProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/DeleteRegisteredClient",
        Coverage::Ceremony(
            "RFC 7592 §2.3: deletion invalidates the client and its registration \
             access token, so a repeat is refused and changes nothing",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/RegisterClient",
        Coverage::Ceremony(
            "RFC 7591 §3: the client presents no operation key; each registration \
             issues a new client, its secret and registration access token once",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/RemoveResourceAccess",
        Coverage::Keyed,
    ),
    ("sid.v1.projects.ProjectService/RemoveRole", Coverage::Keyed),
    (
        "sid.v1.projects.ProjectService/RevokeInitialAccessToken",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/SetResourceAccess",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateApplication",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateClientRole",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateProject",
        Coverage::Keyed,
    ),
    (
        "sid.v1.projects.ProjectService/UpdateRegisteredClient",
        Coverage::Ceremony(
            "RFC 7592 §2.2: the request carries the client's whole metadata and \
             replaces it, so a repeat leaves the same registration",
        ),
    ),
    (
        "sid.v1.projects.ProjectService/UpdateResourceRole",
        Coverage::Keyed,
    ),
];
