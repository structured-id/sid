// SPDX-License-Identifier: AGPL-3.0-only
//! Every CE method that changes state is covered against retries: by a
//! recorded operation result, by its own protocol replay rule, or by a named
//! invariant. A mutating method missing from the record fails here, so a new
//! one cannot advertise safe retry without its mechanism.

use prost_types::method_options::IdempotencyLevel;
use sid_server::operation_coverage::COVERAGE;

/// Every `sid.v1` method that is not declared free of side effects, with
/// its declared level.
fn mutating_methods() -> Vec<(String, IdempotencyLevel)> {
    let pool = prost_reflect::DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET).unwrap();
    let mut methods = Vec::new();
    for service in pool.services() {
        if !service.package_name().starts_with("sid.v1") {
            continue;
        }
        for method in service.methods() {
            let level = method
                .method_descriptor_proto()
                .options
                .as_ref()
                .map(|o| o.idempotency_level())
                .unwrap_or(IdempotencyLevel::IdempotencyUnknown);
            if level != IdempotencyLevel::NoSideEffects {
                methods.push((format!("{}/{}", service.full_name(), method.name()), level));
            }
        }
    }
    methods.sort();
    methods
}

#[test]
fn every_mutating_method_is_covered() {
    let recorded: std::collections::HashSet<&str> = COVERAGE.iter().map(|(m, _)| *m).collect();
    let uncovered: Vec<String> = mutating_methods()
        .into_iter()
        .filter(|(m, _)| !recorded.contains(m.as_str()))
        .map(|(m, level)| format!("{m} {level:?}"))
        .collect();
    assert!(
        uncovered.is_empty(),
        "{} uncovered:\n{}",
        uncovered.len(),
        uncovered.join("\n")
    );
}

#[test]
fn every_recorded_method_exists_and_mutates() {
    let mutating: std::collections::HashSet<String> =
        mutating_methods().into_iter().map(|(m, _)| m).collect();
    for (method, _) in COVERAGE {
        assert!(
            mutating.contains(*method),
            "{method} is not a mutating method"
        );
    }
}
