use super::*;

#[test]
fn test_migrations_are_ordered() {
    for window in MIGRATIONS.windows(2) {
        assert!(
            window[0].name < window[1].name,
            "Migrations must be ordered: {} should come before {}",
            window[0].name,
            window[1].name
        );
    }
}

#[test]
fn test_migrations_have_unique_names() {
    let names: Vec<&str> = MIGRATIONS.iter().map(|m| m.name).collect();
    for (i, name) in names.iter().enumerate() {
        for other in &names[i + 1..] {
            assert_ne!(name, other, "Duplicate migration name: {}", name);
        }
    }
}

#[test]
fn test_migrations_sql_not_empty() {
    for migration in MIGRATIONS {
        assert!(
            !migration.sql.trim().is_empty(),
            "Migration '{}' has empty SQL",
            migration.name
        );
    }
}

/// The migrator applies exactly the migrations in `migrations/`: a file
/// left out of the list never reaches a database, and a listed name with no
/// file would not build.
#[test]
fn test_every_migration_file_is_applied() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .expect("the migrations directory")
        .map(|entry| entry.expect("a migrations entry").file_name())
        .filter_map(|name| {
            name.to_str()
                .and_then(|n| n.strip_suffix(".sql"))
                .map(str::to_owned)
        })
        .collect();
    files.sort();
    let listed: Vec<String> = MIGRATIONS.iter().map(|m| m.name.to_owned()).collect();
    assert_eq!(files, listed, "migrations/ and the migrator's list differ");
}

#[test]
fn test_validate_schema_name_valid() {
    assert!(validate_schema_name("sid").is_ok());
    assert!(validate_schema_name("sid_test").is_ok());
    assert!(validate_schema_name("my-app").is_ok());
    assert!(validate_schema_name("schema123").is_ok());
}

#[test]
fn test_validate_schema_name_invalid() {
    assert!(validate_schema_name("").is_err());
    assert!(validate_schema_name("sid; DROP TABLE").is_err());
    assert!(validate_schema_name("has spaces").is_err());
    assert!(validate_schema_name("has.dots").is_err());
    assert!(validate_schema_name(&"a".repeat(64)).is_err());
}
