// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::{
    Decision, Params, Row, claim_first, document, get_document, get_text, hold_first,
    in_transaction,
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Shape {
    Plain,
    Tagged(String),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Sparse {
    first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<Shape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kept: Option<String>,
    shapes: Vec<Shape>,
}

fn round_trip<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let mut row = Row::new();
    row.insert("doc".into(), document(value, "doc").unwrap());
    get_document(&row, "doc").unwrap()
}

/// A field left out of a document never shifts the fields after it into its
/// place: a mapping with a condition but no transform once read its
/// condition as the transform.
#[test]
fn skipped_fields_keep_the_rest_in_place() {
    let sparse = Sparse {
        first: "a".into(),
        skipped: None,
        kept: Some("scope:email".into()),
        shapes: vec![Shape::Plain, Shape::Tagged("x".into())],
    };
    assert_eq!(round_trip(&sparse), sparse);
}

/// Run `query` in a transaction of its own and commit it.
fn write(db: &coordinode_embed::Database, query: &str) {
    let id = db.begin_transaction().unwrap();
    db.execute_in_transaction(id, query, None).unwrap();
    db.commit_transaction(id).unwrap();
}

/// A decision built on a node another commit changed after the transaction's
/// snapshot runs again on the current node: holding the node must not pin
/// the newer version under a decision made from the older one.
#[test]
fn a_decision_on_a_node_changed_after_the_snapshot_runs_again() {
    let db = coordinode_embed::Database::open_in_memory().unwrap();
    write(&db, "CREATE (p:SidProbe {k: 1, v: 'old'})");
    let attempts = std::cell::Cell::new(0);
    let seen = in_transaction(&db, |tx| {
        attempts.set(attempts.get() + 1);
        let rows = tx.run(
            "MATCH (p:SidProbe) WHERE p.k = 1 RETURN p.v AS v, id(p) AS node",
            Params::default(),
        )?;
        let v = get_text(&rows[0], "v")?;
        if attempts.get() == 1 {
            // Another writer commits between this read and the hold.
            write(&db, "MATCH (p:SidProbe) WHERE p.k = 1 SET p.v = 'new'");
        }
        if !hold_first(tx, &rows)? {
            return Ok(Decision::Abandon(None));
        }
        Ok(Decision::Commit(Some(v)))
    })
    .unwrap();
    assert_eq!(seen.as_deref(), Some("new"));
    assert_eq!(attempts.get(), 2);
}

/// Create a child of parent `k` in a transaction of its own, claiming the
/// parent as a child creation does.
fn create_child(db: &coordinode_embed::Database, k: i64) {
    in_transaction(db, |tx| {
        let rows = tx.run(
            &format!("MATCH (p:SidProbe) WHERE p.k = {k} RETURN id(p) AS node"),
            Params::default(),
        )?;
        if !claim_first(tx, &rows)? {
            return Ok(Decision::Abandon(()));
        }
        tx.run(
            &format!("CREATE (c:SidProbeChild {{parent: {k}}})"),
            Params::default(),
        )?;
        Ok(Decision::Commit(()))
    })
    .unwrap();
}

/// A deletion that decides from the children it reads sees a child created
/// after its read: the child's claim on the parent makes the deletion run
/// again, so no child outlives its parent (the foreign key of a SQL store).
#[test]
fn a_child_created_during_its_parents_deletion_is_seen() {
    let db = coordinode_embed::Database::open_in_memory().unwrap();
    write(&db, "CREATE (p:SidProbe {k: 2})");
    let attempts = std::cell::Cell::new(0);
    let deleted = in_transaction(&db, |tx| {
        attempts.set(attempts.get() + 1);
        let children = tx.run(
            "MATCH (c:SidProbeChild) WHERE c.parent = 2 RETURN c.parent AS p",
            Params::default(),
        )?;
        if attempts.get() == 1 {
            // A child is created and committed between the read and the delete.
            create_child(&db, 2);
        }
        if !children.is_empty() {
            return Ok(Decision::Abandon(false));
        }
        tx.run(
            "MATCH (p:SidProbe) WHERE p.k = 2 DETACH DELETE p",
            Params::default(),
        )?;
        Ok(Decision::Commit(true))
    })
    .unwrap();
    assert!(
        !deleted,
        "the parent was deleted under a child created meanwhile"
    );
    assert_eq!(attempts.get(), 2);
}

/// A free-form JSON value reads back as written, numbers keeping their kind.
#[test]
fn json_values_round_trip() {
    let value = serde_json::json!({"n": 5, "neg": -3, "f": 1.5, "s": "t", "a": [true, null]});
    assert_eq!(round_trip(&value), value);
}
