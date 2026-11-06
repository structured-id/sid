// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::{Decision, Params, Row, document, get_document, get_text, hold_first, in_transaction};

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

/// A free-form JSON value reads back as written, numbers keeping their kind.
#[test]
fn json_values_round_trip() {
    let value = serde_json::json!({"n": 5, "neg": -3, "f": 1.5, "s": "t", "a": [true, null]});
    assert_eq!(round_trip(&value), value);
}
