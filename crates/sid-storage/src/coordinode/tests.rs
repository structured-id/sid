// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::{Row, document, get_document};

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

/// A free-form JSON value reads back as written, numbers keeping their kind.
#[test]
fn json_values_round_trip() {
    let value = serde_json::json!({"n": 5, "neg": -3, "f": 1.5, "s": "t", "a": [true, null]});
    assert_eq!(round_trip(&value), value);
}
