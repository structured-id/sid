// SPDX-License-Identifier: AGPL-3.0-only
//! Public keys a client authenticates with (RFC 7591 §2 `jwks`).

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A client's registered signing keys: a JWK Set (RFC 7517 §5) of public
/// asymmetric keys, each named by a distinct `kid`. Holding one is what
/// makes a `private_key_jwt` client able to authenticate (RFC 7523 §2.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Value", into = "Value")]
pub struct ClientKeySet {
    keys: Vec<Map<String, Value>>,
}

/// Members that carry private or symmetric key material (RFC 7518 §6.2.2,
/// §6.3.2, §6.4.1); a registered key holds none of them.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Base64url length of a 2048-bit RSA modulus, the minimum RFC 7518 §3.3
/// allows: 256 octets without leading zeros (RFC 7518 §6.3.1.1).
const MIN_RSA_MODULUS_CHARS: usize = 342;

impl ClientKeySet {
    /// Most keys one client registers: room for a key and its successors
    /// during a rotation.
    pub const MAX_KEYS: usize = 8;

    /// A key set from its JSON text.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(text).map_err(|e| format!("jwks is not JSON: {e}"))?;
        Self::try_from(value)
    }

    /// The registered keys, in registration order.
    pub fn keys(&self) -> &[Map<String, Value>] {
        &self.keys
    }

    /// The key named `kid`.
    pub fn key(&self, kid: &str) -> Option<&Map<String, Value>> {
        self.keys
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
    }

    /// The key set as its JSON text.
    pub fn to_json(&self) -> String {
        Value::from(self.clone()).to_string()
    }
}

/// Why `key` is not a public signing key a client may register.
fn key_problem(key: &Map<String, Value>) -> Option<String> {
    let text = |name: &str| key.get(name).and_then(Value::as_str);
    if let Some(member) = PRIVATE_MEMBERS.iter().find(|m| key.contains_key(**m)) {
        return Some(format!(
            "a key must be public; it has the member {member:?}"
        ));
    }
    if text("kid").is_none_or(str::is_empty) {
        return Some("every key needs a non-empty kid".to_owned());
    }
    // RFC 7517 §4.2 / §4.3: a key for client authentication verifies signatures.
    if key.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
        return Some("use must be \"sig\"".to_owned());
    }
    if let Some(ops) = key.get("key_ops") {
        let verify_only = ops
            .as_array()
            .is_some_and(|ops| ops.iter().all(|op| op.as_str() == Some("verify")));
        if !verify_only {
            return Some("key_ops may only name \"verify\"".to_owned());
        }
    }
    let present = |names: &[&str]| names.iter().all(|n| text(n).is_some_and(|v| !v.is_empty()));
    // The algorithms each key type can verify (RFC 7518 §3.1, RFC 8037 §3.1).
    let algorithms: &[&str] = match (text("kty"), text("crv")) {
        (Some("OKP"), Some("Ed25519")) if present(&["x"]) => &["EdDSA"],
        (Some("EC"), Some("P-256")) if present(&["x", "y"]) => &["ES256"],
        (Some("EC"), Some("P-384")) if present(&["x", "y"]) => &["ES384"],
        (Some("RSA"), _) if present(&["n", "e"]) => {
            if text("n").is_some_and(|n| n.len() < MIN_RSA_MODULUS_CHARS) {
                return Some("an RSA key must be at least 2048 bits".to_owned());
            }
            &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
        }
        _ => {
            return Some(
                "a key must be an Ed25519 (OKP), P-256/P-384 (EC) or RSA public key \
                 with its public members"
                    .to_owned(),
            );
        }
    };
    match key.get("alg") {
        None => None,
        Some(alg) if alg.as_str().is_some_and(|a| algorithms.contains(&a)) => None,
        Some(_) => Some("alg does not match the key type".to_owned()),
    }
}

impl TryFrom<Value> for ClientKeySet {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Object(mut set) = value else {
            return Err("jwks must be a JSON object".to_owned());
        };
        // RFC 7517 §5: the set's `keys` member is an array of JWKs.
        let Some(Value::Array(members)) = set.remove("keys") else {
            return Err("jwks must have a keys array".to_owned());
        };
        if members.is_empty() {
            return Err("jwks must hold at least one key".to_owned());
        }
        if members.len() > Self::MAX_KEYS {
            return Err(format!("jwks holds more than {} keys", Self::MAX_KEYS));
        }
        let mut keys: Vec<Map<String, Value>> = Vec::with_capacity(members.len());
        for member in members {
            let Value::Object(key) = member else {
                return Err("every key must be a JSON object".to_owned());
            };
            if let Some(problem) = key_problem(&key) {
                return Err(problem);
            }
            // A kid names one key, so a signature's key is never ambiguous.
            let kid = key.get("kid").and_then(Value::as_str);
            if keys
                .iter()
                .any(|k| k.get("kid").and_then(Value::as_str) == kid)
            {
                return Err("two keys share one kid".to_owned());
            }
            keys.push(key);
        }
        Ok(Self { keys })
    }
}

impl From<ClientKeySet> for Value {
    fn from(set: ClientKeySet) -> Self {
        let keys = set.keys.into_iter().map(Value::Object).collect();
        let mut object = Map::new();
        object.insert("keys".to_owned(), Value::Array(keys));
        Value::Object(object)
    }
}

impl fmt::Debug for ClientKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kids: Vec<&str> = self
            .keys
            .iter()
            .filter_map(|k| k.get("kid").and_then(Value::as_str))
            .collect();
        f.debug_struct("ClientKeySet").field("kids", &kids).finish()
    }
}

#[cfg(test)]
mod tests;
