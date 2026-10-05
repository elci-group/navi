//! COMPARE (directive §15): what changed in the realm between two states —
//! two instants of one incident, or reality against a counterfactual branch.

use realm_core::Realm;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub realm_id: String,
    /// Human-readable field changes, e.g. `epistemic_state: ANOMALOUS → SUSPICIOUS`.
    pub details: Vec<String>,
}

/// Fields derived from others (or too bulky to diff usefully) are not
/// listed individually; their sources are.
const SKIP: [&str; 4] = ["visual_contract", "provenance", "realm_id", "source_ids"];

fn short(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Null => "—".into(),
        Value::Object(o) if o.contains_key("percent") => {
            o["percent"].as_str().unwrap_or("?").to_string()
        }
        other => other.to_string(),
    };
    (s.chars().count() <= 80).then_some(s)
}

fn field_changes(a: &Value, b: &Value) -> Vec<String> {
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else {
        return vec![];
    };
    let mut out = vec![];
    for (k, vb) in b {
        if SKIP.contains(&k.as_str()) {
            continue;
        }
        let va = a.get(k).unwrap_or(&Value::Null);
        if va == vb {
            continue;
        }
        if k == "actions" {
            // Per-action lifecycle changes: the most important thing a fork shows.
            let states = |v: &Value| -> BTreeMap<String, String> {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| {
                                (
                                    x["realm_id"]
                                        .as_str()
                                        .unwrap_or("?")
                                        .trim_start_matches("realm:")
                                        .to_string(),
                                    x["state"].as_str().unwrap_or("?").to_string(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let (sa, sb) = (states(va), states(vb));
            for (id, st) in &sb {
                match sa.get(id) {
                    Some(old) if old != st => out.push(format!("action {id}: {old} → {st}")),
                    None => out.push(format!("action {id}: proposed ({st})")),
                    _ => {}
                }
            }
            continue;
        }
        if k == "risk" {
            let m = |v: &Value| v["max_state"].as_str().unwrap_or("none").to_string();
            out.push(format!("risk: {} → {}", m(va), m(vb)));
            continue;
        }
        if k == "trajectory" {
            let n = |v: &Value| v.as_array().map_or(0, Vec::len);
            out.push(format!("trajectory: {} → {} waypoint(s)", n(va), n(vb)));
            continue;
        }
        match (short(va), short(vb)) {
            (Some(x), Some(y)) => out.push(format!("{k}: {x} → {y}")),
            _ => out.push(format!("{k}: changed")),
        }
    }
    out
}

pub fn compare(a: &Realm, b: &Realm) -> Vec<Change> {
    let (va, vb) = (
        serde_json::to_value(a).expect("realm"),
        serde_json::to_value(b).expect("realm"),
    );
    let mut out = vec![];
    for c in ["entities", "edges", "controls", "hazards", "agents"] {
        let index = |v: &Value| -> BTreeMap<String, Value> {
            v[c].as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|x| {
                            (
                                x["realm_id"].as_str().unwrap_or_default().to_string(),
                                x.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let (ia, ib) = (index(&va), index(&vb));
        for (id, x) in &ib {
            match ia.get(id) {
                None => out.push(Change {
                    kind: ChangeKind::Added,
                    realm_id: id.clone(),
                    details: x["visual_contract"]["label"]
                        .as_str()
                        .map(|l| vec![l.to_string()])
                        .unwrap_or_default(),
                }),
                Some(old) if old != x => {
                    let details = field_changes(old, x);
                    if !details.is_empty() {
                        out.push(Change {
                            kind: ChangeKind::Changed,
                            realm_id: id.clone(),
                            details,
                        });
                    }
                }
                _ => {}
            }
        }
        for id in ia.keys().filter(|id| !ib.contains_key(*id)) {
            out.push(Change {
                kind: ChangeKind::Removed,
                realm_id: id.clone(),
                details: vec![],
            });
        }
    }
    out.sort();
    out
}
