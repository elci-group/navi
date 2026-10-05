//! The security DVR (directive §15, §16, §22).
//!
//! A [`Replay`] compiles the realm at every instant of an incident log.
//! For transport it becomes a [`Stream`]: one full snapshot, then ordered
//! deltas, each frame carrying the digest of the realm it must produce, so
//! a client can prove its reconstruction is exact. Semantic events are
//! whole-object upserts — never interpolated.

mod compare;

pub use compare::{compare, Change, ChangeKind};

use navi_events::{IncidentLog, LogViolation};
use navi_ontology::Timestamp;
use realm_core::Realm;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const STREAM_VERSION: &str = "realm-stream/0.1";

/// The realm as of one instant, and what happened at that instant.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub at: Timestamp,
    /// Log sequence numbers of the events at this instant.
    pub events: Vec<u64>,
    /// §16 one-line descriptions of those events.
    pub lines: Vec<String>,
    pub realm: Realm,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Replay {
    pub log_digest: String,
    pub frames: Vec<Frame>,
}

impl Replay {
    /// Validate the log (every prefix) and compile a realm per instant.
    pub fn build(log: &IncidentLog) -> Result<Self, Vec<LogViolation>> {
        let problems = log.validate();
        if !problems.is_empty() {
            return Err(problems);
        }
        let mut frames = vec![];
        for t in log.instants() {
            let g = log.graph_at(t).map_err(|e| vec![e])?;
            let at_t: Vec<&navi_events::LogEntry> =
                log.events.iter().filter(|e| e.at == t).collect();
            frames.push(Frame {
                at: t,
                events: at_t.iter().map(|e| e.seq).collect(),
                lines: at_t
                    .iter()
                    .map(|e| format!("#{} {}", e.seq, e.summary()))
                    .collect(),
                realm: realm_compiler::compile(&g),
            });
        }
        Ok(Self {
            log_digest: log.digest(),
            frames,
        })
    }

    /// Index of the frame in force at instant `t` (the latest at or before).
    pub fn index_at(&self, t: Timestamp) -> Option<usize> {
        self.frames.iter().rposition(|f| f.at <= t)
    }

    pub fn at(&self, t: Timestamp) -> Option<&Frame> {
        self.index_at(t).map(|i| &self.frames[i])
    }

    pub fn stream(&self) -> Stream {
        let first = &self.frames[0];
        let mut frames = vec![];
        for w in self.frames.windows(2) {
            frames.push(DeltaFrame {
                at: w[1].at,
                events: w[1].events.clone(),
                lines: w[1].lines.clone(),
                deltas: deltas(&w[0].realm, &w[1].realm),
                digest: w[1].realm.digest(),
            });
        }
        Stream {
            stream_version: STREAM_VERSION.into(),
            log_digest: self.log_digest.clone(),
            snapshot_at: first.at,
            snapshot_events: first.events.clone(),
            snapshot_lines: first.lines.clone(),
            snapshot_digest: first.realm.digest(),
            snapshot: first.realm.clone(),
            frames,
        }
    }
}

/// The realm collections deltas address, by name in the Realm IR.
pub const COLLECTIONS: [&str; 6] = [
    "entities", "edges", "controls", "hazards", "agents", "evidence",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op", deny_unknown_fields)]
pub enum Delta {
    /// Insert or wholly replace one object (`value.realm_id` names it).
    Upsert { collection: String, value: Value },
    Remove {
        collection: String,
        realm_id: String,
    },
    /// A top-level realm field (epoch, source digest, branch, versions).
    Set { field: String, value: Value },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaFrame {
    pub at: Timestamp,
    pub events: Vec<u64>,
    pub lines: Vec<String>,
    pub deltas: Vec<Delta>,
    /// Digest of the realm after applying this frame's deltas.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub stream_version: String,
    pub log_digest: String,
    pub snapshot_at: Timestamp,
    pub snapshot_events: Vec<u64>,
    pub snapshot_lines: Vec<String>,
    pub snapshot_digest: String,
    pub snapshot: Realm,
    pub frames: Vec<DeltaFrame>,
}

fn by_id(v: &Value) -> Vec<(String, Value)> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| {
                    (
                        x["realm_id"].as_str().unwrap_or_default().to_string(),
                        x.clone(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The ordered deltas that turn `a` into `b`.
pub fn deltas(a: &Realm, b: &Realm) -> Vec<Delta> {
    let (va, vb) = (
        serde_json::to_value(a).expect("realm"),
        serde_json::to_value(b).expect("realm"),
    );
    let (ma, mb) = (
        va.as_object().expect("object"),
        vb.as_object().expect("object"),
    );
    let mut out = vec![];
    for (field, value) in mb {
        if COLLECTIONS.contains(&field.as_str()) {
            continue;
        }
        if ma.get(field) != Some(value) {
            out.push(Delta::Set {
                field: field.clone(),
                value: value.clone(),
            });
        }
    }
    for c in COLLECTIONS {
        let old: std::collections::BTreeMap<String, Value> = by_id(&ma[c]).into_iter().collect();
        let new: std::collections::BTreeMap<String, Value> = by_id(&mb[c]).into_iter().collect();
        for (id, v) in &new {
            if old.get(id) != Some(v) {
                out.push(Delta::Upsert {
                    collection: c.into(),
                    value: v.clone(),
                });
            }
        }
        for id in old.keys().filter(|id| !new.contains_key(*id)) {
            out.push(Delta::Remove {
                collection: c.into(),
                realm_id: id.clone(),
            });
        }
    }
    out
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ReconstructError {
    #[error("stream version {0:?} is not {STREAM_VERSION:?}")]
    Version(String),
    #[error("frame at {at}: unknown collection or field {name:?}")]
    Unknown { at: Timestamp, name: String },
    #[error("frame at {at}: reconstructed state is not valid Realm IR: {message}")]
    Malformed { at: Timestamp, message: String },
    #[error("frame at {at}: digest mismatch (got {got}, stream says {want})")]
    Digest {
        at: Timestamp,
        got: String,
        want: String,
    },
}

/// Rebuild every frame's realm from snapshot + deltas, checking each digest.
pub fn reconstruct(s: &Stream) -> Result<Vec<(Timestamp, Realm)>, ReconstructError> {
    if s.stream_version != STREAM_VERSION {
        return Err(ReconstructError::Version(s.stream_version.clone()));
    }
    let check = |at: Timestamp, r: &Realm, want: &str| {
        let got = r.digest();
        if got == want {
            Ok(())
        } else {
            Err(ReconstructError::Digest {
                at,
                got,
                want: want.into(),
            })
        }
    };
    check(s.snapshot_at, &s.snapshot, &s.snapshot_digest)?;
    let mut out = vec![(s.snapshot_at, s.snapshot.clone())];
    let mut state: Map<String, Value> = serde_json::to_value(&s.snapshot)
        .expect("realm")
        .as_object()
        .expect("object")
        .clone();
    for f in &s.frames {
        for d in &f.deltas {
            match d {
                Delta::Set { field, value } => {
                    if COLLECTIONS.contains(&field.as_str()) || !state.contains_key(field) {
                        return Err(ReconstructError::Unknown {
                            at: f.at,
                            name: field.clone(),
                        });
                    }
                    state.insert(field.clone(), value.clone());
                }
                Delta::Upsert { collection, value } => {
                    if !COLLECTIONS.contains(&collection.as_str()) {
                        return Err(ReconstructError::Unknown {
                            at: f.at,
                            name: collection.clone(),
                        });
                    }
                    let id = value["realm_id"].as_str().unwrap_or_default();
                    let arr = state[collection]
                        .as_array_mut()
                        .expect("collection is an array");
                    arr.retain(|x| x["realm_id"] != id);
                    arr.push(value.clone());
                    arr.sort_by(|a, b| a["realm_id"].as_str().cmp(&b["realm_id"].as_str()));
                }
                Delta::Remove {
                    collection,
                    realm_id,
                } => {
                    if !COLLECTIONS.contains(&collection.as_str()) {
                        return Err(ReconstructError::Unknown {
                            at: f.at,
                            name: collection.clone(),
                        });
                    }
                    let arr = state[collection]
                        .as_array_mut()
                        .expect("collection is an array");
                    arr.retain(|x| x["realm_id"] != realm_id.as_str());
                }
            }
        }
        let realm: Realm = serde_json::from_value(Value::Object(state.clone())).map_err(|e| {
            ReconstructError::Malformed {
                at: f.at,
                message: e.to_string(),
            }
        })?;
        check(f.at, &realm, &f.digest)?;
        out.push((f.at, realm));
    }
    Ok(out)
}
