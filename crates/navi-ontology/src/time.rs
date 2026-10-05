use serde::{Deserialize, Serialize};
use std::fmt;

/// Milliseconds since the Unix epoch. Integer on purpose: canonical state
/// must hash identically across machines (directive §26, determinism).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn millis(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t+{}ms", self.0)
    }
}
