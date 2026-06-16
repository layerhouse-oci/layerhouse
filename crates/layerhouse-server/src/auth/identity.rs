use std::fmt;

use serde::{Deserialize, Serialize};

/// The immutable IdP-issued subject (`sub` claim) that identifies an
/// authenticated principal across username renames and profile changes.
/// Format is opaque per OIDC — Layerhouse never generates or parses internals.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject(String);

impl Subject {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Subject {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Subject {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_preserves_string_shape() {
        let subject = Subject::new("user-abc-123");
        let json = serde_json::to_string(&subject).unwrap();
        assert_eq!(json, "\"user-abc-123\"");
        let back: Subject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, subject);
    }

    #[test]
    fn deserializes_from_bare_string() {
        let value: Subject = serde_json::from_str("\"opaque-sub\"").unwrap();
        assert_eq!(value.as_str(), "opaque-sub");
    }

    #[test]
    fn display_delegates_to_inner() {
        assert_eq!(Subject::new("alice").to_string(), "alice");
    }

    #[test]
    fn partial_eq_against_str_slices() {
        let s = Subject::new("user-1");
        assert_eq!(s, "user-1");
        assert_eq!(s, *"user-1");
    }
}
