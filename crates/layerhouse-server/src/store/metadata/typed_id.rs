//! Typed, prefixed, content-addressable identifiers for Layerhouse-internal
//! entities.
//!
//! All Layerhouse-generated ids share the shape `lhs<kind>-<32 lowercase hex>`,
//! so they are visually distinct from IdP-issued opaque subjects (which we
//! never decorate) and from OCI digests. Each kind gets its own newtype so the
//! type system prevents accidental cross-kind substitution.

#![allow(dead_code)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::LayerhouseError;

const ID_HEX_LEN: usize = 32;

fn validate_id(s: &str, prefix: &str) -> Result<String, LayerhouseError> {
    let suffix = s.strip_prefix(prefix).ok_or_else(|| {
        LayerhouseError::Internal(format!("expected id prefix {prefix:?}, got {s:?}"))
    })?;
    if suffix.len() != ID_HEX_LEN {
        return Err(LayerhouseError::Internal(format!(
            "id {s:?} has wrong hex length: expected {ID_HEX_LEN}"
        )));
    }
    if !suffix
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LayerhouseError::Internal(format!(
            "id {s:?} contains non-lowercase-hex characters"
        )));
    }
    Ok(s.to_string())
}

/// Stable identifier for an organization. Format: `lhsorg-<32 lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OrgId(String);

impl OrgId {
    const PREFIX: &'static str = "lhsorg-";

    pub fn generate() -> Self {
        Self(format!("{}{}", Self::PREFIX, uuid::Uuid::now_v7().simple()))
    }

    pub fn parse(s: &str) -> Result<Self, LayerhouseError> {
        validate_id(s, Self::PREFIX).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for OrgId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OrgId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_parseable_id() {
        for _ in 0..1000 {
            let id = OrgId::generate();
            let parsed = OrgId::parse(id.as_str()).expect("generated id parses");
            assert_eq!(parsed, id);
            assert!(id.as_str().starts_with("lhsorg-"));
            assert_eq!(id.as_str().len(), "lhsorg-".len() + 32);
        }
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        assert!(OrgId::parse("lhsuser-00000000000000000000000000000000").is_err());
        assert!(OrgId::parse("00000000000000000000000000000000").is_err());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(OrgId::parse("lhsorg-").is_err());
        assert!(OrgId::parse("lhsorg-0").is_err());
        assert!(OrgId::parse("lhsorg-000000000000000000000000000000001").is_err());
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        assert!(OrgId::parse("lhsorg-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(OrgId::parse("lhsorg-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
        assert!(OrgId::parse("lhsorg-0000000000000000000000000000000g").is_err());
    }

    #[test]
    fn parse_rejects_trailing_whitespace() {
        assert!(OrgId::parse("lhsorg-00000000000000000000000000000000 ").is_err());
    }

    #[test]
    fn json_round_trip() {
        let id = OrgId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let back: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn deserialize_rejects_malformed() {
        let result: Result<OrgId, _> = serde_json::from_str("\"not-an-id\"");
        assert!(result.is_err());
    }
}
