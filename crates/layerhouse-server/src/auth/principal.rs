use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::LayerhouseError;
use crate::store::metadata::NamespaceEpoch;

use super::token::TokenType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    User,
    Group,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

impl FromStr for PrincipalKind {
    type Err = LayerhouseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "group" => Ok(Self::Group),
            _ => Err(LayerhouseError::NameInvalid(format!(
                "invalid principal kind {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, LayerhouseError> {
        let value = value.as_ref().trim();
        if value.is_empty() {
            return Err(LayerhouseError::NameInvalid(
                "principal provider must not be empty".to_string(),
            ));
        }
        if value.len() > 64 {
            return Err(LayerhouseError::NameInvalid(format!(
                "principal provider must be at most 64 characters: {value:?}"
            )));
        }
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return Err(LayerhouseError::NameInvalid(
                "principal provider must not be empty".to_string(),
            ));
        };
        if !first.is_ascii_lowercase() {
            return Err(LayerhouseError::NameInvalid(format!(
                "principal provider must start with a lowercase ASCII letter: {value:?}"
            )));
        }
        if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
        {
            return Err(LayerhouseError::NameInvalid(format!(
                "principal provider contains invalid characters: {value:?}"
            )));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderId {
    type Err = LayerhouseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalLocalId(String);

impl PrincipalLocalId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, LayerhouseError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(LayerhouseError::NameInvalid(
                "principal id must not be empty".to_string(),
            ));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn encoded(&self) -> String {
        escape_local_id(self.as_str())
    }
}

impl fmt::Display for PrincipalLocalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderQualifiedId(String);

impl ProviderQualifiedId {
    pub fn new(
        provider: impl AsRef<str>,
        kind: PrincipalKind,
        id: impl AsRef<str>,
    ) -> Result<Self, LayerhouseError> {
        let provider = ProviderId::new(provider)?;
        let id = PrincipalLocalId::new(id)?;
        Ok(Self(format!(
            "{}:{}:{}",
            provider.as_str(),
            kind.as_str(),
            id.encoded()
        )))
    }

    pub fn parse(value: impl AsRef<str>) -> Result<Self, LayerhouseError> {
        let value = value.as_ref().trim();
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 3 {
            return Err(LayerhouseError::NameInvalid(format!(
                "principal id must have provider:kind:id shape: {value:?}"
            )));
        }
        let kind = PrincipalKind::from_str(parts[1])?;
        let id = PrincipalLocalId::new(unescape_local_id(parts[2])?)?;
        Self::new(parts[0], kind, id.as_str())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn provider(&self) -> &str {
        self.0.split(':').next().unwrap_or_default()
    }

    pub fn kind(&self) -> PrincipalKind {
        let kind = self.0.split(':').nth(1).unwrap_or_default();
        PrincipalKind::from_str(kind).expect("ProviderQualifiedId is constructed canonically")
    }

    pub fn local_id(&self) -> String {
        unescape_local_id(self.0.split(':').nth(2).unwrap_or_default())
            .expect("ProviderQualifiedId is constructed canonically")
    }
}

impl fmt::Display for ProviderQualifiedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderQualifiedId {
    type Err = LayerhouseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalRef {
    User { id: ProviderQualifiedId },
    Group { id: ProviderQualifiedId },
    Public,
}

impl PrincipalRef {
    pub fn user(id: ProviderQualifiedId) -> Result<Self, LayerhouseError> {
        ensure_kind(&id, PrincipalKind::User)?;
        Ok(Self::User { id })
    }

    pub fn group(id: ProviderQualifiedId) -> Result<Self, LayerhouseError> {
        ensure_kind(&id, PrincipalKind::Group)?;
        Ok(Self::Group { id })
    }

    pub fn stable_key(&self) -> String {
        match self {
            Self::User { id } => format!("user:{id}"),
            Self::Group { id } => format!("group:{id}"),
            Self::Public => "public".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub principal: ProviderQualifiedId,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub group_ids: Vec<ProviderQualifiedId>,
    pub display_groups: Vec<String>,
    pub scopes: Vec<String>,
    pub namespace_epochs: Vec<NamespaceEpoch>,
    pub token_type: TokenType,
}

pub fn stable_group_ids(provider: &str, groups: &[String]) -> Vec<ProviderQualifiedId> {
    let mut seen = BTreeSet::new();
    for group in groups {
        let trimmed = group.trim();
        if uuid::Uuid::parse_str(trimmed).is_ok()
            && let Ok(id) = ProviderQualifiedId::new(provider, PrincipalKind::Group, trimmed)
        {
            seen.insert(id);
        }
    }
    seen.into_iter().collect()
}

fn ensure_kind(id: &ProviderQualifiedId, kind: PrincipalKind) -> Result<(), LayerhouseError> {
    if id.kind() != kind {
        return Err(LayerhouseError::NameInvalid(format!(
            "principal id {id} is not a {}",
            kind.as_str()
        )));
    }
    Ok(())
}

fn escape_local_id(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push('%');
            escaped.push(char::from(HEX[usize::from(byte >> 4)]));
            escaped.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    escaped
}

fn unescape_local_id(value: &str) -> Result<String, LayerhouseError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(LayerhouseError::NameInvalid(format!(
                "principal id contains truncated escape: {value:?}"
            )));
        }
        let high = hex_value(bytes[index + 1]).ok_or_else(|| {
            LayerhouseError::NameInvalid(format!("principal id contains invalid escape: {value:?}"))
        })?;
        let low = hex_value(bytes[index + 2]).ok_or_else(|| {
            LayerhouseError::NameInvalid(format!("principal id contains invalid escape: {value:?}"))
        })?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|err| {
        LayerhouseError::NameInvalid(format!("principal id is not valid UTF-8: {err}"))
    })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_qualified_id_round_trips() {
        let id = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user-1").unwrap();
        assert_eq!(id.as_str(), "kanidm:user:user-1");
        assert_eq!(id.provider(), "kanidm");
        assert_eq!(ProviderQualifiedId::parse(id.as_str()).unwrap(), id);
        assert_eq!(id.local_id(), "user-1".to_string());
        assert_eq!(id.kind(), PrincipalKind::User);
    }

    #[test]
    fn provider_qualified_id_rejects_invalid_provider_segments() {
        assert!(ProviderQualifiedId::new("", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("Kanidm", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("1kanidm", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("kan:idm", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("kanidm.example", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("kanidm", PrincipalKind::User, "").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:user").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:team:u").is_err());
    }

    #[test]
    fn provider_qualified_id_escapes_opaque_local_ids() {
        let id = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user:one/space id")
            .expect("opaque local id should be escaped");

        assert_eq!(id.as_str(), "kanidm:user:user%3Aone%2Fspace%20id");
        assert_eq!(id.local_id(), "user:one/space id".to_string());
        assert_eq!(ProviderQualifiedId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn provider_qualified_id_escape_prevents_local_id_collisions() {
        let literal_colon = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user:1")
            .expect("colon should be escaped");
        let literal_escape = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user%3A1")
            .expect("percent should be escaped");

        assert_eq!(literal_colon.as_str(), "kanidm:user:user%3A1");
        assert_eq!(literal_escape.as_str(), "kanidm:user:user%253A1");
        assert_ne!(literal_colon, literal_escape);
        assert_eq!(literal_colon.local_id(), "user:1".to_string());
        assert_eq!(literal_escape.local_id(), "user%3A1".to_string());
    }

    #[test]
    fn provider_qualified_id_rejects_invalid_escape_sequences() {
        assert!(ProviderQualifiedId::parse("kanidm:user:user%2").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:user:user%xx").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:user:%FF").is_err());
    }

    #[test]
    fn stable_group_ids_keep_only_uuids_and_deduplicate() {
        let groups = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "admins@example.test".to_string(),
            "admins".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "".to_string(),
        ];
        let ids = stable_group_ids("kanidm", &groups);
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0].as_str(),
            "kanidm:group:550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn principal_ref_validates_kind() {
        let user = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "u1").unwrap();
        assert!(PrincipalRef::user(user.clone()).is_ok());
        assert!(PrincipalRef::group(user).is_err());
    }
}
