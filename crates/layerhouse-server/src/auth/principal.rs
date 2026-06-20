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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderQualifiedId(String);

impl ProviderQualifiedId {
    pub fn new(
        provider: impl AsRef<str>,
        kind: PrincipalKind,
        id: impl AsRef<str>,
    ) -> Result<Self, LayerhouseError> {
        let provider = validate_segment("provider", provider.as_ref())?;
        let id = validate_segment("id", id.as_ref())?;
        Ok(Self(format!("{provider}:{}:{id}", kind.as_str())))
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
        Self::new(parts[0], kind, parts[2])
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn kind(&self) -> PrincipalKind {
        let kind = self.0.split(':').nth(1).unwrap_or_default();
        PrincipalKind::from_str(kind).expect("ProviderQualifiedId is constructed canonically")
    }

    pub fn local_id(&self) -> &str {
        self.0.split(':').nth(2).unwrap_or_default()
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

fn validate_segment(name: &str, value: &str) -> Result<String, LayerhouseError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(LayerhouseError::NameInvalid(format!(
            "principal {name} must not be empty"
        )));
    }
    if value.contains(':') {
        return Err(LayerhouseError::NameInvalid(format!(
            "principal {name} must not contain ':'"
        )));
    }
    Ok(value.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_qualified_id_round_trips() {
        let id = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user-1").unwrap();
        assert_eq!(id.as_str(), "kanidm:user:user-1");
        assert_eq!(ProviderQualifiedId::parse(id.as_str()).unwrap(), id);
        assert_eq!(id.local_id(), "user-1");
        assert_eq!(id.kind(), PrincipalKind::User);
    }

    #[test]
    fn provider_qualified_id_rejects_ambiguous_segments() {
        assert!(ProviderQualifiedId::new("", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("kan:idm", PrincipalKind::User, "u").is_err());
        assert!(ProviderQualifiedId::new("kanidm", PrincipalKind::User, "").is_err());
        assert!(ProviderQualifiedId::new("kanidm", PrincipalKind::User, "u:1").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:user").is_err());
        assert!(ProviderQualifiedId::parse("kanidm:team:u").is_err());
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
