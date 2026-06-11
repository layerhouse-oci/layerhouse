use serde::{Deserialize, Serialize};

use crate::auth::identity::Subject;

#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub subject: Subject,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub token_type: TokenType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    OidcAccess,
    PersonalAccess,
    OciBearer,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

/// Deserializes a value that can be either a single string or an array of strings.
/// Returns `Some(vec![single])` for a string, `Some(arr)` for an array, or `None` for null/missing.
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(Some(vec![value.to_string()]))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(item) = seq.next_element::<String>()? {
                vec.push(item);
            }
            Ok(Some(vec))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    #[serde(rename = "sub")]
    pub subject: String,
    pub exp: usize,
    #[serde(default)]
    pub aud: Option<AudienceClaim>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default, rename = "token_type")]
    pub token_type: Option<String>,
    #[serde(default)]
    pub iat: Option<usize>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "serde_json::Value::is_null")]
    pub additional_claims: serde_json::Value,
}

impl TokenClaims {
    pub fn trimmed(value: &Option<String>) -> Option<String> {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    }

    pub fn display_name(&self) -> Option<String> {
        Self::trimmed(&self.name)
    }

    pub fn username(&self) -> Option<String> {
        Self::trimmed(&self.preferred_username)
    }

    pub fn email(&self) -> Option<String> {
        Self::trimmed(&self.email)
    }

    /// Extract groups from claims using the configured group claim path.
    /// When `group_claim` is `"groups"`, returns the standard `groups` field.
    /// Otherwise, traverses a dotted path (e.g., `"realm_access.roles"`)
    /// through `additional_claims`, returning an array of strings at the leaf
    /// or a single string as a one-element vec.
    pub fn extract_groups(&self, group_claim: &str) -> Vec<String> {
        if group_claim == "groups" {
            return self.groups.clone().unwrap_or_default();
        }
        let parts: Vec<&str> = group_claim.split('.').collect();
        let mut current = &self.additional_claims;
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            match current.get(*part) {
                Some(val) if is_last => {
                    if let Some(arr) = val.as_array() {
                        return arr
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(ToString::to_string)
                            .collect();
                    }
                    if let Some(s) = val.as_str() {
                        return vec![s.to_string()];
                    }
                    return vec![];
                }
                Some(val) => {
                    current = val;
                }
                None => return vec![],
            }
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::TokenClaims;

    fn claims(
        name: Option<&str>,
        preferred_username: Option<&str>,
        email: Option<&str>,
    ) -> TokenClaims {
        TokenClaims {
            subject: "subject-uuid".to_string(),
            exp: 1,
            aud: None,
            groups: None,
            name: name.map(ToString::to_string),
            preferred_username: preferred_username.map(ToString::to_string),
            email: email.map(ToString::to_string),
            scope: None,
            token_type: None,
            iat: None,
            iss: None,
            additional_claims: serde_json::Value::Null,
        }
    }

    fn display_label(claims: &TokenClaims) -> String {
        claims
            .display_name()
            .or_else(|| claims.username())
            .or_else(|| claims.email())
            .unwrap_or_else(|| claims.subject.clone())
    }

    #[test]
    fn display_label_prefers_human_profile_claims() {
        assert_eq!(
            display_label(&claims(
                Some("Admin User"),
                Some("admin"),
                Some("admin@example.test")
            )),
            "Admin User"
        );
        assert_eq!(
            display_label(&claims(None, Some("admin"), Some("admin@example.test"))),
            "admin"
        );
        assert_eq!(
            display_label(&claims(None, None, Some("admin@example.test"))),
            "admin@example.test"
        );
        assert_eq!(display_label(&claims(None, None, None)), "subject-uuid");
    }

    #[test]
    fn extract_groups_standard_claim_returns_groups_field() {
        let mut c = claims(None, None, None);
        c.groups = Some(vec!["admin".to_string(), "developer".to_string()]);
        assert_eq!(
            c.extract_groups("groups"),
            vec!["admin".to_string(), "developer".to_string()]
        );
    }

    #[test]
    fn extract_groups_standard_claim_returns_empty_when_none() {
        let c = claims(None, None, None);
        assert!(c.extract_groups("groups").is_empty());
    }

    #[test]
    fn extract_groups_dotted_path_extracts_nested_array() {
        let mut c = claims(None, None, None);
        c.additional_claims = serde_json::json!({
            "realm_access": {
                "roles": ["admin", "viewer"]
            }
        });
        assert_eq!(
            c.extract_groups("realm_access.roles"),
            vec!["admin".to_string(), "viewer".to_string()]
        );
    }

    #[test]
    fn extract_groups_dotted_path_single_string_becomes_vec() {
        let mut c = claims(None, None, None);
        c.additional_claims = serde_json::json!({
            "roles": "admin"
        });
        assert_eq!(c.extract_groups("roles"), vec!["admin".to_string()]);
    }

    #[test]
    fn extract_groups_missing_path_returns_empty() {
        let mut c = claims(None, None, None);
        c.additional_claims = serde_json::json!({"other": "value"});
        assert!(c.extract_groups("nonexistent.path").is_empty());
    }

    #[test]
    fn extract_groups_intermediate_not_object_returns_empty() {
        let mut c = claims(None, None, None);
        c.additional_claims = serde_json::json!({"flat": "not-an-object"});
        assert!(c.extract_groups("flat.nested").is_empty());
    }

    #[test]
    fn flatten_captures_realm_access_roles_from_real_jwt_json() {
        let json = serde_json::json!({
            "sub": "user-1",
            "exp": 9999999999_usize,
            "iss": "https://idp.example.test",
            "aud": "layerhouse",
            "realm_access": {
                "roles": ["admin", "viewer"]
            }
        });
        let claims: TokenClaims =
            serde_json::from_value(json).expect("should deserialize with flatten");
        assert_eq!(claims.subject, "user-1");
        assert_eq!(
            claims.extract_groups("realm_access.roles"),
            vec!["admin".to_string(), "viewer".to_string()]
        );
    }

    #[test]
    fn flatten_captures_flat_roles_from_real_jwt_json() {
        let json = serde_json::json!({
            "sub": "user-2",
            "exp": 9999999999_usize,
            "roles": ["Reader", "Writer"]
        });
        let claims: TokenClaims =
            serde_json::from_value(json).expect("should deserialize with flatten");
        assert_eq!(
            claims.extract_groups("roles"),
            vec!["Reader".to_string(), "Writer".to_string()]
        );
    }

    #[test]
    fn serialize_oci_token_omits_null_additional_claims() {
        let claims = TokenClaims {
            subject: "s".to_string(),
            exp: 1,
            aud: None,
            groups: Some(vec!["g".to_string()]),
            name: None,
            preferred_username: None,
            email: None,
            scope: Some("repository:*:pull".to_string()),
            token_type: Some("oci_bearer".to_string()),
            iat: Some(1),
            iss: Some("layerhouse".to_string()),
            additional_claims: serde_json::Value::Null,
        };
        let serialized = serde_json::to_value(&claims).expect("should serialize");
        // The flattened Null must not appear as a key in the output.
        assert!(
            serialized
                .as_object()
                .unwrap()
                .get("additional_claims")
                .is_none()
        );
        assert!(serialized.as_object().unwrap().get("null").is_none());
    }

    #[test]
    fn groups_claim_accepts_single_string() {
        let json = serde_json::json!({
            "sub": "user-3",
            "exp": 9999999999_usize,
            "groups": "admin"
        });
        let claims: TokenClaims =
            serde_json::from_value(json).expect("single-string groups should deserialize");
        assert_eq!(claims.groups, Some(vec!["admin".to_string()]));
        assert_eq!(claims.extract_groups("groups"), vec!["admin".to_string()]);
    }

    #[test]
    fn groups_claim_accepts_array() {
        let json = serde_json::json!({
            "sub": "user-4",
            "exp": 9999999999_usize,
            "groups": ["admin", "developer"]
        });
        let claims: TokenClaims =
            serde_json::from_value(json).expect("array groups should deserialize");
        assert_eq!(
            claims.groups,
            Some(vec!["admin".to_string(), "developer".to_string()])
        );
    }

    #[test]
    fn groups_claim_is_none_when_missing() {
        let json = serde_json::json!({
            "sub": "user-5",
            "exp": 9999999999_usize
        });
        let claims: TokenClaims =
            serde_json::from_value(json).expect("missing groups should deserialize");
        assert_eq!(claims.groups, None);
        assert!(claims.extract_groups("groups").is_empty());
    }
}
