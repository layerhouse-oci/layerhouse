use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub subject: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub token_type: TokenType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    KanidmAccess,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    #[serde(rename = "sub")]
    pub subject: String,
    pub exp: usize,
    #[serde(default)]
    pub aud: Option<AudienceClaim>,
    #[serde(default)]
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
}
