use axum::Json;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::sync::Arc;

use crate::error::OrbChrysaError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::TokenStore;

#[derive(Debug)]
pub struct TokenQuery {
    pub service: Option<String>,
    pub scope: Vec<String>,
    pub _account: Option<String>,
    pub _client_id: Option<String>,
}

impl TokenQuery {
    fn from_raw_query(raw_query: Option<&str>) -> Result<Self, OrbChrysaError> {
        let pairs: Vec<(String, String)> = match raw_query {
            Some(query) => serde_urlencoded::from_str(query)
                .map_err(|e| OrbChrysaError::NameInvalid(format!("invalid token query: {e}")))?,
            None => Vec::new(),
        };

        let mut query = Self {
            service: None,
            scope: Vec::new(),
            _account: None,
            _client_id: None,
        };

        for (key, value) in pairs {
            match key.as_str() {
                "service" => query.service = Some(value),
                "scope" => query.scope.push(value),
                "account" => query._account = Some(value),
                "client_id" => query._client_id = Some(value),
                _ => {}
            }
        }

        Ok(query)
    }
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

pub async fn token_endpoint<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    RawQuery(raw_query): RawQuery,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Response, OrbChrysaError> {
    let query = TokenQuery::from_raw_query(raw_query.as_deref())?;
    let auth_service = state
        .auth
        .as_ref()
        .ok_or_else(|| OrbChrysaError::Internal("auth not configured".to_string()))?;

    // Extract credentials from Basic auth header
    let (_username, password) =
        extract_basic_auth(&req).ok_or_else(|| OrbChrysaError::Unauthorized {
            message: "authentication required".to_string(),
            realm: Some(auth_service.token_endpoint_url().to_string()),
            service: query.service.clone(),
            scope: scope_string(&query.scope),
        })?;

    // The password field is the token (PAT or OIDC access token)
    let token = &password;
    let identity = auth_service
        .validate_token::<M>(token, &state.core.metadata)
        .await?;

    let requested_scope = scope_string(&query.scope);
    if let Some(scope) = &requested_scope {
        for requested in scope.split_whitespace() {
            if let Some((repository, action)) = crate::auth::permissions::parse_scope(requested) {
                auth_service.check_permission(&identity, &repository, action)?;
            }
        }
    }

    // Mint OCI bearer token
    let token_str = auth_service.mint_oci_token(
        &identity,
        query.service.as_deref().unwrap_or(""),
        requested_scope.as_deref().unwrap_or(""),
    )?;

    let now = chrono::Utc::now();
    let response = TokenResponse {
        token: token_str.clone(),
        access_token: token_str,
        expires_in: 3600,
        issued_at: now.to_rfc3339(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

fn scope_string(scopes: &[String]) -> Option<String> {
    let value = scopes
        .iter()
        .flat_map(|scope| scope.split_whitespace())
        .filter(|scope| !scope.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!value.is_empty()).then_some(value)
}

fn extract_basic_auth(req: &axum::http::Request<axum::body::Body>) -> Option<(String, String)> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{TokenQuery, scope_string};

    #[test]
    fn token_query_accepts_repeated_scope_parameters() {
        let query = TokenQuery::from_raw_query(Some(
            "service=qa&scope=repository%3Aqa%2Fexample%3A%2A&scope=repository%3Aqa%2Fexample%3Apull%2Cpush",
        ))
        .expect("query should parse");

        assert_eq!(query.service.as_deref(), Some("qa"));
        assert_eq!(
            query.scope,
            vec![
                "repository:qa/example:*".to_string(),
                "repository:qa/example:pull,push".to_string(),
            ]
        );
    }

    #[test]
    fn scope_string_joins_repeated_scope_parameters() {
        let scopes = vec![
            "repository:qa/example:*".to_string(),
            "repository:qa/example:pull,push".to_string(),
        ];

        assert_eq!(
            scope_string(&scopes),
            Some("repository:qa/example:* repository:qa/example:pull,push".to_string())
        );
    }

    #[test]
    fn scope_string_filters_empty_scope_parameters() {
        let scopes = vec![" ".to_string(), "repository:qa/example:pull".to_string()];

        assert_eq!(
            scope_string(&scopes),
            Some("repository:qa/example:pull".to_string())
        );
    }
}
