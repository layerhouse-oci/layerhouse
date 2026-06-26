use axum::Json;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::sync::Arc;

use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{AuthorizationStore, TokenStore};

#[derive(Debug)]
pub struct TokenQuery {
    pub service: Option<String>,
    pub scope: Vec<String>,
    pub _account: Option<String>,
    pub _client_id: Option<String>,
}

impl TokenQuery {
    fn from_raw_query(raw_query: Option<&str>) -> Result<Self, LayerhouseError> {
        let pairs: Vec<(String, String)> = match raw_query {
            Some(query) => serde_urlencoded::from_str(query)
                .map_err(|e| LayerhouseError::NameInvalid(format!("invalid token query: {e}")))?,
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

pub async fn token_endpoint<M: TokenStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    RawQuery(raw_query): RawQuery,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Response, LayerhouseError> {
    let query = TokenQuery::from_raw_query(raw_query.as_deref())?;
    let auth_service = state
        .auth
        .as_ref()
        .ok_or_else(|| LayerhouseError::Internal("auth not configured".to_string()))?;

    // Extract credentials from Basic auth header
    let (_username, password) =
        extract_basic_auth(&req).ok_or_else(|| LayerhouseError::Unauthorized {
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
    let mut granted_scopes = Vec::new();
    let mut namespace_epochs = Vec::new();
    if let Some(scope) = &requested_scope {
        for requested in scope.split_whitespace() {
            if let Some((repository, action)) = crate::auth::permissions::parse_scope(requested) {
                let access = match auth_service
                    .check_permission(&identity, &repository, action, &state.core.metadata)
                    .await
                {
                    Ok(access) => access,
                    Err(LayerhouseError::Denied(_)) => continue,
                    Err(e) => return Err(e),
                };
                granted_scopes.push(requested);
                access.record_expected_namespace(&mut namespace_epochs);
            }
        }
    }
    let granted_scope = if granted_scopes.is_empty() {
        None
    } else {
        Some(granted_scopes.join(" "))
    };

    // Mint OCI bearer token
    let token_str = auth_service.mint_oci_token(
        &identity,
        query.service.as_deref().unwrap_or(""),
        granted_scope.as_deref().unwrap_or(""),
        namespace_epochs,
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
    use crate::routes::test_state_with_auth;
    use crate::store::metadata::{PersonalAccessToken, TokenStore};
    use axum::body::{Body, to_bytes};
    use axum::extract::{RawQuery, State};
    use axum::http::Request;
    use base64::Engine;
    use sha2::Digest;

    #[test]
    fn token_query_accepts_repeated_scope_parameters() {
        let query = TokenQuery::from_raw_query(Some(
            "service=qa&scope=repository%3Aqa%2Fexample%3A%2A&scope=repository%3Aqa%2Fexample%3Apull%2Ccreate",
        ))
        .expect("query should parse");

        assert_eq!(query.service.as_deref(), Some("qa"));
        assert_eq!(
            query.scope,
            vec![
                "repository:qa/example:*".to_string(),
                "repository:qa/example:pull,create".to_string(),
            ]
        );
    }

    #[test]
    fn scope_string_joins_repeated_scope_parameters() {
        let scopes = vec![
            "repository:qa/example:*".to_string(),
            "repository:qa/example:pull,create".to_string(),
        ];

        assert_eq!(
            scope_string(&scopes),
            Some("repository:qa/example:* repository:qa/example:pull,create".to_string())
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

    #[tokio::test]
    async fn token_endpoint_mints_authorized_scope_subset() {
        let state = test_state_with_auth(vec![]);
        let raw_pat = "layerhouse-docker-scope-subset";
        state
            .core
            .metadata
            .put_personal_access_token(PersonalAccessToken {
                id: "pat-1".to_string(),
                subject: "builder".to_string(),
                username: Some("builder".to_string()),
                name: "Docker".to_string(),
                token_hash: hex::encode(sha2::Sha256::digest(raw_pat.as_bytes())),
                token_prefix: "layerhouse-docker".to_string(),
                scopes: vec!["repository:users/builder/app:*".to_string()],
                namespace_epochs: Vec::new(),
                created_at: 100,
                last_used_at: None,
                expires_at: None,
            })
            .await
            .unwrap();

        let basic = base64::engine::general_purpose::STANDARD.encode(format!("builder:{raw_pat}"));
        let request = Request::builder()
            .header(axum::http::header::AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::empty())
            .unwrap();
        let response = super::token_endpoint(
            State(state.clone()),
            RawQuery(Some(
                "service=layerhouse&scope=repository%3Ausers%2Fbuilder%2Fapp%3Apull%2Cpush&scope=repository%3Aqa%2Fbase%3Apull"
                    .to_string(),
            )),
            request,
        )
        .await
        .expect("token endpoint should return a reduced token");
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["token"].as_str().unwrap();
        let identity = state
            .auth
            .as_ref()
            .unwrap()
            .validate_token(token, &state.core.metadata)
            .await
            .unwrap();

        assert_eq!(
            identity.scopes,
            vec!["repository:users/builder/app:pull,push"]
        );
    }
}
