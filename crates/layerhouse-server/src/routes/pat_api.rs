use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::Arc;

use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{PersonalAccessToken, TokenStore};

#[derive(Debug, Deserialize)]
pub struct CreatePatRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreatePatResponse {
    pub id: String,
    pub name: String,
    pub token: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PatListItem {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub expires_at: Option<u64>,
}

pub fn routes<M: TokenStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route("/api/v1/tokens", axum::routing::get(list_tokens::<M, B>))
        .route("/api/v1/tokens", axum::routing::post(create_token::<M, B>))
        .route(
            "/api/v1/tokens/{id}",
            axum::routing::delete(revoke_token::<M, B>),
        )
}

async fn list_tokens<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let identity = required_identity(identity)?;
    let tokens = state
        .core
        .metadata
        .list_personal_access_tokens(&identity.subject)
        .await?;
    let items: Vec<PatListItem> = tokens
        .iter()
        .map(|t| PatListItem {
            id: t.id.clone(),
            name: t.name.clone(),
            prefix: t.token_prefix.clone(),
            scopes: t.scopes.clone(),
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
        })
        .collect();
    Ok(Json(items))
}

async fn create_token<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Json(req): Json<CreatePatRequest>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let identity = required_identity(identity)?;
    if req.name.trim().is_empty() {
        return Err(LayerhouseError::NameInvalid(
            "token name is required".to_string(),
        ));
    }

    // Generate raw token: "layerhouse-" + 32 random hex chars
    let mut random_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut random_bytes);
    let raw_token = format!("layerhouse-{}", hex::encode(random_bytes));

    let token_hash = hex::encode(sha2::Sha256::digest(raw_token.as_bytes()));
    let token_prefix = raw_token.chars().take(12).collect::<String>();

    let now = chrono::Utc::now().timestamp() as u64;
    let expires_at = req.expires_in_days.map(|days| now + (days as u64) * 86400);

    let pat = PersonalAccessToken {
        id: uuid::Uuid::new_v4().to_string(),
        subject: identity.subject.clone(),
        username: identity.username.clone(),
        name: req.name.clone(),
        token_hash,
        token_prefix,
        scopes: req.scopes.clone(),
        created_at: now,
        last_used_at: None,
        expires_at,
    };

    state
        .core
        .metadata
        .put_personal_access_token(pat.clone())
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePatResponse {
            id: pat.id,
            name: pat.name,
            token: raw_token,
            scopes: pat.scopes,
            created_at: pat.created_at,
            expires_at: pat.expires_at,
        }),
    ))
}

async fn revoke_token<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let identity = required_identity(identity)?;
    let deleted = state
        .core
        .metadata
        .delete_personal_access_token(&id, &identity.subject)
        .await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(LayerhouseError::NameUnknown(format!(
            "token not found: {}",
            id
        )))
    }
}

fn required_identity(
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
) -> Result<crate::auth::token::AuthIdentity, LayerhouseError> {
    identity
        .map(|Extension(identity)| identity)
        .ok_or_else(|| LayerhouseError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        })
}
