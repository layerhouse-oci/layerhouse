use axum::Extension;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::token::AuthIdentity;
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::metadata::{NamespaceStore, Owner};

#[derive(Debug, Deserialize)]
pub(crate) struct ClaimNamespaceRequest {
    #[serde(default)]
    pub(crate) owner_label: Option<String>,
    #[serde(default)]
    pub(crate) admin_override: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReleaseNamespaceRequest {
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceResponse {
    handle: String,
    owner_kind: String,
    owner_label: String,
    created_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceListResponse {
    pub(crate) namespaces: Vec<NamespaceResponse>,
}

pub(crate) fn namespace_response(ns: &crate::store::metadata::Namespace) -> NamespaceResponse {
    NamespaceResponse {
        handle: ns.handle.clone(),
        owner_kind: match &ns.owner {
            Owner::User(_) => "user".to_string(),
            Owner::Org(_) => "org".to_string(),
        },
        owner_label: ns.owner_label.clone(),
        created_at: ns.created_at,
    }
}

pub(crate) async fn require_admin<M: NamespaceStore, B>(
    state: &Arc<AppState<M, B>>,
    identity: &AuthIdentity,
) -> Result<(), LayerhouseError> {
    if let Some(auth) = state.auth.as_ref() {
        auth.check_admin_access(identity, &state.core.metadata)
            .await?;
    }
    Ok(())
}

pub(crate) fn require_auth<'a, M, B>(
    state: &Arc<AppState<M, B>>,
    identity: Option<&'a Extension<AuthIdentity>>,
) -> Result<&'a AuthIdentity, LayerhouseError> {
    if state.auth.is_none() {
        return Err(LayerhouseError::Internal(
            "auth is not configured".to_string(),
        ));
    }
    let Some(Extension(identity)) = identity else {
        return Err(LayerhouseError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    };
    Ok(identity)
}
