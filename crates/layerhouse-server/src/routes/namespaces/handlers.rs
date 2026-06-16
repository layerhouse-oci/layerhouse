use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use std::sync::Arc;

use crate::auth::token::AuthIdentity;
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{NamespaceStore, Owner, ReleaseReason};

use super::types::{
    ClaimNamespaceRequest, NamespaceListResponse, ReleaseNamespaceRequest, namespace_response,
    require_admin, require_auth,
};

pub(crate) async fn list_namespaces<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;

    let namespaces = state.core.metadata.list_namespaces().await?;
    let items: Vec<_> = namespaces.iter().map(namespace_response).collect();
    Ok((
        StatusCode::OK,
        Json(NamespaceListResponse { namespaces: items }),
    )
        .into_response())
}

pub(crate) async fn list_account_namespaces<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;

    let namespaces = state.core.metadata.list_namespaces().await?;
    let items: Vec<_> = namespaces
        .iter()
        .filter(|ns| matches!(&ns.owner, Owner::User(subject) if subject == &identity.subject))
        .map(namespace_response)
        .collect();
    Ok((
        StatusCode::OK,
        Json(NamespaceListResponse { namespaces: items }),
    )
        .into_response())
}

pub(crate) async fn get_namespace<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;

    let ns = state.core.metadata.get_namespace(&handle).await?;
    match ns {
        Some(ns) => Ok((StatusCode::OK, Json(namespace_response(&ns))).into_response()),
        None => Err(LayerhouseError::NameUnknown(format!(
            "namespace {handle:?} not found"
        ))),
    }
}

pub(crate) async fn claim_namespace<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
    Json(req): Json<ClaimNamespaceRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;

    if req.admin_override {
        require_admin(&state, identity).await?;
    }

    let owner = Owner::User(identity.subject.clone());
    let owner_label = req
        .owner_label
        .as_deref()
        .unwrap_or_else(|| identity.username.as_deref().unwrap_or("unknown"))
        .to_string();
    let now = crate::store::metadata::now_epoch();

    state
        .core
        .metadata
        .claim_namespace(
            &handle,
            owner,
            &owner_label,
            identity.subject.clone(),
            req.admin_override,
            now,
        )
        .await?;

    let ns = state
        .core
        .metadata
        .get_namespace(&handle)
        .await?
        .expect("namespace just claimed");
    Ok((StatusCode::CREATED, Json(namespace_response(&ns))).into_response())
}

pub(crate) async fn release_namespace<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
    Json(req): Json<ReleaseNamespaceRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;

    let reason = match req.reason.as_deref() {
        Some(s) if !s.trim().is_empty() => ReleaseReason::Renamed {
            new_handle: s.trim().to_string(),
        },
        _ => ReleaseReason::OwnerDeleted,
    };
    let now = crate::store::metadata::now_epoch();

    state
        .core
        .metadata
        .release_namespace(&handle, identity.subject.clone(), reason, now)
        .await?;

    Ok((StatusCode::NO_CONTENT, Json(())).into_response())
}

pub(crate) async fn revoke_namespace<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;

    let now = crate::store::metadata::now_epoch();

    state
        .core
        .metadata
        .admin_revoke_namespace(&handle, identity.subject.clone(), now)
        .await?;

    Ok((StatusCode::NO_CONTENT, Json(())).into_response())
}
