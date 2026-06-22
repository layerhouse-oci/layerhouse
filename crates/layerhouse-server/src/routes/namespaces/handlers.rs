use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use std::sync::Arc;

use crate::auth::token::AuthIdentity;
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{
    AuthorizationStore, NamespaceGrant, NamespaceGrantGrantee, NamespaceStore, Owner, ReleaseReason,
};

use super::types::{
    ClaimNamespaceRequest, NamespaceGrantAuditListResponse, NamespaceGrantListResponse,
    NamespaceListResponse, ObservedIdentityListResponse, ObservedUsersQuery,
    PatchNamespaceGrantRequest, PutNamespaceGrantRequest, ReleaseNamespaceRequest,
    namespace_grant_audit_response, namespace_grant_response, namespace_response,
    observed_identity_response, require_admin, require_auth,
};

pub(crate) async fn list_namespaces<M: AuthorizationStore, B: BlobStore>(
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

pub(crate) async fn get_namespace<M: AuthorizationStore, B: BlobStore>(
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

pub(crate) async fn claim_namespace<M: AuthorizationStore, B: BlobStore>(
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

pub(crate) async fn revoke_namespace<M: AuthorizationStore, B: BlobStore>(
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

pub(crate) async fn list_account_namespace_grants<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_namespace_owner(&state, identity, &handle).await?;
    list_namespace_grants_response(&state, &handle).await
}

pub(crate) async fn create_account_namespace_grant<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
    Json(req): Json<PutNamespaceGrantRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_namespace_owner(&state, identity, &handle).await?;
    put_namespace_grant_response(&state, identity, &handle, req, false).await
}

pub(crate) async fn update_account_namespace_grant<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path((handle, grant_id)): Path<(String, String)>,
    Json(req): Json<PatchNamespaceGrantRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_namespace_owner(&state, identity, &handle).await?;
    patch_namespace_grant_response(&state, identity, &handle, &grant_id, req, false).await
}

pub(crate) async fn delete_account_namespace_grant<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path((handle, grant_id)): Path<(String, String)>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_namespace_owner(&state, identity, &handle).await?;
    delete_namespace_grant_response(&state, identity, &handle, &grant_id, None, false).await
}

pub(crate) async fn search_observed_users<M: NamespaceStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Query(query): Query<ObservedUsersQuery>,
) -> Result<Response, LayerhouseError> {
    let _identity = require_auth(&state, identity.as_ref())?;
    let limit = query.limit.unwrap_or(20).clamp(1, 50);
    let users = state
        .core
        .metadata
        .search_observed_identities(query.q.as_deref().unwrap_or_default(), limit)
        .await?;
    Ok((
        StatusCode::OK,
        Json(ObservedIdentityListResponse {
            users: users.iter().map(observed_identity_response).collect(),
        }),
    )
        .into_response())
}

pub(crate) async fn list_admin_namespace_grants<M: AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;
    ensure_namespace_exists(&state, &handle).await?;
    list_namespace_grants_response(&state, &handle).await
}

pub(crate) async fn create_admin_namespace_grant<M: AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
    Json(req): Json<PutNamespaceGrantRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;
    put_namespace_grant_response(&state, identity, &handle, req, true).await
}

pub(crate) async fn update_admin_namespace_grant<M: AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path((handle, grant_id)): Path<(String, String)>,
    Json(req): Json<PatchNamespaceGrantRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;
    patch_namespace_grant_response(&state, identity, &handle, &grant_id, req, true).await
}

pub(crate) async fn delete_admin_namespace_grant<M: AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path((handle, grant_id)): Path<(String, String)>,
    Json(req): Json<AdminGrantReasonRequest>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;
    delete_namespace_grant_response(
        &state,
        identity,
        &handle,
        &grant_id,
        req.reason.as_deref(),
        true,
    )
    .await
}

pub(crate) async fn list_admin_namespace_grant_audit<M: AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(handle): Path<String>,
) -> Result<Response, LayerhouseError> {
    let identity = require_auth(&state, identity.as_ref())?;
    require_admin(&state, identity).await?;
    ensure_namespace_exists(&state, &handle).await?;
    let audit = state
        .core
        .metadata
        .list_namespace_grant_audit(&handle)
        .await?;
    Ok((
        StatusCode::OK,
        Json(NamespaceGrantAuditListResponse {
            audit: audit.iter().map(namespace_grant_audit_response).collect(),
        }),
    )
        .into_response())
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct AdminGrantReasonRequest {
    #[serde(default)]
    reason: Option<String>,
}

async fn list_namespace_grants_response<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    handle: &str,
) -> Result<Response, LayerhouseError> {
    let grants = state.core.metadata.list_namespace_grants(handle).await?;
    Ok((
        StatusCode::OK,
        Json(NamespaceGrantListResponse {
            grants: grants.iter().map(namespace_grant_response).collect(),
        }),
    )
        .into_response())
}

async fn put_namespace_grant_response<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    identity: &AuthIdentity,
    handle: &str,
    req: PutNamespaceGrantRequest,
    admin: bool,
) -> Result<Response, LayerhouseError> {
    ensure_namespace_exists(state, handle).await?;
    let reason = normalized_reason(req.reason.as_deref(), admin)?;
    let grantee = req.grantee.into_grantee()?;
    let existing = matching_grant(state, handle, &grantee).await?;
    let now = crate::store::metadata::now_epoch();
    let action = public_safe_action(&grantee, req.action)?;
    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| grantee.label());
    let grant = NamespaceGrant {
        id: existing
            .as_ref()
            .map(|grant| grant.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        namespace: handle.to_string(),
        grantee,
        action,
        label,
        created_by: identity.subject.clone(),
        created_at: now,
        updated_by: identity.subject.clone(),
        updated_at: now,
    };
    let saved = state
        .core
        .metadata
        .put_namespace_grant(grant, &actor_label(identity), &reason)
        .await?;
    Ok((StatusCode::OK, Json(namespace_grant_response(&saved))).into_response())
}

async fn patch_namespace_grant_response<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    identity: &AuthIdentity,
    handle: &str,
    grant_id: &str,
    req: PatchNamespaceGrantRequest,
    admin: bool,
) -> Result<Response, LayerhouseError> {
    ensure_namespace_exists(state, handle).await?;
    let reason = normalized_reason(req.reason.as_deref(), admin)?;
    let Some(mut grant) = state
        .core
        .metadata
        .get_namespace_grant(handle, grant_id)
        .await?
    else {
        return Err(LayerhouseError::NameUnknown(format!(
            "namespace grant {grant_id:?} not found"
        )));
    };
    grant.action = public_safe_action(&grant.grantee, req.action)?;
    if let Some(label) = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        grant.label = label.to_string();
    }
    grant.updated_by = identity.subject.clone();
    grant.updated_at = crate::store::metadata::now_epoch();
    let saved = state
        .core
        .metadata
        .put_namespace_grant(grant, &actor_label(identity), &reason)
        .await?;
    Ok((StatusCode::OK, Json(namespace_grant_response(&saved))).into_response())
}

async fn delete_namespace_grant_response<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    identity: &AuthIdentity,
    handle: &str,
    grant_id: &str,
    reason: Option<&str>,
    admin: bool,
) -> Result<Response, LayerhouseError> {
    ensure_namespace_exists(state, handle).await?;
    let reason = normalized_reason(reason, admin)?;
    let deleted = state
        .core
        .metadata
        .delete_namespace_grant(
            handle,
            grant_id,
            identity.subject.clone(),
            &actor_label(identity),
            &reason,
            crate::store::metadata::now_epoch(),
        )
        .await?;
    if deleted {
        Ok((StatusCode::NO_CONTENT, Json(())).into_response())
    } else {
        Err(LayerhouseError::NameUnknown(format!(
            "namespace grant {grant_id:?} not found"
        )))
    }
}

async fn matching_grant<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    handle: &str,
    grantee: &NamespaceGrantGrantee,
) -> Result<Option<NamespaceGrant>, LayerhouseError> {
    Ok(state
        .core
        .metadata
        .list_namespace_grants(handle)
        .await?
        .into_iter()
        .find(|grant| grant.grantee.stable_key() == grantee.stable_key()))
}

async fn require_namespace_owner<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    identity: &AuthIdentity,
    handle: &str,
) -> Result<(), LayerhouseError> {
    let ns = ensure_namespace_exists(state, handle).await?;
    match ns.owner {
        Owner::User(subject) if subject == identity.subject => Ok(()),
        _ => Err(LayerhouseError::Denied(format!(
            "namespace {handle:?} is not owned by the caller"
        ))),
    }
}

async fn ensure_namespace_exists<M: NamespaceStore, B: BlobStore>(
    state: &Arc<AppState<M, B>>,
    handle: &str,
) -> Result<crate::store::metadata::Namespace, LayerhouseError> {
    state
        .core
        .metadata
        .get_namespace(handle)
        .await?
        .ok_or_else(|| LayerhouseError::NameUnknown(format!("namespace {handle:?} not found")))
}

fn public_safe_action(
    grantee: &NamespaceGrantGrantee,
    action: crate::auth::permissions::OciAction,
) -> Result<crate::auth::permissions::OciAction, LayerhouseError> {
    if !crate::auth::permissions::is_repository_action(action) {
        return Err(LayerhouseError::NameInvalid(
            "namespace grants only support repository actions".to_string(),
        ));
    }
    if matches!(grantee, NamespaceGrantGrantee::Public) {
        Ok(crate::auth::permissions::OciAction::Pull)
    } else {
        Ok(action)
    }
}

fn actor_label(identity: &AuthIdentity) -> String {
    identity
        .display_name
        .as_deref()
        .or(identity.username.as_deref())
        .or(identity.email.as_deref())
        .unwrap_or_else(|| identity.subject.as_str())
        .to_string()
}

fn normalized_reason(reason: Option<&str>, required: bool) -> Result<String, LayerhouseError> {
    let reason = reason.map(str::trim).filter(|value| !value.is_empty());
    match (required, reason) {
        (true, None) => Err(LayerhouseError::NameInvalid(
            "admin grant changes require a reason".to_string(),
        )),
        (_, Some(reason)) => Ok(reason.to_string()),
        (false, None) => Ok("owner change".to_string()),
    }
}
