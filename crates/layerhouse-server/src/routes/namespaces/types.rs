use axum::Extension;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::permissions::OciAction;
use crate::auth::principal::ProviderQualifiedId;
use crate::auth::token::AuthIdentity;
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::metadata::{
    NamespaceGrant, NamespaceGrantAuditEvent, NamespaceGrantAuditOperation, NamespaceGrantGrantee,
    NamespaceStore, ObservedIdentity, Owner,
};

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

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum NamespaceGrantGranteeRequest {
    Group { id: String },
    User { id: String },
    Public,
}

impl NamespaceGrantGranteeRequest {
    pub(crate) fn into_grantee(self) -> Result<NamespaceGrantGrantee, LayerhouseError> {
        match self {
            Self::Group { id } => Ok(NamespaceGrantGrantee::Group {
                id: ProviderQualifiedId::parse(id)?,
            }),
            Self::User { id } => Ok(NamespaceGrantGrantee::User {
                id: ProviderQualifiedId::parse(id)?,
            }),
            Self::Public => Ok(NamespaceGrantGrantee::Public),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PutNamespaceGrantRequest {
    pub(crate) grantee: NamespaceGrantGranteeRequest,
    pub(crate) action: OciAction,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PatchNamespaceGrantRequest {
    pub(crate) action: OciAction,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ObservedUsersQuery {
    #[serde(default)]
    pub(crate) q: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
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

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum NamespaceGrantGranteeResponse {
    Group { id: String },
    User { id: String },
    Public,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceGrantResponse {
    id: String,
    namespace: String,
    grantee: NamespaceGrantGranteeResponse,
    action: OciAction,
    label: String,
    created_by: String,
    created_at: u64,
    updated_by: String,
    updated_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceGrantListResponse {
    pub(crate) grants: Vec<NamespaceGrantResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceGrantAuditResponse {
    id: String,
    namespace: String,
    grant_id: Option<String>,
    operation: NamespaceGrantAuditOperation,
    actor: String,
    actor_label: String,
    reason: String,
    before: Option<NamespaceGrantResponse>,
    after: Option<NamespaceGrantResponse>,
    created_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct NamespaceGrantAuditListResponse {
    pub(crate) audit: Vec<NamespaceGrantAuditResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ObservedIdentityResponse {
    subject: String,
    username: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    groups: Vec<String>,
    last_seen_at: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ObservedIdentityListResponse {
    pub(crate) users: Vec<ObservedIdentityResponse>,
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

pub(crate) fn namespace_grant_response(grant: &NamespaceGrant) -> NamespaceGrantResponse {
    NamespaceGrantResponse {
        id: grant.id.clone(),
        namespace: grant.namespace.clone(),
        grantee: match &grant.grantee {
            NamespaceGrantGrantee::Group { id } => {
                NamespaceGrantGranteeResponse::Group { id: id.to_string() }
            }
            NamespaceGrantGrantee::User { id } => {
                NamespaceGrantGranteeResponse::User { id: id.to_string() }
            }
            NamespaceGrantGrantee::Public => NamespaceGrantGranteeResponse::Public,
        },
        action: grant.action,
        label: grant.label.clone(),
        created_by: grant.created_by.as_str().to_string(),
        created_at: grant.created_at,
        updated_by: grant.updated_by.as_str().to_string(),
        updated_at: grant.updated_at,
    }
}

pub(crate) fn namespace_grant_audit_response(
    event: &NamespaceGrantAuditEvent,
) -> NamespaceGrantAuditResponse {
    NamespaceGrantAuditResponse {
        id: event.id.clone(),
        namespace: event.namespace.clone(),
        grant_id: event.grant_id.clone(),
        operation: event.operation,
        actor: event.actor.as_str().to_string(),
        actor_label: event.actor_label.clone(),
        reason: event.reason.clone(),
        before: event.before.as_ref().map(namespace_grant_response),
        after: event.after.as_ref().map(namespace_grant_response),
        created_at: event.created_at,
    }
}

pub(crate) fn observed_identity_response(identity: &ObservedIdentity) -> ObservedIdentityResponse {
    ObservedIdentityResponse {
        subject: identity.subject.as_str().to_string(),
        username: identity.username.clone(),
        display_name: identity.display_name.clone(),
        email: identity.email.clone(),
        groups: identity.groups.clone(),
        last_seen_at: identity.last_seen_at,
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
