use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::auth::permissions::{self, GrantSource, OciAction, RepoKind};
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{ManifestStore, NamespaceStore, PersonalAccessToken, TokenStore};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;

// ── PAT create / list / revoke ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PatScopeSelection {
    /// Exact repository name or "team-a/*" namespace pattern.
    pub repository: String,
    /// Selected actions — must be a subset of the actor's max grantable.
    pub actions: Vec<OciAction>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePatRequest {
    pub name: String,
    pub scopes: Vec<PatScopeSelection>,
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

// ── Grantable scope search ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GrantableScopeQuery {
    q: Option<String>,
    n: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct GrantableScopeListResponse {
    scopes: Vec<GrantableScope>,
    namespace_patterns: Vec<NamespacePatternScope>,
    total_matches: u64,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct GrantableScope {
    repository: String,
    max_grantable: OciAction,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kind: Vec<RepoKind>,
    grant_source: GrantSource,
}

#[derive(Debug, Serialize)]
struct NamespacePatternScope {
    pattern: String,
    current_match_count: u64,
    max_grantable: OciAction,
    grant_source: GrantSource,
}

pub fn routes<M, B>() -> Router<Arc<AppState<M, B>>>
where
    M: TokenStore + ManifestStore + NamespaceStore,
    B: BlobStore,
{
    Router::new()
        .route("/api/v1/tokens", axum::routing::get(list_tokens::<M, B>))
        .route("/api/v1/tokens", axum::routing::post(create_token::<M, B>))
        .route(
            "/api/v1/tokens/{id}",
            axum::routing::delete(revoke_token::<M, B>),
        )
        .route(
            "/api/v1/tokens/grantable-scopes",
            axum::routing::get(grantable_scopes::<M, B>),
        )
}

// ── List ──────────────────────────────────────────────────────────────

async fn list_tokens<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let identity = required_identity(identity)?;
    let tokens = state
        .core
        .metadata
        .list_personal_access_tokens(identity.subject.as_str())
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

// ── Create ────────────────────────────────────────────────────────────

async fn create_token<M, B>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Json(req): Json<CreatePatRequest>,
) -> Result<impl IntoResponse, LayerhouseError>
where
    M: TokenStore + NamespaceStore,
    B: BlobStore,
{
    let identity = required_identity(identity)?;
    if req.name.trim().is_empty() {
        return Err(LayerhouseError::NameInvalid(
            "token name is required".to_string(),
        ));
    }

    // 1. Convert structured scope selections to canonical scope strings
    //    and validate each against cross-user personal namespace + ceiling.
    let mut scope_strings: Vec<String> = Vec::with_capacity(req.scopes.len());
    for selection in &req.scopes {
        let repo = selection.repository.trim();
        if repo.is_empty() {
            return Err(LayerhouseError::NameInvalid(
                "scope repository is required".to_string(),
            ));
        }

        // Determine the best action for the scope string.
        let best_action = selection
            .actions
            .iter()
            .max_by_key(|a| permissions::action_rank(**a))
            .copied()
            .unwrap_or(OciAction::Pull);

        let scope_str = format!(
            "repository:{}:{}",
            repo,
            selection
                .actions
                .iter()
                .map(|a| a.scope_token())
                .collect::<Vec<_>>()
                .join(",")
        );

        // Cross-user personal namespace check (already implemented).
        permissions::pat_scope_allowed_for_identity(&scope_str, identity.username.as_deref())?;

        // 2. Ceiling check: the actor cannot grant more than they have.
        if let Some(auth) = state.auth.as_ref() {
            let (max_action, _source) = auth
                .max_grantable_action(&identity, repo, &state.core.metadata)
                .await?;
            for action in &selection.actions {
                if !permissions::action_matches(max_action, *action) {
                    return Err(LayerhouseError::Denied(format!(
                        "cannot grant action {} on repository {repo:?}: \
                         your maximum grantable action is {}",
                        action.scope_token(),
                        max_action.scope_token(),
                    )));
                }
            }
            // 3. Namespace-pattern ceiling: a namespace pattern scope
            //    (e.g. "repository:team-a/*") requires a matching grant.
            if repo.ends_with("/*") {
                let prefix = repo.strip_suffix("/*").unwrap();
                if !prefix.is_empty() && prefix != "*" {
                    let pattern_max =
                        permissions::max_action_for_namespace_pattern(&identity.scopes, prefix);
                    match pattern_max {
                        Some(pm) if permissions::action_matches(pm, best_action) => {
                            // Actor has a matching grant pattern.
                        }
                        _ => {
                            // Check OIDC group grants too.
                            let group_max = state.auth.as_ref().and_then(|a| {
                                a.max_action_from_groups(&identity.groups, &format!("{prefix}/*"))
                            });
                            match group_max {
                                Some(gm) if permissions::action_matches(gm, best_action) => {}
                                _ => {
                                    return Err(LayerhouseError::Denied(format!(
                                        "cannot grant namespace-pattern scope \
                                         {repo:?}: no matching grant pattern found"
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }

        scope_strings.push(scope_str);
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
        subject: identity.subject.as_str().to_string(),
        username: identity.username.clone(),
        name: req.name.clone(),
        token_hash,
        token_prefix,
        scopes: scope_strings.clone(),
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

// ── Revoke ────────────────────────────────────────────────────────────

async fn revoke_token<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let identity = required_identity(identity)?;
    let deleted = state
        .core
        .metadata
        .delete_personal_access_token(&id, identity.subject.as_str())
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

// ── Grantable scope search ────────────────────────────────────────────

async fn grantable_scopes<M, B>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Query(query): Query<GrantableScopeQuery>,
) -> Result<impl IntoResponse, LayerhouseError>
where
    M: ManifestStore + NamespaceStore,
    B: BlobStore,
{
    let identity = required_identity(identity)?;
    let prefix = query.q.as_deref().unwrap_or("").to_lowercase();
    let n = query.n.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

    let repos = state.core.metadata.list_repository_summaries().await?;

    // Filter: only repos the actor can pull, excluding cross-user personal
    // namespaces. Match search prefix.
    let mut grantable: Vec<GrantableScope> = Vec::new();
    if let Some(auth) = state.auth.as_ref() {
        for repo in repos {
            if !prefix.is_empty() && !repo.name.to_lowercase().starts_with(&prefix) {
                continue;
            }
            if let Ok((action, source)) = auth
                .max_grantable_action(&identity, &repo.name, &state.core.metadata)
                .await
            {
                grantable.push(GrantableScope {
                    repository: repo.name,
                    max_grantable: action,
                    kind: Vec::new(),
                    grant_source: source,
                });
            }
        }
    }

    // Derive namespace patterns from the identity's scopes and group grants.
    let mut patterns: Vec<NamespacePatternScope> = Vec::new();
    let mut seen_patterns: BTreeMap<String, OciAction> = BTreeMap::new();

    // From PAT/bearer scopes.
    for (pattern_str, action) in permissions::derive_namespace_patterns(&identity.scopes, &prefix) {
        seen_patterns
            .entry(pattern_str)
            .and_modify(|existing| {
                if permissions::action_rank(action) > permissions::action_rank(*existing) {
                    *existing = action;
                }
            })
            .or_insert(action);
    }

    for (pattern_str, max_grantable) in seen_patterns {
        // Count matching repos for blast-radius display.
        let pattern_repo = pattern_str
            .strip_prefix("repository:")
            .unwrap_or(&pattern_str);
        let prefix_no_star = pattern_repo.strip_suffix("/*").unwrap_or(pattern_repo);
        let match_count = grantable
            .iter()
            .filter(|gs| {
                gs.repository == prefix_no_star
                    || gs.repository.starts_with(&format!("{prefix_no_star}/"))
            })
            .count() as u64;
        patterns.push(NamespacePatternScope {
            pattern: pattern_str,
            current_match_count: match_count,
            max_grantable,
            grant_source: GrantSource::GroupGrant,
        });
    }

    let total_matches = grantable.len() as u64;

    // Cursor-based pagination: cursor is the last repository name.
    let start = query
        .cursor
        .as_deref()
        .and_then(|c| grantable.iter().position(|gs| gs.repository == c))
        .map(|i| i + 1)
        .unwrap_or(0);
    let has_more = start + n < grantable.len();
    let page: Vec<GrantableScope> = grantable.into_iter().skip(start).take(n).collect();
    let next_cursor = if has_more {
        page.last().map(|gs| gs.repository.clone())
    } else {
        None
    };

    Ok(Json(GrantableScopeListResponse {
        scopes: page,
        namespace_patterns: patterns,
        total_matches,
        next_cursor,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::AuthIdentity;
    use crate::auth::token::TokenType;
    use crate::config::PermissionMapping;
    use crate::routes::test_state_with_auth;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::{InMemoryMetadataStore, ManifestEntry, ManifestStore};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    fn identity_with(scopes: Vec<&str>) -> AuthIdentity {
        AuthIdentity {
            subject: crate::auth::identity::Subject::new("user-1"),
            username: Some("alice".to_string()),
            display_name: None,
            email: None,
            groups: Vec::new(),
            scopes: scopes.into_iter().map(|s| s.to_string()).collect(),
            token_type: TokenType::PersonalAccess,
        }
    }

    fn identity_with_groups(scopes: Vec<&str>, groups: Vec<&str>) -> AuthIdentity {
        AuthIdentity {
            subject: crate::auth::identity::Subject::new("user-1"),
            username: Some("alice".to_string()),
            display_name: None,
            email: None,
            groups: groups.into_iter().map(|s| s.to_string()).collect(),
            scopes: scopes.into_iter().map(|s| s.to_string()).collect(),
            token_type: TokenType::OidcAccess,
        }
    }

    fn post_tokens(body: serde_json::Value, identity: Option<AuthIdentity>) -> Request<Body> {
        let mut req = Request::builder()
            .uri("/api/v1/tokens")
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(id) = identity {
            req.extensions_mut().insert(id);
        }
        req
    }

    fn get_grantable_scopes(query: &str, identity: Option<AuthIdentity>) -> Request<Body> {
        let mut req = Request::builder()
            .uri(format!("/api/v1/tokens/grantable-scopes?{query}"))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        if let Some(id) = identity {
            req.extensions_mut().insert(id);
        }
        req
    }

    fn manifest_entry(hex_suffix: u64) -> ManifestEntry {
        let digest =
            crate::oci::digest::Digest::from_str_checked(&format!("sha256:{hex_suffix:064x}"))
                .unwrap();
        ManifestEntry {
            digest,
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            body: b"{}".to_vec(),
            referenced_blobs: Vec::new(),
            subject: None,
            artifact_type: Some("application/vnd.oci.image.config.v1+json".to_string()),
            annotations: None,
            stored_size_bytes: 0,
            manifest_size_bytes: 2,
            created_at: 1_777_593_600,
            last_modified: 1_777_593_600,
            config_summary: None,
        }
    }

    // ── PAT creation: ceiling check ────────────────────────────────────

    #[tokio::test]
    async fn create_pat_rejects_scope_exceeding_grant_ceiling() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has pull+create on team-a/worker; tries to grant update.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["update"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:pull,create"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_pat_allows_exact_ceiling() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has pull+create; grants exactly create.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["create"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:pull,create"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_pat_allows_subset() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has delete (full ladder); grants only pull.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:*"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_pat_rejects_namespace_pattern_without_grant() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has exact repo scope but no namespace-pattern grant.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/*", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:pull"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_pat_allows_namespace_pattern_with_matching_grant() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has namespace-pattern scope in their own grants.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/*", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/*:pull,create"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_pat_allows_namespace_pattern_via_group_grant() {
        let state = test_state_with_auth(vec![PermissionMapping {
            name: "ci-team".to_string(),
            groups: vec!["ci".to_string()],
            scopes: vec!["repository:team-a/*:*".to_string()],
        }]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has no explicit scope but is in the `ci` group.
        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/*", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with_groups(Vec::new(), vec!["ci"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_pat_rejects_cross_user_personal_namespace() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "users/bob/app", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:*:*"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_pat_allows_own_personal_namespace() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "users/alice/app", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec![])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_pat_requires_authentication() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "my-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["pull"]}
                    ]
                }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_pat_rejects_empty_name() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "   ",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:*"])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── List tokens ────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_tokens_returns_empty_for_new_user() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let mut req = Request::builder()
            .uri("/api/v1/tokens")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(identity_with(vec!["repository:team-a/worker:pull"]));

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn list_tokens_requires_authentication() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let req = Request::builder()
            .uri("/api/v1/tokens")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_and_list_token_round_trip() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        // Create a token.
        let create_resp = app
            .clone()
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "ci-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:*"])),
            ))
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(create_resp.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(created["name"], "ci-token");
        assert!(
            created["token"]
                .as_str()
                .unwrap()
                .starts_with("layerhouse-")
        );
        assert!(!created["id"].as_str().unwrap().is_empty());

        // List tokens.
        let mut list_req = Request::builder()
            .uri("/api/v1/tokens")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        list_req
            .extensions_mut()
            .insert(identity_with(vec!["repository:team-a/worker:*"]));

        let list_resp = app.oneshot(list_req).await.unwrap();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let items: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(list_resp.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "ci-token");
    }

    #[tokio::test]
    async fn revoke_token_deletes_and_second_revoke_returns_404() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        // Create a token.
        let create_resp = app
            .clone()
            .oneshot(post_tokens(
                serde_json::json!({
                    "name": "tmp-token",
                    "scopes": [
                        {"repository": "team-a/worker", "actions": ["pull"]}
                    ]
                }),
                Some(identity_with(vec!["repository:team-a/worker:*"])),
            ))
            .await
            .unwrap();
        let body = axum::body::to_bytes(create_resp.into_body(), 4096)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_str().unwrap();

        // Revoke.
        let mut del_req = Request::builder()
            .uri(format!("/api/v1/tokens/{id}"))
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        del_req
            .extensions_mut()
            .insert(identity_with(vec!["repository:team-a/worker:*"]));
        let del_resp = app.clone().oneshot(del_req).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Second revoke → 404.
        let mut del_req2 = Request::builder()
            .uri(format!("/api/v1/tokens/{id}"))
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        del_req2
            .extensions_mut()
            .insert(identity_with(vec!["repository:team-a/worker:*"]));
        let del_resp2 = app.oneshot(del_req2).await.unwrap();
        assert_eq!(del_resp2.status(), StatusCode::NOT_FOUND);
    }

    // ── Grantable scopes ───────────────────────────────────────────────

    async fn seed_repos(
        state: &Arc<AppState<InMemoryMetadataStore, InMemoryBlobStore>>,
        repos: &[&str],
    ) {
        for name in repos {
            let tag = name.split('/').next_back().unwrap_or("latest");
            state
                .core
                .metadata
                .put_manifest(name, tag, manifest_entry(1))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn grantable_scopes_includes_personal_namespace_repos() {
        let state = test_state_with_auth(vec![]);
        seed_repos(&state, &["users/alice/app", "users/alice/backend"]).await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_grantable_scopes("q=users", Some(identity_with(vec![]))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos: Vec<&str> = data["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["repository"].as_str().unwrap())
            .collect();
        assert!(repos.contains(&"users/alice/app"));
        assert!(repos.contains(&"users/alice/backend"));
    }

    #[tokio::test]
    async fn grantable_scopes_excludes_cross_user_personal() {
        let state = test_state_with_auth(vec![]);
        seed_repos(
            &state,
            &["users/alice/app", "users/bob/app", "team-a/worker"],
        )
        .await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Search broadly to see all repos the actor can access.
        let response = app
            .oneshot(get_grantable_scopes(
                "",
                Some(identity_with(vec!["repository:team-a/worker:*"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos: Vec<&str> = data["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["repository"].as_str().unwrap())
            .collect();
        // Alice's own repos AND team-a/worker should appear.
        assert!(repos.contains(&"users/alice/app"));
        assert!(repos.contains(&"team-a/worker"));
        // Bob's repo must NOT appear.
        assert!(!repos.iter().any(|r| r.contains("bob")));
    }

    #[tokio::test]
    async fn grantable_scopes_includes_group_grant_repos() {
        let state = test_state_with_auth(vec![PermissionMapping {
            name: "ci-team".to_string(),
            groups: vec!["ci".to_string()],
            scopes: vec!["repository:team-a/*:pull,create".to_string()],
        }]);
        seed_repos(&state, &["team-a/worker", "team-a/frontend"]).await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_grantable_scopes(
                "q=team-a",
                Some(identity_with_groups(Vec::new(), vec!["ci"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos: Vec<&str> = data["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["repository"].as_str().unwrap())
            .collect();
        assert_eq!(repos.len(), 2);
        assert!(repos.contains(&"team-a/worker"));
        assert!(repos.contains(&"team-a/frontend"));
    }

    #[tokio::test]
    async fn grantable_scopes_derives_namespace_pattern() {
        let state = test_state_with_auth(vec![]);
        seed_repos(&state, &["team-a/worker", "team-a/frontend"]).await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_grantable_scopes(
                "q=team-a",
                Some(identity_with(vec!["repository:team-a/*:pull,create"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let patterns: Vec<&str> = data["namespace_patterns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["pattern"].as_str().unwrap())
            .collect();
        assert!(patterns.contains(&"repository:team-a/*"));
    }

    #[tokio::test]
    async fn grantable_scopes_respects_search_prefix() {
        let state = test_state_with_auth(vec![]);
        seed_repos(&state, &["team-a/worker", "team-a/frontend", "other/repo"]).await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_grantable_scopes(
                "q=team-a",
                Some(identity_with(vec!["repository:*:*"])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos: Vec<&str> = data["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["repository"].as_str().unwrap())
            .collect();
        assert_eq!(repos.len(), 2);
        assert!(!repos.contains(&"other/repo"));
    }

    #[tokio::test]
    async fn grantable_scopes_requires_authentication() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_grantable_scopes("q=team-a", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
