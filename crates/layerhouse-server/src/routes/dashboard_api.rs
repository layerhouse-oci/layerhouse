use std::cmp::Reverse;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::permissions::{self, GrantSource, OciAction};
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::raft::membership;
use crate::store::blob::BlobStore;
use crate::store::metadata::{
    AuthorizationStore, DeleteCounts, ManifestStore, ManifestSummary, NamespaceEpoch, Repository,
    RepositoryStore, Visibility,
};

use super::{AppState, percent_decode};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;

pub fn routes<M: ManifestStore + RepositoryStore + AuthorizationStore, B: BlobStore>()
-> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route(
            "/api/v1/repositories",
            get(list_repositories::<M, B>).post(create_repository::<M, B>),
        )
        .route(
            "/api/v1/repositories/{*path}",
            any(repository_dispatch::<M, B>),
        )
        // Non-admin read-only cluster status — authenticated but not admin-gated.
        // Lives outside /api/v1/admin/ so the middleware prefix check doesn't
        // require admin (delete on *).
        .route("/api/v1/cluster/status", get(cluster_status::<M, B>))
        // Admin-gated cluster management endpoints
        .route("/api/v1/admin/cluster/status", get(cluster_status::<M, B>))
        .route("/api/v1/admin/cluster/join", post(cluster_join::<M, B>))
        .route("/api/v1/admin/cluster/leave", post(cluster_leave::<M, B>))
        .route("/api/v1/admin/gc/status", get(gc_status::<M, B>))
        .route(
            "/api/v1/admin/cluster/members/{node_id}",
            delete(cluster_remove::<M, B>),
        )
}

#[derive(Debug, Deserialize)]
struct RepositoryQuery {
    n: Option<usize>,
    last: Option<String>,
    q: Option<String>,
    recency: Option<String>,
    sort: Option<String>,
    /// Ownership filter: `all` (default), `mine`, `shared`, `public`.
    #[serde(default)]
    filter: OwnershipFilter,
}

#[derive(Debug, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
enum OwnershipFilter {
    #[default]
    All,
    Mine,
    Shared,
    Public,
}

#[derive(Debug, Serialize)]
struct RepositoryListResponse {
    repositories: Vec<EnrichedRepositorySummary>,
    total_reachable: u64,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct EnrichedRepositorySummary {
    name: String,
    tag_count: usize,
    manifest_count: usize,
    stored_size_bytes: u64,
    manifest_size_bytes: u64,
    last_modified: u64,
    description: String,
    created_by: Option<crate::auth::identity::Subject>,
    visibility: Visibility,
    /// Maximum action the actor can perform on this repository.
    access_level: OciAction,
    /// Maximum action the actor could grant in a PAT for this repository.
    max_grantable: OciAction,
    grant_source: GrantSource,
}

#[derive(Debug, Deserialize)]
struct ManifestQuery {
    n: Option<usize>,
    last: Option<String>,
    q: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    tag: Option<String>,
    tagged: Option<bool>,
    platform: Option<String>,
    media_type: Option<String>,
    stored_size_min: Option<u64>,
    stored_size_max: Option<u64>,
    created_after: Option<String>,
    created_before: Option<String>,
    sort: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestListResponse {
    name: String,
    manifests: Vec<ManifestSummary>,
    total: usize,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct ManifestDetailResponse {
    digest: String,
    media_type: String,
    artifact_type: Option<String>,
    stored_size_bytes: u64,
    manifest_size_bytes: u64,
    created_at: u64,
    last_modified: u64,
    tags: Vec<String>,
    subject: Option<String>,
    annotations: Option<serde_json::Value>,
    config_summary: Option<serde_json::Value>,
    body: serde_json::Value,
    /// Where the actor's access to this repository came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_source: Option<GrantSource>,
    /// Maximum action the actor could grant in a PAT for this repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_grantable_action: Option<OciAction>,
}

#[derive(Debug, Deserialize)]
struct BatchDeleteRequest {
    digests: Vec<String>,
}

fn page_size(n: Option<usize>) -> usize {
    n.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
}

fn paginate<T, F>(items: Vec<T>, n: usize, last: Option<&str>, key: F) -> (Vec<T>, bool)
where
    F: Fn(&T) -> &str,
{
    let start = last
        .and_then(|last| items.iter().position(|item| key(item) == last))
        .map(|i| i + 1)
        .unwrap_or(0);
    let mut page: Vec<T> = items.into_iter().skip(start).take(n + 1).collect();
    let has_more = page.len() > n;
    if has_more {
        page.truncate(n);
    }
    (page, has_more)
}

fn with_link<T: Serialize>(
    body: T,
    has_more: bool,
    next_url: Option<String>,
) -> Result<Response, LayerhouseError> {
    let mut response = Json(body).into_response();
    if has_more && let Some(next_url) = next_url {
        let value = format!("<{}>; rel=\"next\"", next_url);
        let header_value = HeaderValue::from_str(&value)
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))?;
        response.headers_mut().insert(header::LINK, header_value);
    }
    Ok(response)
}

fn next_url(base: &str, n: usize, last: &str) -> String {
    format!("{}?n={}&last={}", base, n, last)
}

fn parse_query<T: for<'de> Deserialize<'de>>(uri: &Uri) -> Result<T, LayerhouseError> {
    Query::<T>::try_from_uri(uri)
        .map(|q| q.0)
        .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))
}

fn parse_rfc3339_epoch(value: &str, field: &str) -> Result<u64, LayerhouseError> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| LayerhouseError::NameInvalid(format!("{} is invalid: {}", field, e)))?
        .timestamp();
    u64::try_from(timestamp)
        .map_err(|_| LayerhouseError::NameInvalid(format!("{} must be after 1970-01-01", field)))
}

async fn repository_dispatch<
    M: ManifestStore + RepositoryStore + AuthorizationStore,
    B: BlobStore,
>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response {
    match repository_dispatch_result(state, path, req).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn repository_dispatch_result<
    M: ManifestStore + RepositoryStore + AuthorizationStore,
    B: BlobStore,
>(
    state: Arc<AppState<M, B>>,
    path: String,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = path.trim_end_matches('/');
    let parts: Vec<&str> = path.split('/').collect();

    let identity: Option<Extension<crate::auth::token::AuthIdentity>> = req
        .extensions()
        .get::<crate::auth::token::AuthIdentity>()
        .cloned()
        .map(Extension);

    if method == Method::POST && path.ends_with("/manifests:batch-delete") {
        let name = path
            .strip_suffix("/manifests:batch-delete")
            .unwrap_or(path)
            .to_string();
        let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
        let req: BatchDeleteRequest = serde_json::from_slice(&body)
            .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
        return batch_delete_manifests(State(state), identity, Path(name), Json(req))
            .await
            .map(IntoResponse::into_response);
    }

    if method == Method::PATCH && !parts.is_empty() && !parts.contains(&"manifests") {
        let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
        let req: PatchRepositoryRequest = serde_json::from_slice(&body)
            .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
        return patch_repository(State(state), identity, Path(path.to_string()), Json(req))
            .await
            .map(IntoResponse::into_response);
    }

    if method == Method::DELETE && !parts.is_empty() && !parts.contains(&"manifests") {
        return delete_repository(State(state), identity, Path(path.to_string()))
            .await
            .map(IntoResponse::into_response);
    }

    let Some(manifests_pos) = parts.iter().rposition(|part| *part == "manifests") else {
        return Err(LayerhouseError::NameUnknown(path.to_string()));
    };
    let name = parts[..manifests_pos].join("/");
    let tail = &parts[manifests_pos + 1..];

    // Dashboard repository reads were historically ungated (the middleware only
    // auth-checks `/v2/` and `/api/v1/admin/` paths). A direct GET to
    // `/api/v1/repositories/users/<name>/.../manifests` would leak private
    // manifests. Gate every dashboard repository GET on Pull access here, using
    // the same `check_permission` the OCI and admin paths use.
    if method == Method::GET
        && let (Some(auth), Some(Extension(identity))) = (state.auth.as_ref(), &identity)
    {
        auth.check_permission(
            identity,
            &name,
            crate::auth::permissions::OciAction::Pull,
            &state.core.metadata,
        )
        .await?;
    }

    match (method, tail) {
        (Method::GET, []) => {
            let query = parse_query::<ManifestQuery>(&uri)?;
            list_manifests(State(state), Path(name), Query(query))
                .await
                .map(IntoResponse::into_response)
        }
        (Method::GET, [digest]) => get_manifest(
            State(state),
            Path((name, (*digest).to_string())),
            identity.clone(),
        )
        .await
        .map(IntoResponse::into_response),
        (Method::DELETE, [digest]) => delete_manifest(
            State(state),
            identity.clone(),
            Path((name, (*digest).to_string())),
        )
        .await
        .map(IntoResponse::into_response),
        (Method::GET, [digest, "raw"]) => {
            get_raw_manifest(State(state), Path((name, (*digest).to_string())))
                .await
                .map(IntoResponse::into_response)
        }
        (Method::DELETE, [digest, "tags", tag]) => delete_tag(
            State(state),
            identity.clone(),
            Path((name, (*digest).to_string(), percent_decode(tag))),
        )
        .await
        .map(IntoResponse::into_response),
        _ => Err(LayerhouseError::Unsupported(
            "method not allowed".to_string(),
        )),
    }
}

async fn list_repositories<M: ManifestStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Query(query): Query<RepositoryQuery>,
) -> Result<Response, LayerhouseError> {
    let repos = state.core.metadata.list_repository_summaries().await?;

    // Compute enriched summaries: for each repo the actor can pull, record the
    // access level, maximum grantable action, and grant source.
    let mut enriched: Vec<EnrichedRepositorySummary> = Vec::new();
    if let (Some(auth), Some(Extension(identity))) = (state.auth.as_ref(), &identity) {
        for repo in repos {
            if let Ok((action, source)) = auth
                .max_grantable_action(identity, &repo.name, &state.core.metadata)
                .await
            {
                enriched.push(EnrichedRepositorySummary {
                    name: repo.name,
                    tag_count: repo.tag_count,
                    manifest_count: repo.manifest_count,
                    stored_size_bytes: repo.stored_size_bytes,
                    manifest_size_bytes: repo.manifest_size_bytes,
                    last_modified: repo.last_modified,
                    description: repo.description,
                    created_by: repo.created_by,
                    visibility: repo.visibility,
                    access_level: action,
                    max_grantable: action,
                    grant_source: source,
                });
            }
        }
    } else {
        // Auth-disabled mode: everything is visible, source is public.
        for repo in repos {
            enriched.push(EnrichedRepositorySummary {
                name: repo.name,
                tag_count: repo.tag_count,
                manifest_count: repo.manifest_count,
                stored_size_bytes: repo.stored_size_bytes,
                manifest_size_bytes: repo.manifest_size_bytes,
                last_modified: repo.last_modified,
                description: repo.description,
                created_by: repo.created_by,
                visibility: repo.visibility,
                access_level: OciAction::Delete,
                max_grantable: OciAction::Delete,
                grant_source: GrantSource::Public,
            });
        }
    }

    // Ownership filter.
    if query.filter != OwnershipFilter::All
        && let Some(Extension(ref identity)) = identity
    {
        let username = identity.username.as_deref().unwrap_or("");
        enriched.retain(|repo| match query.filter {
            OwnershipFilter::Mine => permissions::in_personal_namespace(Some(username), &repo.name),
            OwnershipFilter::Shared => {
                !permissions::in_personal_namespace(Some(username), &repo.name)
            }
            OwnershipFilter::Public => repo.visibility == Visibility::PublicPull,
            OwnershipFilter::All => true,
        });
    }

    let q = query.q.unwrap_or_default().to_lowercase();
    if !q.is_empty() {
        enriched.retain(|repo| repo.name.to_lowercase().contains(&q));
    }

    let now = crate::store::metadata::now_epoch();
    match query.recency.as_deref() {
        Some("recent") => {
            enriched.retain(|repo| now.saturating_sub(repo.last_modified) <= 7 * 86_400)
        }
        Some("stale") => {
            enriched.retain(|repo| now.saturating_sub(repo.last_modified) >= 30 * 86_400)
        }
        _ => {}
    }

    match query.sort.as_deref().unwrap_or("updated_desc") {
        "name_asc" => enriched.sort_by(|a, b| a.name.cmp(&b.name)),
        "tag_count_desc" => enriched.sort_by(|a, b| {
            b.tag_count
                .cmp(&a.tag_count)
                .then_with(|| a.name.cmp(&b.name))
        }),
        "updated_asc" => enriched.sort_by(|a, b| {
            a.last_modified
                .cmp(&b.last_modified)
                .then_with(|| a.name.cmp(&b.name))
        }),
        _ => enriched.sort_by(|a, b| {
            b.last_modified
                .cmp(&a.last_modified)
                .then_with(|| a.name.cmp(&b.name))
        }),
    }

    let total_reachable = enriched.len() as u64;
    let n = page_size(query.n);
    let (page, has_more) = paginate(enriched, n, query.last.as_deref(), |repo| {
        repo.name.as_str()
    });
    let next = page
        .last()
        .map(|repo| next_url("/api/v1/repositories", n, &repo.name));
    with_link(
        RepositoryListResponse {
            repositories: page,
            total_reachable,
            next_cursor: next.clone(),
        },
        has_more,
        next,
    )
}

#[derive(Debug, Deserialize)]
struct CreateRepositoryRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    visibility: Visibility,
}

#[derive(Debug, Deserialize)]
struct PatchRepositoryRequest {
    description: Option<String>,
    visibility: Option<Visibility>,
}

/// Create a first-class ("shadow") repository that can exist before any blob is
/// pushed. Requires `Create` permission on the target path; the personal
/// namespace (`users/<username>/*`) grants this implicitly. The caller subject
/// is recorded as `created_by`.
async fn create_repository<
    M: ManifestStore + RepositoryStore + AuthorizationStore,
    B: BlobStore,
>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Json(req): Json<CreateRepositoryRequest>,
) -> Result<Response, LayerhouseError> {
    let name = req.name.trim().to_string();
    validate_repository_name(&name)?;

    let mut expected_namespace = None;
    let created_by = if let Some(auth) = state.auth.as_ref() {
        let Some(Extension(identity)) = identity else {
            return Err(LayerhouseError::Unauthorized {
                message: "authentication required".to_string(),
                realm: None,
                service: None,
                scope: None,
            });
        };
        expected_namespace = auth
            .check_permission(
                &identity,
                &name,
                crate::auth::permissions::OciAction::Create,
                &state.core.metadata,
            )
            .await?
            .expected_namespace;
        Some(identity.subject.clone())
    } else {
        None
    };

    if state.core.metadata.get_repository(&name).await?.is_some() {
        return Err(LayerhouseError::Conflict(format!(
            "repository already exists: {}",
            name
        )));
    }

    let repo = Repository {
        name: name.clone(),
        description: req.description.trim().to_string(),
        created_by,
        visibility: req.visibility,
        created_at: crate::store::metadata::now_epoch(),
    };
    if state.auth.is_some() {
        state
            .core
            .metadata
            .put_repository_with_expected_namespace(repo.clone(), expected_namespace)
            .await?;
    } else {
        state.core.metadata.put_repository(repo.clone()).await?;
    }

    Ok((StatusCode::CREATED, Json(repo)).into_response())
}

async fn require_update_permission(
    auth: &Option<Arc<crate::auth::AuthService>>,
    identity: Option<&Extension<crate::auth::token::AuthIdentity>>,
    name: &str,
    namespaces: &dyn AuthorizationStore,
) -> Result<Option<NamespaceEpoch>, LayerhouseError> {
    let Some(auth) = auth.as_ref() else {
        return Ok(None);
    };
    let Some(Extension(identity)) = identity else {
        return Err(LayerhouseError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    };
    Ok(auth
        .check_permission(identity, name, OciAction::Update, namespaces)
        .await?
        .expected_namespace)
}

async fn patch_repository<M: ManifestStore + RepositoryStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path(name): Path<String>,
    Json(req): Json<PatchRepositoryRequest>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    validate_repository_name(&name)?;

    let expected_namespace =
        require_update_permission(&state.auth, identity.as_ref(), &name, &state.core.metadata)
            .await?;

    let mut repo = state
        .core
        .metadata
        .get_repository(&name)
        .await?
        .ok_or_else(|| LayerhouseError::NameUnknown(name.clone()))?;

    if let Some(description) = req.description {
        repo.description = description.trim().to_string();
    }
    if let Some(visibility) = req.visibility {
        repo.visibility = visibility;
    }

    if state.auth.is_some() {
        state
            .core
            .metadata
            .put_repository_with_expected_namespace(repo.clone(), expected_namespace)
            .await?;
    } else {
        state.core.metadata.put_repository(repo.clone()).await?;
    }

    Ok(Json(repo))
}

async fn require_delete_permission(
    auth: &Option<Arc<crate::auth::AuthService>>,
    identity: Option<&Extension<crate::auth::token::AuthIdentity>>,
    name: &str,
    namespaces: &dyn AuthorizationStore,
) -> Result<Option<NamespaceEpoch>, LayerhouseError> {
    let Some(auth) = auth.as_ref() else {
        return Ok(None);
    };
    let Some(Extension(identity)) = identity else {
        return Err(LayerhouseError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    };
    Ok(auth
        .check_permission(
            identity,
            name,
            crate::auth::permissions::OciAction::Delete,
            namespaces,
        )
        .await?
        .expected_namespace)
}

/// Validate an OCI repository name against the Distribution Spec grammar:
/// lowercase path components separated by `/`, each component matching
/// `[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*`.
fn validate_repository_name(name: &str) -> Result<(), LayerhouseError> {
    if name.is_empty() {
        return Err(LayerhouseError::NameInvalid(
            "repository name is required".to_string(),
        ));
    }
    if name.len() > 255 {
        return Err(LayerhouseError::NameInvalid(
            "repository name exceeds 255 characters".to_string(),
        ));
    }
    for component in name.split('/') {
        if !is_valid_name_component(component) {
            return Err(LayerhouseError::NameInvalid(format!(
                "invalid repository name component: {}",
                component
            )));
        }
    }
    Ok(())
}

fn is_valid_name_component(component: &str) -> bool {
    if component.is_empty() {
        return false;
    }
    let bytes = component.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    // Must start and end with an alphanumeric.
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    // Between alphanumerics, the only valid separator runs are `.`, `_`, `__`,
    // or one-or-more `-`. Any other run (e.g. `..`, `_._`, `_-`) is invalid.
    let mut i = 0;
    while i < bytes.len() {
        if is_alnum(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !is_alnum(bytes[i]) {
            i += 1;
        }
        let run = &component[start..i];
        let valid = run == "." || run == "_" || run == "__" || run.bytes().all(|b| b == b'-');
        if !valid {
            return false;
        }
    }
    true
}

fn type_matches(item: &ManifestSummary, kind: &str) -> bool {
    let artifact_type = item.artifact_type.as_deref().unwrap_or("");
    let is_image = artifact_type.contains("image.config");
    let is_helm = artifact_type.contains("helm.config");
    let is_wasm = artifact_type.contains("wasm.config");
    let is_oci_artifact = artifact_type.contains("artifact.manifest")
        || item.media_type.contains("artifact.manifest");
    match kind {
        "image" => is_image,
        "helm" => is_helm,
        "wasm" => is_wasm,
        "artifact" => is_oci_artifact,
        "unknown" => !is_image && !is_helm && !is_wasm && !is_oci_artifact,
        _ => true,
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let mut rest = value;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }
    if anchored_start && !value.starts_with(parts[0]) {
        return false;
    }
    for part in &parts {
        let Some(idx) = rest.find(part) else {
            return false;
        };
        rest = &rest[idx + part.len()..];
    }
    if anchored_end && let Some(last) = parts.last() {
        return value.ends_with(last);
    }
    true
}

fn search_blob(item: &ManifestSummary) -> String {
    let mut values = vec![
        item.digest.clone(),
        item.media_type.clone(),
        item.artifact_type.clone().unwrap_or_default(),
        item.tags.join(" "),
    ];
    if let Some(summary) = &item.config_summary {
        values.push(summary.to_string());
    }
    if let Some(annotations) = &item.annotations {
        values.push(annotations.to_string());
    }
    values.join(" ").to_lowercase()
}

async fn list_manifests<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(name): Path<String>,
    Query(query): Query<ManifestQuery>,
) -> Result<Response, LayerhouseError> {
    let name = percent_decode(&name);
    let mut manifests = state.core.metadata.list_manifest_summaries(&name).await?;
    let q = query.q.unwrap_or_default().to_lowercase();
    if !q.is_empty() {
        manifests.retain(|item| search_blob(item).contains(&q));
    }
    if let Some(kind) = query.kind.as_deref()
        && kind != "all"
    {
        manifests.retain(|item| type_matches(item, kind));
    }
    if let Some(tagged) = query.tagged {
        manifests.retain(|item| item.tags.is_empty() != tagged);
    }
    if let Some(pattern) = query.tag.as_deref()
        && !pattern.is_empty()
    {
        manifests.retain(|item| item.tags.iter().any(|tag| glob_matches(pattern, tag)));
    }
    if let Some(media_type) = query.media_type.as_deref() {
        manifests.retain(|item| {
            item.artifact_type.as_deref() == Some(media_type) || item.media_type == media_type
        });
    }
    if let Some(platform) = query.platform.as_deref() {
        manifests.retain(|item| search_blob(item).contains(&platform.to_lowercase()));
    }
    if let Some(min) = query.stored_size_min {
        manifests.retain(|item| item.stored_size_bytes >= min);
    }
    if let Some(max) = query.stored_size_max {
        manifests.retain(|item| item.stored_size_bytes <= max);
    }
    if let Some(created_after) = query.created_after.as_deref() {
        let lower = parse_rfc3339_epoch(created_after, "created_after")?;
        manifests.retain(|item| item.created_at >= lower);
    }
    if let Some(created_before) = query.created_before.as_deref() {
        let upper = parse_rfc3339_epoch(created_before, "created_before")?;
        manifests.retain(|item| item.created_at <= upper);
    }

    match query.sort.as_deref().unwrap_or("updated_desc") {
        "updated_asc" => manifests.sort_by_key(|item| item.last_modified),
        "stored_size_desc" => manifests.sort_by_key(|item| Reverse(item.stored_size_bytes)),
        "stored_size_asc" => manifests.sort_by_key(|item| item.stored_size_bytes),
        "digest_asc" => manifests.sort_by(|a, b| a.digest.cmp(&b.digest)),
        "tag_count_desc" => manifests.sort_by_key(|item| Reverse(item.tags.len())),
        _ => manifests.sort_by_key(|item| Reverse(item.last_modified)),
    }

    let total = manifests.len();
    let n = page_size(query.n);
    let (page, has_more) = paginate(manifests, n, query.last.as_deref(), |item| {
        item.digest.as_str()
    });
    let next = page.last().map(|item| {
        next_url(
            &format!("/api/v1/repositories/{}/manifests", name),
            n,
            &item.digest,
        )
    });
    with_link(
        ManifestListResponse {
            name,
            manifests: page,
            total,
            has_more,
        },
        has_more,
        next,
    )
}

async fn get_manifest<M: ManifestStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path((name, digest)): Path<(String, String)>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let manifest = state
        .core
        .metadata
        .list_manifest_summaries(&name)
        .await?
        .into_iter()
        .find(|item| item.digest == digest)
        .ok_or_else(|| LayerhouseError::ManifestUnknown(digest.clone()))?;

    let (access_source, max_grantable_action) =
        if let (Some(auth), Some(Extension(identity))) = (state.auth.as_ref(), &identity) {
            match auth
                .max_grantable_action(identity, &name, &state.core.metadata)
                .await
            {
                Ok((action, source)) => (Some(source), Some(action)),
                Err(_) => (None, None),
            }
        } else {
            (Some(GrantSource::Public), Some(OciAction::Delete))
        };

    Ok(Json(ManifestDetailResponse {
        digest: manifest.digest,
        media_type: manifest.media_type,
        artifact_type: manifest.artifact_type,
        stored_size_bytes: manifest.stored_size_bytes,
        manifest_size_bytes: manifest.manifest_size_bytes,
        created_at: manifest.created_at,
        last_modified: manifest.last_modified,
        tags: manifest.tags,
        subject: manifest.subject,
        annotations: manifest.annotations,
        config_summary: manifest.config_summary,
        body: manifest.body,
        access_source,
        max_grantable_action,
    }))
}

async fn get_raw_manifest<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path((name, digest)): Path<(String, String)>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let entry = state
        .core
        .metadata
        .get_manifest(&name, &digest)
        .await?
        .ok_or_else(|| LayerhouseError::ManifestUnknown(digest.clone()))?;
    let body: serde_json::Value = serde_json::from_slice(&entry.body)
        .map_err(|e| LayerhouseError::Serialization(e.to_string()))?;
    Ok(Json(body))
}

async fn delete_tag<M: ManifestStore + RepositoryStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path((name, digest, tag)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let expected_namespace =
        require_delete_permission(&state.auth, identity.as_ref(), &name, &state.core.metadata)
            .await?;
    let digest = Digest::from_str_checked(&digest)
        .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))?;
    let deleted = if state.auth.is_some() {
        state
            .core
            .metadata
            .delete_tag_with_expected_namespace(&name, &digest, &tag, expected_namespace)
            .await?
    } else {
        state.core.metadata.delete_tag(&name, &digest, &tag).await?
    };
    if !deleted {
        return Err(LayerhouseError::NameUnknown(tag));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_manifest<M: ManifestStore + RepositoryStore + AuthorizationStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path((name, digest)): Path<(String, String)>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let expected_namespace =
        require_delete_permission(&state.auth, identity.as_ref(), &name, &state.core.metadata)
            .await?;
    let digest = Digest::from_str_checked(&digest)
        .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))?;
    let counts = if state.auth.is_some() {
        state
            .core
            .metadata
            .delete_manifests_with_expected_namespace(&name, &[digest], expected_namespace)
            .await?
    } else {
        state
            .core
            .metadata
            .delete_manifests(&name, &[digest])
            .await?
    };
    Ok(Json(counts))
}

async fn batch_delete_manifests<
    M: ManifestStore + RepositoryStore + AuthorizationStore,
    B: BlobStore,
>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path(name): Path<String>,
    Json(req): Json<BatchDeleteRequest>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let expected_namespace =
        require_delete_permission(&state.auth, identity.as_ref(), &name, &state.core.metadata)
            .await?;
    let digests: Result<Vec<_>, _> = req
        .digests
        .iter()
        .map(|digest| {
            Digest::from_str_checked(digest)
                .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))
        })
        .collect();
    let digests = digests?;
    let counts = if state.auth.is_some() {
        state
            .core
            .metadata
            .delete_manifests_with_expected_namespace(&name, &digests, expected_namespace)
            .await?
    } else {
        state
            .core
            .metadata
            .delete_manifests(&name, &digests)
            .await?
    };
    Ok(Json(counts))
}

async fn delete_repository<
    M: ManifestStore + RepositoryStore + AuthorizationStore,
    B: BlobStore,
>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<crate::auth::token::AuthIdentity>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let expected_namespace =
        require_delete_permission(&state.auth, identity.as_ref(), &name, &state.core.metadata)
            .await?;
    let counts: DeleteCounts = if state.auth.is_some() {
        state
            .core
            .metadata
            .delete_repository_with_expected_namespace(&name, expected_namespace.clone())
            .await?
    } else {
        state.core.metadata.delete_repository(&name).await?
    };
    // Also drop any first-class repository metadata so a deleted repo does not
    // linger as an empty shadow entry.
    if state.auth.is_some() {
        state
            .core
            .metadata
            .delete_repository_meta_with_expected_namespace(&name, expected_namespace)
            .await?;
    } else {
        state.core.metadata.delete_repository_meta(&name).await?;
    }
    Ok(Json(counts))
}

#[derive(Debug, Serialize)]
struct ClusterMember {
    node_id: u64,
    address: String,
    role: String,
    status: String,
    commit_index: Option<u64>,
    replication_lag_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DashboardClusterStatus {
    cluster_id: String,
    leader_id: Option<u64>,
    term: u64,
    quorum: usize,
    healthy_voters: usize,
    updated_at: u64,
    voters: Vec<ClusterMember>,
    learners: Vec<ClusterMember>,
}

fn dashboard_status_from_raw(raw: membership::ClusterStatus) -> DashboardClusterStatus {
    let quorum = raw.voters.len() / 2 + 1;
    let local_commit_index = raw.last_applied_log;
    let voters: Vec<ClusterMember> = raw
        .voters
        .iter()
        .map(|node| ClusterMember {
            node_id: node.id,
            address: node.addr.clone(),
            role: if raw.leader_id == Some(node.id) {
                "leader".to_string()
            } else {
                "voter".to_string()
            },
            status: if raw.leader_id == Some(node.id)
                || raw
                    .replication
                    .get(&node.id)
                    .is_some_and(|matching| *matching == raw.last_applied_log)
            {
                "healthy".to_string()
            } else {
                "lagging".to_string()
            },
            commit_index: if raw.leader_id == Some(node.id) {
                local_commit_index
            } else {
                raw.replication
                    .get(&node.id)
                    .and_then(|matching| *matching)
                    .or(local_commit_index)
            },
            replication_lag_ms: if raw.leader_id == Some(node.id) {
                Some(0)
            } else if let (Some(last), Some(matching)) = (
                raw.last_applied_log,
                raw.replication.get(&node.id).and_then(|m| *m),
            ) {
                Some(last.saturating_sub(matching))
            } else {
                None
            },
        })
        .collect();
    let learners = raw
        .learners
        .iter()
        .map(|node| ClusterMember {
            node_id: node.id,
            address: node.addr.clone(),
            role: "learner".to_string(),
            status: "healthy".to_string(),
            commit_index: local_commit_index,
            replication_lag_ms: None,
        })
        .collect();

    DashboardClusterStatus {
        cluster_id: format!("layerhouse-{}", raw.node_id),
        leader_id: raw.leader_id,
        term: raw.term,
        quorum,
        healthy_voters: voters.iter().filter(|v| v.status == "healthy").count(),
        updated_at: crate::store::metadata::now_epoch(),
        voters,
        learners,
    }
}

async fn raw_cluster_status(
    raft: &crate::raft::RaftInstance,
    tls: Option<&crate::config::RaftTlsConfig>,
) -> Result<membership::ClusterStatus, LayerhouseError> {
    let local = membership::build_cluster_status(raft);
    if local.state == membership::NodeState::Leader || local.leader_addr.is_none() {
        return Ok(local);
    }

    let leader_addr = local.leader_addr.as_deref().unwrap_or_default();
    membership::get_status(leader_addr, tls)
        .await
        .map_err(|e| LayerhouseError::Consensus(e.to_string()))
}

async fn cluster_status<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let raft = state
        .raft
        .as_ref()
        .ok_or_else(|| LayerhouseError::Serialization("raft not available".to_string()))?;
    Ok(Json(dashboard_status_from_raw(
        raw_cluster_status(raft, state.raft_tls.as_deref()).await?,
    )))
}

async fn gc_status<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    Ok(Json(state.gc_status.read().await.clone()))
}

async fn cluster_join<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Json(req): Json<membership::JoinRequest>,
) -> Result<Response, LayerhouseError> {
    let raft = state
        .raft
        .as_ref()
        .ok_or_else(|| LayerhouseError::Serialization("raft not available".to_string()))?;
    let response = membership::handle_join(State(raft.clone()), Json(req)).await;
    if response.status().is_success() {
        Ok(Json(dashboard_status_from_raw(
            raw_cluster_status(raft, state.raft_tls.as_deref()).await?,
        ))
        .into_response())
    } else {
        Ok(response)
    }
}

async fn cluster_leave<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<Response, LayerhouseError> {
    let raft = state
        .raft
        .as_ref()
        .ok_or_else(|| LayerhouseError::Serialization("raft not available".to_string()))?;
    let node_id = raft.metrics().borrow().id;
    let response = membership::handle_leave(
        State(raft.clone()),
        Json(membership::LeaveRequest { node_id }),
    )
    .await;
    if response.status().is_success() {
        Ok(Json(dashboard_status_from_raw(
            raw_cluster_status(raft, state.raft_tls.as_deref()).await?,
        ))
        .into_response())
    } else {
        Ok(response)
    }
}

async fn cluster_remove<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(node_id): Path<u64>,
) -> Result<Response, LayerhouseError> {
    let raft = state
        .raft
        .as_ref()
        .ok_or_else(|| LayerhouseError::Serialization("raft not available".to_string()))?;
    let response = membership::handle_leave(
        State(raft.clone()),
        Json(membership::LeaveRequest { node_id }),
    )
    .await;
    if response.status().is_success() {
        Ok(Json(dashboard_status_from_raw(
            raw_cluster_status(raft, state.raft_tls.as_deref()).await?,
        ))
        .into_response())
    } else {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Subject;
    use crate::auth::token::AuthIdentity;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::{InMemoryMetadataStore, ManifestEntry, ManifestStore};
    use axum::body::Body;

    use tower::ServiceExt;

    fn manifest_summary(artifact_type: Option<&str>, media_type: &str) -> ManifestSummary {
        ManifestSummary {
            digest: "sha256:abc".to_string(),
            media_type: media_type.to_string(),
            artifact_type: artifact_type.map(ToString::to_string),
            stored_size_bytes: 1,
            manifest_size_bytes: 2,
            created_at: 1,
            last_modified: 1,
            tags: vec!["latest".to_string()],
            subject: None,
            annotations: None,
            config_summary: None,
            body: serde_json::Value::Null,
        }
    }

    #[test]
    fn manifest_type_filter_uses_artifact_kind_not_manifest_envelope() {
        let image = manifest_summary(
            Some("application/vnd.oci.image.config.v1+json"),
            "application/vnd.oci.image.manifest.v1+json",
        );
        let helm = manifest_summary(
            Some("application/vnd.cncf.helm.config.v1+json"),
            "application/vnd.oci.image.manifest.v1+json",
        );
        let wasm = manifest_summary(
            Some("application/vnd.module.wasm.config.v1+json"),
            "application/vnd.oci.image.manifest.v1+json",
        );
        let unknown = manifest_summary(
            Some("application/vnd.example.unknown.config.v1+json"),
            "application/vnd.oci.image.manifest.v1+json",
        );

        assert!(type_matches(&image, "image"));
        assert!(!type_matches(&helm, "image"));
        assert!(type_matches(&helm, "helm"));
        assert!(type_matches(&wasm, "wasm"));
        assert!(type_matches(&unknown, "unknown"));
        assert!(!type_matches(&unknown, "artifact"));
    }

    #[test]
    fn manifest_search_includes_annotations() {
        let mut item = manifest_summary(
            Some("application/vnd.module.wasm.config.v1+json"),
            "application/vnd.oci.image.manifest.v1+json",
        );
        item.annotations = Some(serde_json::json!({
            "module": "edge-filter",
            "runtime": "wasi"
        }));

        assert!(search_blob(&item).contains("edge-filter"));
    }

    #[test]
    fn parses_rfc3339_manifest_filter_bounds() {
        assert_eq!(
            parse_rfc3339_epoch("2026-05-01T00:00:00Z", "created_after").unwrap(),
            1_777_593_600
        );
        assert!(parse_rfc3339_epoch("not-a-date", "created_after").is_err());
        assert!(parse_rfc3339_epoch("1969-12-31T23:59:59Z", "created_after").is_err());
    }

    use crate::routes::test_state;

    fn manifest_entry(hex_suffix: u64, created_at: u64) -> ManifestEntry {
        let digest = Digest::from_str_checked(&format!("sha256:{hex_suffix:064x}")).unwrap();
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
            created_at,
            last_modified: created_at,
            config_summary: None,
        }
    }

    fn descriptor_digest(id: u64) -> String {
        format!("sha256:{id:064x}")
    }

    fn sized_manifest(config_id: u64, layer_id: u64, layer_size: u64) -> ManifestEntry {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": descriptor_digest(config_id),
                "size": 2
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": descriptor_digest(layer_id),
                    "size": layer_size
                }
            ]
        })
        .to_string()
        .into_bytes();
        let parsed = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        let referenced_blobs = crate::oci::manifest::extract_referenced_digests(&parsed);
        ManifestEntry::from_parsed_json(
            &parsed,
            "application/vnd.oci.image.manifest.v1+json".to_string(),
            body,
            referenced_blobs,
        )
    }

    #[tokio::test]
    async fn repository_dashboard_api_returns_explicit_size_fields() {
        let state = test_state();
        let small = sized_manifest(1, 2, 4);
        let large = sized_manifest(1, 3, 8);
        let expected_manifest_size = small.manifest_size_bytes + large.manifest_size_bytes;

        state
            .core
            .metadata
            .put_manifest("repo/size", "small", small)
            .await
            .unwrap();
        state
            .core
            .metadata
            .put_manifest("repo/size", "large", large)
            .await
            .unwrap();

        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/repositories?q=repo/size")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repo = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|repo| repo["name"].as_str() == Some("repo/size"))
            .unwrap();
        assert_eq!(repo["stored_size_bytes"].as_u64(), Some(14));
        assert_eq!(
            repo["manifest_size_bytes"].as_u64(),
            Some(expected_manifest_size)
        );
        assert!(repo.get("size_bytes").is_none());

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/repositories/repo/size/manifests?sort=stored_size_asc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let manifests = data["manifests"].as_array().unwrap();
        let stored_sizes: Vec<u64> = manifests
            .iter()
            .map(|manifest| manifest["stored_size_bytes"].as_u64().unwrap())
            .collect();
        assert_eq!(stored_sizes, vec![6, 10]);
        assert!(
            manifests
                .iter()
                .all(|manifest| manifest["manifest_size_bytes"].as_u64().unwrap() > 0)
        );
        assert!(
            manifests
                .iter()
                .all(|manifest| manifest.get("size_bytes").is_none())
        );
    }

    #[tokio::test]
    async fn manifest_created_date_filters_apply_to_digest_rows() {
        let state = test_state();
        state
            .core
            .metadata
            .put_manifest("repo/date-filter", "old", manifest_entry(1, 1_777_507_200))
            .await
            .unwrap();
        state
            .core
            .metadata
            .put_manifest(
                "repo/date-filter",
                "inside",
                manifest_entry(2, 1_777_680_000),
            )
            .await
            .unwrap();
        state
            .core
            .metadata
            .put_manifest(
                "repo/date-filter",
                "future",
                manifest_entry(3, 1_777_852_800),
            )
            .await
            .unwrap();

        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(
                        "/api/v1/repositories/repo/date-filter/manifests?created_after=2026-05-01T00:00:00Z&created_before=2026-05-03T00:00:00Z",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: ManifestListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(data.total, 1);
        assert_eq!(
            data.manifests[0].digest,
            "sha256:0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(data.manifests[0].tags, vec!["inside"]);
    }

    #[test]
    fn validates_repository_names() {
        assert!(validate_repository_name("team-a/app").is_ok());
        assert!(validate_repository_name("users/alice/my_app").is_ok());
        assert!(validate_repository_name("a/b/c.d/e__f").is_ok());
        assert!(validate_repository_name("library/ubuntu").is_ok());

        assert!(validate_repository_name("").is_err());
        assert!(validate_repository_name("Team-A/app").is_err()); // uppercase
        assert!(validate_repository_name("team-a/").is_err()); // empty component
        assert!(validate_repository_name("/team-a").is_err());
        assert!(validate_repository_name("team-a//app").is_err());
        assert!(validate_repository_name(".app").is_err()); // leading separator
        assert!(validate_repository_name("app.").is_err()); // trailing separator
        assert!(validate_repository_name("a..b").is_err()); // double dot
        assert!(validate_repository_name("a___b").is_err()); // triple underscore
    }

    use crate::routes::test_state_with_auth;

    fn post_repository(body: serde_json::Value, identity: Option<AuthIdentity>) -> Request<Body> {
        let mut req = Request::builder()
            .uri("/api/v1/repositories")
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(identity) = identity {
            req.extensions_mut().insert(identity);
        }
        req
    }

    fn patch_repository_request(
        name: &str,
        body: serde_json::Value,
        identity: Option<AuthIdentity>,
    ) -> Request<Body> {
        let mut req = Request::builder()
            .uri(format!("/api/v1/repositories/{name}"))
            .method(Method::PATCH)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(identity) = identity {
            req.extensions_mut().insert(identity);
        }
        req
    }

    fn scoped_identity(scopes: Vec<String>) -> AuthIdentity {
        let scope_refs = scopes.iter().map(String::as_str).collect::<Vec<_>>();
        let mut identity = AuthIdentity::for_test(
            "user-1",
            crate::auth::token::TokenType::PersonalAccess,
            &[],
            &scope_refs,
        );
        identity.username = Some("alice".to_string());
        identity
    }

    fn session_identity() -> AuthIdentity {
        let mut identity = AuthIdentity::for_test(
            "user-1",
            crate::auth::token::TokenType::OidcAccess,
            &[],
            &[],
        );
        identity.username = Some("alice".to_string());
        identity
    }

    fn grouped_identity(groups: Vec<&str>) -> AuthIdentity {
        let mut identity = AuthIdentity::for_test(
            "user-1",
            crate::auth::token::TokenType::OidcAccess,
            &groups,
            &[],
        );
        identity.username = Some("alice".to_string());
        identity
    }

    fn team_worker_grant() -> crate::config::ConfigPolicySet {
        crate::config::ConfigPolicySet {
            id: "team-worker".to_string(),
            name: "team-worker".to_string(),
            enabled: true,
            cedar_text: r#"permit(
    principal in Group::"test:group:550e8400-e29b-41d4-a716-446655440040",
    action == Action::"pull",
    resource == Repository::"team-a/worker"
);"#
            .to_string(),
        }
    }

    #[tokio::test]
    async fn create_repository_in_personal_namespace_succeeds() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let response = app
            .oneshot(post_repository(
                serde_json::json!({
                    "name": "users/alice/app",
                    "description": "my app",
                    "visibility": "public_pull"
                }),
                Some(session_identity()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["name"], "users/alice/app");
        assert_eq!(data["description"], "my app");
        assert_eq!(data["created_by"], "user-1");
        assert_eq!(data["visibility"], "public_pull");

        // The shadow repo shows up in the listing even with no pushed content.
        let stored = state
            .core
            .metadata
            .get_repository("users/alice/app")
            .await
            .unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn create_repository_denied_without_create_grant() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_repository(
                serde_json::json!({ "name": "team-a/app" }),
                Some(scoped_identity(vec![
                    "repository:team-a/app:pull".to_string(),
                ])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_repository_conflict_when_exists() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let first = app
            .clone()
            .oneshot(post_repository(
                serde_json::json!({ "name": "users/alice/app" }),
                Some(session_identity()),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(post_repository(
                serde_json::json!({ "name": "users/alice/app" }),
                Some(session_identity()),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_repository_requires_identity_when_auth_enabled() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(post_repository(
                serde_json::json!({ "name": "users/alice/app" }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_repository_updates_metadata_for_owner() {
        let state = test_state_with_auth(vec![]);
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "users/alice/app".to_string(),
                description: "old".to_string(),
                created_by: Some(Subject::new("user-1")),
                visibility: Visibility::Private,
                created_at: 123,
            })
            .await
            .unwrap();
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let response = app
            .oneshot(patch_repository_request(
                "users/alice/app",
                serde_json::json!({
                    "description": "  new description  ",
                    "visibility": "public_pull"
                }),
                Some(session_identity()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["description"], "new description");
        assert_eq!(data["visibility"], "public_pull");
        assert_eq!(data["created_at"], 123);

        state
            .auth
            .as_ref()
            .unwrap()
            .check_public_pull("users/alice/app", &state.core.metadata)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn patch_repository_private_disables_public_pull() {
        let state = test_state_with_auth(vec![]);
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "users/alice/app".to_string(),
                description: "public".to_string(),
                created_by: Some(Subject::new("user-1")),
                visibility: Visibility::PublicPull,
                created_at: 123,
            })
            .await
            .unwrap();
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let response = app
            .oneshot(patch_repository_request(
                "users/alice/app",
                serde_json::json!({ "visibility": "private" }),
                Some(session_identity()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        state
            .auth
            .as_ref()
            .unwrap()
            .check_public_pull("users/alice/app", &state.core.metadata)
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn patch_repository_denied_without_update_grant() {
        let state = test_state_with_auth(vec![]);
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "team-a/app".to_string(),
                description: "old".to_string(),
                created_by: None,
                visibility: Visibility::Private,
                created_at: 123,
            })
            .await
            .unwrap();
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(patch_repository_request(
                "team-a/app",
                serde_json::json!({ "description": "new" }),
                Some(scoped_identity(vec![
                    "repository:team-a/app:pull".to_string(),
                ])),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn patch_repository_requires_identity_when_auth_enabled() {
        let state = test_state_with_auth(vec![]);
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "users/alice/app".to_string(),
                description: "old".to_string(),
                created_by: None,
                visibility: Visibility::Private,
                created_at: 123,
            })
            .await
            .unwrap();
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(patch_repository_request(
                "users/alice/app",
                serde_json::json!({ "description": "new" }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn patch_repository_missing_metadata_returns_not_found() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(patch_repository_request(
                "users/alice/missing",
                serde_json::json!({ "description": "new" }),
                Some(session_identity()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn patch_repository_allows_auth_disabled_mode() {
        let state = test_state();
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "team-a/app".to_string(),
                description: "old".to_string(),
                created_by: None,
                visibility: Visibility::Private,
                created_at: 123,
            })
            .await
            .unwrap();
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let response = app
            .oneshot(patch_repository_request(
                "team-a/app",
                serde_json::json!({ "description": "new", "visibility": "public_pull" }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let stored = state
            .core
            .metadata
            .get_repository("team-a/app")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.description, "new");
        assert_eq!(stored.visibility, Visibility::PublicPull);
    }

    #[tokio::test]
    async fn shadow_repository_appears_in_listing() {
        let state = test_state();
        state
            .core
            .metadata
            .put_repository(crate::store::metadata::Repository {
                name: "users/alice/empty".to_string(),
                description: "nothing pushed yet".to_string(),
                created_by: Some(Subject::new("alice")),
                visibility: Visibility::Private,
                created_at: 123,
            })
            .await
            .unwrap();

        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/repositories?q=users/alice/empty")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repo = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"].as_str() == Some("users/alice/empty"))
            .unwrap();
        assert_eq!(repo["manifest_count"].as_u64(), Some(0));
        assert_eq!(repo["description"], "nothing pushed yet");
        assert_eq!(repo["created_by"], "alice");
    }

    // ── Repository list: reachability filtering ───────────────────────

    async fn seed_manifest(
        state: &Arc<AppState<InMemoryMetadataStore, InMemoryBlobStore>>,
        name: &str,
        tag: &str,
    ) {
        state
            .core
            .metadata
            .put_manifest(name, tag, manifest_entry(1, 1_777_593_600))
            .await
            .unwrap();
    }

    fn get_repositories(query: &str, identity: Option<AuthIdentity>) -> Request<Body> {
        let uri = if query.is_empty() {
            "/api/v1/repositories".to_string()
        } else {
            format!("/api/v1/repositories?{query}")
        };
        let mut req = Request::builder()
            .uri(uri)
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        if let Some(id) = identity {
            req.extensions_mut().insert(id);
        }
        req
    }

    #[tokio::test]
    async fn list_repositories_filters_by_pull_permission() {
        let state = test_state_with_auth(vec![]);
        seed_manifest(&state, "team-a/frontend", "latest").await;
        seed_manifest(&state, "team-a/backend", "latest").await;
        seed_manifest(&state, "team-b/worker", "latest").await;
        seed_manifest(&state, "public/app", "latest").await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Actor has pull only on team-a repos.
        let response = app
            .oneshot(get_repositories(
                "",
                Some(scoped_identity(vec![
                    "repository:team-a/*:pull".to_string(),
                ])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"team-a/frontend"));
        assert!(names.contains(&"team-a/backend"));
        assert_eq!(data["total_reachable"], 2);
    }

    #[tokio::test]
    async fn list_repositories_excludes_cross_user_personal() {
        let state = test_state_with_auth(vec![team_worker_grant()]);
        seed_manifest(&state, "users/alice/app", "latest").await;
        seed_manifest(&state, "users/bob/app", "latest").await;
        seed_manifest(&state, "team-a/worker", "latest").await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // Alice sees her own repos + shared, but never Bob's.
        let response = app
            .oneshot(get_repositories(
                "",
                Some(grouped_identity(vec![
                    "550e8400-e29b-41d4-a716-446655440040",
                ])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"users/alice/app"));
        assert!(names.contains(&"team-a/worker"));
        assert!(!names.iter().any(|n| n.contains("bob")));
    }

    #[tokio::test]
    async fn list_repositories_mine_filter() {
        let state = test_state_with_auth(vec![]);
        seed_manifest(&state, "users/alice/app", "latest").await;
        seed_manifest(&state, "users/alice/backend", "latest").await;
        seed_manifest(&state, "team-a/worker", "latest").await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        // `mine` filter: only personal namespace repos.
        let response = app
            .oneshot(get_repositories("filter=mine", Some(session_identity())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.iter().all(|n| n.starts_with("users/alice/")));
    }

    #[tokio::test]
    async fn list_repositories_empty() {
        let state = test_state_with_auth(vec![]);
        // No repos seeded; actor has no pull grants.
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_repositories("", Some(session_identity())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos = data["repositories"].as_array().unwrap();
        assert!(repos.is_empty());
        assert_eq!(data["total_reachable"], 0);
    }

    #[tokio::test]
    async fn list_repositories_includes_access_metadata() {
        let state = test_state_with_auth(vec![]);
        seed_manifest(&state, "users/alice/app", "latest").await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_repositories("", Some(session_identity())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repo = &data["repositories"].as_array().unwrap()[0];
        // Personal namespace should have delete-level access.
        assert_eq!(repo["access_level"], "delete");
        assert_eq!(repo["max_grantable"], "delete");
        assert_eq!(repo["grant_source"], "personal");
    }

    #[tokio::test]
    async fn list_repositories_shared_filter() {
        let state = test_state_with_auth(vec![team_worker_grant()]);
        seed_manifest(&state, "users/alice/app", "latest").await;
        seed_manifest(&state, "team-a/worker", "latest").await;
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state);

        let response = app
            .oneshot(get_repositories(
                "filter=shared",
                Some(grouped_identity(vec![
                    "550e8400-e29b-41d4-a716-446655440040",
                ])),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = data["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        // Only non-personal repos.
        assert_eq!(names, vec!["team-a/worker"]);
    }
}
