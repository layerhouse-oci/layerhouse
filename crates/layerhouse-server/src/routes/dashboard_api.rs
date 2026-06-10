use std::cmp::Reverse;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::raft::membership;
use crate::store::blob::BlobStore;
use crate::store::metadata::{DeleteCounts, ManifestStore, ManifestSummary, RepositorySummary};

use super::{AppState, percent_decode};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;

pub fn routes<M: ManifestStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route("/api/v1/repositories", get(list_repositories::<M, B>))
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
}

#[derive(Debug, Serialize)]
struct RepositoryListResponse {
    repositories: Vec<RepositorySummary>,
    total: usize,
    has_more: bool,
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

async fn repository_dispatch<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response {
    match repository_dispatch_result(state, path, req).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn repository_dispatch_result<M: ManifestStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    path: String,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = path.trim_end_matches('/');
    let parts: Vec<&str> = path.split('/').collect();

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
        return batch_delete_manifests(State(state), Path(name), Json(req))
            .await
            .map(IntoResponse::into_response);
    }

    if method == Method::DELETE && !parts.is_empty() && !parts.contains(&"manifests") {
        return delete_repository(State(state), Path(path.to_string()))
            .await
            .map(IntoResponse::into_response);
    }

    let Some(manifests_pos) = parts.iter().rposition(|part| *part == "manifests") else {
        return Err(LayerhouseError::NameUnknown(path.to_string()));
    };
    let name = parts[..manifests_pos].join("/");
    let tail = &parts[manifests_pos + 1..];

    match (method, tail) {
        (Method::GET, []) => {
            let query = parse_query::<ManifestQuery>(&uri)?;
            list_manifests(State(state), Path(name), Query(query))
                .await
                .map(IntoResponse::into_response)
        }
        (Method::GET, [digest]) => get_manifest(State(state), Path((name, (*digest).to_string())))
            .await
            .map(IntoResponse::into_response),
        (Method::DELETE, [digest]) => {
            delete_manifest(State(state), Path((name, (*digest).to_string())))
                .await
                .map(IntoResponse::into_response)
        }
        (Method::GET, [digest, "raw"]) => {
            get_raw_manifest(State(state), Path((name, (*digest).to_string())))
                .await
                .map(IntoResponse::into_response)
        }
        (Method::DELETE, [digest, "tags", tag]) => delete_tag(
            State(state),
            Path((name, (*digest).to_string(), percent_decode(tag))),
        )
        .await
        .map(IntoResponse::into_response),
        _ => Err(LayerhouseError::Unsupported(
            "method not allowed".to_string(),
        )),
    }
}

async fn list_repositories<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Query(query): Query<RepositoryQuery>,
) -> Result<Response, LayerhouseError> {
    let mut repos = state.core.metadata.list_repository_summaries().await?;
    let q = query.q.unwrap_or_default().to_lowercase();
    if !q.is_empty() {
        repos.retain(|repo| repo.name.to_lowercase().contains(&q));
    }

    let now = crate::store::metadata::now_epoch();
    match query.recency.as_deref() {
        Some("recent") => repos.retain(|repo| now.saturating_sub(repo.last_modified) <= 7 * 86_400),
        Some("stale") => repos.retain(|repo| now.saturating_sub(repo.last_modified) >= 30 * 86_400),
        _ => {}
    }

    match query.sort.as_deref().unwrap_or("updated_desc") {
        "name_asc" => repos.sort_by(|a, b| a.name.cmp(&b.name)),
        "tag_count_desc" => repos.sort_by(|a, b| {
            b.tag_count
                .cmp(&a.tag_count)
                .then_with(|| a.name.cmp(&b.name))
        }),
        "updated_asc" => repos.sort_by(|a, b| {
            a.last_modified
                .cmp(&b.last_modified)
                .then_with(|| a.name.cmp(&b.name))
        }),
        _ => repos.sort_by(|a, b| {
            b.last_modified
                .cmp(&a.last_modified)
                .then_with(|| a.name.cmp(&b.name))
        }),
    }

    let total = repos.len();
    let n = page_size(query.n);
    let (page, has_more) = paginate(repos, n, query.last.as_deref(), |repo| repo.name.as_str());
    let next = page
        .last()
        .map(|repo| next_url("/api/v1/repositories", n, &repo.name));
    with_link(
        RepositoryListResponse {
            repositories: page,
            total,
            has_more,
        },
        has_more,
        next,
    )
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

async fn get_manifest<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path((name, digest)): Path<(String, String)>,
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

async fn delete_tag<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path((name, digest, tag)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let digest = Digest::from_str_checked(&digest)
        .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))?;
    if !state.core.metadata.delete_tag(&name, &digest, &tag).await? {
        return Err(LayerhouseError::NameUnknown(tag));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_manifest<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path((name, digest)): Path<(String, String)>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let digest = Digest::from_str_checked(&digest)
        .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))?;
    let counts = state
        .core
        .metadata
        .delete_manifests(&name, &[digest])
        .await?;
    Ok(Json(counts))
}

async fn batch_delete_manifests<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(name): Path<String>,
    Json(req): Json<BatchDeleteRequest>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let digests: Result<Vec<_>, _> = req
        .digests
        .iter()
        .map(|digest| {
            Digest::from_str_checked(digest)
                .ok_or_else(|| LayerhouseError::DigestInvalid(digest.clone()))
        })
        .collect();
    let counts = state
        .core
        .metadata
        .delete_manifests(&name, &digests?)
        .await?;
    Ok(Json(counts))
}

async fn delete_repository<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let name = percent_decode(&name);
    let counts: DeleteCounts = state.core.metadata.delete_repository(&name).await?;
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
}
