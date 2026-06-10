pub mod admin;
pub mod blobs;
pub mod catalog;
pub mod dashboard_api;
pub mod manifests;
pub mod pat_api;
pub mod referrers;
pub mod session_api;
pub mod tags;
pub mod uploads;
pub mod v2;

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Json, Router};

use crate::auth::AuthService;
use crate::config::{CookieSecureMode, RaftTlsConfig};
use crate::mirror::MirrorManager;
use crate::raft::membership;
use crate::store::blob::BlobStore;
use crate::store::metadata::MetadataStore;
use crate::store::upload::UploadTracker;

// ── AppState ─────────────────────────────────────────────────────────

/// Always-present registry core: stores, upload tracking, concurrency limit.
pub struct RegistryCore<M, B> {
    pub metadata: M,
    pub blobs: B,
    pub uploads: UploadTracker,
    pub upload_semaphore: tokio::sync::Semaphore,
}

/// Full application state — core + optional subsystems.
pub struct AppState<M, B> {
    pub core: RegistryCore<M, B>,
    pub mirror: MirrorManager,
    pub gc_status: Arc<tokio::sync::RwLock<crate::gc::GcStatus>>,
    pub raft: Option<std::sync::Arc<crate::raft::RaftInstance>>,
    pub raft_tls: Option<Arc<RaftTlsConfig>>,
    pub auth: Option<Arc<AuthService>>,
    pub server_tls_enabled: bool,
    pub cookie_secure_mode: CookieSecureMode,
}

/// Convenience constructor for tests: a fully initialized AppState
/// with in-memory stores and no Raft/auth/semaphore overhead.
#[cfg(test)]
pub(crate) fn test_state() -> Arc<
    AppState<crate::store::metadata::InMemoryMetadataStore, crate::store::blob::InMemoryBlobStore>,
> {
    Arc::new(AppState {
        core: RegistryCore {
            metadata: crate::store::metadata::InMemoryMetadataStore::default(),
            blobs: crate::store::blob::InMemoryBlobStore::default(),
            uploads: UploadTracker::default(),
            upload_semaphore: tokio::sync::Semaphore::new(8),
        },
        mirror: MirrorManager::new(),
        gc_status: Arc::new(tokio::sync::RwLock::new(crate::gc::GcStatus::default())),
        raft: None,
        raft_tls: None,
        auth: None,
        server_tls_enabled: false,
        cookie_secure_mode: CookieSecureMode::Disabled,
    })
}

#[cfg(test)]
pub(crate) fn test_state_with_auth(
    permissions: Vec<crate::config::PermissionMapping>,
) -> Arc<
    AppState<crate::store::metadata::InMemoryMetadataStore, crate::store::blob::InMemoryBlobStore>,
> {
    Arc::new(AppState {
        core: RegistryCore {
            metadata: crate::store::metadata::InMemoryMetadataStore::default(),
            blobs: crate::store::blob::InMemoryBlobStore::default(),
            uploads: UploadTracker::default(),
            upload_semaphore: tokio::sync::Semaphore::new(8),
        },
        mirror: MirrorManager::new(),
        gc_status: Arc::new(tokio::sync::RwLock::new(crate::gc::GcStatus::default())),
        raft: None,
        raft_tls: None,
        auth: Some(Arc::new(crate::auth::AuthService::for_test(permissions))),
        server_tls_enabled: false,
        cookie_secure_mode: CookieSecureMode::Disabled,
    })
}

pub fn build_router<M: MetadataStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    include_raft_status: bool,
) -> Router {
    let mut router = Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/readyz", axum::routing::get(readyz::<M, B>))
        .route("/metrics", axum::routing::get(metrics::<M, B>))
        .route("/v2/", axum::routing::get(v2::v2_check::<M, B>))
        .route(
            "/v2/token",
            axum::routing::get(crate::auth::token_endpoint::token_endpoint::<M, B>),
        )
        .route(
            "/oauth2/start",
            axum::routing::get(crate::auth::oauth2::oauth2_start::<M, B>)
                .post(crate::auth::oauth2::oauth2_start::<M, B>),
        )
        .route(
            "/oauth2/callback",
            axum::routing::get(crate::auth::oauth2::oauth2_callback::<M, B>),
        )
        .merge(catalog::routes::<M, B>())
        .merge(admin::routes::<M, B>())
        .merge(dashboard_api::routes::<M, B>())
        .merge(pat_api::routes::<M, B>())
        .merge(session_api::routes::<M, B>())
        .route("/v2/{*path}", axum::routing::any(dispatch::<M, B>))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware::auth_middleware::<M, B>,
        ));

    if include_raft_status {
        router = router.route(
            "/raft/status",
            axum::routing::get(server_raft_status::<M, B>),
        );
    }
    router.with_state(state)
}

async fn healthz() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

async fn readyz<M: MetadataStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> impl IntoResponse {
    if let Err(err) = state.core.blobs.health_check().await {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("s3 unavailable: {err}"),
        );
    }
    let Some(raft) = state.raft.as_ref() else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "raft unavailable".to_string(),
        );
    };
    let status = membership::build_cluster_status(raft);
    if status.leader_id.is_none() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "raft has no leader".to_string(),
        );
    }
    (axum::http::StatusCode::OK, "ready".to_string())
}

async fn metrics<M: MetadataStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> impl IntoResponse {
    let mut body = String::from(
        "# HELP layerhouse_up Registry process health.\n\
         # TYPE layerhouse_up gauge\n\
         layerhouse_up 1\n",
    );

    if let Some(raft) = state.raft.as_ref() {
        let status = membership::build_cluster_status(raft);
        let quorum = status.voters.len() / 2 + 1;
        let healthy_voters = status
            .voters
            .iter()
            .filter(|node| {
                status.leader_id == Some(node.id)
                    || status
                        .replication
                        .get(&node.id)
                        .is_some_and(|matching| *matching == status.last_applied_log)
            })
            .count();
        body.push_str(&format!(
            "# HELP layerhouse_raft_leader 1 if this node is the Raft leader.\n\
             # TYPE layerhouse_raft_leader gauge\n\
             layerhouse_raft_leader {}\n\
             # HELP layerhouse_raft_quorum Required healthy voters for quorum.\n\
             # TYPE layerhouse_raft_quorum gauge\n\
             layerhouse_raft_quorum {}\n\
             # HELP layerhouse_raft_healthy_voters Voters caught up with the leader.\n\
             # TYPE layerhouse_raft_healthy_voters gauge\n\
             layerhouse_raft_healthy_voters {}\n",
            u8::from(status.state == membership::NodeState::Leader),
            quorum,
            healthy_voters
        ));
    }

    let gc = state.gc_status.read().await;
    body.push_str(&format!(
        "# HELP layerhouse_gc_last_run_timestamp_seconds Last GC sweep start time.\n\
         # TYPE layerhouse_gc_last_run_timestamp_seconds gauge\n\
         layerhouse_gc_last_run_timestamp_seconds {}\n\
         # HELP layerhouse_gc_last_deleted_blobs Blobs deleted by the last GC sweep.\n\
         # TYPE layerhouse_gc_last_deleted_blobs gauge\n\
         layerhouse_gc_last_deleted_blobs {}\n\
         # HELP layerhouse_gc_last_delete_errors Blob delete errors from the last GC sweep.\n\
         # TYPE layerhouse_gc_last_delete_errors gauge\n\
         layerhouse_gc_last_delete_errors {}\n",
        gc.last_run_at, gc.deleted, gc.delete_errors
    ));

    if let Some(auth) = state.auth.as_ref() {
        let metrics = auth.jwks_metrics().await;
        body.push_str(&format!(
            "# HELP layerhouse_auth_jwks_keys Cached OIDC JWKS verification keys.\n\
             # TYPE layerhouse_auth_jwks_keys gauge\n\
             layerhouse_auth_jwks_keys {}\n\
             # HELP layerhouse_auth_jwks_cache_age_seconds Age of the cached JWKS material.\n\
             # TYPE layerhouse_auth_jwks_cache_age_seconds gauge\n\
             layerhouse_auth_jwks_cache_age_seconds {}\n\
             # HELP layerhouse_auth_jwks_stale_cache 1 when serving from S3 last-good JWKS cache.\n\
             # TYPE layerhouse_auth_jwks_stale_cache gauge\n\
             layerhouse_auth_jwks_stale_cache {}\n\
             # HELP layerhouse_auth_jwks_refresh_failures_total JWKS refresh failure count.\n\
             # TYPE layerhouse_auth_jwks_refresh_failures_total counter\n\
             layerhouse_auth_jwks_refresh_failures_total {}\n",
            metrics.key_count,
            metrics.cache_age_seconds,
            u8::from(metrics.stale_mode),
            metrics.refresh_failures
        ));
        if let Some(endpoint) = metrics.endpoint {
            body.push_str(&format!(
                "# HELP layerhouse_auth_jwks_endpoint_info Active JWKS source endpoint.\n\
                 # TYPE layerhouse_auth_jwks_endpoint_info gauge\n\
                 layerhouse_auth_jwks_endpoint_info{{endpoint=\"{}\"}} 1\n",
                endpoint.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

/// Read-only /raft/status served on the main server router.
/// Returns the same full ClusterStatus as the raft listener's /raft/status.
async fn server_raft_status<M: MetadataStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, crate::error::LayerhouseError> {
    let raft = state.raft.as_ref().ok_or_else(|| {
        crate::error::LayerhouseError::Serialization("raft not available".to_string())
    })?;
    Ok(Json(membership::build_cluster_status(raft)))
}

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, Uri};
use axum::response::Response;

/// Build a `HeaderValue` from a string, mapping errors to `LayerhouseError::Serialization`.
pub fn percent_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            result.push(byte);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
}

pub fn query_params(uri: &Uri) -> std::collections::HashMap<String, String> {
    uri.query()
        .map(|q| {
            q.split('&')
                .filter_map(|pair| {
                    let (key, value) = pair.split_once('=')?;
                    Some((percent_decode(key), percent_decode(value)))
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn dispatch<M: MetadataStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    req: Request<Body>,
) -> Response {
    let method = req.method().clone();
    let path = path.trim_end_matches('/');

    // /v2/<name>/blobs/uploads/<session_id>
    if let Some((name, session_id)) = split_at(path, &["blobs", "uploads"]) {
        return uploads::dispatch_session(state, &method, name, session_id, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    // /v2/<name>/blobs/uploads  (no session id)
    if let Some(name) = path.strip_suffix("/blobs/uploads") {
        return uploads::dispatch_start(state, &method, name, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    // /v2/<name>/manifests/<reference>
    if let Some((name, reference)) = split_at(path, &["manifests"]) {
        return manifests::dispatch(state, &method, name, reference, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    // /v2/<name>/tags/list
    if let Some(name) = path.strip_suffix("/tags/list") {
        return tags::dispatch(state, &method, name, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    // /v2/<name>/referrers/<digest>
    if let Some((name, digest)) = split_at(path, &["referrers"]) {
        return referrers::dispatch(state, &method, name, digest, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    // /v2/<name>/blobs/<digest>
    if let Some((name, digest)) = split_at(path, &["blobs"]) {
        return blobs::dispatch(state, &method, name, digest, req)
            .await
            .unwrap_or_else(|e| e.into_response());
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Match a path ending with `/<segments…>/<value>`.
/// Returns `(prefix, value)` where prefix is everything before the matched suffix.
///
/// Example: `split_at("library/ubuntu/blobs/sha256:abc", &["blobs"])`
/// returns `Some(("library/ubuntu", "sha256:abc"))`.
fn split_at<'a>(path: &'a str, segments: &[&str]) -> Option<(&'a str, &'a str)> {
    let mut needle = String::from("/");
    for seg in segments {
        needle.push_str(seg);
        needle.push('/');
    }
    let idx = path.rfind(&needle)?;
    let prefix = &path[..idx];
    let value = &path[idx + needle.len()..];
    Some((prefix, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard;
    use crate::oci::digest::Digest;

    use axum::body::Body;

    use tower::ServiceExt;

    #[tokio::test]
    async fn api_routes_not_shadowed_by_spa_fallback() {
        let state = test_state();
        let router = build_router(state, true).merge(dashboard::dashboard_router());

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v2/_catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");

        assert!(
            content_type.contains("application/json"),
            "/v2/_catalog should return JSON, got Content-Type: {}",
            content_type
        );
    }

    #[tokio::test]
    async fn spa_fallback_serves_html_for_unknown_paths() {
        let state = test_state();
        let router = build_router(state, true).merge(dashboard::dashboard_router());

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some-random-page")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");

        assert!(
            content_type.contains("text/html"),
            "SPA fallback should return HTML, got Content-Type: {}",
            content_type
        );
    }

    #[tokio::test]
    async fn monolithic_blob_upload_with_digest_completes_immediately() {
        let state = test_state();
        let router = build_router(state, true);
        let body = b"monolithic upload body";
        let digest = Digest::sha256(body);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v2/repo/blobs/uploads/?digest={}", digest))
                    .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(&body[..]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn gc_status_endpoint_returns_current_counters() {
        let state = test_state();
        {
            let mut status = state.gc_status.write().await;
            status.last_run_at = 42;
            status.scanned = 7;
        }
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/gc/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["last_run_at"], 42);
        assert_eq!(json["scanned"], 7);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_process_health_metric() {
        let state = test_state();
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("layerhouse_up 1"));
    }

    #[tokio::test]
    async fn oauth2_callback_without_code_restarts_login() {
        let state = test_state();
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/oauth2/callback")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/oauth2/start")
        );
    }

    #[tokio::test]
    async fn oauth2_callback_missing_state_cookie_redirects_to_error_page() {
        let state = test_state();
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/oauth2/callback?code=abc&state=expected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_oauth2_state_error_redirect(response);
    }

    #[tokio::test]
    async fn oauth2_callback_malformed_state_cookie_redirects_to_error_page() {
        let state = test_state();
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/oauth2/callback?code=abc&state=expected")
                    .header(axum::http::header::COOKIE, "layerhouse_oauth2=malformed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_oauth2_state_error_redirect(response);
    }

    #[tokio::test]
    async fn oauth2_callback_state_mismatch_redirects_to_error_page() {
        let state = test_state();
        let router = build_router(state, true);

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/oauth2/callback?code=abc&state=expected")
                    .header(
                        axum::http::header::COOKIE,
                        "layerhouse_oauth2=different.verifier",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_oauth2_state_error_redirect(response);
    }

    fn assert_oauth2_state_error_redirect(response: Response) {
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/?oauth_error=state#/oauth2/error")
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("layerhouse_oauth2=; HttpOnly; SameSite=Lax; Path=/oauth2; Max-Age=0")
        );
    }

    #[test]
    fn query_params_decodes_percent_encoded_values() {
        let uri: axum::http::Uri = "/v2/repo/referrers/sha256%3Aabc?artifactType=a%2Fb&empty="
            .parse()
            .expect("valid uri");
        let params = query_params(&uri);

        assert_eq!(params.get("artifactType").map(String::as_str), Some("a/b"));
        assert_eq!(params.get("empty").map(String::as_str), Some(""));
    }
}
