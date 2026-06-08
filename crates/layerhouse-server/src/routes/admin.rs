use std::sync::Arc;

use aioduct::ProxyConfig;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::error::LayerhouseError;
use crate::store::blob::BlobStore;
#[allow(unused_imports)]
use crate::store::metadata::{
    AdminStore, HelmStore, JobStore, MirrorConfigStore, MirrorRule, MirrorRulePublic,
    MirrorStrategy, OutboundProxy, OutboundProxyProtocol, ProxyCache, ProxyCachePublic, WarmFilter,
    WarmImage,
};

use super::AppState;

#[derive(Deserialize)]
struct ListRulesQuery {
    include_secrets: Option<bool>,
}

#[derive(Deserialize)]
struct GetRuleQuery {
    include_secrets: Option<bool>,
}

fn required(value: &str, field: &str) -> Result<(), LayerhouseError> {
    if value.trim().is_empty() {
        return Err(LayerhouseError::NameInvalid(format!(
            "{} is required",
            field
        )));
    }
    Ok(())
}

fn normalize_optional(value: &mut Option<String>) {
    *value = value.take().and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
}

fn validate_outbound_proxy(proxy: &mut OutboundProxy) -> Result<(), LayerhouseError> {
    normalize_optional(&mut proxy.url);
    normalize_optional(&mut proxy.username);
    normalize_optional(&mut proxy.password);

    match proxy.protocol {
        OutboundProxyProtocol::None => {
            proxy.url = None;
            proxy.username = None;
            proxy.password = None;
            Ok(())
        }
        OutboundProxyProtocol::Http => {
            let url = proxy.url.as_deref().ok_or_else(|| {
                LayerhouseError::NameInvalid(
                    "outbound_proxy.url is required for HTTP proxy".to_string(),
                )
            })?;
            ProxyConfig::http(url).map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
            Ok(())
        }
        OutboundProxyProtocol::Socks4 => {
            let url = proxy.url.as_deref().ok_or_else(|| {
                LayerhouseError::NameInvalid(
                    "outbound_proxy.url is required for SOCKS4 proxy".to_string(),
                )
            })?;
            ProxyConfig::socks4(url).map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
            Ok(())
        }
        OutboundProxyProtocol::Socks5 => {
            let url = proxy.url.as_deref().ok_or_else(|| {
                LayerhouseError::NameInvalid(
                    "outbound_proxy.url is required for SOCKS5h proxy".to_string(),
                )
            })?;
            ProxyConfig::socks5h(url).map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?;
            Ok(())
        }
        OutboundProxyProtocol::Https => Err(LayerhouseError::NameInvalid(
            "HTTPS outbound proxy is deferred until aioduct exposes HTTPS proxy support"
                .to_string(),
        )),
    }
}

fn validate_strategy(strategy: &MirrorStrategy) -> Result<(), LayerhouseError> {
    match strategy {
        MirrorStrategy::All => Ok(()),
        MirrorStrategy::Latest { count } if *count > 0 => Ok(()),
        MirrorStrategy::Latest { .. } => Err(LayerhouseError::NameInvalid(
            "strategy.count must be greater than zero".to_string(),
        )),
        MirrorStrategy::Pattern { pattern } if !pattern.trim().is_empty() => Ok(()),
        MirrorStrategy::Pattern { .. } => Err(LayerhouseError::NameInvalid(
            "strategy.pattern is required".to_string(),
        )),
    }
}

fn validate_warm_filters(filters: &[WarmFilter]) -> Result<(), LayerhouseError> {
    let has_none = filters
        .iter()
        .any(|filter| matches!(filter, WarmFilter::None));
    if has_none && filters.len() > 1 {
        return Err(LayerhouseError::NameInvalid(
            "warm_filters.none is exclusive".to_string(),
        ));
    }

    for filter in filters {
        match filter {
            WarmFilter::None | WarmFilter::All => {}
            WarmFilter::Latest { count, .. } if *count > 0 => {}
            WarmFilter::Latest { .. } => {
                return Err(LayerhouseError::NameInvalid(
                    "warm_filters.latest.count must be greater than zero".to_string(),
                ));
            }
            WarmFilter::Pattern { pattern } if !pattern.trim().is_empty() => {}
            WarmFilter::Pattern { .. } => {
                return Err(LayerhouseError::NameInvalid(
                    "warm_filters.pattern is required".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_mirror_rule(rule: &mut MirrorRule) -> Result<(), LayerhouseError> {
    required(&rule.id, "id")?;
    required(&rule.local_prefix, "local_prefix")?;
    required(&rule.upstream_registry, "upstream_registry")?;
    if rule.plain_http && rule.insecure_tls {
        return Err(LayerhouseError::NameInvalid(
            "plain_http and insecure_tls are mutually exclusive".to_string(),
        ));
    }
    normalize_optional(&mut rule.upstream_prefix);
    normalize_optional(&mut rule.schedule);
    normalize_optional(&mut rule.username);
    normalize_optional(&mut rule.password);
    validate_strategy(&rule.strategy)?;
    validate_outbound_proxy(&mut rule.outbound_proxy)
}

fn validate_proxy_cache(cache: &mut ProxyCache) -> Result<(), LayerhouseError> {
    required(&cache.id, "id")?;
    required(&cache.local_prefix, "local_prefix")?;
    required(&cache.upstream_registry, "upstream_registry")?;
    if cache.plain_http && cache.insecure_tls {
        return Err(LayerhouseError::NameInvalid(
            "plain_http and insecure_tls are mutually exclusive".to_string(),
        ));
    }
    normalize_optional(&mut cache.upstream_prefix);
    normalize_optional(&mut cache.warm_schedule);
    normalize_optional(&mut cache.username);
    normalize_optional(&mut cache.password);
    validate_warm_filters(&cache.warm_filters)?;
    validate_outbound_proxy(&mut cache.outbound_proxy)
}

pub fn routes<M: AdminStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route("/api/v1/admin/mirror/rules", get(list_rules::<M, B>))
        .route(
            "/api/v1/admin/mirror/rules/{id}",
            get(get_rule::<M, B>)
                .put(put_rule::<M, B>)
                .delete(delete_rule::<M, B>),
        )
        .route(
            "/api/v1/admin/mirror/rules/{id}/trigger",
            post(trigger_rule::<M, B>),
        )
        .route("/api/v1/admin/mirror/jobs", get(list_jobs::<M, B>))
        .route("/api/v1/admin/mirror/jobs/{id}", get(get_job::<M, B>))
        .route(
            "/api/v1/admin/mirror/jobs/{id}/runs",
            get(list_job_runs::<M, B>),
        )
        .route("/api/v1/admin/proxy-cache", get(list_proxy_caches::<M, B>))
        .route(
            "/api/v1/admin/proxy-cache/{id}",
            get(get_proxy_cache::<M, B>)
                .put(put_proxy_cache::<M, B>)
                .delete(delete_proxy_cache::<M, B>),
        )
        .route(
            "/api/v1/admin/proxy-cache/{id}/warm",
            post(trigger_proxy_cache_warm::<M, B>),
        )
        .route("/api/v1/admin/mirror/warm", get(list_warm::<M, B>))
        .route(
            "/api/v1/admin/mirror/warm/{id}",
            get(get_warm::<M, B>)
                .put(put_warm::<M, B>)
                .delete(delete_warm::<M, B>),
        )
        .route("/api/v1/admin/jobs", get(list_jobs::<M, B>))
        .route("/api/v1/admin/jobs/{id}", get(get_job::<M, B>))
        .route("/api/v1/admin/jobs/{id}/trigger", post(trigger_job::<M, B>))
        .route("/api/v1/admin/jobs/{id}/runs", get(list_job_runs::<M, B>))
        .route("/api/v1/admin/helm/charts", get(list_helm_charts::<M, B>))
        .route(
            "/api/v1/admin/helm/charts/{name}/versions",
            get(list_helm_versions::<M, B>),
        )
}

async fn list_rules<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Query(query): Query<ListRulesQuery>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let rules = state.core.metadata.list_mirror_rules().await?;
    if query.include_secrets.unwrap_or(false) {
        Ok(Json(
            serde_json::to_value(rules)
                .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
        )
        .into_response())
    } else {
        let public: Vec<MirrorRulePublic> = rules.iter().map(|r| r.into()).collect();
        Ok(Json(
            serde_json::to_value(public)
                .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
        )
        .into_response())
    }
}

async fn get_rule<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
    Query(query): Query<GetRuleQuery>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.get_mirror_rule(&id).await? {
        Some(rule) => {
            if query.include_secrets.unwrap_or(false) {
                Ok(Json(rule).into_response())
            } else {
                Ok(Json(MirrorRulePublic::from(&rule)).into_response())
            }
        }
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn put_rule<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
    Json(mut rule): Json<MirrorRule>,
) -> Result<impl IntoResponse, LayerhouseError> {
    rule.id = id;
    validate_mirror_rule(&mut rule)?;
    if rule.created_at == 0 {
        rule.created_at = crate::store::metadata::now_epoch();
    }
    state.core.metadata.put_mirror_rule(rule).await?;
    state.mirror.invalidate_rules_cache().await;
    Ok(axum::http::StatusCode::OK)
}

async fn delete_rule<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    state.core.metadata.delete_mirror_rule(&id).await?;
    state.mirror.invalidate_rules_cache().await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn trigger_rule<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.trigger_mirror_rule(&id).await? {
        Some(job) => Ok(Json(job).into_response()),
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn list_proxy_caches<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let caches = state.core.metadata.list_proxy_caches().await?;
    let public: Vec<ProxyCachePublic> = caches.iter().map(|c| c.into()).collect();
    Ok(Json(public))
}

async fn get_proxy_cache<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.get_proxy_cache(&id).await? {
        Some(cache) => Ok(Json(ProxyCachePublic::from(&cache)).into_response()),
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn put_proxy_cache<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
    Json(mut cache): Json<ProxyCache>,
) -> Result<impl IntoResponse, LayerhouseError> {
    cache.id = id;
    validate_proxy_cache(&mut cache)?;
    if cache.created_at == 0 {
        cache.created_at = crate::store::metadata::now_epoch();
    }
    state.core.metadata.put_proxy_cache(cache).await?;
    state.mirror.invalidate_proxy_cache().await;
    Ok(axum::http::StatusCode::OK)
}

async fn delete_proxy_cache<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    state.core.metadata.delete_proxy_cache(&id).await?;
    state.mirror.invalidate_proxy_cache().await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn trigger_proxy_cache_warm<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.trigger_proxy_cache_warm(&id).await? {
        Some(job) => Ok(Json(job).into_response()),
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn list_warm<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let images = state.core.metadata.list_warm_images().await?;
    Ok(Json(images))
}

async fn get_warm<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.get_warm_image(&id).await? {
        Some(image) => Ok(Json(image).into_response()),
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn put_warm<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
    Json(mut image): Json<WarmImage>,
) -> Result<impl IntoResponse, LayerhouseError> {
    image.id = id;
    state.core.metadata.put_warm_image(image).await?;
    Ok(axum::http::StatusCode::OK)
}

async fn delete_warm<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, LayerhouseError> {
    state.core.metadata.delete_warm_image(&id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// Sync job endpoints

async fn list_jobs<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let jobs = state.core.metadata.list_sync_jobs().await?;
    Ok(Json(jobs))
}

async fn get_job<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.get_sync_job(&id).await? {
        Some(job) => Ok(Json(job).into_response()),
        None => Err(LayerhouseError::NameUnknown(id)),
    }
}

async fn trigger_job<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
) -> Result<Response, LayerhouseError> {
    if state.core.metadata.trigger_sync_job(&id).await? {
        Ok(axum::http::StatusCode::OK.into_response())
    } else {
        Err(LayerhouseError::NameUnknown(id))
    }
}

async fn list_job_runs<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let runs = state.core.metadata.list_sync_job_runs(&id, limit).await?;
    Ok(Json(runs))
}

// Helm chart endpoints

async fn list_helm_charts<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let charts = state.core.metadata.list_helm_charts().await?;
    Ok(Json(charts))
}

async fn list_helm_versions<M: AdminStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Path(name): Path<String>,
) -> Result<Response, LayerhouseError> {
    match state.core.metadata.list_helm_chart_versions(&name).await? {
        Some(versions) => Ok(Json(versions).into_response()),
        None => Err(LayerhouseError::NameUnknown(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::{
        InMemoryMetadataStore, MirrorConfigStore, MirrorRule, MirrorStrategy, OutboundProxy,
        OutboundProxyProtocol, ProxyCache, SyncJob, SyncJobKind,
    };
    use axum::body::Body;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::routes::test_state;

    async fn seed_rule(state: &AppState<InMemoryMetadataStore, InMemoryBlobStore>) {
        state
            .core
            .metadata
            .put_mirror_rule(MirrorRule {
                id: "test-rule".to_string(),
                direction: Default::default(),
                local_prefix: "local/test".to_string(),
                upstream_registry: "docker.io".to_string(),
                upstream_prefix: Some("library/test".to_string()),
                schedule: Some("*/30 * * * *".to_string()),
                strategy: MirrorStrategy::All,
                plain_http: false,
                insecure_tls: false,
                outbound_proxy: Default::default(),
                username: Some("admin".to_string()),
                password: Some("secret123".to_string()),
                created_at: 1,
            })
            .await
            .unwrap();
    }

    fn router(state: Arc<AppState<InMemoryMetadataStore, InMemoryBlobStore>>) -> axum::Router {
        routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state)
    }

    #[tokio::test]
    async fn list_rules_excludes_credentials_by_default() {
        let state = test_state();
        seed_rule(&state).await;
        let app = router(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/mirror/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            !text.contains("\"username\":"),
            "username value field leaked: {}",
            text
        );
        assert!(
            !text.contains("\"password\":"),
            "password value field leaked: {}",
            text
        );
        assert!(
            !text.contains("secret123"),
            "password value leaked: {}",
            text
        );
        assert!(text.contains("test-rule"), "rule id should be present");
        assert!(
            text.contains("local/test"),
            "local_prefix should be present"
        );
    }

    #[tokio::test]
    async fn list_rules_includes_credentials_when_requested() {
        let state = test_state();
        seed_rule(&state).await;
        let app = router(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/mirror/rules?include_secrets=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            text.contains("username"),
            "username should be present: {}",
            text
        );
        assert!(
            text.contains("password"),
            "password should be present: {}",
            text
        );
        assert!(
            text.contains("secret123"),
            "password value should be present"
        );
    }

    #[tokio::test]
    async fn get_rule_excludes_credentials_by_default() {
        let state = test_state();
        seed_rule(&state).await;
        let app = router(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/mirror/rules/test-rule")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            !text.contains("\"username\":"),
            "username value field leaked in get: {}",
            text
        );
        assert!(
            !text.contains("\"password\":"),
            "password value field leaked in get: {}",
            text
        );
        assert!(text.contains("test-rule"), "rule id should be present");
    }

    #[tokio::test]
    async fn get_rule_includes_credentials_when_requested() {
        let state = test_state();
        seed_rule(&state).await;
        let app = router(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/mirror/rules/test-rule?include_secrets=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            text.contains("username"),
            "username should be present in get: {}",
            text
        );
        assert!(
            text.contains("password"),
            "password should be present in get: {}",
            text
        );
    }

    #[tokio::test]
    async fn get_rule_404_on_unknown_id() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/mirror/rules/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_rule_rejects_https_proxy() {
        let state = test_state();
        let app = router(state);
        let rule = serde_json::json!({
            "id": "ignored",
            "local_prefix": "mirror/docker",
            "upstream_registry": "docker.io",
            "strategy": { "type": "all" },
            "outbound_proxy": {
                "protocol": "https",
                "url": "https://proxy.example.com:8443"
            }
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/mirror/rules/blocked")
                    .header("content-type", "application/json")
                    .body(Body::from(rule.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 2048)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("aioduct"),
            "expected deferred message: {text}"
        );
    }

    #[tokio::test]
    async fn put_rule_rejects_conflicting_upstream_transport_modes() {
        let state = test_state();
        let app = router(state);
        let rule = serde_json::json!({
            "id": "ignored",
            "local_prefix": "mirror/docker",
            "upstream_registry": "docker.io",
            "strategy": { "type": "all" },
            "plain_http": true,
            "insecure_tls": true
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/mirror/rules/conflict")
                    .header("content-type", "application/json")
                    .body(Body::from(rule.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_proxy_cache_accepts_insecure_tls_mode() {
        let state = test_state();
        let app = router(state.clone());
        let cache = serde_json::json!({
            "id": "ignored",
            "local_prefix": "cache/internal",
            "upstream_registry": "registry.internal:5443",
            "warm_filters": [{ "type": "none" }],
            "insecure_tls": true
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/proxy-cache/internal")
                    .header("content-type", "application/json")
                    .body(Body::from(cache.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let saved = state
            .core
            .metadata
            .get_proxy_cache("internal")
            .await
            .unwrap()
            .expect("proxy cache should be saved");
        assert!(saved.insecure_tls);
        assert!(!saved.plain_http);
    }

    #[tokio::test]
    async fn put_rule_direct_clears_proxy_details() {
        let state = test_state();
        let app = router(state.clone());
        let rule = serde_json::json!({
            "id": "ignored",
            "local_prefix": "mirror/docker",
            "upstream_registry": "registry-1.docker.io",
            "strategy": { "type": "all" },
            "outbound_proxy": {
                "protocol": "none",
                "url": "http://proxy.example.com:8080",
                "username": "user",
                "password": "secret"
            }
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/mirror/rules/docker")
                    .header("content-type", "application/json")
                    .body(Body::from(rule.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let saved = state
            .core
            .metadata
            .get_mirror_rule("docker")
            .await
            .unwrap()
            .expect("mirror rule should be saved");
        assert_eq!(saved.outbound_proxy.protocol, OutboundProxyProtocol::None);
        assert_eq!(saved.outbound_proxy.url, None);
        assert_eq!(saved.outbound_proxy.username, None);
        assert_eq!(saved.outbound_proxy.password, None);
    }

    #[tokio::test]
    async fn get_proxy_cache_excludes_credentials_by_default() {
        let state = test_state();
        state
            .core
            .metadata
            .put_proxy_cache(ProxyCache {
                id: "docker".to_string(),
                local_prefix: "cache/docker".to_string(),
                upstream_registry: "registry-1.docker.io".to_string(),
                upstream_prefix: Some("library".to_string()),
                warm_filters: vec![WarmFilter::None],
                warm_schedule: None,
                plain_http: false,
                insecure_tls: false,
                outbound_proxy: OutboundProxy {
                    protocol: OutboundProxyProtocol::Socks5,
                    url: Some("socks5://127.0.0.1:1080".to_string()),
                    username: Some("proxy-user".to_string()),
                    password: Some("proxy-secret".to_string()),
                },
                username: Some("upstream-user".to_string()),
                password: Some("upstream-secret".to_string()),
                created_at: 1,
            })
            .await
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/admin/proxy-cache/docker")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("\"username\":"),
            "upstream username field leaked: {text}"
        );
        assert!(
            !text.contains("\"password\":"),
            "password field leaked: {text}"
        );
        assert!(
            !text.contains("upstream-secret") && !text.contains("proxy-secret"),
            "secret value leaked: {text}"
        );
        assert!(
            text.contains("\"username_configured\":true")
                && text.contains("\"password_configured\":true"),
            "credential configured flags should be present: {text}"
        );
    }

    #[tokio::test]
    async fn put_proxy_cache_rejects_https_proxy() {
        let state = test_state();
        let app = router(state);
        let cache = serde_json::json!({
            "id": "ignored",
            "local_prefix": "cache/docker",
            "upstream_registry": "registry-1.docker.io",
            "warm_filters": [{ "type": "none" }],
            "outbound_proxy": {
                "protocol": "https",
                "url": "https://proxy.example.com:8443"
            }
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/proxy-cache/docker")
                    .header("content-type", "application/json")
                    .body(Body::from(cache.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 2048)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("aioduct"),
            "expected deferred message: {text}"
        );
    }

    #[tokio::test]
    async fn put_proxy_cache_direct_clears_proxy_details() {
        let state = test_state();
        let app = router(state.clone());
        let cache = serde_json::json!({
            "id": "ignored",
            "local_prefix": "cache/docker",
            "upstream_registry": "registry-1.docker.io",
            "warm_filters": [{ "type": "none" }],
            "outbound_proxy": {
                "protocol": "none",
                "url": "http://proxy.example.com:8080",
                "username": "user",
                "password": "secret"
            }
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/proxy-cache/docker")
                    .header("content-type", "application/json")
                    .body(Body::from(cache.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let saved = state
            .core
            .metadata
            .get_proxy_cache("docker")
            .await
            .unwrap()
            .expect("proxy cache should be saved");
        assert_eq!(saved.outbound_proxy.protocol, OutboundProxyProtocol::None);
        assert_eq!(saved.outbound_proxy.url, None);
        assert_eq!(saved.outbound_proxy.username, None);
        assert_eq!(saved.outbound_proxy.password, None);
    }

    #[tokio::test]
    async fn trigger_proxy_cache_warm_returns_sync_job() {
        let state = test_state();
        state
            .core
            .metadata
            .put_proxy_cache(ProxyCache {
                id: "docker".to_string(),
                local_prefix: "cache/docker".to_string(),
                upstream_registry: "registry-1.docker.io".to_string(),
                upstream_prefix: Some("library".to_string()),
                warm_filters: vec![WarmFilter::Pattern {
                    pattern: "v2.*".to_string(),
                }],
                warm_schedule: None,
                plain_http: false,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            })
            .await
            .unwrap();

        let app = router(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/proxy-cache/docker/warm")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let job: SyncJob = serde_json::from_slice(&body).unwrap();
        assert_eq!(job.kind, SyncJobKind::ProxyCache);
        assert_eq!(job.rule_id.as_deref(), Some("docker"));
        assert_eq!(job.tags, vec!["v2.*"]);
    }

    #[tokio::test]
    async fn trigger_rule_conflicts_with_queued_one_shot_job() {
        let state = test_state();
        state
            .core
            .metadata
            .put_mirror_rule(MirrorRule {
                id: "docker".to_string(),
                direction: Default::default(),
                local_prefix: "mirror/docker".to_string(),
                upstream_registry: "registry-1.docker.io".to_string(),
                upstream_prefix: Some("library/nginx".to_string()),
                schedule: None,
                strategy: MirrorStrategy::All,
                plain_http: false,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            })
            .await
            .unwrap();

        let app = router(state);
        let first = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/mirror/rules/docker/trigger")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), axum::http::StatusCode::OK);

        let second = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/mirror/rules/docker/trigger")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(second.status(), axum::http::StatusCode::CONFLICT);
    }
}
