use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;

use crate::error::LayerhouseError;
use crate::store::blob::BlobStore;
use crate::store::metadata::ManifestStore;

use super::AppState;

#[derive(Deserialize)]
struct CatalogQuery {
    n: Option<usize>,
    last: Option<String>,
}

async fn catalog<M: ManifestStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    Query(query): Query<CatalogQuery>,
) -> Result<impl IntoResponse, LayerhouseError> {
    let repos = state
        .core
        .metadata
        .list_repositories(query.n, query.last.as_deref())
        .await?;

    let body = serde_json::json!({
        "repositories": repos,
    });

    Ok(axum::Json(body))
}

pub fn routes<M: ManifestStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new().route("/v2/_catalog", get(catalog::<M, B>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_state;
    use axum::body::Body;

    use tower::ServiceExt;

    fn app() -> axum::Router {
        let state = test_state();
        routes::<crate::store::metadata::InMemoryMetadataStore, crate::store::blob::InMemoryBlobStore>()
            .with_state(state)
    }

    #[tokio::test]
    async fn catalog_returns_empty_repos() {
        let response = app()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v2/_catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["repositories"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn catalog_returns_repos_after_manifest_push() {
        let state = test_state();
        let entry = crate::store::metadata::ManifestEntry {
            digest: crate::oci::digest::Digest::from_str_checked(
                "sha256:0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            content_type: "application/vnd.oci.image.manifest.v1+json".into(),
            body: b"{}".to_vec(),
            referenced_blobs: vec![],
            subject: None,
            artifact_type: None,
            annotations: None,
            stored_size_bytes: 0,
            manifest_size_bytes: 2,
            created_at: crate::store::metadata::now_epoch(),
            last_modified: crate::store::metadata::now_epoch(),
            config_summary: None,
        };
        state
            .core
            .metadata
            .put_manifest("test-repo", "latest", entry)
            .await
            .unwrap();

        let app = routes::<
            crate::store::metadata::InMemoryMetadataStore,
            crate::store::blob::InMemoryBlobStore,
        >()
        .with_state(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v2/_catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["repositories"].as_array().unwrap().len(), 1);
    }
}
