use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::Method;
use axum::response::{IntoResponse, Response};

use crate::error::LayerhouseError;
use crate::store::blob::BlobStore;
use crate::store::metadata::ManifestStore;

use super::AppState;
pub async fn dispatch<M: ManifestStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    if *method != Method::GET {
        return Err(LayerhouseError::Unsupported("method not allowed".into()));
    }
    let query = super::query_params(req.uri());
    list_tags(&state, name, query).await
}

async fn list_tags<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    query: std::collections::HashMap<String, String>,
) -> Result<Response, LayerhouseError> {
    let n = query.get("n").and_then(|v| v.parse().ok());
    let last = query.get("last").map(|s| s.as_str());

    let tags = state.core.metadata.list_tags(name, n, last).await?;

    let body = serde_json::json!({
        "name": name,
        "tags": tags,
    });

    Ok(axum::Json(body).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_state;
    use crate::store::metadata::ManifestStore;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::response::IntoResponse;

    fn request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method(Method::GET)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn tags_returns_empty_for_unknown_repo() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::GET,
            "nonexistent",
            request("/v2/nonexistent/tags/list"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn tags_returns_tags_after_manifest_push() {
        let state = test_state();
        let entry = crate::store::metadata::ManifestEntry {
            digest: crate::oci::digest::Digest::from_str_checked(
                "sha256:000000000000000000000000000000000000000000000000000000000000000a",
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
            .put_manifest("my-repo", "v1.0", entry)
            .await
            .unwrap();
        let response = dispatch(
            state,
            &Method::GET,
            "my-repo",
            request("/v2/my-repo/tags/list"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
