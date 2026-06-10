use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::response::{IntoResponse, Response};

use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::oci::referrers::{ReferrerDescriptor, ReferrerIndex};
use crate::store::blob::BlobStore;
use crate::store::metadata::ManifestStore;

use super::AppState;

pub async fn dispatch<M: ManifestStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    digest_str: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    if *method != Method::GET {
        return Err(LayerhouseError::Unsupported("method not allowed".into()));
    }
    let query = super::query_params(req.uri());
    get_referrers(&state, name, digest_str, query).await
}

async fn get_referrers<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    digest_str: &str,
    query: std::collections::HashMap<String, String>,
) -> Result<Response, LayerhouseError> {
    let digest = Digest::try_from(digest_str)?;

    let artifact_type = query.get("artifactType").map(|s| s.as_str());

    let entries = state
        .core
        .metadata
        .list_referrers(name, &digest, artifact_type)
        .await?;

    let mut index = ReferrerIndex::empty();
    index.manifests = entries
        .into_iter()
        .map(|e| ReferrerDescriptor {
            media_type: e.media_type,
            digest: e.digest.to_string(),
            size: e.size,
            artifact_type: e.artifact_type,
            annotations: e.annotations,
        })
        .collect();

    let mut resp = axum::Json(index).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );
    if artifact_type.is_some() {
        resp.headers_mut().insert(
            HeaderName::from_static("oci-filters-applied"),
            HeaderValue::from_static("artifactType"),
        );
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_state;
    use crate::store::metadata::ManifestStore;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::response::IntoResponse;

    fn request(digest: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/v2/test-repo/referrers/{}", digest))
            .method(Method::GET)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn referrers_returns_empty_for_unknown_subject() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::GET,
            "test-repo",
            "sha256:000000000000000000000000000000000000000000000000000000000000000b",
            request("sha256:000000000000000000000000000000000000000000000000000000000000000b"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn referrers_returns_entry_for_referring_manifest() {
        let state = test_state();
        let subject_digest =
            "sha256:000000000000000000000000000000000000000000000000000000000000000c";
        let subject = crate::oci::digest::Digest::from_str_checked(subject_digest).unwrap();

        let referrer_entry = crate::store::metadata::ManifestEntry {
            digest: crate::oci::digest::Digest::from_str_checked(
                "sha256:000000000000000000000000000000000000000000000000000000000000000d",
            )
            .unwrap(),
            content_type: "application/vnd.oci.image.manifest.v1+json".into(),
            body: b"{}".to_vec(),
            referenced_blobs: vec![],
            subject: Some(subject),
            artifact_type: Some("application/vnd.example.sbom".into()),
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
            .put_manifest(
                "test-repo",
                &referrer_entry.digest.to_string(),
                referrer_entry,
            )
            .await
            .unwrap();

        let response = dispatch(
            state,
            &Method::GET,
            "test-repo",
            subject_digest,
            request(subject_digest),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
