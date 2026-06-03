use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::error::OrbChrysaError;
use crate::oci::digest::Digest;
use crate::store::blob::{BlobStore, BlobStream};
#[allow(unused_imports)]
use crate::store::metadata::{ManifestStore, RegistryStore};

use super::AppState;

fn body_from_blob_stream(stream: BlobStream) -> Body {
    match stream {
        BlobStream::S3(output) => {
            Body::from_stream(ReaderStream::new(output.body.into_async_read()))
        }
        #[cfg(test)]
        BlobStream::Memory(stream) => Body::from_stream(stream),
    }
}

pub async fn dispatch<M: RegistryStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    digest_str: &str,
    req: Request<Body>,
) -> Result<Response, OrbChrysaError> {
    match *method {
        Method::HEAD => head_blob(&state, name, digest_str).await,
        Method::GET => get_blob(&state, name, digest_str, req).await,
        Method::DELETE => delete_blob(&state, name, digest_str).await,
        _ => Err(OrbChrysaError::Unsupported("method not allowed".into())),
    }
}

async fn stat_or_pull<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    digest: &Digest,
    digest_str: &str,
) -> Result<crate::store::blob::BlobInfo, OrbChrysaError> {
    let lifecycle = state.core.metadata.blob_lifecycle_status(digest).await?;
    if lifecycle.delete_requested && !lifecycle.referenced {
        return Err(OrbChrysaError::BlobUnknown(digest_str.to_string()));
    }

    match state.core.blobs.stat(digest).await {
        Ok(info) => return Ok(info),
        Err(OrbChrysaError::BlobUnknown(_)) => {}
        Err(e) => return Err(e),
    }

    match state
        .mirror
        .pull_blob(name, digest, &state.core.metadata, &state.core.blobs)
        .await
    {
        Ok(true) => state
            .core
            .blobs
            .stat(digest)
            .await
            .map_err(|_| OrbChrysaError::BlobUnknown(digest_str.to_string())),
        Ok(false) => Err(OrbChrysaError::BlobUnknown(digest_str.to_string())),
        Err(e) => Err(e),
    }
}

async fn head_blob<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    digest_str: &str,
) -> Result<Response, OrbChrysaError> {
    let digest = Digest::try_from(digest_str)?;

    let info = stat_or_pull(state, name, &digest, digest_str).await?;

    Ok((
        StatusCode::OK,
        [
            ("Content-Length", info.size.to_string().as_str()),
            ("Docker-Content-Digest", &digest.to_string()),
            ("Content-Type", "application/octet-stream"),
            ("Accept-Ranges", "bytes"),
        ],
    )
        .into_response())
}

async fn get_blob<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    digest_str: &str,
    req: Request<Body>,
) -> Result<Response, OrbChrysaError> {
    let digest = Digest::try_from(digest_str)?;

    let range_header = req
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref range_value) = range_header {
        return get_blob_range(state, name, &digest, range_value).await;
    }

    let info = stat_or_pull(state, name, &digest, digest_str).await?;

    if state.core.blobs.redirect_enabled() {
        let location = state.core.blobs.presigned_url(&digest).await?;
        let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
        resp.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location)
                .map_err(|e| OrbChrysaError::Serialization(e.to_string()))?,
        );
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        resp.headers_mut().insert(
            "Docker-Content-Digest",
            HeaderValue::from_str(&digest.to_string())
                .map_err(|e| OrbChrysaError::Serialization(e.to_string()))?,
        );
        resp.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        resp.headers_mut()
            .insert("Accept-Ranges", HeaderValue::from_static("bytes"));
        return Ok(resp);
    }

    let stream = state
        .core
        .blobs
        .get(&digest)
        .await
        .map_err(|_| OrbChrysaError::BlobUnknown(digest_str.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            ("Content-Type", "application/octet-stream"),
            ("Docker-Content-Digest", &digest.to_string()),
            ("Content-Length", &info.size.to_string()),
            ("Accept-Ranges", "bytes"),
        ],
        body_from_blob_stream(stream),
    )
        .into_response())
}

async fn get_blob_range<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    digest: &Digest,
    range_value: &str,
) -> Result<Response, OrbChrysaError> {
    let digest_str = &digest.to_string();
    let info = stat_or_pull(state, name, digest, digest_str).await?;

    let total_size = info.size;

    let (start, end) = parse_range(range_value, total_size)
        .ok_or_else(|| OrbChrysaError::Unsupported("invalid range".into()))?;

    let stream = state
        .core
        .blobs
        .get_range(digest, start, end)
        .await
        .map_err(|_| OrbChrysaError::BlobUnknown(digest.to_string()))?;

    let content_length = end - start + 1;
    let content_range = format!("bytes {}-{}/{}", start, end, total_size);

    Ok((
        StatusCode::PARTIAL_CONTENT,
        [
            ("Content-Type", "application/octet-stream"),
            ("Docker-Content-Digest", &digest.to_string()),
            ("Content-Length", &content_length.to_string()),
            ("Content-Range", &content_range),
            ("Accept-Ranges", "bytes"),
        ],
        body_from_blob_stream(stream),
    )
        .into_response())
}

fn parse_range(range_value: &str, total_size: u64) -> Option<(u64, u64)> {
    if total_size == 0 {
        return None;
    }

    let range_value = range_value.strip_prefix("bytes=")?;
    let (start_str, end_str) = range_value.split_once('-')?;

    if start_str.is_empty() {
        // suffix range: -500 means last 500 bytes
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = total_size.saturating_sub(suffix_len);
        Some((start, total_size - 1))
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end = if end_str.is_empty() {
            total_size - 1
        } else {
            end_str.parse().ok()?
        };
        if start > end || start >= total_size {
            return None;
        }
        Some((start, end.min(total_size - 1)))
    }
}

async fn delete_blob<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    _name: &str,
    digest_str: &str,
) -> Result<Response, OrbChrysaError> {
    let digest = Digest::try_from(digest_str)?;

    state
        .core
        .metadata
        .record_blob_delete_request(&digest)
        .await?;

    Ok(StatusCode::ACCEPTED.into_response())
}

#[cfg(test)]
mod tests {
    use super::{dispatch, parse_range};
    use crate::config::CookieSecureMode;
    use crate::mirror::MirrorManager;
    use crate::oci::digest::Digest;
    use crate::routes::{AppState, RegistryCore};
    use crate::store::blob::{BlobStore, InMemoryBlobStore};
    use crate::store::metadata::{InMemoryMetadataStore, ManifestEntry, ManifestStore, now_epoch};
    use crate::store::upload::UploadTracker;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, StatusCode, header};
    use axum::response::IntoResponse;
    use bytes::Bytes;
    use std::sync::Arc;

    fn test_state(
        blobs: InMemoryBlobStore,
    ) -> Arc<AppState<InMemoryMetadataStore, InMemoryBlobStore>> {
        Arc::new(AppState {
            core: RegistryCore {
                metadata: InMemoryMetadataStore::default(),
                blobs,
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

    fn request(range: Option<&str>) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().uri("/");
        if let Some(range) = range {
            builder = builder.header(header::RANGE, range);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn seed_blob(blobs: &InMemoryBlobStore, body: &'static [u8]) -> Digest {
        let digest = Digest::sha256(body);
        let session_id = format!("upload-{}", digest.hex);
        blobs.start_upload(&session_id).await.unwrap();
        blobs
            .push_chunk(&session_id, Bytes::from_static(body))
            .await
            .unwrap();
        blobs.complete_upload(&session_id, &digest).await.unwrap();
        digest
    }

    async fn seed_referencing_manifest(
        metadata: &InMemoryMetadataStore,
        blob_digest: Digest,
    ) -> Digest {
        let now = now_epoch();
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": blob_digest.to_string(),
                "size": 1
            },
            "layers": []
        })
        .to_string()
        .into_bytes();
        let manifest_digest = Digest::sha256(&body);
        metadata
            .put_manifest(
                "repo",
                "latest",
                ManifestEntry {
                    digest: manifest_digest.clone(),
                    content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    body,
                    referenced_blobs: vec![blob_digest],
                    subject: None,
                    artifact_type: None,
                    annotations: None,
                    size_bytes: 0,
                    created_at: now,
                    last_modified: now,
                    config_summary: None,
                },
            )
            .await
            .unwrap();
        manifest_digest
    }

    #[test]
    fn parse_range_handles_standard_ranges() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=950-2000", 1000), Some((950, 999)));
    }

    #[test]
    fn parse_range_rejects_invalid_or_empty_ranges() {
        assert_eq!(parse_range("bytes=0-0", 0), None);
        assert_eq!(parse_range("bytes=-0", 1000), None);
        assert_eq!(parse_range("items=0-1", 1000), None);
        assert_eq!(parse_range("bytes=900-800", 1000), None);
        assert_eq!(parse_range("bytes=1000-1001", 1000), None);
    }

    #[tokio::test]
    async fn full_get_redirects_when_redirect_mode_is_enabled() {
        let blobs = InMemoryBlobStore::with_redirect_enabled();
        let digest = seed_blob(&blobs, b"redirect-data").await;
        let state = test_state(blobs);

        let response = dispatch(
            state,
            &Method::GET,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            &format!("memory://{}", digest)
        );
        assert_eq!(
            response.headers().get("Docker-Content-Digest").unwrap(),
            &digest.to_string()
        );
        assert_eq!(response.headers().get(header::CONTENT_LENGTH).unwrap(), "0");
        assert_eq!(response.headers().get("Accept-Ranges").unwrap(), "bytes");
    }

    #[tokio::test]
    async fn head_never_redirects_even_when_redirect_mode_is_enabled() {
        let blobs = InMemoryBlobStore::with_redirect_enabled();
        let digest = seed_blob(&blobs, b"head-data").await;
        let state = test_state(blobs);

        let response = dispatch(
            state,
            &Method::HEAD,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response.headers().get("Docker-Content-Digest").unwrap(),
            &digest.to_string()
        );
    }

    #[tokio::test]
    async fn range_get_proxies_even_when_redirect_mode_is_enabled() {
        let blobs = InMemoryBlobStore::with_redirect_enabled();
        let digest = seed_blob(&blobs, b"abcdef").await;
        let state = test_state(blobs);

        let response = dispatch(
            state,
            &Method::GET,
            "repo",
            &digest.to_string(),
            request(Some("bytes=1-3")),
        )
        .await
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert!(response.headers().get(header::LOCATION).is_none());
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"bcd");
    }

    #[tokio::test]
    async fn missing_blob_still_returns_blob_unknown_in_redirect_mode() {
        let state = test_state(InMemoryBlobStore::with_redirect_enabled());
        let missing = Digest::sha256(b"missing");

        let response = dispatch(
            state,
            &Method::GET,
            "repo",
            &missing.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("BLOB_UNKNOWN"));
    }

    #[tokio::test]
    async fn blob_delete_records_metadata_request_without_deleting_bytes() {
        let blobs = InMemoryBlobStore::default();
        let digest = seed_blob(&blobs, b"keep-me").await;
        let state = test_state(blobs);
        seed_referencing_manifest(&state.core.metadata, digest.clone()).await;

        let delete_response = dispatch(
            state.clone(),
            &Method::DELETE,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(delete_response.status(), StatusCode::ACCEPTED);

        let get_response = dispatch(
            state.clone(),
            &Method::GET,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(get_response.status(), StatusCode::OK);

        state.core.blobs.stat(&digest).await.unwrap();
    }

    #[tokio::test]
    async fn unreferenced_blob_delete_hides_blob_until_gc_deletes_bytes() {
        let blobs = InMemoryBlobStore::default();
        let digest = seed_blob(&blobs, b"hide-me").await;
        let state = test_state(blobs);

        let delete_response = dispatch(
            state.clone(),
            &Method::DELETE,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(delete_response.status(), StatusCode::ACCEPTED);

        let get_response = dispatch(
            state.clone(),
            &Method::GET,
            "repo",
            &digest.to_string(),
            request(None),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        state.core.blobs.stat(&digest).await.unwrap();
    }
}
