use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::authorization::AuthorizedRepositoryAccess;
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::store::blob::BlobStore;
use crate::store::metadata::ManifestStore;
use crate::store::upload::UploadSession;

use super::AppState;

fn unknown_upload(session_id: &str) -> LayerhouseError {
    LayerhouseError::BlobUploadUnknown(session_id.to_string())
}

async fn upload_session<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    session_id: &str,
) -> Result<UploadSession, LayerhouseError> {
    let session = state
        .core
        .uploads
        .get(session_id)
        .await?
        .ok_or_else(|| unknown_upload(session_id))?;
    if !session.belongs_to(name) {
        return Err(unknown_upload(session_id));
    }
    Ok(session)
}

pub async fn dispatch_start<M: ManifestStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    if *method != Method::POST {
        return Err(LayerhouseError::Unsupported("method not allowed".into()));
    }
    let _permit = state
        .core
        .upload_semaphore
        .try_acquire()
        .map_err(|_| LayerhouseError::TooManyRequests("upload limit reached".into()))?;
    start_upload(&state, name, req).await
}

pub async fn dispatch_session<M: ManifestStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    session_id: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    match *method {
        Method::GET => get_upload_status(&state, name, session_id).await,
        Method::PATCH => patch_upload(&state, name, session_id, req).await,
        Method::PUT => complete_upload(&state, name, session_id, req).await,
        Method::DELETE => cancel_upload(&state, name, session_id).await,
        _ => Err(LayerhouseError::Unsupported("method not allowed".into())),
    }
}

async fn start_upload<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    let expected_namespace = req
        .extensions()
        .get::<AuthorizedRepositoryAccess>()
        .and_then(|access| access.expected_namespace.clone());
    let query = super::query_params(req.uri());

    if let Some(digest_str) = query.get("digest") {
        let digest = Digest::from_str_checked(digest_str)
            .ok_or_else(|| LayerhouseError::DigestInvalid(digest_str.clone()))?;
        let body = axum::body::to_bytes(req.into_body(), 1024 * 1024 * 1024)
            .await
            .map_err(|e| LayerhouseError::BlobUploadInvalid(e.to_string()))?;
        let session_id = uuid::Uuid::new_v4().to_string();

        state.core.blobs.start_upload(&session_id).await?;
        if !body.is_empty() {
            state.core.blobs.push_chunk(&session_id, body).await?;
        }
        state
            .core
            .blobs
            .complete_upload(&session_id, &digest)
            .await
            .map_err(|e| LayerhouseError::DigestInvalid(e.to_string()))?;
        state
            .core
            .metadata
            .clear_blob_delete_request(&digest)
            .await?;

        return Ok((
            StatusCode::CREATED,
            [
                (
                    "Location",
                    format!("/v2/{}/blobs/{}", name, digest).as_str(),
                ),
                ("Docker-Content-Digest", &digest.to_string()),
            ],
        )
            .into_response());
    }

    if let (Some(mount_digest), Some(from_repo)) = (query.get("mount"), query.get("from")) {
        let digest = Digest::from_str_checked(mount_digest)
            .ok_or_else(|| LayerhouseError::DigestInvalid(mount_digest.clone()))?;

        if state.core.blobs.stat(&digest).await.is_ok() {
            if state.auth.is_some() {
                state
                    .core
                    .metadata
                    .mount_blob_with_expected_namespace(
                        from_repo,
                        name,
                        &digest,
                        expected_namespace,
                    )
                    .await?;
            } else {
                state
                    .core
                    .metadata
                    .mount_blob(from_repo, name, &digest)
                    .await?;
            }
            state
                .core
                .metadata
                .clear_blob_delete_request(&digest)
                .await?;

            return Ok((
                StatusCode::CREATED,
                [
                    (
                        "Location",
                        format!("/v2/{}/blobs/{}", name, digest).as_str(),
                    ),
                    ("Docker-Content-Digest", &digest.to_string()),
                ],
            )
                .into_response());
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    state.core.blobs.start_upload(&session_id).await?;
    state
        .core
        .uploads
        .create(session_id.clone(), name.to_string())
        .await?;

    Ok((
        StatusCode::ACCEPTED,
        [
            (
                "Location",
                format!("/v2/{}/blobs/uploads/{}", name, session_id).as_str(),
            ),
            ("Docker-Upload-UUID", session_id.as_str()),
            ("Range", "0-0"),
        ],
    )
        .into_response())
}

async fn patch_upload<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    session_id: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    let session = upload_session(state, name, session_id).await?;

    if let Some(range) = req
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        && let Some(start) = parse_content_range_start(range)
        && start != session.offset
    {
        return Ok((
            StatusCode::RANGE_NOT_SATISFIABLE,
            [
                (
                    "Location",
                    format!("/v2/{}/blobs/uploads/{}", name, session_id).as_str(),
                ),
                ("Docker-Upload-UUID", session_id),
                (
                    "Range",
                    format!("0-{}", session.offset.saturating_sub(1)).as_str(),
                ),
            ],
        )
            .into_response());
    }

    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| LayerhouseError::BlobUploadInvalid(e.to_string()))?;

    let new_offset = state.core.blobs.push_chunk(session_id, body).await?;

    state
        .core
        .uploads
        .update_offset(session_id, new_offset)
        .await?;

    Ok((
        StatusCode::ACCEPTED,
        [
            (
                "Location",
                format!("/v2/{}/blobs/uploads/{}", name, session_id).as_str(),
            ),
            ("Docker-Upload-UUID", session_id),
            (
                "Range",
                format!("0-{}", new_offset.saturating_sub(1)).as_str(),
            ),
        ],
    )
        .into_response())
}

fn parse_content_range_start(range: &str) -> Option<u64> {
    let range = range.strip_prefix("bytes ").unwrap_or(range);
    let (start, _) = range.split_once('-')?;
    start.parse().ok()
}

async fn complete_upload<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    session_id: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    upload_session(state, name, session_id).await?;

    let query = super::query_params(req.uri());
    let digest_str = query
        .get("digest")
        .ok_or_else(|| LayerhouseError::DigestInvalid("missing digest query param".into()))?
        .clone();
    let digest = Digest::from_str_checked(&digest_str)
        .ok_or_else(|| LayerhouseError::DigestInvalid(digest_str.clone()))?;

    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| LayerhouseError::BlobUploadInvalid(e.to_string()))?;

    if !body.is_empty() {
        state.core.blobs.push_chunk(session_id, body).await?;
    }

    state
        .core
        .blobs
        .complete_upload(session_id, &digest)
        .await
        .map_err(|e| LayerhouseError::DigestInvalid(e.to_string()))?;
    state
        .core
        .metadata
        .clear_blob_delete_request(&digest)
        .await?;

    state.core.uploads.remove(session_id).await?;

    Ok((
        StatusCode::CREATED,
        [
            (
                "Location",
                format!("/v2/{}/blobs/{}", name, digest).as_str(),
            ),
            ("Docker-Content-Digest", &digest.to_string()),
        ],
    )
        .into_response())
}

async fn get_upload_status<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    session_id: &str,
) -> Result<Response, LayerhouseError> {
    let session = upload_session(state, name, session_id).await?;

    Ok((
        StatusCode::NO_CONTENT,
        [
            (
                "Location",
                format!("/v2/{}/blobs/uploads/{}", name, session_id).as_str(),
            ),
            ("Docker-Upload-UUID", session_id),
            (
                "Range",
                format!("0-{}", session.offset.saturating_sub(1)).as_str(),
            ),
        ],
    )
        .into_response())
}

async fn cancel_upload<M: ManifestStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    session_id: &str,
) -> Result<Response, LayerhouseError> {
    upload_session(state, name, session_id).await?;

    state.core.blobs.delete_upload(session_id).await?;
    state.core.uploads.remove(session_id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_state;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::response::IntoResponse;

    fn request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method(method)
            .header("Content-Type", "application/octet-stream")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn start_upload_returns_location_header() {
        let state = test_state();
        let response = dispatch_start(
            state,
            &Method::POST,
            "test-repo",
            request(Method::POST, "/v2/test-repo/blobs/uploads/"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_some()
        );
    }

    #[tokio::test]
    async fn get_nonexistent_upload_returns_404() {
        let state = test_state();
        let response = dispatch_session(
            state,
            &Method::GET,
            "test-repo",
            "nonexistent-session-id",
            request(
                Method::GET,
                "/v2/test-repo/blobs/uploads/nonexistent-session-id",
            ),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_upload_returns_no_content() {
        let state = test_state();
        let response = dispatch_session(
            state,
            &Method::DELETE,
            "test-repo",
            "nonexistent-session-id",
            request(
                Method::DELETE,
                "/v2/test-repo/blobs/uploads/nonexistent-session-id",
            ),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        // DELETE on unknown upload is an error
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_post_to_start_upload_rejected() {
        let state = test_state();
        let response = dispatch_start(
            state,
            &Method::GET,
            "test-repo",
            request(Method::GET, "/v2/test-repo/blobs/uploads/"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
