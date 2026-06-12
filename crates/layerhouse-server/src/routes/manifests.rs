use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::permissions::OciAction;
use crate::auth::token::AuthIdentity;
use crate::error::LayerhouseError;
use crate::oci::digest::Digest;
use crate::oci::manifest;
use crate::store::blob::BlobStore;
#[allow(unused_imports)]
use crate::store::metadata::{
    ManifestEntry, ManifestStore, NamespaceStore, RegistryStore, now_epoch,
};

use super::AppState;

struct ManifestResponseParts {
    content_type: String,
    digest: String,
    content_length: Option<u64>,
    body: Option<Vec<u8>>,
}

impl ManifestResponseParts {
    fn from_entry(entry: ManifestEntry, include_body: bool) -> Self {
        let content_length = entry.body.len() as u64;
        Self {
            content_type: entry.content_type,
            digest: entry.digest.to_string(),
            content_length: Some(content_length),
            body: include_body.then_some(entry.body),
        }
    }

    fn from_head(head: crate::mirror::client::ManifestHead) -> Self {
        Self {
            content_type: head.content_type,
            digest: head.digest,
            content_length: head.content_length,
            body: None,
        }
    }
}

fn docker_content_digest_header() -> HeaderName {
    HeaderName::from_static("docker-content-digest")
}

fn oci_subject_header() -> HeaderName {
    HeaderName::from_static("oci-subject")
}

pub async fn dispatch<M: RegistryStore + NamespaceStore, B: BlobStore>(
    state: Arc<AppState<M, B>>,
    method: &Method,
    name: &str,
    reference: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    match *method {
        Method::GET => respond_manifest(&state, name, reference, true).await,
        Method::HEAD => respond_manifest(&state, name, reference, false).await,
        Method::PUT => put_manifest(&state, name, reference, req).await,
        Method::DELETE => delete_manifest(&state, name, reference).await,
        _ => Err(LayerhouseError::Unsupported("method not allowed".into())),
    }
}

async fn resolve_manifest<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    reference: &str,
) -> Result<ManifestResponseParts, LayerhouseError> {
    resolve_manifest_for_response(state, name, reference, true).await
}

async fn resolve_manifest_for_response<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    reference: &str,
    include_body: bool,
) -> Result<ManifestResponseParts, LayerhouseError> {
    match state.core.metadata.get_manifest(name, reference).await? {
        Some(entry) => {
            if let Some(validated) = Box::pin(state.mirror.validate_cached_proxy_tag(
                name,
                reference,
                entry.clone(),
                &state.core.metadata,
                &state.core.blobs,
            ))
            .await?
            {
                return Ok(ManifestResponseParts::from_entry(validated, include_body));
            }
            Ok(ManifestResponseParts::from_entry(entry, include_body))
        }
        None if include_body => {
            let pulled = Box::pin(state.mirror.pull_manifest_lazy(
                name,
                reference,
                &state.core.metadata,
                &state.core.blobs,
            ))
            .await?;
            pulled
                .map(|entry| ManifestResponseParts::from_entry(entry, true))
                .ok_or_else(|| LayerhouseError::ManifestUnknown(reference.to_string()))
        }
        None => {
            let head = Box::pin(
                state
                    .mirror
                    .head_manifest(name, reference, &state.core.metadata),
            )
            .await?;
            head.map(ManifestResponseParts::from_head)
                .ok_or_else(|| LayerhouseError::ManifestUnknown(reference.to_string()))
        }
    }
}

async fn respond_manifest<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    reference: &str,
    include_body: bool,
) -> Result<Response, LayerhouseError> {
    let parts = if include_body {
        resolve_manifest(state, name, reference).await?
    } else {
        resolve_manifest_for_response(state, name, reference, false).await?
    };

    let mut response = match parts.body {
        Some(body) => (StatusCode::OK, body).into_response(),
        None => StatusCode::OK.into_response(),
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&parts.content_type)
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
    );
    response.headers_mut().insert(
        docker_content_digest_header(),
        HeaderValue::from_str(&parts.digest)
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
    );
    if let Some(content_length) = parts.content_length {
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content_length.to_string())
                .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
        );
    }
    Ok(response)
}

async fn put_manifest<M: RegistryStore + NamespaceStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    reference: &str,
    req: Request<Body>,
) -> Result<Response, LayerhouseError> {
    let identity = req.extensions().get::<AuthIdentity>().cloned();
    let headers = req.headers().clone();
    let body = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|e| LayerhouseError::ManifestInvalid(e.to_string()))?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();

    if !manifest::is_manifest_media_type(&content_type) {
        return Err(LayerhouseError::ManifestInvalid(format!(
            "unsupported media type: {}",
            content_type
        )));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| LayerhouseError::ManifestInvalid(format!("invalid JSON: {}", e)))?;

    let digests = manifest::extract_referenced_digests(&parsed);
    let blob_checks: Vec<_> = digests.iter().map(|d| state.core.blobs.stat(d)).collect();
    let results = futures::future::join_all(blob_checks).await;
    for (i, result) in results.into_iter().enumerate() {
        if result.is_err() {
            return Err(LayerhouseError::ManifestBlobUnknown(digests[i].to_string()));
        }
    }

    // Write-time action re-check. The middleware resolved Create vs Update from
    // a metadata lookup *before* the body was read, leaving a TOCTOU window: a
    // request challenged/authorized as Create can still race to overwrite an
    // existing tag. Re-resolve existence here and, if this is an overwrite,
    // require the Update tier against the caller's identity before committing.
    // Skipped entirely when auth is disabled (no AuthService).
    if let Some(auth) = state.auth.as_ref() {
        let overwrite = state
            .core
            .metadata
            .get_manifest(name, reference)
            .await?
            .is_some();
        if overwrite {
            let identity = identity.ok_or_else(|| LayerhouseError::Unauthorized {
                message: "authentication required".to_string(),
                realm: None,
                service: None,
                scope: None,
            })?;
            auth.check_permission(&identity, name, OciAction::Update, &state.core.metadata)
                .await?;
        }
    }

    let digest = Digest::sha256(&body);
    let mut seen_refs = std::collections::BTreeSet::new();
    let referenced_blobs: Vec<Digest> = digests
        .into_iter()
        .filter(|digest| seen_refs.insert(digest.to_string()))
        .collect();
    let entry =
        ManifestEntry::from_parsed_json(&parsed, content_type, body.to_vec(), referenced_blobs);
    let subject = entry.subject.clone();

    state
        .core
        .metadata
        .put_manifest(name, reference, entry)
        .await?;

    let mut resp = StatusCode::CREATED.into_response();
    let location = format!("/v2/{}/manifests/{}", name, digest);
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
    );
    resp.headers_mut().insert(
        docker_content_digest_header(),
        HeaderValue::from_str(&digest.to_string())
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
    );
    if let Some(ref subj) = subject {
        resp.headers_mut().insert(
            oci_subject_header(),
            HeaderValue::from_str(&subj.to_string())
                .map_err(|e| LayerhouseError::Serialization(e.to_string()))?,
        );
    }
    Ok(resp)
}

async fn delete_manifest<M: RegistryStore, B: BlobStore>(
    state: &AppState<M, B>,
    name: &str,
    reference: &str,
) -> Result<Response, LayerhouseError> {
    let digest = Digest::from_str_checked(reference)
        .ok_or_else(|| LayerhouseError::Unsupported("tag deletion not supported".into()))?;

    state.core.metadata.delete_manifest(name, &digest).await?;

    Ok(StatusCode::ACCEPTED.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{test_state, test_state_with_auth};
    use crate::store::metadata::{
        MirrorConfigStore, OutboundProxy, ProxyCache, ProxyCacheTagValidation, WarmFilter,
    };
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderValue, Method, Request, StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use bytes::Bytes;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn request(method: Method, reference: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/v2/test-repo/manifests/{}", reference))
            .method(method)
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::empty())
            .unwrap()
    }

    fn manifest_request(method: Method, name: &str, reference: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/v2/{}/manifests/{}", name, reference))
            .method(method)
            .body(Body::empty())
            .unwrap()
    }

    fn blob_request(method: Method, name: &str, digest: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/v2/{}/blobs/{}", name, digest))
            .method(method)
            .body(Body::empty())
            .unwrap()
    }

    #[derive(Clone)]
    struct DockerPullCapture {
        index_body: Bytes,
        index_digest: String,
        child_body: Bytes,
        child_digest: String,
        blob_body: Bytes,
        blob_digest: String,
        include_head_digest: bool,
        index_heads: Arc<AtomicUsize>,
        index_gets: Arc<AtomicUsize>,
        child_heads: Arc<AtomicUsize>,
        child_gets: Arc<AtomicUsize>,
        blob_gets: Arc<AtomicUsize>,
    }

    fn manifest_response(
        status: StatusCode,
        body: Option<Bytes>,
        digest: Option<&str>,
        content_type: &str,
        content_length: usize,
    ) -> Response {
        let mut response = match body {
            Some(body) => (status, body).into_response(),
            None => status.into_response(),
        };
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("valid content type"),
        );
        if let Some(digest) = digest {
            response.headers_mut().insert(
                docker_content_digest_header(),
                HeaderValue::from_str(digest).expect("valid digest header"),
            );
        }
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content_length.to_string()).expect("valid content length"),
        );
        response
    }

    async fn start_docker_pull_registry(include_head_digest: bool) -> (String, DockerPullCapture) {
        const INDEX_CT: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
        const MANIFEST_CT: &str = "application/vnd.docker.distribution.manifest.v2+json";

        let blob_body = Bytes::from_static(b"docker config");
        let blob_digest = Digest::sha256(&blob_body).to_string();
        let child_body = Bytes::from(format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "{MANIFEST_CT}",
                "config": {{
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "digest": "{blob_digest}",
                    "size": {}
                }},
                "layers": []
            }}"#,
            blob_body.len()
        ));
        let child_digest = Digest::sha256(&child_body).to_string();
        let index_body = Bytes::from(format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "{INDEX_CT}",
                "manifests": [{{
                    "mediaType": "{MANIFEST_CT}",
                    "digest": "{child_digest}",
                    "size": {},
                    "platform": {{ "os": "linux", "architecture": "amd64" }}
                }}]
            }}"#,
            child_body.len()
        ));
        let index_digest = Digest::sha256(&index_body).to_string();
        let capture = DockerPullCapture {
            index_body,
            index_digest,
            child_body,
            child_digest,
            blob_body,
            blob_digest,
            include_head_digest,
            index_heads: Arc::new(AtomicUsize::new(0)),
            index_gets: Arc::new(AtomicUsize::new(0)),
            child_heads: Arc::new(AtomicUsize::new(0)),
            child_gets: Arc::new(AtomicUsize::new(0)),
            blob_gets: Arc::new(AtomicUsize::new(0)),
        };

        let app = axum::Router::new()
            .route("/v2/", get(|| async { StatusCode::OK }))
            .route(
                "/v2/library/alpine/manifests/3",
                get(|State(capture): State<DockerPullCapture>| async move {
                    capture.index_gets.fetch_add(1, Ordering::SeqCst);
                    manifest_response(
                        StatusCode::OK,
                        Some(capture.index_body.clone()),
                        Some(&capture.index_digest),
                        INDEX_CT,
                        capture.index_body.len(),
                    )
                })
                .head(|State(capture): State<DockerPullCapture>| async move {
                    capture.index_heads.fetch_add(1, Ordering::SeqCst);
                    manifest_response(
                        StatusCode::OK,
                        None,
                        capture
                            .include_head_digest
                            .then_some(capture.index_digest.as_str()),
                        INDEX_CT,
                        capture.index_body.len(),
                    )
                }),
            )
            .route(
                "/v2/library/alpine/manifests/{digest}",
                get(|State(capture): State<DockerPullCapture>| async move {
                    capture.child_gets.fetch_add(1, Ordering::SeqCst);
                    manifest_response(
                        StatusCode::OK,
                        Some(capture.child_body.clone()),
                        Some(&capture.child_digest),
                        MANIFEST_CT,
                        capture.child_body.len(),
                    )
                })
                .head(|State(capture): State<DockerPullCapture>| async move {
                    capture.child_heads.fetch_add(1, Ordering::SeqCst);
                    manifest_response(
                        StatusCode::OK,
                        None,
                        Some(&capture.child_digest),
                        MANIFEST_CT,
                        capture.child_body.len(),
                    )
                }),
            )
            .route(
                "/v2/library/alpine/blobs/{digest}",
                get(|State(capture): State<DockerPullCapture>| async move {
                    capture.blob_gets.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, capture.blob_body.clone()).into_response()
                }),
            )
            .with_state(capture.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind docker pull registry");
        let addr = listener.local_addr().expect("docker pull registry addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve docker pull registry");
        });

        (addr.to_string(), capture)
    }

    #[derive(Clone)]
    struct MutableManifestCapture {
        body: Arc<StdMutex<Bytes>>,
        head_fails: Arc<AtomicBool>,
        get_fails: Arc<AtomicBool>,
        heads: Arc<AtomicUsize>,
        gets: Arc<AtomicUsize>,
    }

    impl MutableManifestCapture {
        fn new(body: Bytes) -> Self {
            Self {
                body: Arc::new(StdMutex::new(body)),
                head_fails: Arc::new(AtomicBool::new(false)),
                get_fails: Arc::new(AtomicBool::new(false)),
                heads: Arc::new(AtomicUsize::new(0)),
                gets: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_body(&self, body: Bytes) {
            *self.body.lock().expect("mutable manifest lock") = body;
        }

        fn body(&self) -> Bytes {
            self.body.lock().expect("mutable manifest lock").clone()
        }

        fn digest(&self) -> String {
            Digest::sha256(&self.body()).to_string()
        }

        fn reset_counts(&self) {
            self.heads.store(0, Ordering::SeqCst);
            self.gets.store(0, Ordering::SeqCst);
        }
    }

    fn tiny_manifest_body(label: &str) -> Bytes {
        Bytes::from(format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.empty.v1+json",
                    "digest": "sha256:{:064x}",
                    "size": 2
                }},
                "layers": [],
                "annotations": {{ "test.label": "{}" }}
            }}"#,
            label.bytes().map(u64::from).sum::<u64>(),
            label
        ))
    }

    fn mutable_manifest_response(
        status: StatusCode,
        body: Option<Bytes>,
        digest: &str,
    ) -> Response {
        let content_length = body.as_ref().map(|body| body.len()).unwrap_or(0);
        manifest_response(
            status,
            body,
            Some(digest),
            "application/vnd.oci.image.manifest.v1+json",
            content_length,
        )
    }

    async fn start_mutable_manifest_registry() -> (String, MutableManifestCapture) {
        let capture = MutableManifestCapture::new(tiny_manifest_body("v1"));
        let app = axum::Router::new()
            .route("/v2/", get(|| async { StatusCode::OK }))
            .route(
                "/v2/upstream/app/manifests/{reference}",
                get(|State(capture): State<MutableManifestCapture>| async move {
                    capture.gets.fetch_add(1, Ordering::SeqCst);
                    if capture.get_fails.load(Ordering::SeqCst) {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                    let body = capture.body();
                    let digest = Digest::sha256(&body).to_string();
                    mutable_manifest_response(StatusCode::OK, Some(body), &digest)
                })
                .head(
                    |State(capture): State<MutableManifestCapture>| async move {
                        capture.heads.fetch_add(1, Ordering::SeqCst);
                        if capture.head_fails.load(Ordering::SeqCst) {
                            return StatusCode::BAD_GATEWAY.into_response();
                        }
                        let body = capture.body();
                        let digest = Digest::sha256(&body).to_string();
                        mutable_manifest_response(StatusCode::OK, None, &digest)
                    },
                ),
            )
            .with_state(capture.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mutable registry");
        let addr = listener.local_addr().expect("mutable registry addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mutable registry");
        });

        (addr.to_string(), capture)
    }

    type TestAppState = Arc<
        crate::routes::AppState<
            crate::store::metadata::InMemoryMetadataStore,
            crate::store::blob::InMemoryBlobStore,
        >,
    >;

    async fn put_docker_proxy_cache(state: &TestAppState, registry: String) {
        state
            .core
            .metadata
            .put_proxy_cache(ProxyCache {
                id: "docker".to_string(),
                local_prefix: "mirror/docker".to_string(),
                upstream_registry: registry,
                upstream_prefix: Some("/".to_string()),
                warm_filters: vec![WarmFilter::None],
                warm_schedule: None,
                plain_http: true,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            })
            .await
            .expect("put docker proxy cache");
    }

    async fn assert_tag_head(state: TestAppState, capture: DockerPullCapture, name: &'static str) {
        let tag_head = dispatch(
            state,
            &Method::HEAD,
            name,
            "3",
            manifest_request(Method::HEAD, name, "3"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(tag_head.status(), StatusCode::OK);
        assert_eq!(capture.index_heads.load(Ordering::SeqCst), 1);
        assert_eq!(capture.index_gets.load(Ordering::SeqCst), 0);
    }

    async fn assert_tag_get(state: TestAppState, capture: DockerPullCapture, name: &'static str) {
        let tag_get = dispatch(
            state,
            &Method::GET,
            name,
            "3",
            manifest_request(Method::GET, name, "3"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(tag_get.status(), StatusCode::OK);
        let tag_body = axum::body::to_bytes(tag_get.into_body(), 1024 * 1024)
            .await
            .expect("tag body");
        assert_eq!(tag_body, capture.index_body);
        assert_eq!(capture.index_heads.load(Ordering::SeqCst), 2);
        assert_eq!(capture.index_gets.load(Ordering::SeqCst), 1);
        assert_eq!(capture.child_gets.load(Ordering::SeqCst), 0);
        assert_eq!(capture.blob_gets.load(Ordering::SeqCst), 0);
    }

    async fn assert_child_get(state: TestAppState, capture: DockerPullCapture, name: &'static str) {
        let child_get = dispatch(
            state,
            &Method::GET,
            name,
            &capture.child_digest,
            manifest_request(Method::GET, name, &capture.child_digest),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(child_get.status(), StatusCode::OK);
        let child_body = axum::body::to_bytes(child_get.into_body(), 1024 * 1024)
            .await
            .expect("child body");
        assert_eq!(child_body, capture.child_body);
        assert_eq!(capture.child_heads.load(Ordering::SeqCst), 1);
        assert_eq!(capture.child_gets.load(Ordering::SeqCst), 1);
        assert_eq!(capture.blob_gets.load(Ordering::SeqCst), 0);
    }

    async fn assert_blob_head(state: TestAppState, capture: DockerPullCapture, name: &'static str) {
        let blob_head = crate::routes::blobs::dispatch(
            state,
            &Method::HEAD,
            name,
            &capture.blob_digest,
            blob_request(Method::HEAD, name, &capture.blob_digest),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(blob_head.status(), StatusCode::OK);
        assert_eq!(capture.blob_gets.load(Ordering::SeqCst), 1);
    }

    async fn assert_blob_get(state: TestAppState, capture: DockerPullCapture, name: &'static str) {
        let blob_get = crate::routes::blobs::dispatch(
            state,
            &Method::GET,
            name,
            &capture.blob_digest,
            blob_request(Method::GET, name, &capture.blob_digest),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(blob_get.status(), StatusCode::OK);
        let blob_body = axum::body::to_bytes(blob_get.into_body(), 1024 * 1024)
            .await
            .expect("blob body");
        assert_eq!(blob_body, capture.blob_body);
        assert_eq!(capture.blob_gets.load(Ordering::SeqCst), 1);
    }

    async fn get_manifest_response(state: TestAppState, name: &str, reference: &str) -> Response {
        dispatch(
            state,
            &Method::GET,
            name,
            reference,
            manifest_request(Method::GET, name, reference),
        )
        .await
        .unwrap_or_else(|e| e.into_response())
    }

    async fn head_manifest_response(state: TestAppState, name: &str, reference: &str) -> Response {
        dispatch(
            state,
            &Method::HEAD,
            name,
            reference,
            manifest_request(Method::HEAD, name, reference),
        )
        .await
        .unwrap_or_else(|e| e.into_response())
    }

    async fn response_body(response: Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body")
    }

    async fn seed_stale_proxy_validation(
        state: &TestAppState,
        name: &str,
        tag: &str,
        upstream_digest: String,
    ) {
        state
            .core
            .metadata
            .put_proxy_cache_tag_validation(ProxyCacheTagValidation {
                cache_id: "docker".to_string(),
                repository: name.to_string(),
                tag: tag.to_string(),
                upstream_digest,
                last_validated_at: 1,
            })
            .await
            .expect("seed stale proxy validation");
    }

    #[tokio::test]
    async fn get_nonexistent_manifest_returns_404() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::GET,
            "test-repo",
            "latest",
            request(Method::GET, "latest"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn head_nonexistent_manifest_returns_404() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::HEAD,
            "test-repo",
            "latest",
            request(Method::HEAD, "latest"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn head_proxy_manifest_falls_back_to_get_digest_without_storing_manifest() {
        let (registry, capture) = start_docker_pull_registry(false).await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;

        let response = dispatch(
            state.clone(),
            &Method::HEAD,
            "mirror/docker/library/alpine",
            "3",
            manifest_request(Method::HEAD, "mirror/docker/library/alpine", "3"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(docker_content_digest_header())
                .and_then(|value| value.to_str().ok()),
            Some(capture.index_digest.as_str())
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/vnd.docker.distribution.manifest.list.v2+json")
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("head body");
        assert!(body.is_empty());
        assert!(
            state
                .core
                .metadata
                .get_manifest("mirror/docker/library/alpine", "3")
                .await
                .expect("get manifest")
                .is_none()
        );
        assert_eq!(capture.index_heads.load(Ordering::SeqCst), 1);
        assert_eq!(capture.index_gets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_cache_route_supports_docker_multi_arch_pull_sequence() {
        let (registry, capture) = start_docker_pull_registry(true).await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/library/alpine";

        assert_tag_head(state.clone(), capture.clone(), name).await;
        assert_tag_get(state.clone(), capture.clone(), name).await;
        assert_child_get(state.clone(), capture.clone(), name).await;
        assert_blob_head(state.clone(), capture.clone(), name).await;
        assert_blob_get(state, capture, name).await;
    }

    #[tokio::test]
    async fn proxy_cache_fresh_tag_validation_serves_cached_manifest() {
        let (registry, capture) = start_mutable_manifest_registry().await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/upstream/app";

        let first = get_manifest_response(state.clone(), name, "stable").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(response_body(first).await, tiny_manifest_body("v1"));
        assert!(capture.heads.load(Ordering::SeqCst) >= 1);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 1);

        capture.reset_counts();
        let second = get_manifest_response(state.clone(), name, "stable").await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(response_body(second).await, tiny_manifest_body("v1"));
        let head = head_manifest_response(state, name, "stable").await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(response_body(head).await.is_empty());
        assert_eq!(capture.heads.load(Ordering::SeqCst), 0);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_cache_stale_validation_same_digest_updates_timestamp_with_head_only() {
        let (registry, capture) = start_mutable_manifest_registry().await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/upstream/app";

        let first = get_manifest_response(state.clone(), name, "stable").await;
        assert_eq!(first.status(), StatusCode::OK);
        let digest = capture.digest();
        seed_stale_proxy_validation(&state, name, "stable", digest.clone()).await;

        capture.reset_counts();
        let second = get_manifest_response(state.clone(), name, "stable").await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(response_body(second).await, tiny_manifest_body("v1"));
        assert!(capture.heads.load(Ordering::SeqCst) >= 1);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 0);

        let validation = state
            .core
            .metadata
            .get_proxy_cache_tag_validation("docker", name, "stable")
            .await
            .expect("validation lookup")
            .expect("validation should be stored");
        assert_eq!(validation.upstream_digest, digest);
        assert!(validation.last_validated_at > 1);
    }

    #[tokio::test]
    async fn proxy_cache_stale_validation_changed_digest_refreshes_manifest() {
        let (registry, capture) = start_mutable_manifest_registry().await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/upstream/app";

        let first = get_manifest_response(state.clone(), name, "latest").await;
        assert_eq!(first.status(), StatusCode::OK);
        let old_digest = capture.digest();
        seed_stale_proxy_validation(&state, name, "latest", old_digest).await;
        capture.set_body(tiny_manifest_body("v2"));

        capture.reset_counts();
        let second = get_manifest_response(state.clone(), name, "latest").await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(response_body(second).await, tiny_manifest_body("v2"));
        assert_eq!(capture.heads.load(Ordering::SeqCst), 1);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 1);

        let validation = state
            .core
            .metadata
            .get_proxy_cache_tag_validation("docker", name, "latest")
            .await
            .expect("validation lookup")
            .expect("validation should be stored");
        assert_eq!(validation.upstream_digest, capture.digest());
    }

    #[tokio::test]
    async fn proxy_cache_stale_validation_failure_serves_cached_manifest() {
        let (registry, capture) = start_mutable_manifest_registry().await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/upstream/app";

        let first = get_manifest_response(state.clone(), name, "latest").await;
        assert_eq!(first.status(), StatusCode::OK);
        let old_digest = capture.digest();
        seed_stale_proxy_validation(&state, name, "latest", old_digest).await;
        capture.set_body(tiny_manifest_body("v2"));
        capture.head_fails.store(true, Ordering::SeqCst);

        capture.reset_counts();
        let second = get_manifest_response(state.clone(), name, "latest").await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(response_body(second).await, tiny_manifest_body("v1"));
        assert!(capture.heads.load(Ordering::SeqCst) >= 1);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 0);

        let validation = state
            .core
            .metadata
            .get_proxy_cache_tag_validation("docker", name, "latest")
            .await
            .expect("validation lookup")
            .expect("stale validation should remain");
        assert_eq!(validation.last_validated_at, 1);
    }

    #[tokio::test]
    async fn proxy_cache_digest_reference_bypasses_tag_validation() {
        let (registry, capture) = start_mutable_manifest_registry().await;
        let state = test_state();
        put_docker_proxy_cache(&state, registry).await;
        let name = "mirror/docker/upstream/app";

        let first = get_manifest_response(state.clone(), name, "latest").await;
        assert_eq!(first.status(), StatusCode::OK);
        let digest = capture.digest();

        capture.reset_counts();
        let by_digest = get_manifest_response(state, name, &digest).await;
        assert_eq!(by_digest.status(), StatusCode::OK);
        assert_eq!(response_body(by_digest).await, tiny_manifest_body("v1"));
        assert_eq!(capture.heads.load(Ordering::SeqCst), 0);
        assert_eq!(capture.gets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn put_invalid_json_rejected() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::PUT,
            "test-repo",
            "latest",
            Request::builder()
                .uri("/v2/test-repo/manifests/latest")
                .method(Method::PUT)
                .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .body(Body::from(b"not json".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_tag_rejected() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::DELETE,
            "test-repo",
            "latest",
            request(Method::DELETE, "latest"),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        // Tag deletion (non-digest reference) is not allowed through this endpoint
        assert_eq!(
            response.status(),
            axum::http::StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn delete_nonexistent_digest_returns_accepted() {
        let state = test_state();
        let response = dispatch(
            state,
            &Method::DELETE,
            "test-repo",
            "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
            request(
                Method::DELETE,
                "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
            ),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        // DELETE is idempotent
        assert_eq!(response.status(), axum::http::StatusCode::ACCEPTED);
    }

    fn empty_manifest_put(
        name: &str,
        reference: &str,
        identity: Option<AuthIdentity>,
    ) -> Request<Body> {
        let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}"#.to_vec();
        let mut req = Request::builder()
            .uri(format!("/v2/{}/manifests/{}", name, reference))
            .method(Method::PUT)
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(body))
            .unwrap();
        if let Some(identity) = identity {
            req.extensions_mut().insert(identity);
        }
        req
    }

    fn identity_with_scopes(scopes: Vec<String>) -> AuthIdentity {
        AuthIdentity {
            subject: crate::auth::identity::Subject::new("user-1"),
            username: Some("alice".to_string()),
            display_name: None,
            email: None,
            groups: Vec::new(),
            scopes,
            token_type: crate::auth::token::TokenType::PersonalAccess,
        }
    }

    // Claim `handle` for an org owner unrelated to the test identity, so the
    // namespace gate is satisfied (the handle is live) but ownership grants
    // nothing implicitly — the write decision falls through to the RBAC scope
    // re-check the test is actually exercising.
    async fn claim_for_other_owner(state: &TestAppState, handle: &str) {
        state
            .core
            .metadata
            .claim_namespace(
                handle,
                crate::store::metadata::Owner::Org(
                    crate::store::metadata::typed_id::OrgId::generate(),
                ),
                handle,
                crate::auth::identity::Subject::new("ns-claimer"),
                true,
                1,
            )
            .await
            .expect("claim namespace");
    }

    // A create-only grant can push a brand-new tag, but the write-time re-check
    // blocks the same identity from overwriting the now-existing tag — closing
    // the TOCTOU window left by the middleware's pre-body action resolution.
    #[tokio::test]
    async fn put_manifest_overwrite_denied_without_update_grant() {
        let state = test_state_with_auth(vec![]);
        claim_for_other_owner(&state, "team-a").await;
        let create_only =
            identity_with_scopes(vec!["repository:team-a/app:pull,create".to_string()]);

        // First push: tag is absent, so this is a Create — allowed.
        let response = dispatch(
            state.clone(),
            &Method::PUT,
            "team-a/app",
            "v1",
            empty_manifest_put("team-a/app", "v1", Some(create_only.clone())),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);

        // Second push: tag now exists, so this is an overwrite (Update) — the
        // create-only grant must be rejected at write time.
        let response = dispatch(
            state.clone(),
            &Method::PUT,
            "team-a/app",
            "v1",
            empty_manifest_put("team-a/app", "v1", Some(create_only)),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    // An update-tier grant overwrites an existing tag successfully.
    #[tokio::test]
    async fn put_manifest_overwrite_allowed_with_update_grant() {
        let state = test_state_with_auth(vec![]);
        claim_for_other_owner(&state, "team-a").await;
        let updater =
            identity_with_scopes(vec!["repository:team-a/app:pull,create,update".to_string()]);

        let response = dispatch(
            state.clone(),
            &Method::PUT,
            "team-a/app",
            "v1",
            empty_manifest_put("team-a/app", "v1", Some(updater.clone())),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);

        let response = dispatch(
            state,
            &Method::PUT,
            "team-a/app",
            "v1",
            empty_manifest_put("team-a/app", "v1", Some(updater)),
        )
        .await
        .unwrap_or_else(|e| e.into_response());
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    }

    // Personal namespace grants the full ladder, so overwrites are allowed
    // without any explicit scope.
    #[tokio::test]
    async fn put_manifest_overwrite_allowed_in_personal_namespace() {
        let state = test_state_with_auth(vec![]);
        let owner = identity_with_scopes(Vec::new());

        for _ in 0..2 {
            let response = dispatch(
                state.clone(),
                &Method::PUT,
                "users/alice/app",
                "v1",
                empty_manifest_put("users/alice/app", "v1", Some(owner.clone())),
            )
            .await
            .unwrap_or_else(|e| e.into_response());
            assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        }
    }
}
