use std::collections::HashMap;
use std::time::Duration;

use aioduct::{ProxyConfig, ProxySettings, StatusCode, TokioClient};
use bytes::Bytes;
use futures::StreamExt;
use http::header::LOCATION;
use http::header::WWW_AUTHENTICATE;
use http_body_util::{BodyExt, StreamBody};
use tokio::sync::RwLock;

use crate::error::LayerhouseError;

/// Strip credentials and path from a proxy URL for safe logging.
fn redact_proxy_url(url: &str) -> String {
    // Parse out scheme://host:port only, dropping userinfo, path, query, fragment.
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("socks5://") {
        ("socks5", rest)
    } else if let Some(rest) = url.strip_prefix("socks4://") {
        ("socks4", rest)
    } else {
        // Can't parse — redact entirely to be safe.
        return "<redacted>".to_string();
    };
    let host_port = rest.split('/').next().unwrap_or(rest);
    // Strip userinfo (user:pass@host → host)
    let host = host_port.split('@').next_back().unwrap_or(host_port);
    format!("{}://{}", scheme, host)
}
use crate::store::metadata::{OutboundProxy, OutboundProxyProtocol};

const MANIFEST_ACCEPT: &str = "\
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    */*";

const MAX_RETRIES: u32 = 5;
const INITIAL_BACKOFF_MS: u64 = 200;

#[derive(Debug, Clone, Copy)]
enum UpstreamScope {
    Pull,
    PushPull,
}

impl UpstreamScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::PushPull => "pull,push",
        }
    }
}

struct RetryRequest<'a> {
    method: http::Method,
    url: &'a str,
    accept: Option<&'a str>,
    content_type: Option<&'a str>,
    body: Option<Bytes>,
    scope: UpstreamScope,
}

#[derive(Debug, Clone)]
pub struct UpstreamRef {
    pub registry: String,
    pub repository: String,
    pub scheme: String,
    pub insecure_tls: bool,
    pub outbound_proxy: OutboundProxy,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl UpstreamRef {
    pub fn new(
        registry: &str,
        repository: &str,
        plain_http: bool,
        insecure_tls: bool,
        outbound_proxy: OutboundProxy,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        let api_registry = if registry == "docker.io" {
            "registry-1.docker.io".to_string()
        } else {
            registry.to_string()
        };

        let repository = if (registry == "docker.io" || registry == "registry-1.docker.io")
            && !repository.contains('/')
        {
            format!("library/{}", repository)
        } else {
            repository.to_string()
        };

        let scheme = if plain_http {
            "http".to_string()
        } else if insecure_tls {
            "https".to_string()
        } else {
            let hostname = api_registry.split(':').next().unwrap_or(&api_registry);
            if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "[::1]" {
                "http".to_string()
            } else {
                "https".to_string()
            }
        };

        Self {
            registry: api_registry,
            repository,
            scheme,
            insecure_tls,
            outbound_proxy,
            username,
            password,
        }
    }

    fn base_url(&self) -> String {
        format!("{}://{}", self.scheme, self.registry)
    }
}

pub struct ManifestData {
    pub body: Vec<u8>,
    pub content_type: String,
    #[expect(
        dead_code,
        reason = "kept from upstream Docker-Content-Digest for future verification"
    )]
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct BlobDescriptor {
    pub digest: String,
    #[expect(dead_code, reason = "descriptor size is retained from OCI metadata")]
    pub size: u64,
}

#[derive(Debug, serde::Deserialize)]
struct TagsListResponse {
    tags: Option<Vec<String>>,
}

pub struct UpstreamClient {
    http: TokioClient,
    proxied: RwLock<HashMap<String, TokioClient>>,
    tokens: RwLock<HashMap<String, String>>,
}

struct BearerChallenge {
    realm: String,
    service: Option<String>,
}

fn parse_bearer_challenge(header: &str) -> Result<BearerChallenge, LayerhouseError> {
    let header = header.strip_prefix("Bearer ").unwrap_or(header);
    let mut realm = None;
    let mut service = None;

    let mut remaining = header;
    while !remaining.is_empty() {
        remaining = remaining.trim_start_matches([',', ' ']);
        let Some((key, rest)) = remaining.split_once('=') else {
            break;
        };
        let key = key.trim();

        let (value, rest) = if let Some(rest) = rest.strip_prefix('"') {
            let end = rest.find('"').unwrap_or(rest.len());
            (&rest[..end], rest.get(end + 1..).unwrap_or(""))
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };

        match key {
            "realm" => realm = Some(value.to_string()),
            "service" => service = Some(value.to_string()),
            _ => {}
        }
        remaining = rest;
    }

    Ok(BearerChallenge {
        realm: realm
            .ok_or_else(|| LayerhouseError::Upstream("no realm in Bearer challenge".into()))?,
        service,
    })
}

fn is_retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::INTERNAL_SERVER_ERROR
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::GATEWAY_TIMEOUT
        || status == StatusCode::REQUEST_TIMEOUT
}

fn is_retryable_err(e: &aioduct::SendError) -> bool {
    e.is_connect() || e.is_timeout()
}

async fn backoff(attempt: u32) {
    let ms = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

impl UpstreamClient {
    pub fn new() -> Self {
        let http = Self::build_http_client(None, false).expect("failed to create HTTP client");

        Self {
            http,
            proxied: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
        }
    }

    fn cache_key(upstream: &UpstreamRef, scope: UpstreamScope) -> String {
        format!(
            "{}|{}|repository:{}:{}:{}:{}",
            Self::client_cache_key(&upstream.outbound_proxy, upstream.insecure_tls),
            upstream.registry,
            upstream.repository,
            upstream.scheme,
            upstream.insecure_tls,
            scope.as_str()
        )
    }

    fn client_key(proxy: &OutboundProxy) -> String {
        format!(
            "{:?}|{}|{}",
            proxy.protocol,
            proxy.url.as_deref().unwrap_or(""),
            proxy.username.as_deref().unwrap_or("")
        )
    }

    fn client_cache_key(proxy: &OutboundProxy, insecure_tls: bool) -> String {
        format!("{}|insecure_tls={}", Self::client_key(proxy), insecure_tls)
    }

    fn build_http_client(
        proxy: Option<&OutboundProxy>,
        insecure_tls: bool,
    ) -> Result<TokioClient, LayerhouseError> {
        let mut builder = TokioClient::builder()
            .user_agent("layerhouse/0.1")
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(30));

        if insecure_tls {
            builder = builder.danger_accept_invalid_certs();
        }

        if let Some(proxy) = proxy
            && proxy.protocol != OutboundProxyProtocol::None
        {
            let Some(url) = proxy.url.as_deref().filter(|v| !v.trim().is_empty()) else {
                return Err(LayerhouseError::NameInvalid(
                    "outbound_proxy.url is required when proxy protocol is not none".into(),
                ));
            };
            let mut config = match proxy.protocol {
                OutboundProxyProtocol::None => unreachable!("none proxy protocol filtered above"),
                OutboundProxyProtocol::Http => ProxyConfig::http(url)
                    .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?,
                OutboundProxyProtocol::Socks4 => ProxyConfig::socks4(url)
                    .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?,
                OutboundProxyProtocol::Socks5 => ProxyConfig::socks5h(url)
                    .map_err(|e| LayerhouseError::NameInvalid(e.to_string()))?,
                OutboundProxyProtocol::Https => {
                    return Err(LayerhouseError::Unsupported(
                        "HTTPS outbound proxy is deferred until aioduct exposes HTTPS proxy support"
                            .into(),
                    ));
                }
            };

            if let (Some(username), Some(password)) = (&proxy.username, &proxy.password)
                && (!username.is_empty() || !password.is_empty())
            {
                config = config.basic_auth(username, password);
            }
            builder = builder.proxy_settings(ProxySettings::all(config));
            tracing::info!(
                "outbound proxy configured: protocol={:?} host={}",
                proxy.protocol,
                redact_proxy_url(url),
            );
        }

        builder
            .build()
            .map_err(|e| LayerhouseError::Upstream(format!("HTTP client: {}", e)))
    }

    async fn http(&self, upstream: &UpstreamRef) -> Result<TokioClient, LayerhouseError> {
        if upstream.outbound_proxy.protocol == OutboundProxyProtocol::None && !upstream.insecure_tls
        {
            return Ok(self.http.clone());
        }

        let key = Self::client_cache_key(&upstream.outbound_proxy, upstream.insecure_tls);
        {
            let cache = self.proxied.read().await;
            if let Some(client) = cache.get(&key) {
                tracing::info!("outbound proxy: cache hit");
                return Ok(client.clone());
            }
        }

        let proxy = if upstream.outbound_proxy.protocol == OutboundProxyProtocol::None {
            None
        } else {
            Some(&upstream.outbound_proxy)
        };
        let client = Self::build_http_client(proxy, upstream.insecure_tls)?;
        self.proxied.write().await.insert(key, client.clone());
        Ok(client)
    }

    async fn ensure_auth_scope(
        &self,
        upstream: &UpstreamRef,
        scope: UpstreamScope,
    ) -> Result<(), LayerhouseError> {
        let url = format!("{}/v2/", upstream.base_url());
        let http = self.http(upstream).await?;
        let mut req = http
            .get(&url)
            .map_err(|e| LayerhouseError::Upstream(format!("auth probe: {}", e)))?;
        if let (Some(u), Some(p)) = (&upstream.username, &upstream.password) {
            req = req.basic_auth(u, Some(p));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| LayerhouseError::Upstream(format!("auth probe: {}", e)))?;

        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(());
        }

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                LayerhouseError::Upstream(format!(
                    "401 without WWW-Authenticate from {}",
                    upstream.registry
                ))
            })?
            .to_string();

        let token_scope = format!("repository:{}:{}", upstream.repository, scope.as_str());
        let token = self.fetch_token(&www_auth, &token_scope, upstream).await?;
        let key = Self::cache_key(upstream, scope);
        self.tokens.write().await.insert(key, token);
        Ok(())
    }

    pub async fn ensure_auth(&self, upstream: &UpstreamRef) -> Result<(), LayerhouseError> {
        self.ensure_auth_scope(upstream, UpstreamScope::Pull).await
    }

    pub async fn ensure_push_auth(&self, upstream: &UpstreamRef) -> Result<(), LayerhouseError> {
        self.ensure_auth_scope(upstream, UpstreamScope::PushPull)
            .await
    }

    async fn refresh_auth(
        &self,
        upstream: &UpstreamRef,
        scope: UpstreamScope,
    ) -> Result<(), LayerhouseError> {
        let key = Self::cache_key(upstream, scope);
        self.tokens.write().await.remove(&key);
        self.ensure_auth_scope(upstream, scope).await
    }

    async fn fetch_token(
        &self,
        www_auth: &str,
        scope: &str,
        upstream: &UpstreamRef,
    ) -> Result<String, LayerhouseError> {
        let challenge = parse_bearer_challenge(www_auth)?;

        let mut url = format!("{}?scope={}", challenge.realm, scope);
        if let Some(service) = &challenge.service {
            url.push_str(&format!("&service={}", service));
        }

        let http = self.http(upstream).await?;
        let mut req = http
            .get(&url)
            .map_err(|e| LayerhouseError::Upstream(format!("token fetch: {}", e)))?;
        if let (Some(u), Some(p)) = (&upstream.username, &upstream.password) {
            req = req.basic_auth(u, Some(p));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| LayerhouseError::Upstream(format!("token fetch: {}", e)))?
            .error_for_status()
            .map_err(|e| LayerhouseError::Upstream(format!("token fetch: {}", e)))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| LayerhouseError::Upstream(format!("token response: {}", e)))?;

        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| LayerhouseError::Upstream("no token in auth response".into()))
    }

    async fn apply_auth<'a>(
        &self,
        builder: aioduct::RequestBuilderSend<
            'a,
            aioduct::runtime::tokio_rt::TokioRuntime,
            aioduct::runtime::tokio_rt::TcpConnector,
        >,
        key: &str,
    ) -> aioduct::RequestBuilderSend<
        'a,
        aioduct::runtime::tokio_rt::TokioRuntime,
        aioduct::runtime::tokio_rt::TcpConnector,
    > {
        if let Some(token) = self.tokens.read().await.get(key) {
            builder.bearer_auth(token)
        } else {
            builder
        }
    }

    async fn retry(
        &self,
        upstream: &UpstreamRef,
        method: http::Method,
        url: &str,
        accept: Option<&str>,
    ) -> Result<aioduct::Response, LayerhouseError> {
        self.retry_with_body(
            upstream,
            RetryRequest {
                method,
                url,
                accept,
                content_type: None,
                body: None,
                scope: UpstreamScope::Pull,
            },
        )
        .await
    }

    async fn retry_with_body(
        &self,
        upstream: &UpstreamRef,
        request: RetryRequest<'_>,
    ) -> Result<aioduct::Response, LayerhouseError> {
        let key = Self::cache_key(upstream, request.scope);
        let mut last_err: Option<LayerhouseError> = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                backoff(attempt - 1).await;
            }

            let http = self.http(upstream).await?;
            let builder = http
                .request(request.method.clone(), request.url)
                .map_err(|e| LayerhouseError::Upstream(e.to_string()))?;
            let builder = if let Some(accept_val) = request.accept {
                builder
                    .header_str("accept", accept_val)
                    .map_err(|e| LayerhouseError::Upstream(e.to_string()))?
            } else {
                builder
            };
            let builder = self.apply_auth(builder, &key).await;
            let builder = if let Some(content_type_val) = request.content_type {
                builder
                    .header_str("content-type", content_type_val)
                    .map_err(|e| LayerhouseError::Upstream(e.to_string()))?
            } else {
                builder
            };
            let builder = if let Some(body) = &request.body {
                builder.body(body.clone())
            } else {
                builder
            };

            tracing::debug!(
                method = %request.method,
                url = %request.url,
                proxy = %upstream.outbound_proxy.protocol != OutboundProxyProtocol::None,
                attempt = attempt,
                "upstream request",
            );

            let resp = match builder.send().await {
                Ok(r) => r,
                Err(e) => {
                    if is_retryable_err(&e) && attempt < MAX_RETRIES {
                        tracing::warn!("upstream retry {}/{}: {}", attempt + 1, MAX_RETRIES, e);
                        last_err = Some(LayerhouseError::Upstream(e.to_string()));
                        continue;
                    }
                    return Err(LayerhouseError::Upstream(e.to_string()));
                }
            };

            if resp.status() == StatusCode::UNAUTHORIZED && attempt < MAX_RETRIES {
                if self.refresh_auth(upstream, request.scope).await.is_err() {
                    tracing::warn!("upstream auth refresh failed");
                }
                last_err = Some(LayerhouseError::Upstream("401 Unauthorized".into()));
                continue;
            }

            if is_retryable(resp.status()) && attempt < MAX_RETRIES {
                tracing::warn!(
                    "upstream retry {}/{}: HTTP {}",
                    attempt + 1,
                    MAX_RETRIES,
                    resp.status()
                );
                last_err = Some(LayerhouseError::Upstream(format!("HTTP {}", resp.status())));
                continue;
            }

            return Ok(resp);
        }

        Err(last_err.unwrap_or_else(|| LayerhouseError::Upstream("max retries exceeded".into())))
    }

    pub async fn head_manifest(
        &self,
        upstream: &UpstreamRef,
        reference: &str,
    ) -> Result<Option<(String, String)>, LayerhouseError> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            upstream.base_url(),
            upstream.repository,
            reference
        );
        let resp = self
            .retry(upstream, http::Method::HEAD, &url, Some(MANIFEST_ACCEPT))
            .await?;

        match resp.status() {
            StatusCode::OK => {
                let digest = resp
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                Ok(Some((digest, ct)))
            }
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(LayerhouseError::Upstream(format!(
                "HEAD manifest {} failed: {}",
                reference, s
            ))),
        }
    }

    pub async fn get_manifest(
        &self,
        upstream: &UpstreamRef,
        reference: &str,
    ) -> Result<ManifestData, LayerhouseError> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            upstream.base_url(),
            upstream.repository,
            reference
        );
        let resp = self
            .retry(upstream, http::Method::GET, &url, Some(MANIFEST_ACCEPT))
            .await?
            .error_for_status()
            .map_err(|e| LayerhouseError::Upstream(format!("GET manifest {}: {}", reference, e)))?;

        let digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .to_string();
        let body = resp
            .bytes()
            .await
            .map_err(|e| LayerhouseError::Upstream(format!("GET manifest body: {}", e)))?
            .to_vec();

        Ok(ManifestData {
            body,
            content_type,
            digest,
        })
    }

    pub async fn get_blob(
        &self,
        upstream: &UpstreamRef,
        digest: &str,
    ) -> Result<aioduct::Response, LayerhouseError> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            upstream.base_url(),
            upstream.repository,
            digest
        );
        self.retry(upstream, http::Method::GET, &url, None)
            .await?
            .error_for_status()
            .map_err(|e| LayerhouseError::Upstream(format!("GET blob {}: {}", digest, e)))
    }

    pub async fn head_blob(
        &self,
        upstream: &UpstreamRef,
        digest: &str,
    ) -> Result<bool, LayerhouseError> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            upstream.base_url(),
            upstream.repository,
            digest
        );
        let resp = self.retry(upstream, http::Method::HEAD, &url, None).await?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(LayerhouseError::Upstream(format!(
                "HEAD blob {} failed: {}",
                digest, s
            ))),
        }
    }

    pub async fn put_manifest(
        &self,
        upstream: &UpstreamRef,
        reference: &str,
        manifest: &[u8],
        content_type: &str,
    ) -> Result<(), LayerhouseError> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            upstream.base_url(),
            upstream.repository,
            reference
        );
        let resp = self
            .retry_with_body(
                upstream,
                RetryRequest {
                    method: http::Method::PUT,
                    url: &url,
                    accept: None,
                    content_type: Some(content_type),
                    body: Some(Bytes::copy_from_slice(manifest)),
                    scope: UpstreamScope::PushPull,
                },
            )
            .await?;

        match resp.status() {
            StatusCode::CREATED | StatusCode::ACCEPTED | StatusCode::OK => Ok(()),
            s => Err(LayerhouseError::Upstream(format!(
                "PUT manifest {} failed: {}",
                reference, s
            ))),
        }
    }

    pub async fn push_blob_stream(
        &self,
        upstream: &UpstreamRef,
        digest: &str,
        size: u64,
        stream: crate::store::blob::ByteStream,
    ) -> Result<(), LayerhouseError> {
        let start_url = format!(
            "{}/v2/{}/blobs/uploads/",
            upstream.base_url(),
            upstream.repository
        );
        let start_resp = self
            .retry_with_body(
                upstream,
                RetryRequest {
                    method: http::Method::POST,
                    url: &start_url,
                    accept: None,
                    content_type: None,
                    body: None,
                    scope: UpstreamScope::PushPull,
                },
            )
            .await?;

        if !matches!(
            start_resp.status(),
            StatusCode::ACCEPTED | StatusCode::CREATED
        ) {
            return Err(LayerhouseError::Upstream(format!(
                "POST blob upload {} failed: {}",
                digest,
                start_resp.status()
            )));
        }

        let upload_location = absolute_location(
            upstream,
            start_resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    LayerhouseError::Upstream("blob upload response missing Location".into())
                })?,
        );

        let upload_url = append_query(&upload_location, "digest", digest);
        let body_stream = stream.map(|chunk| {
            chunk
                .map(hyper::body::Frame::data)
                .map_err(aioduct::Error::Other)
        });
        let request_body = StreamBody::new(body_stream).boxed_unsync();
        let key = Self::cache_key(upstream, UpstreamScope::PushPull);

        let http = self.http(upstream).await?;
        let builder = http
            .put(&upload_url)
            .map_err(|e| LayerhouseError::Upstream(format!("PUT blob upload: {}", e)))?
            .header_str("content-type", "application/octet-stream")
            .map_err(|e| LayerhouseError::Upstream(e.to_string()))?
            .header_str("content-length", &size.to_string())
            .map_err(|e| LayerhouseError::Upstream(e.to_string()))?;
        let builder = self
            .apply_auth(builder, &key)
            .await
            .body_stream(request_body);
        let resp = builder
            .send()
            .await
            .map_err(|e| LayerhouseError::Upstream(format!("PUT blob upload {}: {}", digest, e)))?;

        match resp.status() {
            StatusCode::CREATED | StatusCode::ACCEPTED => Ok(()),
            s => Err(LayerhouseError::Upstream(format!(
                "PUT blob upload {} failed: {}",
                digest, s
            ))),
        }
    }

    pub async fn list_tags(&self, upstream: &UpstreamRef) -> Result<Vec<String>, LayerhouseError> {
        self.ensure_auth(upstream).await?;
        let mut tags = Vec::new();
        let mut last: Option<String> = None;

        let base = upstream.base_url();
        tracing::info!(
            "list_tags: requesting {}/v2/{}/tags/list (proxy={})",
            base,
            upstream.repository,
            upstream.outbound_proxy.protocol != OutboundProxyProtocol::None,
        );

        loop {
            let url = match &last {
                Some(last) => format!(
                    "{}/v2/{}/tags/list?n=100&last={}",
                    upstream.base_url(),
                    upstream.repository,
                    last
                ),
                None => format!(
                    "{}/v2/{}/tags/list?n=100",
                    upstream.base_url(),
                    upstream.repository
                ),
            };
            let resp = self
                .retry(upstream, http::Method::GET, &url, None)
                .await?
                .error_for_status()
                .map_err(|e| LayerhouseError::Upstream(format!("GET tags list: {}", e)))?;
            let body: TagsListResponse = resp
                .json()
                .await
                .map_err(|e| LayerhouseError::Upstream(format!("tags list response: {}", e)))?;
            let page = body.tags.unwrap_or_default();
            if page.is_empty() {
                break;
            }
            last = page.last().cloned();
            let got_full_page = page.len() == 100;
            tags.extend(page);
            if !got_full_page {
                break;
            }
        }

        tags.sort();
        tags.dedup();
        Ok(tags)
    }
}

fn absolute_location(upstream: &UpstreamRef, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        format!("{}{}", upstream.base_url(), location)
    } else {
        format!("{}/{}", upstream.base_url(), location)
    }
}

fn append_query(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{}{}{}={}", url, sep, key, value)
}

pub fn is_index_manifest(content_type: &str) -> bool {
    matches!(
        content_type,
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

pub fn extract_blob_descriptors(manifest: &serde_json::Value) -> Vec<BlobDescriptor> {
    let mut blobs = Vec::new();

    if let Some(config) = manifest.get("config")
        && let (Some(digest), Some(size)) = (
            config.get("digest").and_then(|d| d.as_str()),
            config.get("size").and_then(|s| s.as_u64()),
        )
    {
        blobs.push(BlobDescriptor {
            digest: digest.to_string(),
            size,
        });
    }

    if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let (Some(digest), Some(size)) = (
                layer.get("digest").and_then(|d| d.as_str()),
                layer.get("size").and_then(|s| s.as_u64()),
            ) {
                blobs.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size,
                });
            }
        }
    }

    blobs
}

pub fn extract_child_manifests(index: &serde_json::Value) -> Vec<BlobDescriptor> {
    let mut children = Vec::new();
    if let Some(manifests) = index.get("manifests").and_then(|m| m.as_array()) {
        for m in manifests {
            if let (Some(digest), Some(size)) = (
                m.get("digest").and_then(|d| d.as_str()),
                m.get("size").and_then(|s| s.as_u64()),
            ) {
                children.push(BlobDescriptor {
                    digest: digest.to_string(),
                    size,
                });
            }
        }
    }
    children
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::metadata::OutboundProxy;

    #[test]
    fn upstream_ref_uses_plain_http_when_requested() {
        let upstream = UpstreamRef::new(
            "registry.example.com",
            "team/app",
            true,
            false,
            OutboundProxy::default(),
            None,
            None,
        );

        assert_eq!(upstream.scheme, "http");
        assert!(!upstream.insecure_tls);
    }

    #[test]
    fn upstream_ref_uses_https_for_insecure_tls_even_on_localhost() {
        let upstream = UpstreamRef::new(
            "localhost:5443",
            "team/app",
            false,
            true,
            OutboundProxy::default(),
            None,
            None,
        );

        assert_eq!(upstream.scheme, "https");
        assert!(upstream.insecure_tls);
    }

    #[test]
    fn upstream_cache_key_distinguishes_insecure_tls() {
        let secure = UpstreamRef::new(
            "registry.example.com",
            "team/app",
            false,
            false,
            OutboundProxy::default(),
            None,
            None,
        );
        let insecure = UpstreamRef::new(
            "registry.example.com",
            "team/app",
            false,
            true,
            OutboundProxy::default(),
            None,
            None,
        );

        assert_ne!(
            UpstreamClient::cache_key(&secure, UpstreamScope::Pull),
            UpstreamClient::cache_key(&insecure, UpstreamScope::Pull)
        );
    }
}
