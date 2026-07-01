use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, FORWARDED, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use http_body_util::{BodyExt, Limited};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use wasmtime_wasi_http::DEFAULT_FORBIDDEN_HEADERS;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::types::{DnsErrorPayload, ErrorCode};
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, hyper_request_error};

pub(crate) const DIRECTORY_HTTP_HEADER_LIMIT_BYTES: usize = 16 * 1024;
pub(crate) const DIRECTORY_HTTP_BODY_LIMIT_BYTES: usize = 1024 * 1024;
const DIRECTORY_HTTP_BODY_CHUNK_LIMIT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct DirectoryHttpPolicy {
    allowed_origin: Option<AllowedOrigin>,
    authorization: Option<HeaderValue>,
    tls_policy: DirectoryTlsPolicy,
    header_limit_bytes: usize,
    body_limit_bytes: usize,
}

#[derive(Clone, Debug)]
struct AllowedOrigin {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
}

#[derive(Clone, Debug)]
pub(crate) enum DirectoryHttpTlsConfig {
    SystemRoots,
    CustomCaPem(Vec<u8>),
    InsecureSkipVerify,
}

#[derive(Clone, Debug)]
enum DirectoryTlsPolicy {
    PlainHttp,
    Tls(Arc<ClientConfig>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum DirectoryHttpPolicyError {
    #[error("directory connector HTTP egress is not configured")]
    EgressNotConfigured,
    #[error("directory connector base origin is invalid")]
    InvalidBaseOrigin,
    #[error("directory connector API token cannot be used as an authorization header")]
    InvalidAuthorizationHeader,
    #[error("directory connector HTTP request origin is not allowed")]
    OriginMismatch,
    #[error("directory connector HTTP request TLS mode does not match its origin")]
    TlsMismatch,
    #[error("directory connector TLS trust settings are invalid for its origin")]
    InvalidTlsTrust,
    #[error("directory connector custom CA bundle is invalid")]
    InvalidCaBundle,
    #[error("directory connector HTTP request contains forbidden header {0}")]
    ForbiddenHeader(String),
    #[error("directory connector HTTP request host header is invalid")]
    InvalidHostHeader,
    #[error("directory connector HTTP request content-length is invalid")]
    InvalidContentLength,
    #[error(
        "directory connector HTTP request headers are too large: {actual} bytes, max {max} bytes"
    )]
    HeadersTooLarge { actual: usize, max: usize },
    #[error("directory connector HTTP request body is too large: {actual} bytes, max {max} bytes")]
    BodyTooLarge { actual: usize, max: usize },
    #[error("directory connector HTTP request exceeded the connector call timeout")]
    TimeoutBudgetExpired,
}

impl DirectoryHttpPolicy {
    #[cfg(test)]
    pub(crate) fn deny_all() -> Self {
        Self {
            allowed_origin: None,
            authorization: None,
            tls_policy: DirectoryTlsPolicy::PlainHttp,
            header_limit_bytes: DIRECTORY_HTTP_HEADER_LIMIT_BYTES,
            body_limit_bytes: DIRECTORY_HTTP_BODY_LIMIT_BYTES,
        }
    }

    pub(crate) fn for_connector_origin(
        base_origin: &str,
        api_token: &str,
        tls_config: DirectoryHttpTlsConfig,
    ) -> Result<Self, DirectoryHttpPolicyError> {
        if base_origin != base_origin.trim() || base_origin.contains('#') {
            return Err(DirectoryHttpPolicyError::InvalidBaseOrigin);
        }
        let Some((_, authority_text)) = base_origin.split_once("://") else {
            return Err(DirectoryHttpPolicyError::InvalidBaseOrigin);
        };
        if authority_text.is_empty() || authority_text.contains('/') || authority_text.contains('?')
        {
            return Err(DirectoryHttpPolicyError::InvalidBaseOrigin);
        }

        let uri = base_origin
            .parse::<Uri>()
            .map_err(|_| DirectoryHttpPolicyError::InvalidBaseOrigin)?;
        let scheme = uri
            .scheme()
            .cloned()
            .ok_or(DirectoryHttpPolicyError::InvalidBaseOrigin)?;
        let authority = uri
            .authority()
            .cloned()
            .ok_or(DirectoryHttpPolicyError::InvalidBaseOrigin)?;
        let has_explicit_path_or_query = match uri.path_and_query().map(|value| value.as_str()) {
            None | Some("/") => false,
            Some(_) => true,
        };
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || has_explicit_path_or_query
            || authority.as_str().contains('@')
        {
            return Err(DirectoryHttpPolicyError::InvalidBaseOrigin);
        }

        let authorization = HeaderValue::from_str(&format!("Bearer {api_token}"))
            .map_err(|_| DirectoryHttpPolicyError::InvalidAuthorizationHeader)?;
        if authorization.as_bytes().is_empty()
            || api_token.is_empty()
            || api_token.chars().any(char::is_whitespace)
        {
            return Err(DirectoryHttpPolicyError::InvalidAuthorizationHeader);
        }
        if projected_authorized_header_bytes(0, &authorization) > DIRECTORY_HTTP_HEADER_LIMIT_BYTES
        {
            return Err(DirectoryHttpPolicyError::HeadersTooLarge {
                actual: projected_authorized_header_bytes(0, &authorization),
                max: DIRECTORY_HTTP_HEADER_LIMIT_BYTES,
            });
        }
        let tls_policy = DirectoryTlsPolicy::from_origin(uri.scheme_str(), tls_config)?;

        Ok(Self {
            allowed_origin: Some(AllowedOrigin { scheme, authority }),
            authorization: Some(authorization),
            tls_policy,
            header_limit_bytes: DIRECTORY_HTTP_HEADER_LIMIT_BYTES,
            body_limit_bytes: DIRECTORY_HTTP_BODY_LIMIT_BYTES,
        })
    }

    fn is_forbidden_guest_header(&self, name: &HeaderName) -> bool {
        if DEFAULT_FORBIDDEN_HEADERS.contains(name) {
            return true;
        }

        let name = name.as_str();
        name == AUTHORIZATION.as_str()
            || name == COOKIE.as_str()
            || name == FORWARDED.as_str()
            || name.starts_with("proxy-")
            || name.starts_with("x-forwarded-")
    }

    fn validate_origin(
        &self,
        uri: &Uri,
        config: &OutgoingRequestConfig,
        headers: &HeaderMap,
    ) -> Result<(), DirectoryHttpPolicyError> {
        let allowed = self
            .allowed_origin
            .as_ref()
            .ok_or(DirectoryHttpPolicyError::EgressNotConfigured)?;
        if uri.scheme() != Some(&allowed.scheme) || uri.authority() != Some(&allowed.authority) {
            return Err(DirectoryHttpPolicyError::OriginMismatch);
        }

        let expects_tls = allowed.scheme == http::uri::Scheme::HTTPS;
        if config.use_tls != expects_tls {
            return Err(DirectoryHttpPolicyError::TlsMismatch);
        }

        if let Some(host) = headers.get(HOST) {
            let host = host
                .to_str()
                .map_err(|_| DirectoryHttpPolicyError::InvalidHostHeader)?;
            if !host.eq_ignore_ascii_case(allowed.authority.as_str()) {
                return Err(DirectoryHttpPolicyError::OriginMismatch);
            }
        }

        Ok(())
    }

    fn validate_headers(&self, headers: &HeaderMap) -> Result<usize, DirectoryHttpPolicyError> {
        for name in headers.keys() {
            if name == HOST {
                continue;
            }
            if self.is_forbidden_guest_header(name) {
                return Err(DirectoryHttpPolicyError::ForbiddenHeader(
                    name.as_str().to_string(),
                ));
            }
        }

        let header_bytes = header_bytes(headers);
        if header_bytes > self.header_limit_bytes {
            return Err(DirectoryHttpPolicyError::HeadersTooLarge {
                actual: header_bytes,
                max: self.header_limit_bytes,
            });
        }

        Ok(header_bytes)
    }

    fn validate_content_length(&self, headers: &HeaderMap) -> Result<(), DirectoryHttpPolicyError> {
        let mut lengths = headers.get_all(CONTENT_LENGTH).iter();
        let Some(length) = lengths.next() else {
            return Ok(());
        };
        if lengths.next().is_some() {
            return Err(DirectoryHttpPolicyError::InvalidContentLength);
        }

        let length = length
            .to_str()
            .map_err(|_| DirectoryHttpPolicyError::InvalidContentLength)?
            .parse::<usize>()
            .map_err(|_| DirectoryHttpPolicyError::InvalidContentLength)?;
        if length > self.body_limit_bytes {
            return Err(DirectoryHttpPolicyError::BodyTooLarge {
                actual: length,
                max: self.body_limit_bytes,
            });
        }

        Ok(())
    }
}

impl DirectoryTlsPolicy {
    fn from_origin(
        scheme: Option<&str>,
        tls_config: DirectoryHttpTlsConfig,
    ) -> Result<Self, DirectoryHttpPolicyError> {
        match (scheme, tls_config) {
            (Some("http"), DirectoryHttpTlsConfig::SystemRoots) => Ok(Self::PlainHttp),
            (Some("http"), _) => Err(DirectoryHttpPolicyError::InvalidTlsTrust),
            (Some("https"), DirectoryHttpTlsConfig::SystemRoots) => Ok(Self::Tls(Arc::new(
                system_roots_client_config()
                    .map_err(|_| DirectoryHttpPolicyError::InvalidTlsTrust)?,
            ))),
            (Some("https"), DirectoryHttpTlsConfig::CustomCaPem(pem)) => {
                Ok(Self::Tls(Arc::new(custom_ca_client_config(&pem)?)))
            }
            (Some("https"), DirectoryHttpTlsConfig::InsecureSkipVerify) => Ok(Self::Tls(Arc::new(
                insecure_skip_verify_client_config()
                    .map_err(|_| DirectoryHttpPolicyError::InvalidTlsTrust)?,
            ))),
            _ => Err(DirectoryHttpPolicyError::InvalidBaseOrigin),
        }
    }
}

fn system_roots_client_config() -> Result<ClientConfig, rustls::Error> {
    let root_cert_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    )
}

fn custom_ca_client_config(pem: &[u8]) -> Result<ClientConfig, DirectoryHttpPolicyError> {
    let mut reader = BufReader::new(pem);
    let mut certificates = Vec::new();
    loop {
        match rustls_pemfile::read_one(&mut reader)
            .map_err(|_| DirectoryHttpPolicyError::InvalidCaBundle)?
        {
            Some(rustls_pemfile::Item::X509Certificate(cert)) => certificates.push(cert),
            Some(_) => return Err(DirectoryHttpPolicyError::InvalidCaBundle),
            None => break,
        }
    }
    if certificates.is_empty() {
        return Err(DirectoryHttpPolicyError::InvalidCaBundle);
    }

    let mut root_cert_store = RootCertStore::empty();
    let (valid, invalid) = root_cert_store.add_parsable_certificates(certificates);
    if valid == 0 || invalid > 0 {
        return Err(DirectoryHttpPolicyError::InvalidCaBundle);
    }

    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| DirectoryHttpPolicyError::InvalidTlsTrust)?
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    )
}

fn insecure_skip_verify_client_config() -> Result<ClientConfig, rustls::Error> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DirectoryHttpHooks {
    policy: DirectoryHttpPolicy,
    call_started: Instant,
    call_timeout: Duration,
}

impl DirectoryHttpHooks {
    pub(crate) fn new(policy: DirectoryHttpPolicy, call_timeout: Duration) -> Self {
        Self {
            policy,
            call_started: Instant::now(),
            call_timeout,
        }
    }

    pub(crate) fn header_limit_bytes(&self) -> usize {
        self.policy.header_limit_bytes
    }

    pub(crate) fn prepare_request(
        &self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> Result<(hyper::Request<HyperOutgoingBody>, OutgoingRequestConfig), DirectoryHttpPolicyError>
    {
        let remaining = self
            .call_timeout
            .checked_sub(self.call_started.elapsed())
            .ok_or(DirectoryHttpPolicyError::TimeoutBudgetExpired)?;
        if remaining.is_zero() {
            return Err(DirectoryHttpPolicyError::TimeoutBudgetExpired);
        }

        self.policy
            .validate_origin(request.uri(), &config, request.headers())?;
        self.policy.validate_content_length(request.headers())?;
        let header_bytes = self.policy.validate_headers(request.headers())?;
        let authorization = self
            .policy
            .authorization
            .as_ref()
            .ok_or(DirectoryHttpPolicyError::EgressNotConfigured)?;

        let projected = projected_authorized_header_bytes(header_bytes, authorization);
        if projected > self.policy.header_limit_bytes {
            return Err(DirectoryHttpPolicyError::HeadersTooLarge {
                actual: projected,
                max: self.policy.header_limit_bytes,
            });
        }

        let (mut parts, body) = request.into_parts();
        parts.headers.insert(AUTHORIZATION, authorization.clone());
        let body = Limited::new(body, self.policy.body_limit_bytes)
            .map_err(|_| ErrorCode::HttpProtocolError)
            .boxed_unsync();

        Ok((
            hyper::Request::from_parts(parts, body),
            OutgoingRequestConfig {
                use_tls: config.use_tls,
                connect_timeout: cap_timeout(config.connect_timeout, remaining),
                first_byte_timeout: cap_timeout(config.first_byte_timeout, remaining),
                between_bytes_timeout: cap_timeout(config.between_bytes_timeout, remaining),
            },
        ))
    }
}

impl WasiHttpHooks for DirectoryHttpHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let (request, config) = self
            .prepare_request(request, config)
            .map_err(directory_policy_error_code)?;
        let tls_policy = self.policy.tls_policy.clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(send_request_with_tls_policy(request, config, tls_policy).await)
        });
        Ok(HostFutureIncomingResponse::pending(handle))
    }

    fn is_forbidden_header(&mut self, name: &HeaderName) -> bool {
        self.policy.is_forbidden_guest_header(name)
    }

    fn outgoing_body_buffer_chunks(&mut self) -> usize {
        1
    }

    fn outgoing_body_chunk_size(&mut self) -> usize {
        DIRECTORY_HTTP_BODY_CHUNK_LIMIT_BYTES.min(self.policy.body_limit_bytes)
    }
}

async fn send_request_with_tls_policy(
    mut request: hyper::Request<HyperOutgoingBody>,
    OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    }: OutgoingRequestConfig,
    tls_policy: DirectoryTlsPolicy,
) -> Result<IncomingResponse, ErrorCode> {
    let authority = request
        .uri()
        .authority()
        .ok_or(ErrorCode::HttpRequestUriInvalid)?
        .clone();
    let connect_authority = match authority.port() {
        Some(_) => authority.to_string(),
        None if use_tls => format!("{}:443", authority.as_str()),
        None => format!("{}:80", authority.as_str()),
    };

    let tcp_stream = timeout(connect_timeout, TcpStream::connect(&connect_authority))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(tcp_error_code)?;

    let (mut sender, worker) = if use_tls {
        let DirectoryTlsPolicy::Tls(client_config) = tls_policy else {
            return Err(ErrorCode::TlsProtocolError);
        };
        let server_name = ServerName::try_from(authority.host().to_string())
            .map_err(|_| dns_error("invalid dns name"))?;
        let connector = TlsConnector::from(client_config);
        let stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|err| {
                tracing::warn!("directory connector TLS protocol error: {err:?}");
                ErrorCode::TlsProtocolError
            })?;
        let stream = TokioIo::new(stream);

        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(stream),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!("directory connector HTTP connection error: {err}");
            }
        });
        (sender, worker)
    } else {
        let stream = TokioIo::new(tcp_stream);
        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(stream),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!("directory connector HTTP connection error: {err}");
            }
        });
        (sender, worker)
    };

    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(path_and_query)
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;

    let resp = timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(hyper_request_error)?
        .map(|body| body.map_err(hyper_request_error).boxed_unsync());

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout,
    })
}

fn tcp_error_code(error: std::io::Error) -> ErrorCode {
    if error.kind() == std::io::ErrorKind::AddrNotAvailable
        || error
            .to_string()
            .starts_with("failed to lookup address information")
    {
        dns_error("address not available")
    } else {
        ErrorCode::ConnectionRefused
    }
}

fn dns_error(message: impl Into<String>) -> ErrorCode {
    ErrorCode::DnsError(DnsErrorPayload {
        rcode: Some(message.into()),
        info_code: Some(0),
    })
}

fn cap_timeout(timeout: Duration, cap: Duration) -> Duration {
    if timeout > cap { cap } else { timeout }
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum()
}

fn projected_authorized_header_bytes(existing: usize, authorization: &HeaderValue) -> usize {
    existing + AUTHORIZATION.as_str().len() + authorization.as_bytes().len()
}

fn directory_policy_error_code(error: DirectoryHttpPolicyError) -> ErrorCode {
    match error {
        DirectoryHttpPolicyError::TimeoutBudgetExpired => ErrorCode::ConnectionTimeout,
        DirectoryHttpPolicyError::EgressNotConfigured
        | DirectoryHttpPolicyError::InvalidBaseOrigin
        | DirectoryHttpPolicyError::InvalidAuthorizationHeader
        | DirectoryHttpPolicyError::OriginMismatch
        | DirectoryHttpPolicyError::TlsMismatch
        | DirectoryHttpPolicyError::InvalidTlsTrust
        | DirectoryHttpPolicyError::InvalidCaBundle
        | DirectoryHttpPolicyError::ForbiddenHeader(_)
        | DirectoryHttpPolicyError::InvalidHostHeader
        | DirectoryHttpPolicyError::InvalidContentLength
        | DirectoryHttpPolicyError::HeadersTooLarge { .. }
        | DirectoryHttpPolicyError::BodyTooLarge { .. } => ErrorCode::HttpProtocolError,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http::header::HeaderName;
    use http_body_util::{Empty, Full};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::ServerConfig;
    use time::{Duration as TimeDuration, OffsetDateTime};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn policy() -> DirectoryHttpPolicy {
        DirectoryHttpPolicy::for_connector_origin(
            "https://kanidm.example.test:8443",
            "secret",
            DirectoryHttpTlsConfig::SystemRoots,
        )
        .unwrap()
    }

    fn hooks() -> DirectoryHttpHooks {
        DirectoryHttpHooks::new(policy(), Duration::from_millis(2_000))
    }

    fn config(use_tls: bool) -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls,
            connect_timeout: Duration::from_secs(600),
            first_byte_timeout: Duration::from_secs(600),
            between_bytes_timeout: Duration::from_secs(600),
        }
    }

    fn empty_body() -> HyperOutgoingBody {
        Empty::<Bytes>::new()
            .map_err(|never: Infallible| match never {})
            .boxed_unsync()
    }

    fn request(uri: &'static str) -> hyper::Request<HyperOutgoingBody> {
        hyper::Request::builder()
            .uri(uri)
            .header(HOST, "kanidm.example.test:8443")
            .body(empty_body())
            .unwrap()
    }

    fn request_with_host(uri: String, host: String) -> hyper::Request<HyperOutgoingBody> {
        hyper::Request::builder()
            .uri(uri)
            .header(HOST, host)
            .body(empty_body())
            .unwrap()
    }

    fn expect_policy_error(
        result: Result<
            (hyper::Request<HyperOutgoingBody>, OutgoingRequestConfig),
            DirectoryHttpPolicyError,
        >,
    ) -> DirectoryHttpPolicyError {
        match result {
            Ok(_) => panic!("expected directory HTTP policy error"),
            Err(error) => error,
        }
    }

    #[test]
    fn directory_http_host_injects_authorization_after_policy_checks() {
        let (request, config) = hooks()
            .prepare_request(
                request("https://kanidm.example.test:8443/api/person?name=alice"),
                config(true),
            )
            .unwrap();

        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer secret"
        );
        assert_eq!(
            request.uri().to_string(),
            "https://kanidm.example.test:8443/api/person?name=alice"
        );
        assert!(config.connect_timeout <= Duration::from_millis(2_000));
        assert!(config.first_byte_timeout <= Duration::from_millis(2_000));
        assert!(config.between_bytes_timeout <= Duration::from_millis(2_000));
    }

    #[test]
    fn directory_http_host_rejects_wrong_origin_and_tls_mode() {
        let wrong_origin = expect_policy_error(hooks().prepare_request(
            request("https://evil.example.test/api/person"),
            config(true),
        ));
        assert_eq!(wrong_origin, DirectoryHttpPolicyError::OriginMismatch);

        let wrong_tls = expect_policy_error(hooks().prepare_request(
            request("https://kanidm.example.test:8443/api/person"),
            config(false),
        ));
        assert_eq!(wrong_tls, DirectoryHttpPolicyError::TlsMismatch);
    }

    #[test]
    fn directory_http_host_rejects_forbidden_headers() {
        let mut hooks = hooks();
        for name in [
            AUTHORIZATION,
            COOKIE,
            FORWARDED,
            HeaderName::from_static("proxy-authorization"),
            HeaderName::from_static("x-forwarded-for"),
        ] {
            assert!(hooks.is_forbidden_header(&name));

            let mut request = request("https://kanidm.example.test:8443/api/person");
            request
                .headers_mut()
                .insert(name.clone(), "blocked".parse().unwrap());
            let error = expect_policy_error(hooks.prepare_request(request, config(true)));
            assert_eq!(
                error,
                DirectoryHttpPolicyError::ForbiddenHeader(name.as_str().to_string())
            );
        }
    }

    #[test]
    fn directory_http_host_rejects_oversized_headers_and_declared_body() {
        let mut overlong_header = request("https://kanidm.example.test:8443/api/person");
        overlong_header.headers_mut().insert(
            HeaderName::from_static("x-layerhouse-test"),
            "a".repeat(DIRECTORY_HTTP_HEADER_LIMIT_BYTES)
                .parse()
                .unwrap(),
        );
        let header_error =
            expect_policy_error(hooks().prepare_request(overlong_header, config(true)));
        assert!(matches!(
            header_error,
            DirectoryHttpPolicyError::HeadersTooLarge { .. }
        ));

        let mut overlong_body = request("https://kanidm.example.test:8443/api/person");
        overlong_body.headers_mut().insert(
            CONTENT_LENGTH,
            (DIRECTORY_HTTP_BODY_LIMIT_BYTES + 1)
                .to_string()
                .parse()
                .unwrap(),
        );
        let body_error = expect_policy_error(hooks().prepare_request(overlong_body, config(true)));
        assert_eq!(
            body_error,
            DirectoryHttpPolicyError::BodyTooLarge {
                actual: DIRECTORY_HTTP_BODY_LIMIT_BYTES + 1,
                max: DIRECTORY_HTTP_BODY_LIMIT_BYTES,
            }
        );
    }

    #[test]
    fn directory_http_host_caps_timeouts_to_remaining_call_budget() {
        let hooks = DirectoryHttpHooks {
            policy: policy(),
            call_started: Instant::now() - Duration::from_millis(1_900),
            call_timeout: Duration::from_millis(2_000),
        };
        let (_, config) = hooks
            .prepare_request(
                request("https://kanidm.example.test:8443/api/person"),
                config(true),
            )
            .unwrap();

        assert!(config.connect_timeout <= Duration::from_millis(100));
        assert!(config.first_byte_timeout <= Duration::from_millis(100));
        assert!(config.between_bytes_timeout <= Duration::from_millis(100));
    }

    #[test]
    fn directory_http_host_deny_all_policy_rejects_before_injection() {
        let hooks = DirectoryHttpHooks::new(
            DirectoryHttpPolicy::deny_all(),
            Duration::from_millis(2_000),
        );
        let error = expect_policy_error(hooks.prepare_request(
            request("https://kanidm.example.test:8443/api/person"),
            config(true),
        ));

        assert_eq!(error, DirectoryHttpPolicyError::EgressNotConfigured);
    }

    #[test]
    fn directory_http_host_rejects_ca_config_for_plain_http() {
        let error = DirectoryHttpPolicy::for_connector_origin(
            "http://kanidm.example.test:8080",
            "secret",
            DirectoryHttpTlsConfig::InsecureSkipVerify,
        )
        .unwrap_err();

        assert_eq!(error, DirectoryHttpPolicyError::InvalidTlsTrust);
    }

    #[test]
    fn directory_http_host_rejects_invalid_custom_ca() {
        let error = DirectoryHttpPolicy::for_connector_origin(
            "https://kanidm.example.test:8443",
            "secret",
            DirectoryHttpTlsConfig::CustomCaPem(b"not pem".to_vec()),
        )
        .unwrap_err();

        assert_eq!(error, DirectoryHttpPolicyError::InvalidCaBundle);
    }

    #[test]
    fn directory_http_host_accepts_insecure_tls_for_https() {
        DirectoryHttpPolicy::for_connector_origin(
            "https://kanidm.example.test:8443",
            "secret",
            DirectoryHttpTlsConfig::InsecureSkipVerify,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn directory_http_host_sends_https_with_custom_ca() {
        let tls = test_tls_config("localhost");
        let (base_origin, authorization_rx) = spawn_tls_http_server(tls.server_config).await;
        let policy = DirectoryHttpPolicy::for_connector_origin(
            &base_origin,
            "secret",
            DirectoryHttpTlsConfig::CustomCaPem(tls.ca_pem),
        )
        .unwrap();

        let hooks = DirectoryHttpHooks::new(policy, Duration::from_millis(2_000));
        let authority = base_origin.trim_start_matches("https://").to_string();
        let (request, config) = hooks
            .prepare_request(
                request_with_host(format!("{base_origin}/api/person"), authority),
                config(true),
            )
            .unwrap();
        let response =
            send_request_with_tls_policy(request, config, hooks.policy.tls_policy.clone())
                .await
                .unwrap();

        assert_eq!(response.resp.status(), http::StatusCode::OK);
        let authorization = tokio::time::timeout(Duration::from_secs(1), authorization_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authorization.as_deref(), Some("Bearer secret"));
    }

    #[tokio::test]
    async fn directory_http_host_sends_https_with_insecure_tls() {
        let tls = test_tls_config("localhost");
        let (base_origin, authorization_rx) = spawn_tls_http_server(tls.server_config).await;
        let policy = DirectoryHttpPolicy::for_connector_origin(
            &base_origin,
            "secret",
            DirectoryHttpTlsConfig::InsecureSkipVerify,
        )
        .unwrap();

        let hooks = DirectoryHttpHooks::new(policy, Duration::from_millis(2_000));
        let authority = base_origin.trim_start_matches("https://").to_string();
        let (request, config) = hooks
            .prepare_request(
                request_with_host(format!("{base_origin}/api/person"), authority),
                config(true),
            )
            .unwrap();
        let response =
            send_request_with_tls_policy(request, config, hooks.policy.tls_policy.clone())
                .await
                .unwrap();

        assert_eq!(response.resp.status(), http::StatusCode::OK);
        let authorization = tokio::time::timeout(Duration::from_secs(1), authorization_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authorization.as_deref(), Some("Bearer secret"));
    }

    struct TestTlsConfig {
        ca_pem: Vec<u8>,
        server_config: ServerConfig,
    }

    fn test_tls_config(host: &str) -> TestTlsConfig {
        let now = OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params =
            CertificateParams::new(vec!["layerhouse-test-ca.local".to_string()]).unwrap();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "layerhouse-test-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params.not_before = now - TimeDuration::days(1);
        ca_params.not_after = now + TimeDuration::days(30);
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec![host.to_string()]).unwrap();
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = now - TimeDuration::days(1);
        leaf_params.not_after = now + TimeDuration::days(30);
        let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

        let leaf_pem = leaf.pem();
        let mut cert_reader = BufReader::new(leaf_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key_pem = leaf_key.serialize_pem();
        let mut key_reader = BufReader::new(key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .unwrap()
            .unwrap();
        let server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();

        TestTlsConfig {
            ca_pem: ca.pem().into_bytes(),
            server_config,
        }
    }

    async fn spawn_tls_http_server(
        server_config: ServerConfig,
    ) -> (String, oneshot::Receiver<Option<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (authorization_tx, authorization_rx) = oneshot::channel();
        let authorization_tx = Arc::new(Mutex::new(Some(authorization_tx)));
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            let authorization_tx = authorization_tx.clone();
            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let authorization_tx = authorization_tx.clone();
                    async move {
                        let authorization = request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .map(ToString::to_string);
                        if let Some(sender) = authorization_tx.lock().unwrap().take() {
                            let _ = sender.send(authorization);
                        }
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                            b"ok",
                        ))))
                    }
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        (
            format!("https://localhost:{}", addr.port()),
            authorization_rx,
        )
    }
}
