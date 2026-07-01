use std::time::{Duration, Instant};

use http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, FORWARDED, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use http_body_util::{BodyExt, Limited};
use thiserror::Error;
use wasmtime_wasi_http::DEFAULT_FORBIDDEN_HEADERS;
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, default_send_request};

pub(crate) const DIRECTORY_HTTP_HEADER_LIMIT_BYTES: usize = 16 * 1024;
pub(crate) const DIRECTORY_HTTP_BODY_LIMIT_BYTES: usize = 1024 * 1024;
const DIRECTORY_HTTP_BODY_CHUNK_LIMIT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct DirectoryHttpPolicy {
    allowed_origin: Option<AllowedOrigin>,
    authorization: Option<HeaderValue>,
    header_limit_bytes: usize,
    body_limit_bytes: usize,
}

#[derive(Clone, Debug)]
struct AllowedOrigin {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
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
            header_limit_bytes: DIRECTORY_HTTP_HEADER_LIMIT_BYTES,
            body_limit_bytes: DIRECTORY_HTTP_BODY_LIMIT_BYTES,
        }
    }

    pub(crate) fn for_connector_origin(
        base_origin: &str,
        api_token: &str,
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

        Ok(Self {
            allowed_origin: Some(AllowedOrigin { scheme, authority }),
            authorization: Some(authorization),
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
        Ok(default_send_request(request, config))
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

    use bytes::Bytes;
    use http::header::HeaderName;
    use http_body_util::Empty;

    use super::*;

    fn policy() -> DirectoryHttpPolicy {
        DirectoryHttpPolicy::for_connector_origin("https://kanidm.example.test:8443", "secret")
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
}
