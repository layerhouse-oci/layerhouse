mod http_host;
mod startup;
mod test_api;
mod wasm;

use async_trait::async_trait;
use thiserror::Error;

pub(crate) use startup::{DirectoryStartupError, validate_directory_startup};

pub const ERROR_MESSAGE_LIMIT_BYTES: usize = 512;

#[async_trait]
pub trait DirectoryConnector: Send + Sync {
    async fn connector_info(&self) -> Result<ConnectorInfo, DirectoryError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorInfo {
    pub name: String,
    pub version: String,
    pub provider: String,
    pub abi_version: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DirectoryError {
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    #[error("unsupported provider: {0}")]
    UnsupportedProvider(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("upstream unauthorized: {0}")]
    UpstreamUnauthorized(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("internal connector error: {0}")]
    Internal(String),
}

pub(crate) fn sanitize_connector_error_message(raw: &str) -> String {
    let normalized = raw
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();

    let mut sanitized = if contains_sensitive_context(&normalized) {
        "connector error contained redacted sensitive context".to_string()
    } else {
        redact_url_queries(&redact_bearer_tokens(&normalized))
    };

    truncate_at_utf8_boundary(&mut sanitized, ERROR_MESSAGE_LIMIT_BYTES);
    if sanitized.is_empty() {
        "connector error".to_string()
    } else {
        sanitized
    }
}

fn contains_sensitive_context(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "authorization:",
        "cookie:",
        "set-cookie:",
        "request body:",
        "response body:",
        "debug dump",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn redact_bearer_tokens(message: &str) -> String {
    let mut words = message.split_whitespace().peekable();
    let mut redacted = Vec::new();

    while let Some(word) = words.next() {
        redacted.push(word.to_string());
        if word.eq_ignore_ascii_case("bearer") && words.peek().is_some() {
            let _ = words.next();
            redacted.push("[redacted]".to_string());
        }
    }

    redacted.join(" ")
}

fn redact_url_queries(message: &str) -> String {
    message
        .split_whitespace()
        .map(|word| {
            if (word.starts_with("https://") || word.starts_with("http://")) && word.contains('?') {
                let base = word.split_once('?').map(|(base, _)| base).unwrap_or(word);
                format!("{base}?[redacted]")
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_at_utf8_boundary(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }

    let mut boundary = limit;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::test_api::{SearchFilter, TlsMode};
    use super::*;

    #[test]
    fn sanitizes_control_chars_and_outer_whitespace() {
        let message = sanitize_connector_error_message(" \ninvalid\tquery\r ");
        assert_eq!(message, "invalid query");
    }

    #[test]
    fn sanitizes_sensitive_context() {
        let message = sanitize_connector_error_message(
            "Authorization: Bearer secret-token response body: {}",
        );
        assert_eq!(
            message,
            "connector error contained redacted sensitive context"
        );
    }

    #[test]
    fn caps_sanitized_message_at_utf8_boundary() {
        let raw = format!("{}é", "a".repeat(ERROR_MESSAGE_LIMIT_BYTES - 1));
        let message = sanitize_connector_error_message(&raw);
        assert_eq!(message.len(), ERROR_MESSAGE_LIMIT_BYTES - 1);
        assert!(message.is_char_boundary(message.len()));
    }

    #[test]
    fn host_types_cover_mvp_variants() {
        let tls_modes = [
            TlsMode::PlainHttp,
            TlsMode::SystemRoots,
            TlsMode::CustomCa,
            TlsMode::InsecureSkipVerify,
        ];
        assert_eq!(tls_modes.len(), 4);

        let filter = SearchFilter::ExactLocalId("alice".to_string());
        assert!(matches!(filter, SearchFilter::ExactLocalId(_)));
    }
}
