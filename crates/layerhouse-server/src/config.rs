use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::principal::ProviderId;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("HOSTNAME env var not set; must be <prefix>-<N>")]
    HostnameNotSet,
    #[error("HOSTNAME '{0}' must contain a dash followed by a number (e.g. layerhouse-0)")]
    HostnameNoDash(String),
    #[error(
        "HOSTNAME '{hostname}' trailing segment '{segment}' is not a number; expected <prefix>-<N>"
    )]
    HostnameNotNumeric { hostname: String, segment: String },
    #[error("failed to read config file: {0}")]
    ReadFile(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseToml(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub raft: RaftConfig,
    #[serde(default)]
    pub gc: GcConfig,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_provider_name")]
    pub provider_name: String,
    pub issuer_url: String,
    #[serde(default)]
    pub issuer_internal_url: Option<String>,
    #[serde(default)]
    pub issuer_internal_urls: Vec<String>,
    #[serde(default)]
    pub jwks_urls: Vec<String>,
    pub client_id: String,
    pub client_secret: String,
    pub token_endpoint_url: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    #[serde(default = "default_jwks_refresh_seconds")]
    pub jwks_refresh_seconds: u64,
    #[serde(default = "default_jwks_cache_s3_key")]
    pub jwks_cache_s3_key: String,
    #[serde(default = "default_jwks_max_stale_seconds")]
    pub jwks_max_stale_seconds: u64,
    pub token_signing_keys: Vec<String>,
    pub session_encryption_key: String,
    pub permissions: Vec<PermissionMapping>,
    #[serde(default = "default_cookie_secure_mode")]
    pub cookie_secure_mode: CookieSecureMode,
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    #[serde(default = "default_login_scopes")]
    pub login_scopes: String,
    #[serde(default)]
    pub access_token_audience: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CookieSecureMode {
    Auto,
    Enabled,
    Disabled,
}

fn default_cookie_secure_mode() -> CookieSecureMode {
    CookieSecureMode::Auto
}

fn default_group_claim() -> String {
    "groups".to_string()
}

fn default_provider_name() -> String {
    "oidc".to_string()
}

pub fn default_login_scopes() -> String {
    "openid profile email groups".to_string()
}

impl AuthConfig {
    pub fn issuer_internal_url(&self) -> &str {
        self.issuer_internal_url
            .as_deref()
            .unwrap_or(&self.issuer_url)
    }

    pub fn issuer_internal_urls(&self) -> Vec<&str> {
        let urls: Vec<&str> = self
            .issuer_internal_urls
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect();
        if urls.is_empty() {
            vec![self.issuer_internal_url()]
        } else {
            urls
        }
    }

    pub fn jwks_urls(&self) -> Vec<&str> {
        self.jwks_urls
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect()
    }

    /// Returns `None` when `access_token_audience` is empty or unset,
    /// signalling "fall back to client_id". An explicit non-empty value
    /// is returned as `Some`.
    pub fn effective_access_token_audience(&self) -> Option<&str> {
        self.access_token_audience
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PermissionMapping {
    pub name: String,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
}

fn default_jwks_refresh_seconds() -> u64 {
    300
}

fn default_jwks_cache_s3_key() -> String {
    "auth/jwks/last-good.json".to_string()
}

fn default_jwks_max_stale_seconds() -> u64 {
    24 * 60 * 60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcConfig {
    #[serde(default = "default_gc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_gc_grace_period")]
    pub grace_period_secs: u64,
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_gc_interval(),
            grace_period_secs: default_gc_grace_period(),
            dry_run: false,
        }
    }
}

fn default_gc_interval() -> u64 {
    3600
}

fn default_gc_grace_period() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_concurrent_uploads")]
    pub max_concurrent_uploads: usize,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_uploads: default_max_concurrent_uploads(),
            max_concurrent_requests: default_max_concurrent_requests(),
        }
    }
}

fn default_max_concurrent_uploads() -> usize {
    64
}

fn default_max_concurrent_requests() -> usize {
    512
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub s3: S3Config,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub redirect: S3RedirectConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3RedirectConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub public_endpoint: String,
    #[serde(default = "default_redirect_expires_secs")]
    pub expires_secs: u64,
}

fn default_listen() -> String {
    "0.0.0.0:5050".to_string()
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_redirect_expires_secs() -> u64 {
    900
}

impl Default for S3RedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_endpoint: String::new(),
            expires_secs: default_redirect_expires_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RaftConfig {
    #[serde(default = "default_raft_listen")]
    pub listen: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    pub discovery_dns: String,
    #[serde(default)]
    pub tls: Option<RaftTlsConfig>,
    #[serde(default)]
    pub kubernetes: RaftKubernetesConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RaftTlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub server_ca_path: String,
    pub client_ca_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RaftKubernetesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub statefulset_name: String,
    #[serde(default = "default_kubernetes_reconcile_seconds")]
    pub reconcile_seconds: u64,
}

impl Default for RaftKubernetesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            namespace: String::new(),
            statefulset_name: String::new(),
            reconcile_seconds: default_kubernetes_reconcile_seconds(),
        }
    }
}

fn default_raft_listen() -> String {
    "0.0.0.0:5051".to_string()
}

fn default_data_dir() -> String {
    "/tmp/raft".to_string()
}

fn default_kubernetes_reconcile_seconds() -> u64 {
    2
}

/// Parse node ID from HOSTNAME env var.
/// Expects format `<prefix>-<N>` where N is a non-negative integer.
/// Returns ordinal + 1 (so layerhouse-0 → node_id 1).
pub fn resolve_node_id() -> Result<u64, ConfigError> {
    let hostname = std::env::var("HOSTNAME").map_err(|_| ConfigError::HostnameNotSet)?;
    if !hostname.contains('-') {
        return Err(ConfigError::HostnameNoDash(hostname));
    }
    let ordinal_str = hostname.rsplit('-').next().unwrap_or("");
    let ordinal: u64 = ordinal_str
        .parse()
        .map_err(|_| ConfigError::HostnameNotNumeric {
            hostname: hostname.clone(),
            segment: ordinal_str.to_string(),
        })?;
    Ok(ordinal + 1)
}

/// Build the advertise address from HOSTNAME and the raft listen port.
/// LAYERHOUSE_RAFT_ADVERTISE_HOST can override the host portion when pods need
/// to advertise a DNS name that differs from HOSTNAME.
/// e.g. HOSTNAME=layerhouse-0 + port 5051 -> "layerhouse-0:5051"
pub fn resolve_advertise_addr(listen: &str) -> Result<String, ConfigError> {
    let hostname = std::env::var("LAYERHOUSE_RAFT_ADVERTISE_HOST")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map_err(|_| ConfigError::HostnameNotSet)?;
    let port = listen.rsplit(':').next().unwrap_or("5051");
    Ok(format!("{}:{}", hostname, port))
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.storage.s3.redirect.enabled
            && self.storage.s3.redirect.public_endpoint.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "storage.s3.redirect.public_endpoint is required when redirect is enabled"
                    .to_string(),
            ));
        }
        if let Some(tls) = &self.server.tls
            && (tls.cert_path.trim().is_empty() || tls.key_path.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "server.tls.cert_path and server.tls.key_path are required when server.tls is set"
                    .to_string(),
            ));
        }
        if listeners_conflict(&self.server.listen, &self.raft.listen) {
            return Err(ConfigError::Invalid(
                "server.listen and raft.listen must use different bind addresses".to_string(),
            ));
        }
        if let Some(tls) = &self.raft.tls
            && (tls.cert_path.trim().is_empty()
                || tls.key_path.trim().is_empty()
                || tls.server_ca_path.trim().is_empty()
                || tls.client_ca_path.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "raft.tls.cert_path, raft.tls.key_path, raft.tls.server_ca_path, and raft.tls.client_ca_path are required when raft.tls is set"
                    .to_string(),
            ));
        }
        if self.raft.kubernetes.enabled {
            if self.raft.kubernetes.namespace.trim().is_empty()
                || self.raft.kubernetes.statefulset_name.trim().is_empty()
            {
                return Err(ConfigError::Invalid(
                    "raft.kubernetes.namespace and raft.kubernetes.statefulset_name are required when raft.kubernetes.enabled is true"
                        .to_string(),
                ));
            }
            if self.raft.kubernetes.reconcile_seconds == 0 {
                return Err(ConfigError::Invalid(
                    "raft.kubernetes.reconcile_seconds must be greater than zero".to_string(),
                ));
            }
        }
        if let Some(auth) = &self.auth {
            validate_auth_config(auth)?;
        }
        Ok(())
    }

    pub fn default_dev() -> Self {
        if std::env::var("HOSTNAME").is_err() {
            // SAFETY: called before tokio runtime starts, single-threaded at this point
            unsafe { std::env::set_var("HOSTNAME", "layerhouse-0") };
        }
        Config {
            server: ServerConfig {
                listen: default_listen(),
                limits: LimitsConfig::default(),
                tls: None,
            },
            storage: StorageConfig {
                s3: S3Config {
                    endpoint: "http://localhost:9000".to_string(),
                    bucket: "layerhouse".to_string(),
                    region: default_region(),
                    access_key: "rustfsadmin".to_string(),
                    secret_key: "rustfsadmin".to_string(),
                    path_style: true,
                    redirect: S3RedirectConfig::default(),
                },
            },
            raft: RaftConfig {
                listen: default_raft_listen(),
                data_dir: default_data_dir(),
                discovery_dns: "localhost".to_string(),
                tls: None,
                kubernetes: RaftKubernetesConfig::default(),
            },
            gc: GcConfig::default(),
            auth: None,
        }
    }
}

fn listeners_conflict(left: &str, right: &str) -> bool {
    match (
        left.parse::<std::net::SocketAddr>(),
        right.parse::<std::net::SocketAddr>(),
    ) {
        (Ok(left), Ok(right)) => {
            left.port() == right.port()
                && (left.ip() == right.ip()
                    || left.ip().is_unspecified()
                    || right.ip().is_unspecified())
        }
        _ => left == right,
    }
}

fn validate_auth_config(auth: &AuthConfig) -> Result<(), ConfigError> {
    if auth.issuer_url.trim().is_empty()
        || auth.client_id.trim().is_empty()
        || auth.client_secret.trim().is_empty()
        || auth.token_endpoint_url.trim().is_empty()
        || auth.redirect_uri.trim().is_empty()
    {
        return Err(ConfigError::Invalid(
            "auth.issuer_url, auth.client_id, auth.client_secret, auth.token_endpoint_url, and auth.redirect_uri are required when auth is set"
                .to_string(),
        ));
    }

    if auth
        .issuer_internal_urls
        .iter()
        .any(|url| url.trim().is_empty())
    {
        return Err(ConfigError::Invalid(
            "auth.issuer_internal_urls must not contain empty entries".to_string(),
        ));
    }
    if auth.jwks_urls.iter().any(|url| url.trim().is_empty()) {
        return Err(ConfigError::Invalid(
            "auth.jwks_urls must not contain empty entries".to_string(),
        ));
    }
    if auth.jwks_refresh_seconds == 0 {
        return Err(ConfigError::Invalid(
            "auth.jwks_refresh_seconds must be greater than zero".to_string(),
        ));
    }
    if auth.jwks_cache_s3_key.trim().is_empty() || auth.jwks_cache_s3_key.starts_with('/') {
        return Err(ConfigError::Invalid(
            "auth.jwks_cache_s3_key must be a non-empty relative S3 key".to_string(),
        ));
    }
    if auth.jwks_max_stale_seconds == 0 {
        return Err(ConfigError::Invalid(
            "auth.jwks_max_stale_seconds must be greater than zero".to_string(),
        ));
    }

    if auth.token_signing_keys.is_empty() {
        return Err(ConfigError::Invalid(
            "auth.token_signing_keys must contain at least one base64-encoded key".to_string(),
        ));
    }
    for (idx, key) in auth.token_signing_keys.iter().enumerate() {
        base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|e| {
                ConfigError::Invalid(format!("auth.token_signing_keys[{idx}] is not base64: {e}"))
            })?;
    }

    let session_key = base64::engine::general_purpose::STANDARD
        .decode(&auth.session_encryption_key)
        .map_err(|e| {
            ConfigError::Invalid(format!("auth.session_encryption_key is not base64: {e}"))
        })?;
    if session_key.len() != 32 {
        return Err(ConfigError::Invalid(format!(
            "auth.session_encryption_key must decode to 32 bytes, got {}",
            session_key.len()
        )));
    }

    if auth.group_claim.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "auth.group_claim must not be empty".to_string(),
        ));
    }
    ProviderId::new(&auth.provider_name)
        .map_err(|err| ConfigError::Invalid(format!("auth.provider_name is invalid: {err}")))?;
    if auth.login_scopes.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "auth.login_scopes must not be empty".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn base_config() -> Config {
        Config {
            server: ServerConfig {
                listen: default_listen(),
                limits: LimitsConfig::default(),
                tls: None,
            },
            storage: StorageConfig {
                s3: S3Config {
                    endpoint: "http://localhost:9000".to_string(),
                    bucket: "layerhouse".to_string(),
                    region: default_region(),
                    access_key: "access".to_string(),
                    secret_key: "secret".to_string(),
                    path_style: true,
                    redirect: S3RedirectConfig::default(),
                },
            },
            raft: RaftConfig {
                listen: default_raft_listen(),
                data_dir: default_data_dir(),
                discovery_dns: "layerhouse".to_string(),
                tls: None,
                kubernetes: RaftKubernetesConfig::default(),
            },
            gc: GcConfig::default(),
            auth: None,
        }
    }

    #[test]
    fn server_tls_validates_required_paths() {
        let mut config = base_config();
        config.server.tls = Some(ServerTlsConfig {
            cert_path: "/certs/tls.crt".to_string(),
            key_path: "/certs/tls.key".to_string(),
        });
        assert!(config.validate().is_ok());

        config.server.tls = Some(ServerTlsConfig {
            cert_path: String::new(),
            key_path: "/certs/tls.key".to_string(),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn public_and_raft_listeners_must_be_distinct() {
        let mut config = base_config();
        config.raft.listen = config.server.listen.clone();

        assert!(config.validate().is_err());

        config.raft.listen = "0.0.0.0:5051".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn raft_tls_validates_required_paths() {
        let mut config = base_config();
        config.raft.tls = Some(RaftTlsConfig {
            cert_path: "/certs/raft/tls.crt".to_string(),
            key_path: "/certs/raft/tls.key".to_string(),
            server_ca_path: "/certs/raft/ca.crt".to_string(),
            client_ca_path: "/certs/raft/ca.crt".to_string(),
        });
        assert!(config.validate().is_ok());

        config.raft.tls = Some(RaftTlsConfig {
            cert_path: "/certs/raft/tls.crt".to_string(),
            key_path: "/certs/raft/tls.key".to_string(),
            server_ca_path: String::new(),
            client_ca_path: "/certs/raft/ca.crt".to_string(),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn kubernetes_reconcile_validates_required_fields() {
        let mut config = base_config();
        config.raft.kubernetes.enabled = true;
        assert!(config.validate().is_err());

        config.raft.kubernetes.namespace = "layerhouse".to_string();
        config.raft.kubernetes.statefulset_name = "layerhouse".to_string();
        assert!(config.validate().is_ok());

        config.raft.kubernetes.reconcile_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn auth_validates_signing_and_session_keys() {
        let mut config = base_config();
        config.auth = Some(AuthConfig {
            provider_name: "kanidm".to_string(),
            issuer_url: "https://idp.example.test".to_string(),
            issuer_internal_url: None,
            issuer_internal_urls: Vec::new(),
            jwks_urls: Vec::new(),
            client_id: "layerhouse".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint_url: "https://idp.example.test/oauth2/token".to_string(),
            redirect_uri: "https://registry.example.test/oauth2/callback".to_string(),
            tls_insecure_skip_verify: false,
            jwks_refresh_seconds: 300,
            jwks_cache_s3_key: "auth/jwks/last-good.json".to_string(),
            jwks_max_stale_seconds: 86_400,
            token_signing_keys: vec![base64::engine::general_purpose::STANDARD.encode(b"signing")],
            session_encryption_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            permissions: Vec::new(),
            cookie_secure_mode: CookieSecureMode::Auto,
            group_claim: "groups".to_string(),
            login_scopes: "openid profile email groups".to_string(),
            access_token_audience: None,
        });
        assert!(config.validate().is_ok());

        config.auth.as_mut().unwrap().token_signing_keys.clear();
        assert!(config.validate().is_err());

        config.auth.as_mut().unwrap().token_signing_keys = vec!["not-base64".to_string()];
        assert!(config.validate().is_err());

        config.auth.as_mut().unwrap().token_signing_keys =
            vec![base64::engine::general_purpose::STANDARD.encode(b"signing")];
        config.auth.as_mut().unwrap().session_encryption_key =
            base64::engine::general_purpose::STANDARD.encode([1u8; 31]);
        assert!(config.validate().is_err());
    }

    #[test]
    fn auth_provider_name_uses_principal_provider_grammar() {
        let mut config = base_config();
        config.auth = Some(AuthConfig {
            provider_name: "kanidm-prod_1".to_string(),
            issuer_url: "https://idp.example.test".to_string(),
            issuer_internal_url: None,
            issuer_internal_urls: Vec::new(),
            jwks_urls: Vec::new(),
            client_id: "layerhouse".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint_url: "https://idp.example.test/oauth2/token".to_string(),
            redirect_uri: "https://registry.example.test/oauth2/callback".to_string(),
            tls_insecure_skip_verify: false,
            jwks_refresh_seconds: 300,
            jwks_cache_s3_key: "auth/jwks/last-good.json".to_string(),
            jwks_max_stale_seconds: 86_400,
            token_signing_keys: vec![base64::engine::general_purpose::STANDARD.encode(b"signing")],
            session_encryption_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            permissions: Vec::new(),
            cookie_secure_mode: CookieSecureMode::Auto,
            group_claim: "groups".to_string(),
            login_scopes: "openid profile email groups".to_string(),
            access_token_audience: None,
        });
        assert!(config.validate().is_ok());

        config.auth.as_mut().unwrap().provider_name = "Kanidm".to_string();
        assert!(config.validate().is_err());

        config.auth.as_mut().unwrap().provider_name = "1kanidm".to_string();
        assert!(config.validate().is_err());

        config.auth.as_mut().unwrap().provider_name = "kanidm.example".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn auth_internal_issuer_list_prefers_ordered_list() {
        let auth = AuthConfig {
            provider_name: "kanidm".to_string(),
            issuer_url: "https://idp.example.test".to_string(),
            issuer_internal_url: Some("https://legacy.internal".to_string()),
            issuer_internal_urls: vec![
                "https://idp-a.internal".to_string(),
                "https://idp-b.internal".to_string(),
            ],
            jwks_urls: vec!["https://jwks-a.internal/key.jwk".to_string()],
            client_id: "layerhouse".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint_url: "https://idp.example.test/oauth2/token".to_string(),
            redirect_uri: "https://registry.example.test/oauth2/callback".to_string(),
            tls_insecure_skip_verify: false,
            jwks_refresh_seconds: 300,
            jwks_cache_s3_key: "auth/jwks/last-good.json".to_string(),
            jwks_max_stale_seconds: 86_400,
            token_signing_keys: vec![base64::engine::general_purpose::STANDARD.encode(b"signing")],
            session_encryption_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            permissions: Vec::new(),
            cookie_secure_mode: CookieSecureMode::Auto,
            group_claim: "groups".to_string(),
            login_scopes: "openid profile email groups".to_string(),
            access_token_audience: None,
        };

        assert_eq!(
            auth.issuer_internal_urls(),
            vec!["https://idp-a.internal", "https://idp-b.internal"]
        );
        assert_eq!(auth.jwks_urls(), vec!["https://jwks-a.internal/key.jwk"]);
    }
}
