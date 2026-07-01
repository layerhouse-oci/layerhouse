use std::path::{Path, PathBuf};

use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};

use super::*;
use crate::config::{
    CookieSecureMode, GcConfig, LimitsConfig, RaftConfig, RaftKubernetesConfig, S3Config,
    S3RedirectConfig, ServerConfig, StorageConfig,
};

fn base_directory_config(dir: &Path, component_bytes: &[u8]) -> DirectoryConfig {
    std::fs::write(dir.join("connector.wasm"), component_bytes).unwrap();
    std::fs::write(dir.join("token"), "kanidm-token\n").unwrap();
    DirectoryConfig {
        enabled: true,
        component_path: Some("connector.wasm".to_string()),
        component_sha256: Some(sha256_digest(component_bytes)),
        base_origin: Some("https://kanidm.example.test".to_string()),
        api_token_file: Some("token".to_string()),
        tls_ca_file: None,
        tls_insecure_skip_verify: false,
        timeout_ms: None,
        max_concurrent_calls: None,
        memory_limit_bytes: None,
    }
}

fn config_with_directory(directory: DirectoryConfig) -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:5000".to_string(),
            limits: LimitsConfig::default(),
            tls: None,
        },
        storage: StorageConfig {
            s3: S3Config {
                endpoint: "http://localhost:9000".to_string(),
                bucket: "layerhouse".to_string(),
                region: "us-east-1".to_string(),
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                path_style: true,
                redirect: S3RedirectConfig::default(),
            },
        },
        raft: RaftConfig {
            listen: "127.0.0.1:5051".to_string(),
            data_dir: "./data".to_string(),
            discovery_dns: "layerhouse".to_string(),
            tls: None,
            kubernetes: RaftKubernetesConfig::default(),
        },
        gc: GcConfig::default(),
        auth: Some(AuthConfig {
            provider_name: "kanidm".to_string(),
            issuer_url: "https://idp.example.test".to_string(),
            issuer_internal_url: None,
            issuer_internal_urls: Vec::new(),
            jwks_urls: Vec::new(),
            client_id: "layerhouse".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint_url: "https://idp.example.test/oauth2/token".to_string(),
            redirect_uri: "https://registry.example.test/oauth2/callback".to_string(),
            logout_url: None,
            tls_insecure_skip_verify: false,
            jwks_refresh_seconds: 300,
            jwks_cache_s3_key: "auth/jwks/last-good.json".to_string(),
            jwks_max_stale_seconds: 86_400,
            token_signing_keys: vec![base64::engine::general_purpose::STANDARD.encode(b"signing")],
            session_encryption_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            policy_sets: Vec::new(),
            cookie_secure_mode: CookieSecureMode::Auto,
            group_claim: "groups".to_string(),
            login_scopes: "openid profile email groups".to_string(),
            access_token_audience: None,
            directory: Some(directory),
        }),
    }
}

#[tokio::test]
async fn directory_startup_skips_when_auth_or_directory_is_disabled() {
    let no_auth = Config {
        auth: None,
        ..config_with_directory(DirectoryConfig {
            enabled: true,
            component_path: None,
            component_sha256: None,
            base_origin: None,
            api_token_file: None,
            tls_ca_file: None,
            tls_insecure_skip_verify: false,
            timeout_ms: None,
            max_concurrent_calls: None,
            memory_limit_bytes: None,
        })
    };
    validate_directory_startup(&no_auth, None).await.unwrap();

    let disabled_directory = config_with_directory(DirectoryConfig {
        enabled: false,
        component_path: None,
        component_sha256: None,
        base_origin: None,
        api_token_file: None,
        tls_ca_file: None,
        tls_insecure_skip_verify: false,
        timeout_ms: None,
        max_concurrent_calls: None,
        memory_limit_bytes: None,
    });
    validate_directory_startup(&disabled_directory, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn directory_startup_rejects_digest_mismatch_before_component_load() {
    let temp = TempDir::new().unwrap();
    let mut directory = base_directory_config(temp.path(), b"not a component");
    directory.component_sha256 = Some(format!("sha256:{}", "a".repeat(64)));
    let config = config_with_directory(directory);

    let error = validate_directory_startup(&config, Some(temp.path()))
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("auth.directory.component_sha256 mismatch"));
    assert!(error.contains("expected sha256:"));
    assert!(error.contains("actual sha256:"));
}

#[tokio::test]
async fn directory_startup_rejects_token_header_content() {
    let temp = TempDir::new().unwrap();
    let directory = base_directory_config(temp.path(), b"not a component");
    std::fs::write(temp.path().join("token"), "Bearer secret\n").unwrap();
    let config = config_with_directory(directory);

    let error = validate_directory_startup(&config, Some(temp.path()))
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("raw token value"));
    assert!(!error.contains("secret"));
}

#[test]
fn directory_startup_allows_one_final_token_line_ending_only() {
    let temp = TempDir::new().unwrap();
    let token_file = temp.path().join("token");
    std::fs::write(&token_file, "kanidm-token\r\n").unwrap();
    validate_api_token_file(&token_file).unwrap();

    std::fs::write(&token_file, "kanidm-token\n\n").unwrap();
    let error = validate_api_token_file(&token_file)
        .unwrap_err()
        .to_string();
    assert!(error.contains("must not contain whitespace"));
}

#[test]
fn directory_startup_rejects_empty_and_private_key_ca_files() {
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    std::fs::write(&ca_file, "").unwrap();
    let empty = validate_tls_ca_file(&ca_file).unwrap_err().to_string();
    assert!(empty.contains("must not be empty"));

    let key = KeyPair::generate().unwrap();
    std::fs::write(&ca_file, key.serialize_pem()).unwrap();
    let private_key = validate_tls_ca_file(&ca_file).unwrap_err().to_string();
    assert!(private_key.contains("must not contain private keys"));
}

#[test]
fn directory_startup_accepts_pem_ca_bundle() {
    let temp = TempDir::new().unwrap();
    let ca_file = temp.path().join("ca.pem");
    std::fs::write(&ca_file, test_ca_pem()).unwrap();

    validate_tls_ca_file(&ca_file).unwrap();
}

#[test]
fn directory_startup_rejects_bad_connector_metadata() {
    let empty_name = ConnectorInfo {
        name: String::new(),
        version: "0.0.3".to_string(),
        provider: "kanidm".to_string(),
        abi_version: EXPECTED_ABI_VERSION.to_string(),
    };
    assert!(validate_connector_info(&empty_name).is_err());

    let bad_abi = ConnectorInfo {
        name: "Kanidm Directory".to_string(),
        version: "0.0.3".to_string(),
        provider: "kanidm".to_string(),
        abi_version: "0.0.2".to_string(),
    };
    let error = validate_connector_info(&bad_abi).unwrap_err().to_string();
    assert!(error.contains("ABI version mismatch"));

    let bad_provider = ConnectorInfo {
        name: "Kanidm Directory".to_string(),
        version: "0.0.3".to_string(),
        provider: "Kanidm".to_string(),
        abi_version: EXPECTED_ABI_VERSION.to_string(),
    };
    let error = validate_connector_info(&bad_provider)
        .unwrap_err()
        .to_string();
    assert!(error.contains("principal provider"));
}

#[tokio::test]
async fn directory_startup_validates_fake_component_when_available() {
    let Some(fake_component_path) = fake_component_path() else {
        eprintln!(
            "skipping directory_startup_validates_fake_component_when_available; run `just connector-check`"
        );
        return;
    };
    let bytes = std::fs::read(&fake_component_path).unwrap();
    let temp = TempDir::new().unwrap();
    std::fs::write(temp.path().join("token"), "fake-token\n").unwrap();
    let config = config_with_directory(DirectoryConfig {
        enabled: true,
        component_path: Some(fake_component_path.display().to_string()),
        component_sha256: Some(sha256_digest(&bytes)),
        base_origin: Some("https://fake.example.test".to_string()),
        api_token_file: Some("token".to_string()),
        tls_ca_file: None,
        tls_insecure_skip_verify: false,
        timeout_ms: Some(2_000),
        max_concurrent_calls: Some(4),
        memory_limit_bytes: Some(64 * 1024 * 1024),
    });

    validate_directory_startup(&config, Some(temp.path()))
        .await
        .unwrap();
}

fn fake_component_path() -> Option<PathBuf> {
    std::env::var_os("LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT").map(PathBuf::from)
}

fn test_ca_pem() -> String {
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
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + Duration::days(30);
    CertifiedIssuer::self_signed(ca_params, ca_key)
        .unwrap()
        .pem()
}
