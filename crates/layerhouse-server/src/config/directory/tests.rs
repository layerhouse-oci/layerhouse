use std::path::{Path, PathBuf};

use super::{DirectoryConfig, validate_directory_config};
use crate::config::ConfigError;

fn base_directory_config() -> DirectoryConfig {
    DirectoryConfig {
        enabled: true,
        component_path: Some("connectors/kanidm-directory-connector.wasm".to_string()),
        component_sha256: Some(format!("sha256:{}", "a".repeat(64))),
        base_origin: Some("https://kanidm.example.test:8443".to_string()),
        api_token_file: Some("secrets/kanidm-directory-token".to_string()),
        tls_ca_file: None,
        tls_insecure_skip_verify: false,
        timeout_ms: None,
        max_concurrent_calls: None,
        memory_limit_bytes: None,
    }
}

fn config_dir() -> &'static Path {
    Path::new("/etc/layerhouse")
}

fn assert_directory_config_invalid(mut directory: DirectoryConfig, expected: &str) {
    directory.enabled = true;
    match validate_directory_config(&directory, Some(config_dir())) {
        Err(ConfigError::Invalid(message)) => {
            assert!(
                message.contains(expected),
                "expected error containing {expected:?}, got {message:?}"
            );
        }
        other => panic!("expected invalid config, got {other:?}"),
    }
}

#[test]
fn directory_config_disabled_is_allowed_without_connector_fields() {
    let directory = DirectoryConfig {
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
    };

    assert!(validate_directory_config(&directory, None).is_ok());
}

#[test]
fn directory_config_enabled_requires_explicit_connector_fields() {
    let mut directory = base_directory_config();
    directory.component_path = None;
    assert_directory_config_invalid(directory, "auth.directory.component_path");

    let mut directory = base_directory_config();
    directory.component_sha256 = None;
    assert_directory_config_invalid(directory, "auth.directory.component_sha256");

    let mut directory = base_directory_config();
    directory.base_origin = None;
    assert_directory_config_invalid(directory, "auth.directory.base_origin");

    let mut directory = base_directory_config();
    directory.api_token_file = None;
    assert_directory_config_invalid(directory, "auth.directory.api_token_file");
}

#[test]
fn directory_config_checksum_requires_oci_sha256() {
    for invalid in [
        "a".repeat(64),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
        "sha256:not-hex".to_string(),
    ] {
        let mut directory = base_directory_config();
        directory.component_sha256 = Some(invalid);
        assert_directory_config_invalid(directory, "sha256:<64 lowercase hex>");
    }

    let directory = base_directory_config();
    assert!(validate_directory_config(&directory, Some(config_dir())).is_ok());
}

#[test]
fn directory_config_paths_resolve_relative_to_config_dir() {
    let directory = base_directory_config();
    assert_eq!(
        directory
            .resolve_component_path(Some(config_dir()))
            .unwrap(),
        Some(config_dir().join("connectors/kanidm-directory-connector.wasm"))
    );
    assert_eq!(
        directory
            .resolve_api_token_file(Some(config_dir()))
            .unwrap(),
        Some(config_dir().join("secrets/kanidm-directory-token"))
    );

    let mut directory = base_directory_config();
    directory.component_path = Some("/opt/layerhouse/connectors/kanidm.wasm".to_string());
    assert_eq!(
        directory
            .resolve_component_path(Some(config_dir()))
            .unwrap(),
        Some(PathBuf::from("/opt/layerhouse/connectors/kanidm.wasm"))
    );
}

#[test]
fn directory_config_relative_paths_require_config_dir_when_enabled() {
    let directory = base_directory_config();
    assert!(validate_directory_config(&directory, Some(config_dir())).is_ok());
    assert!(validate_directory_config(&directory, None).is_err());

    let mut directory = base_directory_config();
    directory.component_path = Some("/opt/layerhouse/connectors/kanidm.wasm".to_string());
    directory.api_token_file = Some("/run/secrets/kanidm-token".to_string());
    directory.tls_ca_file = Some("/etc/ssl/private-ca.pem".to_string());
    assert!(validate_directory_config(&directory, None).is_ok());
}

#[test]
fn directory_config_base_origin_requires_plain_origin() {
    for invalid in [
        "kanidm.example.test",
        "ftp://kanidm.example.test",
        "https://user@kanidm.example.test",
        "https://kanidm.example.test/",
        "https://kanidm.example.test/oauth2",
        "https://kanidm.example.test?debug=true",
        "https://kanidm.example.test#fragment",
        " https://kanidm.example.test",
    ] {
        let mut directory = base_directory_config();
        directory.base_origin = Some(invalid.to_string());
        assert_directory_config_invalid(directory, "auth.directory.base_origin");
    }

    for valid in ["https://kanidm.example.test", "http://127.0.0.1:8443"] {
        let mut directory = base_directory_config();
        directory.base_origin = Some(valid.to_string());
        assert!(validate_directory_config(&directory, Some(config_dir())).is_ok());
    }
}

#[test]
fn directory_config_tls_rules_follow_base_origin() {
    let mut directory = base_directory_config();
    directory.base_origin = Some("http://kanidm.example.test".to_string());
    directory.tls_insecure_skip_verify = true;
    assert_directory_config_invalid(directory, "tls_insecure_skip_verify");

    let mut directory = base_directory_config();
    directory.base_origin = Some("http://kanidm.example.test".to_string());
    directory.tls_ca_file = Some("certs/kanidm-ca.pem".to_string());
    assert_directory_config_invalid(directory, "tls_ca_file");

    let mut directory = base_directory_config();
    directory.tls_ca_file = Some("certs/kanidm-ca.pem".to_string());
    assert!(validate_directory_config(&directory, Some(config_dir())).is_ok());

    let mut directory = base_directory_config();
    directory.tls_ca_file = Some("certs/kanidm-ca.pem".to_string());
    directory.tls_insecure_skip_verify = true;
    assert_directory_config_invalid(directory, "mutually exclusive");
}

#[test]
fn directory_config_defaults_and_positive_limits() {
    let mut directory = base_directory_config();
    assert_eq!(directory.timeout_ms(), 2_000);
    assert_eq!(directory.max_concurrent_calls(), 8);
    assert_eq!(directory.memory_limit_bytes(), 64 * 1024 * 1024);

    directory.timeout_ms = Some(1);
    directory.max_concurrent_calls = Some(1);
    directory.memory_limit_bytes = Some(1);
    assert!(validate_directory_config(&directory, Some(config_dir())).is_ok());

    let mut directory = base_directory_config();
    directory.timeout_ms = Some(0);
    assert_directory_config_invalid(directory, "timeout_ms");

    let mut directory = base_directory_config();
    directory.max_concurrent_calls = Some(0);
    assert_directory_config_invalid(directory, "max_concurrent_calls");

    let mut directory = base_directory_config();
    directory.memory_limit_bytes = Some(0);
    assert_directory_config_invalid(directory, "memory_limit_bytes");
}

#[test]
fn directory_config_rejects_unknown_sha256_file_field() {
    let result = toml::from_str::<DirectoryConfig>(
        r#"
enabled = true
component_sha256_file = "connectors/kanidm-directory-connector.wasm.sha256"
"#,
    );

    assert!(result.is_err());
}
